use super::{Broadcastr, normalize_url, retry_with_backoff_endless};
use crate::{Policy, proxied_client_builder, retry_with_backoff};
use anyhow::{self as ah, Context};
use backoff as bf;
use futures::{
    StreamExt,
    future::{join_all, try_join_all},
};
use nostr::{Event, EventId, Filter, RelayUrl, Timestamp, serde_json};
use nostr_sdk::{client::Client as NostrClient, relay::RelayStatus};
use reqwest::{ClientBuilder, Url};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    net::IpAddr,
    ops::Sub,
    sync::Arc,
    time::Instant,
};
use tokio::{
    sync::{RwLock, watch},
    time,
};

#[derive(Debug)]
pub(crate) struct RelayLists {
    pub(crate) read_write: HashSet<Url>,
    pub(crate) read: HashSet<Url>,
    pub(crate) block: HashSet<Url>,
    pub(crate) client_relays: HashSet<RelayUrl>,
}

impl RelayLists {
    pub(crate) async fn new(args: &Broadcastr, nostr_client: &NostrClient) -> ah::Result<Self> {
        let client_relays = nostr_client.relays().await;
        let banned = client_relays
            .values()
            .filter(|i| i.status() == RelayStatus::Banned)
            .map(|i| normalize_url(i.url().as_str().parse()?))
            .collect::<ah::Result<HashSet<Url>>>()?;

        let empty = Default::default();
        let read_write = &args.relays.as_ref().unwrap_or(&empty).0;
        let read = &args.read_relays.as_ref().unwrap_or(&empty).0;
        let block = &args
            .block_relays
            .as_ref()
            .unwrap_or(&empty)
            .0
            .union(&banned)
            .cloned()
            .collect();

        // TODO: if link is down all relays will be blocked?

        let futures = [read_write, read, block]
            .into_iter()
            .map(async |list| Self::fetch_and_parse(list, args).await);
        let mut lists = try_join_all(futures)
            .await?
            .into_iter()
            .collect::<Vec<HashSet<Url>>>();

        let mut block = lists.pop().context("blocked")?;
        let read = lists.pop().context("read")?;
        let read_write = lists.pop().context("read_write")?;

        block.extend(banned);
        let read_write = read_write.sub(&block).sub(&read);
        let read = read.sub(&block);

        Ok(Self {
            read_write,
            read,
            block,
            client_relays: client_relays.into_keys().collect(),
        })
    }

    pub(crate) async fn fetch_and_parse(
        relays_or_relays_lists: &HashSet<Url>,
        args: &Broadcastr,
    ) -> ah::Result<HashSet<Url>> {
        let futures = relays_or_relays_lists
            .iter()
            .map(async |uri| -> ah::Result<_> {
                let result = if ["wss", "ws"].contains(&uri.scheme()) {
                    vec![uri.to_string()]
                } else if uri.scheme() == "file" {
                    serde_json::from_reader(File::open(uri.path())?).map_err(|e| {
                        ah::anyhow!(r#"{}, expected format: ["ws://a","wss://b"]"#, e)
                    })?
                } else if ["https", "http"].contains(&uri.scheme()) {
                    ClientBuilder::new()
                        .connect_timeout(args.connection_timeout.0)
                        .timeout(args.request_timeout.0)
                        .build()?
                        .get(uri.as_ref())
                        .send()
                        .await?
                        .json::<Vec<String>>()
                        .await?
                } else {
                    ah::bail!("unexpected relay item {uri}");
                }
                .into_iter()
                .map(|i| normalize_url(i.parse()?));
                log::debug!("fetched {} relays from {uri}", result.len());
                Ok(result)
            });
        let result = try_join_all(futures)
            .await?
            .into_iter()
            .flatten()
            .collect::<ah::Result<HashSet<Url>>>()?;
        Ok(result)
    }
}
