use crate::relays::Relays;

use super::{Broadcastr, normalize_url};
use anyhow::{self as ah, Context};
use futures::future::try_join_all;
use nostr::{RelayUrl, serde_json};
use nostr_sdk::relay::RelayStatus;
use reqwest::{ClientBuilder, Url};
use std::{collections::HashSet, fs::File, ops::Sub};

#[derive(Debug)]
pub(crate) struct RelayLists {
    pub read_write: HashSet<Url>,
    pub read: HashSet<Url>,
    pub block: HashSet<Url>,
    pub nip66_discovered: HashSet<Url>,
    pub client_relays: HashSet<RelayUrl>,
}

impl RelayLists {
    pub(crate) async fn new(relays: &Relays) -> ah::Result<Self> {
        let args = &relays.args;

        let discovered: HashSet<Url> = {
            let mut locked = relays.nip66_discovered.lock().await;
            let value: HashSet<Url> = locked.clone();
            locked.clear();
            value
        };

        let client_relays = relays.nostr_client.relays().await;
        let nip66_discovered = discovered.sub(
            &client_relays
                .keys()
                .map(|i| normalize_url(i.as_str().parse()?))
                .collect::<ah::Result<HashSet<_>>>()?,
        );

        let banned = client_relays
            .values()
            .filter(|i| i.status() == RelayStatus::Banned)
            .map(|i| normalize_url(i.url().as_str().parse()?))
            .collect::<ah::Result<HashSet<Url>>>()?;

        let empty = Default::default();
        let read_write = &args
            .relays
            .as_ref()
            .unwrap_or(&empty)
            .0
            .union(&nip66_discovered)
            .cloned()
            .collect();
        let read = &args.read_relays.as_ref().unwrap_or(&empty).0;
        let block = &args
            .block_relays
            .as_ref()
            .unwrap_or(&empty)
            .0
            .union(&banned)
            .cloned()
            .collect();

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
            nip66_discovered,
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
                        .connect_timeout(args.connect_timeout.0)
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
