use crate::relays::{Caps, Relays};

use super::{Broadcastr, normalize_url};
use anyhow::{self as ah, Context};
use futures::future::{join_all, try_join_all};
use nostr::serde_json;
use nostr_sdk::relay::RelayStatus;
use reqwest::{ClientBuilder, Url};
use std::{collections::HashSet, fs::File, ops::Sub};

#[derive(Debug)]
pub(crate) struct RelayLists {
    pub read_write: HashSet<Url>,
    pub read: HashSet<Url>,
    pub block: HashSet<Url>,
}

impl RelayLists {
    pub(crate) async fn new(relays: &Relays, caps: Caps) -> ah::Result<Self> {
        let args = &relays.args;

        let client_read_write = relays
            .nostr_client
            .relays()
            .with_capabilities(caps.read_write)
            .await
            .values()
            .filter(|i| i.status() != RelayStatus::Banned)
            .map(|i| normalize_url(i.url().as_str().parse()?))
            .collect::<ah::Result<HashSet<Url>>>()?;
        let client_read = relays
            .nostr_client
            .relays()
            .with_capabilities(caps.read)
            .await
            .values()
            .filter(|i| i.status() != RelayStatus::Banned)
            .map(|i| normalize_url(i.url().as_str().parse()?))
            .collect::<ah::Result<HashSet<Url>>>()?;
        let client_block = relays
            .nostr_client
            .relays()
            .await
            .values()
            .filter(|i| i.status() == RelayStatus::Banned)
            .map(|i| normalize_url(i.url().as_str().parse()?))
            .collect::<ah::Result<HashSet<Url>>>()?;

        let policy_block: HashSet<_> = { relays.policy.policy.block_relays.read().await.clone() };

        let empty = Default::default();
        let read_write = &args
            .relays
            .as_ref()
            .unwrap_or(&empty)
            .0
            .union(&client_read_write)
            .cloned()
            .collect();
        let read = &args
            .read_relays
            .as_ref()
            .unwrap_or(&empty)
            .0
            .union(&client_read)
            .cloned()
            .collect();
        let block = &args
            .block_relays
            .as_ref()
            .unwrap_or(&empty)
            .0
            .iter()
            .chain(&client_block)
            .chain(&policy_block)
            .cloned()
            .collect();

        let futures = [read_write, read, block].into_iter().map(async |list| {
            Self::fetch_and_parse(list, args)
                .await
                .inspect_err(|e| log::error!("fetch_and_parse {list:?}: {e:?}"))
        });
        let mut lists = join_all(futures)
            .await
            .into_iter()
            .collect::<Vec<ah::Result<HashSet<Url>>>>();

        let block = lists.pop().context("blocked")?.context("blocked")?;
        let read = lists.pop().context("read")?.unwrap_or_default();
        let read_write = lists.pop().context("read_write")?.unwrap_or_default();

        let read_write = read_write.sub(&block).sub(&read);
        let read = read.sub(&block);

        Ok(Self {
            read_write,
            read,
            block,
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
                Ok(result)
            });
        let result = try_join_all(futures)
            .await?
            .into_iter()
            .flatten()
            .collect::<ah::Result<HashSet<Url>>>()?;
        Ok(result)
    }

    pub(crate) fn contains(&self, url: &Url) -> bool {
        self.read_write.contains(url) || self.read.contains(url) || self.block.contains(url)
    }
}
