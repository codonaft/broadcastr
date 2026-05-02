use super::Broadcastr;
use crate::relays::{Caps, Relays};
use anyhow::{self as ah, Context};
use futures::future::{join_all, try_join_all};
use nostr::{serde_json, types::RelayUrl};
use nostr_sdk::relay::RelayStatus;
use reqwest::{ClientBuilder, Url};
use std::{
    collections::{BTreeSet, HashSet},
    fs::File,
    ops::Sub,
};

#[derive(Debug)]
pub(crate) struct RelayLists {
    pub read_write: BTreeSet<RelayUrl>,
    pub read: BTreeSet<RelayUrl>,
    pub block: BTreeSet<RelayUrl>,
}

impl RelayLists {
    pub(crate) async fn new(relays: &Relays, caps: Caps) -> ah::Result<Self> {
        let args = &relays.args;

        let client_read_write = {
            relays
                .nostr_client
                .relays()
                .with_capabilities(caps.read_write)
                .await
                .values()
                .filter(|i| i.status() != RelayStatus::Banned)
                .map(|i| i.url())
                .cloned()
                .collect::<Vec<_>>()
        };
        let client_read = {
            relays
                .nostr_client
                .relays()
                .with_capabilities(caps.read)
                .await
                .values()
                .filter(|i| i.status() != RelayStatus::Banned)
                .map(|i| i.url())
                .cloned()
                .collect::<Vec<_>>()
        };
        let client_block = {
            relays
                .nostr_client
                .relays()
                .await
                .values()
                .filter(|i| i.status() == RelayStatus::Banned)
                .map(|i| i.url())
                .cloned()
                .collect::<Vec<_>>()
        };

        let policy_block: BTreeSet<_> = { relays.policy.policy.block_relays.read().await.clone() };

        let empty = Default::default();
        let futures = [
            &args.relays.as_ref().unwrap_or(&empty).0,
            &args.read_relays.as_ref().unwrap_or(&empty).0,
            &args.block_relays.as_ref().unwrap_or(&empty).0,
        ]
        .into_iter()
        .map(async |list| {
            Self::fetch_and_parse(list, args)
                .await
                .inspect_err(|e| log::error!("fetch_and_parse {list:?}: {e:?}"))
        });
        let mut lists = join_all(futures)
            .await
            .into_iter()
            .collect::<Vec<ah::Result<BTreeSet<_>>>>();

        let block = lists
            .pop()
            .context("block")?
            .context("block")?
            .into_iter()
            .chain(client_block)
            .chain(policy_block)
            .collect::<BTreeSet<_>>();
        let read = lists
            .pop()
            .context("read")?
            .unwrap_or_default()
            .into_iter()
            .chain(client_read)
            .collect::<BTreeSet<_>>();
        let read_write = lists
            .pop()
            .context("read_write")?
            .unwrap_or_default()
            .into_iter()
            .chain(client_read_write)
            .collect::<BTreeSet<_>>();

        let read_write = read_write.sub(&block).sub(&read);
        let read = read.sub(&block);

        let read_write = read_write
            .into_iter()
            .take(
                args.max_relays
                    .map(|max| max.get().saturating_sub(read.len()))
                    .unwrap_or(usize::MAX),
            )
            .collect();

        Ok(Self {
            read_write,
            read,
            block,
        })
    }

    pub(crate) async fn fetch_and_parse(
        relays_or_relays_lists: &HashSet<Url>,
        args: &Broadcastr,
    ) -> ah::Result<BTreeSet<RelayUrl>> {
        let futures = relays_or_relays_lists
            .iter()
            .map(async |uri| -> ah::Result<_> {
                let result = if ["wss", "ws"].contains(&uri.scheme()) {
                    vec![uri.as_str().parse()?]
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
                        .json::<Vec<RelayUrl>>()
                        .await?
                } else {
                    ah::bail!("unexpected relay item {uri}");
                }
                .into_iter();
                Ok(result)
            });
        let result = try_join_all(futures)
            .await?
            .into_iter()
            .flatten()
            .collect::<BTreeSet<RelayUrl>>();
        Ok(result)
    }

    pub(crate) fn contains(&self, url: &RelayUrl) -> bool {
        self.read_write.contains(url) || self.read.contains(url) || self.block.contains(url)
    }

    pub(crate) fn healthy_relays(&self) -> usize {
        self.read_write.len().saturating_add(self.read.len())
    }
}
