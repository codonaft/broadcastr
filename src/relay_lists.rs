use super::Broadcastr;
use crate::relays::Relays;
use anyhow::{self as ah, Context};
use futures::future::{join_all, try_join_all};
use nostr::{Kind as EventKind, filter::Filter, nips::nip65, serde_json, types::RelayUrl};
use nostr_sdk::relay::{RelayCapabilities, RelayStatus};
use reqwest::{ClientBuilder, Url};
use std::{
    collections::{BTreeSet, HashSet},
    fs::File,
    ops::Sub,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct RelayLists {
    pub read_write: BTreeSet<RelayUrl>,
    pub read: BTreeSet<RelayUrl>,
    pub block: BTreeSet<RelayUrl>,
    pub gossip: GossipRelayLists,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct GossipRelayLists {
    pub read: BTreeSet<RelayUrl>,
    pub write: BTreeSet<RelayUrl>,
}

impl RelayLists {
    pub(crate) async fn new(relays: &Relays) -> ah::Result<Self> {
        let args = &relays.args;

        let client_read_write = {
            relays
                .nostr_client
                .relays()
                .with_capabilities(RelayCapabilities::READ | RelayCapabilities::WRITE)
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
                .with_capabilities(RelayCapabilities::READ)
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
            .chain(relays.policy.blocked_relays().await)
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

        Ok(Self {
            read_write,
            read,
            block,
            gossip: Default::default(),
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
        self.read_write.contains(url)
            || self.read.contains(url)
            || self.block.contains(url)
            || self.gossip.read.contains(url)
            || self.gossip.write.contains(url)
    }
}

impl GossipRelayLists {
    pub(crate) async fn fetch(
        relays: &Relays,
        block: &BTreeSet<RelayUrl>,
    ) -> ah::Result<GossipRelayLists> {
        let mut lists = GossipRelayLists::default();
        if !relays.args.no_gossip_discovery
            && let Some(pubkeys) = &relays.args.pubkeys
        {
            // TODO: if no pubkeys - extract them from events we've broadcasted
            let filter = Filter::new()
                .kind(EventKind::RelayList)
                .authors(pubkeys.0.iter().copied());
            for event in relays
                .nostr_client
                .fetch_events(filter)
                .timeout(relays.args.request_timeout.0)
                .await
                .context("fetch gossip")?
            {
                for (relay_url, metadata) in nip65::extract_owned_relay_list(event) {
                    if block.contains(&relay_url) {
                        continue;
                    }
                    if let Some(nip65::RelayMetadata::Read) = metadata {
                        lists.read.insert(relay_url);
                    } else if let Some(nip65::RelayMetadata::Write) = metadata {
                        lists.write.insert(relay_url);
                    } else {
                        lists.read.insert(relay_url.clone());
                        lists.write.insert(relay_url);
                    }
                }
            }
        }
        Ok(lists)
    }
}
