use super::Broadcastr;
use crate::relays::{Relays, UpdateMode};
use anyhow::{self as ah, Context};
use futures::future::{join_all, try_join_all};
use indexmap::{IndexMap, IndexSet};
use itertools::Itertools;
use nostr::{
    Kind as EventKind, Timestamp,
    filter::{Filter, MatchEventOptions},
    key::PublicKey,
    nips::nip65,
    serde_json,
    types::RelayUrl,
};
use nostr_sdk::relay::{RelayCapabilities, RelayStatus};
use reqwest::{ClientBuilder, Url};
use std::{fs::File, num::NonZeroUsize, ops::Sub};

pub(crate) const MAX_SEEN_AUTHORS: NonZeroUsize = NonZeroUsize::new(3).unwrap();
pub(crate) const MAX_GOSSIP_RELAYS_PER_USER: usize = 3;

#[derive(Debug, Clone, Default)]
pub(crate) struct RelayLists {
    pub read_write: IndexSet<RelayUrl>,
    pub read: IndexSet<RelayUrl>,
    pub block: IndexSet<RelayUrl>,
    pub author_to_relays: IndexMap<PublicKey, IndexSet<RelayUrl>>,
}

impl RelayLists {
    pub(crate) async fn new(relays: &Relays, mode: UpdateMode) -> ah::Result<Self> {
        let args = &relays.args;

        let client_read_write = get_relays(
            relays,
            Some(RelayCapabilities::READ | RelayCapabilities::WRITE),
            false,
        )
        .await;
        let client_read = get_relays(relays, Some(RelayCapabilities::READ), false).await;
        let client_block = get_relays(relays, None, true).await;

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
            .collect::<Vec<ah::Result<IndexSet<_>>>>();

        let block = lists
            .pop()
            .context("block")?
            .context("block")?
            .into_iter()
            .chain(client_block)
            .chain(relays.policy.blocked_relays().await)
            .collect::<IndexSet<_>>();
        let read = lists
            .pop()
            .context("read")?
            .unwrap_or_default()
            .into_iter()
            .chain(client_read)
            .collect::<IndexSet<_>>();
        let read_write = lists
            .pop()
            .context("read_write")?
            .unwrap_or_default()
            .into_iter()
            .chain(client_read_write)
            .collect::<IndexSet<_>>();

        let read_write = read_write.sub(&block).sub(&read);
        let read = read.sub(&block);

        let author_to_relays = Self::fetch_gossip_relays(relays, &block, mode).await?;

        Ok(Self {
            read_write,
            read,
            block,
            author_to_relays,
        })
    }

    async fn fetch_gossip_relays(
        relays: &Relays,
        block: &IndexSet<RelayUrl>,
        mode: UpdateMode,
    ) -> ah::Result<IndexMap<PublicKey, IndexSet<RelayUrl>>> {
        if mode == UpdateMode::InitializeRelays || relays.args.no_gossip_discovery {
            return Ok(Default::default());
        }

        let mut old_gossip = {
            relays
                .policy
                .relay_lists()
                .read() // TODO: too many readers?
                .await
                .author_to_relays
                .clone()
        };

        let cached_gossip = if mode == UpdateMode::PartialGossipUpdate {
            // TODO: relay list is now connected to the instance of relay list
            Some(old_gossip.clone())
        } else {
            None
        };

        // TODO: weird connection?
        let seen_authors = {
            relays
                .seen_authors
                .lock()
                .await
                .iter()
                .map(|(i, _)| *i)
                .collect::<IndexSet<_>>()
        };
        let mut authors = relays
            .args
            .pubkeys
            .clone()
            .unwrap_or_default()
            .0
            .iter()
            .copied()
            .chain(seen_authors)
            .collect::<IndexSet<_>>();

        let mut author_to_relays = authors
            .iter()
            .map(|i| (*i, IndexSet::<RelayUrl>::default()))
            .collect::<IndexMap<_, _>>();

        if let Some(cached_gossip) = cached_gossip {
            for (pubkey, relays) in cached_gossip {
                if !relays.is_empty() {
                    authors.shift_remove(&pubkey);
                }
                author_to_relays.insert(pubkey, relays);
            }
        }

        if authors.is_empty() {
            return Ok(author_to_relays);
        }

        let interval = relays.args.update_interval.0.as_secs();
        let now = Timestamp::now().as_secs();
        let filter = Filter::new()
            .until(Timestamp::from_secs(now.saturating_add(interval)))
            .kind(EventKind::RelayList)
            .authors(authors.iter().copied());

        let filter = if mode == UpdateMode::InitializeGossip {
            filter
        } else {
            filter.since(Timestamp::from_secs(now.saturating_sub(interval)))
        };

        log::info!("filter={filter:?}"); // TODO

        for event in relays
            .nostr_client
            .fetch_events(filter.clone()) // TODO
            .timeout(relays.args.request_timeout.0)
            .await
            .context("fetch gossip")?
            .into_iter()
            .chunk_by(|e| e.pubkey)
            .into_iter()
            .flat_map(|(_, events)| {
                events
                    .into_iter()
                    .filter(|e| filter.match_event(e, MatchEventOptions::default()))
                    .max_by_key(|e| e.created_at)
                    .into_iter()
            })
        {
            log::info!("event={event:?}"); // TODO
            let pubkey = event.pubkey;
            for (relay_url, _) in
                nip65::extract_owned_relay_list(event).take(MAX_GOSSIP_RELAYS_PER_USER)
            {
                if !block.contains(&relay_url)
                    && let Some(urls) = author_to_relays.get_mut(&pubkey)
                {
                    urls.insert(relay_url);
                }
            }
        }

        for (author, relays) in author_to_relays.iter_mut() {
            if relays.is_empty()
                && let Some(old_relays) = old_gossip.swap_remove(author)
            {
                *relays = old_relays;
            }
        }

        log::info!("current gossip state: {author_to_relays:?}"); // TODO
        Ok(author_to_relays)
    }

    async fn fetch_and_parse(
        relays_or_relays_lists: &IndexSet<Url>,
        args: &Broadcastr,
    ) -> ah::Result<IndexSet<RelayUrl>> {
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
            .collect::<IndexSet<RelayUrl>>();
        Ok(result)
    }

    pub(crate) fn contains(&self, url: &RelayUrl) -> bool {
        self.read_write.contains(url)
            || self.read.contains(url)
            || self.block.contains(url)
            || self.author_to_relays.values().any(|i| i.contains(url))
    }
}

async fn get_relays(
    relays: &Relays,
    caps: Option<RelayCapabilities>,
    banned: bool,
) -> Vec<RelayUrl> {
    let builder = relays.nostr_client.relays();

    if let Some(caps) = caps {
        builder.with_capabilities(caps)
    } else {
        builder
    }
    .await
    .values()
    .filter(|i| banned == (i.status() == RelayStatus::Banned))
    .map(|i| i.url().clone())
    .collect()
}
