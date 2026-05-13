use crate::{
    Broadcastr, is_onion, now, proxied_client_builder,
    relays::{RelayListCreatedAt, Relays, UpdateMode},
};
use anyhow::{self as ah, Context};
use core::str::FromStr;
use futures::future::{join_all, try_join_all};
use indexmap::{IndexMap, IndexSet};
use itertools::Itertools;
use lru::LruCache;
use nostr::{
    Kind as EventKind, Timestamp,
    filter::{Filter, MatchEventOptions},
    key::PublicKey,
    nips::nip65,
    serde_json,
    types::RelayUrl,
};
use reqwest::Url;
use std::{fs::File, num::NonZeroUsize, ops::Sub, time::Duration};

pub(crate) const MAX_SEEN_AUTHORS: NonZeroUsize = NonZeroUsize::new(3).unwrap();
pub(crate) const MAX_GOSSIP_RELAYS_PER_USER: usize = 5;

#[derive(Debug, Clone, Default)]
pub(crate) struct RelayLists {
    pub read_write: IndexSet<RelayUrl>,
    pub read: IndexSet<RelayUrl>,
    pub block: IndexMap<RelayUrl, Duration>,
    pub author_to_relays: IndexMap<PublicKey, IndexSet<RelayUrl>>,
    pub outdated: IndexSet<RelayUrl>,
    pub relay_to_kinds: IndexMap<RelayUrl, IndexSet<EventKind>>,
}

struct ParsedUrlFragments {
    relay_to_kinds: IndexMap<RelayUrl, IndexSet<EventKind>>,
    lists: Vec<ah::Result<IndexSet<RelayUrl>>>,
}

impl RelayLists {
    pub(crate) async fn update(
        relays: &Relays,
        mode: UpdateMode,
        seen_pubkeys: &mut LruCache<PublicKey, RelayListCreatedAt>,
    ) -> ah::Result<Self> {
        let now = now();
        let old = {
            let lists = relays.policy.relay_lists();
            let lists = lists.read().await;
            let block = lists
                .block
                .iter()
                .filter(|(_, created)| now.saturating_sub(**created) < relays.args.block_ttl.0)
                .map(|(url, created)| (url.clone(), *created))
                .collect::<IndexMap<RelayUrl, Duration>>();
            Self {
                block,
                ..(lists.clone())
            }
        };

        let args = &relays.args;
        let futures = [&args.relays, &args.read_relays, &args.block_relays]
            .into_iter()
            .map(async |list| {
                if let Some(list) = list {
                    Self::fetch_and_parse(relays, &list.0, args)
                        .await
                        .inspect_err(|e| log::error!("fetch_and_parse {list:?}: {e:?}"))
                } else {
                    Ok(Default::default())
                }
            });
        let raw_lists = join_all(futures)
            .await
            .into_iter()
            .collect::<Vec<ah::Result<Vec<_>>>>();

        let ParsedUrlFragments {
            relay_to_kinds,
            mut lists,
        } = ParsedUrlFragments::parse(raw_lists)?;

        let relays_with_unmatched_allowed_kinds = if let Some(allowed_kinds) = &relays.args.kinds {
            relay_to_kinds
                .iter()
                .filter(|(_, kinds)| kinds.is_disjoint(&allowed_kinds.0))
                .map(|(i, _)| i.clone())
                .collect()
        } else {
            IndexSet::<RelayUrl>::default()
        };

        if !relays_with_unmatched_allowed_kinds.is_empty() {
            log::debug!(
                "ignoring relays with non-intersecting allowed kinds: \
                 {relays_with_unmatched_allowed_kinds:?}"
            );
        }

        let block = lists
            .pop()
            .context("block")?
            .context("block")?
            .into_iter()
            .map(|i| (i, Duration::MAX))
            .chain(
                relays
                    .banned_client_relays()
                    .await
                    .into_iter()
                    .map(|i| (i, now)),
            )
            .chain(old.block.clone())
            .collect::<IndexMap<_, _>>();

        let block_relays = block.keys().cloned().collect();
        let read = lists
            .pop()
            .context("read")?
            .unwrap_or_default()
            .union(&old.read)
            .cloned()
            .collect::<IndexSet<RelayUrl>>()
            .sub(&block_relays)
            .sub(&relays_with_unmatched_allowed_kinds);
        let read_write = lists
            .pop()
            .context("read_write")?
            .unwrap_or_default()
            .union(&old.read_write)
            .cloned()
            .collect::<IndexSet<RelayUrl>>()
            .sub(&block_relays)
            .sub(&read)
            .sub(&relays_with_unmatched_allowed_kinds);

        let author_to_relays = Self::fetch_gossip_relays(
            relays,
            &block_relays,
            mode,
            seen_pubkeys,
            old.author_to_relays,
        )
        .await?;

        let outdated = relays
            .client_relays()
            .await
            .sub(&block.keys().cloned().collect::<IndexSet<_>>())
            .sub(&read_write)
            .sub(&read)
            .sub(
                &author_to_relays
                    .values()
                    .flat_map(|i| i.iter().cloned())
                    .collect::<IndexSet<_>>(),
            );

        Ok(Self {
            read_write,
            read,
            block,
            author_to_relays,
            outdated,
            relay_to_kinds,
        })
    }

    async fn fetch_gossip_relays(
        relays: &Relays,
        block: &IndexSet<RelayUrl>,
        mode: UpdateMode,
        seen_pubkeys: &mut LruCache<PublicKey, RelayListCreatedAt>,
        mut old_gossip: IndexMap<PublicKey, IndexSet<RelayUrl>>,
    ) -> ah::Result<IndexMap<PublicKey, IndexSet<RelayUrl>>> {
        if mode == UpdateMode::InitializeRelays || relays.args.no_gossip_discovery {
            return Ok(Default::default());
        }

        let cached_gossip = if mode == UpdateMode::PartialGossipUpdate {
            Some(old_gossip.clone())
        } else {
            None
        };

        let mut authors = relays
            .args
            .pubkeys
            .clone()
            .unwrap_or_default()
            .0
            .iter()
            .copied()
            .chain(seen_pubkeys.iter().map(|(i, _)| *i))
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
        let since = seen_pubkeys
            .iter()
            .map(|(_, i)| i.to_u64().saturating_add(1))
            .reduce(u64::min)
            .unwrap_or_default()
            .into();
        let filter = Filter::new()
            .since(since)
            .until(Timestamp::from_secs(now.saturating_add(interval)))
            .kind(EventKind::RelayList)
            .authors(authors.iter().copied());

        for event in relays
            .nostr_client
            .fetch_events(filter.clone())
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
            log::debug!("gossip event={event:?}");
            let pubkey = event.pubkey;
            if !seen_pubkeys.contains(&pubkey) {
                seen_pubkeys.put(pubkey, Default::default());
            }
            let entry = seen_pubkeys
                .get_mut(&pubkey)
                .context("seen_pubkeys entry")?;
            *entry = RelayListCreatedAt::new(
                [entry.to_u64(), event.created_at.as_secs()]
                    .into_iter()
                    .reduce(u64::max),
            );
            for (relay_url, _) in nip65::extract_relay_list(&event) {
                if !block.contains(&relay_url)
                    && let Some(urls) = author_to_relays.get_mut(&pubkey)
                {
                    if urls.len() >= MAX_GOSSIP_RELAYS_PER_USER {
                        break;
                    }
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

        log::debug!("current gossip state: {author_to_relays:?}");
        Ok(author_to_relays)
    }

    async fn fetch_and_parse(
        relays: &Relays,
        relays_or_relays_lists: &IndexSet<Url>,
        args: &Broadcastr,
    ) -> ah::Result<Vec<Url>> {
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
                    proxied_client_builder(args)?
                        .build()?
                        .get(uri.as_ref())
                        .send()
                        .await?
                        .json::<Vec<Url>>()
                        .await?
                } else {
                    ah::bail!("unexpected relay item {uri}");
                }
                .into_iter()
                .filter(|uri| relays.maybe_can_connect_to_tor() || !is_onion(uri));
                Ok(result)
            });
        let result = try_join_all(futures)
            .await?
            .into_iter()
            .flatten()
            .collect::<Vec<Url>>();
        Ok(result)
    }

    pub(crate) fn contains(&self, url: &RelayUrl) -> bool {
        self.read_write.contains(url)
            || self.read.contains(url)
            || self.block.contains_key(url)
            || self.author_to_relays.values().any(|i| i.contains(url))
    }
}

impl ParsedUrlFragments {
    fn parse(lists_dirty: Vec<ah::Result<Vec<Url>>>) -> ah::Result<Self> {
        let mut relay_to_kinds: IndexMap<RelayUrl, IndexSet<EventKind>> = IndexMap::default();
        let mut lists: Vec<ah::Result<IndexSet<RelayUrl>>> = vec![];

        for i in lists_dirty {
            match i {
                Ok(list) => {
                    let mut new_list = IndexSet::default();
                    for mut url in list {
                        let relay_url = if let Some(fragment) = url.fragment()
                            && let Some((_, kinds)) = fragment.split_once("k=")
                        {
                            let kinds = kinds
                                .split('+')
                                .map(EventKind::from_str)
                                .collect::<Result<IndexSet<_>, _>>()
                                .map_err(ah::Error::from)?;

                            url.set_fragment(None);

                            let relay_url = url.as_str().parse::<RelayUrl>()?;
                            if !kinds.is_empty() {
                                relay_to_kinds.entry(relay_url.clone()).or_insert(kinds);
                            }
                            relay_url
                        } else {
                            url.as_str().parse::<RelayUrl>()?
                        };
                        new_list.insert(relay_url);
                    }
                    lists.push(Ok(new_list));
                },
                Err(e) => {
                    lists.push(Err(e));
                },
            }
        }

        log::debug!("per relay allow-list: {relay_to_kinds:?}");
        Ok(Self {
            relay_to_kinds,
            lists,
        })
    }
}
