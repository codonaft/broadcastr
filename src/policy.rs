use crate::{Broadcastr, UPDATE_INTERVAL};
use anyhow as ah;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use lru::LruCache;
use nostr::{
    Alphabet, Event, EventId, Kind as EventKind, PublicKey, RelayUrl, SingleLetterTag,
    SubscriptionId, Tag, Timestamp, util::BoxedFuture,
};
use nostr_sdk::{
    client::{Client as NostrClient, Connection, GossipConfig, GossipRelayLimits},
    prelude::{AdmitPolicy, AdmitStatus, PolicyError},
    relay::{RelayEventLimits, RelayLimits},
};
use reqwest::Url;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock, watch};

const MAX_SEEN_EVENTS: NonZeroUsize = NonZeroUsize::new(32768).unwrap();

pub(crate) struct ClientAndPolicy {
    pub nostr_client: NostrClient,
    pub policy: Arc<Policy>,
    pub seen_relay_info: RwLock<HashSet<Url>>,
    pub azzamo_block_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
}

#[derive(Debug)]
pub(crate) struct Policy {
    pub policy: InnerPolicy,
    pub seen_event_ids: Mutex<LruCache<EventId, ()>>,
    pub events_by_author: RateLimitBy<PublicKey>,
    pub events_by_ip: RateLimitBy<IpAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct InnerPolicy {
    pub pubkeys: HashSet<PublicKey>,
    pub no_mentions: bool,
    pub kinds: HashSet<EventKind>,
    pub min_pow: Option<u8>,
    pub block_relays: Arc<RwLock<HashSet<Url>>>,
    pub azzamo_block_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
}

type RateLimitBy<I> = RateLimiter<I, DefaultKeyedStateStore<I>, DefaultClock>;

impl ClientAndPolicy {
    pub(crate) fn new(args: &Broadcastr, connection: Connection) -> ah::Result<Self> {
        let block_relays = Arc::new(RwLock::new(HashSet::default()));
        let seen_relay_info = RwLock::new(HashSet::default());
        let (azzamo_block_pubkeys_sender, azzamo_block_pubkeys_receiver) =
            watch::channel(HashSet::default());
        let policy = InnerPolicy {
            pubkeys: args.pubkeys.clone().unwrap_or_default().0,
            no_mentions: args.no_mentions,
            kinds: args.event_kinds.clone().unwrap_or_default().0,
            min_pow: args.min_pow,
            block_relays: block_relays.clone(),
            azzamo_block_pubkeys_receiver,
        };

        let relay_limits = RelayLimits {
            events: RelayEventLimits {
                max_size: Some(args.max_msg_size as u32),
                max_num_tags: Some(32), // TODO: arg
                max_num_tags_per_kind: HashMap::from([(EventKind::ContactList, Some(u16::MAX))]),
                ..Default::default()
            },
            ..Default::default()
        };

        let nostr_client = NostrClient::builder()
            // event signing is not supported
            .automatic_authentication(false)
            .gossip_config(GossipConfig {
                limits: if args.no_gossip {
                    GossipRelayLimits {
                        read_relays_per_user: 0,
                        write_relays_per_user: 0,
                        hint_relays_per_user: 0,
                        most_used_relays_per_user: 0,
                        nip17_relays: 0,
                    }
                } else {
                    GossipRelayLimits::default()
                },
                ..Default::default()
            })
            .relay_limits(relay_limits)
            .connection(connection)
            .ban_relay_on_mismatch(true)
            .admit_policy(policy.clone())
            .build();
        let policy = Arc::new(Policy::new(policy, args));

        Ok(Self {
            nostr_client,
            policy,
            seen_relay_info,
            azzamo_block_pubkeys_sender,
        })
    }
}

impl Policy {
    fn new(policy: InnerPolicy, args: &Broadcastr) -> Self {
        Self {
            policy,
            seen_event_ids: Mutex::new(LruCache::new(MAX_SEEN_EVENTS)),
            events_by_author: RateLimiter::keyed(Quota::per_minute(
                args.max_events_by_author_per_min,
            )),
            events_by_ip: RateLimiter::keyed(Quota::per_minute(args.max_events_by_ip_per_min)),
        }
    }

    pub(crate) async fn check(&self, event: &Event, ip: Option<IpAddr>) -> ah::Result<()> {
        let event_id = event.id;

        {
            let mut seen = self.seen_event_ids.lock().await;
            if seen.contains(&event_id) {
                ah::bail!("rate-limit: too many attempts to transmit the same event");
            }
            seen.put(event_id, ());
        }

        self.policy.check_event(event)?;

        if self.events_by_author.check_key(&event.pubkey).is_err() {
            ah::bail!("rate-limit: too many attempts to transmit event by the same author");
        }

        if let Some(ip) = ip
            && self.events_by_ip.check_key(&ip).is_err()
        {
            ah::bail!("rate-limit: too many events from the same IP");
        }

        log::debug!("received event {event_id}");
        Ok(())
    }

    pub(crate) async fn forget(&self, id: EventId) {
        self.seen_event_ids.lock().await.pop(&id);
    }
}

impl InnerPolicy {
    fn check_event(&self, event: &Event) -> ah::Result<()> {
        if let Some(min_pow) = self.min_pow
            && !event.check_pow(min_pow)
        {
            ah::bail!("unexpected pow < {min_pow}");
        }

        if !self.kinds.is_empty() && !self.kinds.contains(&event.kind) {
            ah::bail!("unexpected kind {}", event.kind);
        } else if !self.pubkeys.is_empty() {
            if self.pubkeys.contains(&event.pubkey) {
                return Ok(());
            }

            if self.no_mentions {
                ah::bail!("unexpected author");
            } else if !self.mentions_allowed_pubkeys(event) {
                ah::bail!("unexpected author or mentioned public key");
            }
        }

        if event.created_at
            > Timestamp::from_secs(
                Timestamp::now()
                    .as_secs()
                    .saturating_add(UPDATE_INTERVAL.as_secs()),
            )
        {
            ah::bail!("event from the future");
        }

        if self.is_spam(event) {
            ah::bail!("listed as spam");
        }
        Ok(())
    }

    async fn check_relay(&self, url: &RelayUrl) -> Result<AdmitStatus, PolicyError> {
        let block_relays = { self.block_relays.read().await }
            .iter()
            .map(|i| i.as_str().parse().map_err(PolicyError::backend))
            .collect::<Result<HashSet<RelayUrl>, PolicyError>>()?;

        let result = if block_relays.contains(url) {
            AdmitStatus::Rejected {
                reason: Some("relay from block-list".to_string()),
            }
        } else {
            AdmitStatus::Success
        };
        Ok(result)
    }

    fn mentions_allowed_pubkeys(&self, event: &Event) -> bool {
        event
            .tags
            .iter()
            .flat_map(mentioned_pubkey)
            .any(|i| self.pubkeys.contains(&i))
    }

    fn is_spam(&self, event: &Event) -> bool {
        self.azzamo_block_pubkeys_receiver
            .borrow()
            .contains(&event.pubkey)
    }
}

impl AdmitPolicy for InnerPolicy {
    fn admit_relay<'a>(
        &'a self,
        url: &'a RelayUrl,
    ) -> BoxedFuture<'a, Result<AdmitStatus, PolicyError>> {
        Box::pin(self.check_relay(url))
    }

    fn admit_connection<'a>(
        &'a self,
        url: &'a RelayUrl,
    ) -> BoxedFuture<'a, Result<AdmitStatus, PolicyError>> {
        Box::pin(self.check_relay(url))
    }

    fn admit_event<'a>(
        &'a self,
        _url: &'a RelayUrl,
        _subscription_id: &'a SubscriptionId,
        event: &'a Event,
    ) -> BoxedFuture<'a, Result<AdmitStatus, PolicyError>> {
        Box::pin(async move {
            if let Err(e) = self.check_event(event) {
                return Ok(AdmitStatus::Rejected {
                    reason: Some(format!("{e}")),
                });
            }
            Ok(AdmitStatus::Success)
        })
    }
}

fn mentioned_pubkey(tag: &Tag) -> Option<PublicKey> {
    if tag.single_letter_tag() == Some(SingleLetterTag::lowercase(Alphabet::P))
        && let Some(pubkey) = tag.content()
    {
        return pubkey.parse().ok();
    }
    None
}
