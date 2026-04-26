use crate::{Broadcastr, UPDATE_INTERVAL};
use anyhow as ah;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use lru::LruCache;
use nostr_sdk::{
    Alphabet, Client as NostrClient, ClientOptions, Event, EventId, Kind as EventKind, PublicKey,
    RelayUrl, SingleLetterTag, SubscriptionId, Tag, Timestamp,
    prelude::{AdmitPolicy, AdmitStatus, PolicyError},
    util::BoxedFuture,
};
use reqwest::Url;
use std::{collections::HashSet, net::IpAddr, num::NonZeroUsize, sync::Arc};
use tokio::sync::{RwLock, watch};

const MAX_SEEN_EVENTS: NonZeroUsize = NonZeroUsize::new(32768).unwrap();

pub(crate) struct ClientAndPolicy {
    pub nostr_client: NostrClient,
    pub policy: Arc<Policy>,
    pub blocked_relays_sender: watch::Sender<HashSet<Url>>,
    pub azzamo_blocked_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
}

#[derive(Debug)]
pub(crate) struct Policy {
    policy: InnerPolicy,
    seen_event_ids: RwLock<LruCache<EventId, ()>>,
    events_by_author: RateLimitBy<PublicKey>,
    events_by_ip: RateLimitBy<IpAddr>,
}

#[derive(Debug, Clone)]
struct InnerPolicy {
    allowed_pubkeys: HashSet<PublicKey>,
    disable_mentions: bool,
    allowed_kinds: HashSet<EventKind>,
    min_pow: Option<u8>,
    blocked_relays_receiver: watch::Receiver<HashSet<Url>>,
    azzamo_blocked_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
}

type RateLimitBy<I> = RateLimiter<I, DefaultKeyedStateStore<I>, DefaultClock>;

impl ClientAndPolicy {
    pub(crate) fn new(args: &Broadcastr, opts: ClientOptions) -> ah::Result<Self> {
        let (blocked_relays_sender, blocked_relays_receiver) = watch::channel(HashSet::default());
        let (azzamo_blocked_pubkeys_sender, azzamo_blocked_pubkeys_receiver) =
            watch::channel(HashSet::default());
        let policy = InnerPolicy {
            allowed_pubkeys: args.allowed_pubkeys.clone().unwrap_or_default().0,
            disable_mentions: args.disable_mentions,
            allowed_kinds: args.allowed_kinds.clone().unwrap_or_default().0,
            min_pow: args.min_pow,
            blocked_relays_receiver,
            azzamo_blocked_pubkeys_receiver,
        };

        if policy.disable_mentions && policy.allowed_pubkeys.is_empty() {
            ah::bail!(
                "--disable-mentions does nothing if --allowed-pubkeys is not set; perhaps you \
                 forgot to set the --allowed-pubkeys"
            );
        }

        let nostr_client = NostrClient::builder()
            .opts(opts)
            .admit_policy(policy.clone())
            .build();
        let policy = Arc::new(Policy::new(policy, args));

        Ok(Self {
            nostr_client,
            policy,
            blocked_relays_sender,
            azzamo_blocked_pubkeys_sender,
        })
    }
}

impl Policy {
    fn new(policy: InnerPolicy, args: &Broadcastr) -> Self {
        Self {
            policy,
            seen_event_ids: RwLock::new(LruCache::new(MAX_SEEN_EVENTS)),
            events_by_author: RateLimiter::keyed(Quota::per_minute(
                args.max_events_by_author_per_min,
            )),
            events_by_ip: RateLimiter::keyed(Quota::per_minute(args.max_events_by_ip_per_min)),
        }
    }

    pub(crate) async fn check(&self, event: &Event, ip: Option<IpAddr>) -> ah::Result<()> {
        let event_id = event.id;

        {
            if self.seen_event_ids.read().await.contains(&event_id) {
                ah::bail!("rate-limit: too many attempts to transmit the same event");
            }
        }

        {
            self.seen_event_ids.write().await.put(event_id, ());
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
        self.seen_event_ids.write().await.pop(&id);
    }
}

impl InnerPolicy {
    fn check_event(&self, event: &Event) -> ah::Result<()> {
        if let Some(min_pow) = self.min_pow
            && !event.check_pow(min_pow)
        {
            ah::bail!("unexpected pow < {min_pow}");
        }

        if !self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(&event.kind) {
            ah::bail!("unexpected kind {}", event.kind);
        } else if !self.allowed_pubkeys.is_empty() {
            if self.allowed_pubkeys.contains(&event.pubkey) {
                return Ok(());
            }

            if self.disable_mentions {
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

    fn mentions_allowed_pubkeys(&self, event: &Event) -> bool {
        event
            .tags
            .iter()
            .flat_map(mentioned_pubkey)
            .any(|i| self.allowed_pubkeys.contains(&i))
    }

    fn is_spam(&self, event: &Event) -> bool {
        self.azzamo_blocked_pubkeys_receiver
            .borrow()
            .contains(&event.pubkey)
    }
}

impl AdmitPolicy for InnerPolicy {
    fn admit_connection<'a>(
        &'a self,
        url: &'a RelayUrl,
    ) -> BoxedFuture<'a, Result<AdmitStatus, PolicyError>> {
        Box::pin(async move {
            let blocked_relays = self
                .blocked_relays_receiver
                .borrow()
                .iter()
                .map(|i| i.as_str().parse().map_err(PolicyError::backend))
                .collect::<Result<HashSet<RelayUrl>, PolicyError>>()?;

            let result = if blocked_relays.contains(url) {
                AdmitStatus::Rejected {
                    reason: Some("relay from block-list".to_string()),
                }
            } else {
                AdmitStatus::Success
            };
            Ok(result)
        })
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
