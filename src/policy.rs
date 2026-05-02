use crate::{Broadcastr, UPDATE_INTERVAL};
use anyhow as ah;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use lru::LruCache;
use nostr::{
    Event, EventId, Kind as EventKind, PublicKey, RelayUrl, SubscriptionId, Timestamp,
    util::BoxedFuture,
};
use nostr_sdk::prelude::{AdmitPolicy, AdmitStatus, PolicyError};
use std::{
    collections::{BTreeSet, HashSet},
    net::IpAddr,
    num::NonZeroUsize,
    sync::Arc,
};
use tokio::sync::{Mutex, RwLock, watch};

const MAX_SEEN_EVENTS: NonZeroUsize = NonZeroUsize::new(32768).unwrap();

// TODO: rename
#[derive(Debug)]
pub(crate) struct Policy {
    pub policy: InnerPolicy, // TODO: rename?
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
    pub no_nip66_discovery: bool,
    pub block_relays: Arc<RwLock<BTreeSet<RelayUrl>>>,
    pub azzamo_block_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
}

type RateLimitBy<I> = RateLimiter<I, DefaultKeyedStateStore<I>, DefaultClock>;

impl Policy {
    pub(crate) fn new(policy: InnerPolicy, args: &Broadcastr) -> Self {
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

    pub(crate) async fn block(&self, relay_url: &RelayUrl) -> ah::Result<()> {
        self.policy
            .block_relays
            .write()
            .await
            .insert(relay_url.clone());
        Ok(())
    }
}

impl InnerPolicy {
    pub(crate) fn new(
        args: &Broadcastr,
        block_relays: Arc<RwLock<BTreeSet<RelayUrl>>>,
        azzamo_block_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
    ) -> Self {
        Self {
            pubkeys: args.pubkeys.clone().unwrap_or_default().0,
            no_mentions: args.no_mentions,
            kinds: args.kinds.clone().unwrap_or_default().0,
            min_pow: args.min_pow,
            no_nip66_discovery: args.no_nip66_discovery,
            block_relays: block_relays.clone(),
            azzamo_block_pubkeys_receiver,
        }
    }

    fn check_event(&self, event: &Event) -> ah::Result<()> {
        if let Some(min_pow) = self.min_pow
            && !event.check_pow(min_pow)
        {
            ah::bail!("unexpected pow < {min_pow}");
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

        if !self.no_nip66_discovery
            && event.kind == EventKind::RelayDiscovery
            && !self.is_spam(event)
        {
            return Ok(());
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

        if self.is_spam(event) {
            ah::bail!("listed as spam");
        }
        Ok(())
    }

    async fn check_relay(&self, url: &RelayUrl) -> Result<AdmitStatus, PolicyError> {
        let block_relays = {
            self.block_relays
                .read()
                .await
                .iter()
                .map(|i| i.as_str().parse().map_err(PolicyError::backend))
                .collect::<Result<HashSet<RelayUrl>, PolicyError>>()?
        };

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
            .public_keys()
            .find(|i| self.pubkeys.contains(i))
            .is_some()
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
