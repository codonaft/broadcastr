use crate::{
    Broadcastr, Policy, backoff,
    nostr_utils::{self, APPLICATION_NOSTR_JSON, has_publish_limitation},
    policy::InnerPolicy,
    proxied_client_builder,
    relay_lists::{MAX_SEEN_AUTHORS, RelayLists},
    spam::check_possible_spam,
};
use anyhow::{self as ah, Context};
use backon::{BackoffBuilder, Retryable};
use core::convert::From;
use futures::{StreamExt, future::join_all};
use indexmap::{IndexMap, IndexSet};
use itertools::{Either, Itertools};
use lru::LruCache;
use nostr::{
    Alphabet, Event, Filter, Kind as EventKind, PublicKey, RelayUrl, Timestamp,
    event::tag::TagCodec,
    filter::{MatchEventOptions, SingleLetterTag},
    nips::{nip11::RelayInformationDocument, nip66::Nip66Tag},
    serde_json,
    util::JsonUtil,
};
use nostr_sdk::{
    client::{Client as NostrClient, GossipConfig, GossipRelayLimits},
    proxy::Proxy,
    relay::{Error as RelayError, RelayEventLimits, RelayLimits, RelayStatus, ReqExitPolicy},
};
use reqwest::{Client as HttpClient, Url, header};
use std::{
    collections::{HashMap, HashSet},
    iter,
    net::IpAddr,
    ops::Sub,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    sync::{Mutex, RwLock, Semaphore, watch},
    time,
    time::sleep,
};

const RELAY_CAPABILITY: SingleLetterTag = SingleLetterTag::uppercase(Alphabet::R);
const RELAY_NETWORK_TYPE: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::N);
const LABEL: SingleLetterTag = SingleLetterTag::lowercase(Alphabet::L);

const MAX_CONCURRENT_FAILURE_CHECKS: usize = 4;
const FATAL_CONNECTION_ERRORS: [&str; 7] = [
    "dns error",
    "InvalidCertificate",
    "ExpiredContext",
    "UnrecognisedName",
    "NotValidForNameContext",
    "tls handshake eof",
    "0.0.0.0:443",
];

const WARMUP: Duration = Duration::from_secs(15);
const WEEK_SECS: u64 = 7 * Duration::from_hours(24).as_secs();

const NEWEST_EVENT_ATTEMPTS: usize = 3;

#[derive(Debug)]
pub(crate) struct Relays {
    pub nostr_client: NostrClient,
    pub http_client: HttpClient,
    pub args: Broadcastr,
    pub policy: Arc<Policy>,
    pub seen_pubkeys: Arc<Mutex<LruCache<PublicKey, RelayListCreatedAt>>>,
    pub facts: RwLock<RelayFacts>,
    pub relays_failure_budget: Semaphore,
}

#[derive(Debug)]
pub(crate) struct RelayFacts {
    pub found_relevant_event: LruCache<RelayUrl, ()>,
    pub seen_relay_info_after_failure: HashSet<RelayUrl>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RelayListCreatedAt(Option<Timestamp>);

#[derive(Debug)]
pub(crate) struct RelaysAndSenders {
    pub relays: Arc<Relays>,
    pub azzamo_block_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateMode {
    InitializeRelays,
    InitializeGossip,
    FullUpdate,
    FirstFullUpdate,
    PartialGossipUpdate,
}

#[derive(Debug)]
struct QueryEvent {
    newest_event: Event,
    found_on_relays: IndexSet<RelayUrl>,
    relays_without_event: IndexSet<RelayUrl>,
}

impl Relays {
    pub(crate) async fn run(this: Arc<Self>) -> ah::Result<()> {
        {
            let mut seen_pubkeys = this.seen_pubkeys.lock().await;
            let mut intervals = backoff(&this.args).build();

            for mode in [UpdateMode::InitializeRelays, UpdateMode::InitializeGossip] {
                while let Err(e) = Self::maybe_init(this.clone(), mode, &mut seen_pubkeys).await {
                    log::error!("initialization failure: {e}");
                    sleep(intervals.next().context("backoff")?).await;
                }
            }
        }

        let mut interval = time::interval(this.args.update_interval.0);
        interval.tick().await;
        let _ = Self::update(this.clone(), UpdateMode::FirstFullUpdate).await;

        loop {
            interval.tick().await;

            let attempt = || {
                let this = this.clone();
                async move { Self::update(this, UpdateMode::FullUpdate).await }
            };

            attempt.retry(backoff(&this.args)).await?;
        }
    }

    async fn maybe_init(
        this: Arc<Self>,
        mode: UpdateMode,
        seen_pubkeys: &mut LruCache<PublicKey, RelayListCreatedAt>,
    ) -> ah::Result<()> {
        if let UpdateMode::InitializeGossip = mode
            && !this.args.no_gossip_discovery
        {
            return Ok(());
        }

        if let Err(e) = this.update_relays(mode, seen_pubkeys).await {
            log::error!("failed to update relays: {e}");
        }
        Self::update_subscriptions(this, mode, WARMUP).await
    }

    async fn update(this: Arc<Self>, mode: UpdateMode) -> ah::Result<()> {
        {
            let seen_pubkeys = this.seen_pubkeys.clone();
            let mut seen_pubkeys = seen_pubkeys.lock().await;

            if let Err(e) = this.update_relays(mode, &mut seen_pubkeys).await {
                log::error!("failed to update relays: {e}");
            }
        }

        let timeout = this.args.update_interval.0;
        Self::update_subscriptions(this, mode, timeout).await
    }

    async fn update_relays(
        &self,
        mode: UpdateMode,
        seen_pubkeys: &mut LruCache<PublicKey, RelayListCreatedAt>,
    ) -> ah::Result<()> {
        log::info!("updating relays mode {mode:?}");

        let RelayLists {
            read_write,
            read,
            block,
            author_to_relays,
            outdated,
            relay_to_kinds,
        } = RelayLists::update(self, mode, seen_pubkeys).await?;

        let current_relay_lists = self.policy.relay_lists();

        if read_write.is_empty()
            && read.is_empty()
            && author_to_relays.is_empty()
            && !block.is_empty()
        {
            let mut write = current_relay_lists.write().await;
            *write = RelayLists {
                read_write,
                read,
                block: Default::default(),
                author_to_relays,
                outdated,
                relay_to_kinds,
            };
            return Err(ah::anyhow!("all relays are blocked"));
            // add_relay may aquire read lock from policy
            // so we drop the write lock here
        }

        let gossip = author_to_relays
            .clone()
            .into_values()
            .flat_map(|i| i.into_iter())
            .collect::<IndexSet<_>>();

        for i in &outdated {
            self.remove_relay(i).await;
        }
        if !outdated.is_empty() {
            log::info!("removed {} outdated relays", outdated.len());
        }

        if mode != UpdateMode::InitializeRelays {
            let client_relays = self.nostr_client.relays().await;
            let missing_gossip =
                gossip.sub(&client_relays.keys().cloned().collect::<IndexSet<_>>());
            let all_relays = client_relays.len().saturating_add(missing_gossip.len());
            if let Some(max_relays) = self.args.max_relays
                && all_relays >= max_relays.into()
            {
                let missing_pool_size = all_relays.saturating_sub(max_relays.into());
                if missing_pool_size > 0 {
                    let offline = client_relays
                        .iter()
                        .filter(|(_, i)| !i.status().is_connected());
                    let connected = client_relays
                        .iter()
                        .filter(|(_, i)| i.status().is_connected());
                    let evicted = offline
                        .chain(connected)
                        .map(|(i, _)| i)
                        .filter(|i| !gossip.contains(*i) && !read.contains(*i))
                        .take(missing_pool_size)
                        .collect::<IndexSet<_>>();
                    for i in &evicted {
                        self.remove_relay(i).await;
                    }
                    log::info!(
                        "evicted {} relays for {missing_pool_size} gossip relays",
                        evicted.len()
                    );
                }
            }

            for i in &gossip {
                self.add_relay(i).await;
            }
        }

        for i in read.iter().chain(&read_write) {
            self.add_relay(i).await;
        }

        let blocked_relays = block.clone();
        {
            let mut write = current_relay_lists.write().await;
            *write = RelayLists {
                read_write,
                read,
                block,
                author_to_relays,
                outdated,
                relay_to_kinds,
            };
        }

        log::debug!("finished updating relays");
        self.reconnect(blocked_relays).await;
        Ok(())
    }

    async fn reconnect(&self, blocked_relays: IndexMap<RelayUrl, Duration>) {
        log::debug!("connecting");
        let start = Instant::now();
        self.nostr_client
            .connect()
            .and_wait(self.args.connect_timeout.0)
            .await;
        let elapsed = elapsed(start);

        let client_relays = self.nostr_client.relays().await;
        let connected_relays = client_relays
            .values()
            .filter(|i| i.status().is_connected())
            .count();

        let blocked_relays = blocked_relays
            .keys()
            .map(|i| i.to_string())
            .collect::<Vec<_>>();
        log::info!(
            "currently connected to {connected_relays} of {} relays, blocked {} relays",
            client_relays.len(),
            blocked_relays.len(),
        );
        log::debug!("reconnected in {elapsed}, blocked relays: {blocked_relays:?}");
    }

    async fn update_subscriptions(
        this: Arc<Self>,
        mode: UpdateMode,
        timeout: Duration,
    ) -> ah::Result<()> {
        let mut futures = vec![];
        let policy = ReqExitPolicy::WaitDurationAfterEOSE(timeout);

        if let UpdateMode::FirstFullUpdate
        | UpdateMode::FullUpdate
        | UpdateMode::PartialGossipUpdate = mode
            && this.args.subscribe
            && let (Some(pubkeys), Some(kinds)) =
                (this.args.pubkeys.clone(), this.args.kinds.clone())
        {
            let this = this.clone();
            futures.push(tokio::spawn(async move {
                let filter = this.filter_in_update_interval_with_age(0).kinds(kinds.0);
                let mut filters = vec![filter.clone().authors(pubkeys.0.iter().copied())];
                if !this.args.no_mentions {
                    // TODO: q-tag? probably no, because "Authors of the e and q tags SHOULD be added as p tags to notify of a new reply or quote"
                    filters.push(filter.pubkeys(pubkeys.0));
                }

                log::debug!("subscribing to {filters:?}");
                let mut stream = this
                    .nostr_client
                    .stream_events(filters.clone())
                    .timeout(timeout)
                    .policy(policy)
                    .await
                    .context("subscription")?;

                while let Some((stream_relay_url, stream_event)) = stream.next().await {
                    match stream_event {
                        Ok(event) => {
                            if filters
                                .iter()
                                .any(|i| i.match_event(&event, MatchEventOptions::default()))
                            {
                                let event_id = event.id;
                                let allow_protected = false;
                                if let Err(e) = Self::spawn_handle_event(
                                    this.clone(),
                                    event,
                                    None,
                                    IndexSet::from([stream_relay_url]),
                                    allow_protected,
                                )
                                .await
                                {
                                    log::debug!("ignored event {event_id} from subscription: {e}");
                                } else {
                                    log::info!("accepted event {event_id} from subscription");
                                }
                            }
                        },
                        Err(e) => {
                            Self::spawn_handle_relay_error(this.clone(), e, stream_relay_url).await;
                        },
                    }
                }
                Ok::<_, ah::Error>(())
            }));
        }

        let client_relays = this.client_relays().await;
        let mut free_pool_entries = if let Some(max) = this.args.max_relays {
            max.get().saturating_sub(client_relays.len())
        } else {
            usize::MAX
        };

        if free_pool_entries > 0 {
            let restored = {
                this.facts
                    .read()
                    .await
                    .found_relevant_event
                    .iter()
                    .map(|(i, _)| i)
                    .filter(|&i| !client_relays.contains(i))
                    .take(free_pool_entries)
                    .cloned()
                    .collect::<IndexSet<RelayUrl>>()
            };

            if !restored.is_empty() {
                log::info!("restored {} relays", restored.len());
                free_pool_entries = free_pool_entries.saturating_sub(restored.len());
                {
                    this.policy
                        .relay_lists()
                        .write()
                        .await
                        .read_write
                        .extend(restored);
                }
            }
        }

        if mode != UpdateMode::PartialGossipUpdate
            && !this.args.no_nip66_discovery
            && free_pool_entries > 0
        {
            futures.push(tokio::spawn(async move {
                log::debug!("discovering relays");
                let filter = this
                    .filter_in_update_interval_with_age(match mode {
                        UpdateMode::InitializeRelays => 2 * WEEK_SECS,
                        UpdateMode::FirstFullUpdate => WEEK_SECS,
                        _ => 0,
                    })
                    .kind(EventKind::RelayDiscovery)
                    .custom_tag(RELAY_CAPABILITY, "!auth")
                    .custom_tag(RELAY_CAPABILITY, "!payment");

                let clearnet = filter.clone().custom_tag(RELAY_NETWORK_TYPE, "clearnet");
                let ssl = clearnet.clone().custom_tag(RELAY_CAPABILITY, "ssl");
                let mut filters = vec![clearnet.clone(), ssl.clone()];

                let min_pow = this.args.min_pow.unwrap_or_default();
                if min_pow == 0 {
                    filters.extend([
                        clearnet.custom_tag(RELAY_NETWORK_TYPE, "!pow"),
                        ssl.custom_tag(RELAY_NETWORK_TYPE, "!pow"),
                    ]);
                }

                if this.maybe_can_connect_to_tor() {
                    let tor = filter.custom_tag(RELAY_NETWORK_TYPE, "tor");
                    filters.push(tor.clone());
                    if min_pow == 0 {
                        filters.push(tor.custom_tag(RELAY_NETWORK_TYPE, "!pow"));
                    }
                }

                let mut stream = this
                    .nostr_client
                    .stream_events(filters)
                    .timeout(timeout)
                    .policy(policy)
                    .await
                    .context("relay_discovery")?;

                let mut discovered = IndexSet::<RelayUrl>::default();
                let mut discovered_bot_unfriendly = IndexSet::<RelayUrl>::default();
                let relay_lists: RelayLists = { this.policy.relay_lists().read().await.clone() };
                while let Some((_, stream_event)) = stream.next().await {
                    if let Ok(event) = stream_event
                        && event.kind == EventKind::RelayDiscovery
                        && !this.args.no_nip66_discovery
                        && let Some(Ok(url)) =
                            event.tags.identifier().as_deref().map(RelayUrl::parse)
                        && !relay_lists.contains(&url)
                        && (this.maybe_can_connect_to_tor() || !url.is_onion())
                    {
                        if event.tags.iter().any(|t| {
                            // TODO
                            t.single_letter_tag() == Some(LABEL)
                                && t.as_slice()
                                    .get(1)
                                    .map(|t| t.to_lowercase().contains("cloudflare"))
                                    .unwrap_or_default()
                        }) {
                            discovered_bot_unfriendly.insert(url);
                        } else {
                            discovered.insert(url);
                            free_pool_entries -= 1;
                            if free_pool_entries == 0 {
                                break;
                            }
                        }
                    }
                }

                discovered_bot_unfriendly = discovered_bot_unfriendly
                    .into_iter()
                    .take(free_pool_entries)
                    .collect();

                log::info!(
                    "discovered {} new relays + {} bot-unfriendly relays",
                    discovered.len(),
                    discovered_bot_unfriendly.len()
                );

                {
                    this.policy
                        .relay_lists()
                        .write()
                        .await
                        .read_write
                        .extend(discovered.into_iter().chain(discovered_bot_unfriendly));
                };

                Ok::<_, ah::Error>(())
            }));
        }

        let start = Instant::now();
        let result = join_all(futures)
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map(|_| ())
            .inspect_err(|e| log::error!("subscriptions: {e}"));
        log::debug!("closed subscriptions after {}", elapsed(start));
        result.map_err(ah::Error::from)
    }

    pub(crate) async fn spawn_handle_event(
        this: Arc<Self>,
        event: Event,
        ip: Option<IpAddr>,
        found_on_relays: IndexSet<RelayUrl>,
        allow_protected: bool,
    ) -> ah::Result<()> {
        this.policy.check(&event, ip).await?;

        if !allow_protected && !this.args.no_protect && event.is_protected() {
            let event_id = event.id;
            log::info!("ignoring event {event_id} due to NIP-70 protection tag");
            return Err(ah::anyhow!("protected"));
        }

        tokio::spawn(async move {
            if !this.args.no_mentions
                && let Some(nostr_utils::PublicKeys(authors)) = &this.args.pubkeys
                && event.tags.public_keys().any(|p| authors.contains(&p))
                && let Err(e) = check_possible_spam(&event).await
            {
                log::error!("possible spam check failure: {e}");
            } else if let Err(e) = Self::handle_event(this, event, found_on_relays, 1).await {
                log::error!("failed to handle a message: {e}");
            }
        });
        Ok(())
    }

    async fn handle_event(
        this: Arc<Self>,
        event: Event,
        found_on_relays: IndexSet<RelayUrl>,
        retry: usize,
    ) -> ah::Result<()> {
        let mut pubkeys = HashSet::default();

        {
            let mut seen_pubkeys = this.seen_pubkeys.lock().await;
            for i in iter::once(event.pubkey).chain(event.tags.public_keys()) {
                seen_pubkeys.put(i, Default::default());
                pubkeys.insert(i);
            }

            this.update_relays(UpdateMode::PartialGossipUpdate, &mut seen_pubkeys)
                .await?;
        }

        let event_id = event.id;
        let QueryEvent {
            newest_event,
            found_on_relays,
            relays_without_event,
        } = QueryEvent::find(&event, &pubkeys, &this, &found_on_relays)
            .await
            .context("query")?;

        let newest_event_id = newest_event.id;
        if event_id != newest_event.id {
            log::info!("{event_id} is outdated, broadcasting {newest_event_id} instead");
        }

        let found_on_relays_before_broadcasting = found_on_relays.len();
        if relays_without_event.is_empty() {
            ah::bail!(
                "already found the event {newest_event_id} on all of the \
                 {found_on_relays_before_broadcasting} relays, not going to broadcast it",
            );
        } else {
            let found_message = if found_on_relays_before_broadcasting > 0 {
                format!(
                    "found event {newest_event_id} on {found_on_relays_before_broadcasting} \
                     relays, "
                )
            } else {
                "".to_string()
            };
            log::info!(
                "{found_message}broadcasting to {} relays (of all of the {} relays)",
                relays_without_event.len(),
                found_on_relays_before_broadcasting.saturating_add(relays_without_event.len()),
            );

            join_all(relays_without_event.into_iter().map(|relay_url| {
                let this = this.clone();
                let newest_event = newest_event.clone();
                async move {
                    let relay = this.nostr_client.relay(relay_url).await?;
                    if let Some(relay) = relay
                        && relay.status() != RelayStatus::Banned
                    {
                        relay.wait_for_connection(this.args.connect_timeout.0).await;
                        relay
                            .send_event(&newest_event)
                            .wait_for_ok(true)
                            .ok_timeout(this.args.request_timeout.0)
                            .authentication_timeout(Duration::from_secs(0))
                            .await?;
                    }
                    Ok::<_, ah::Error>(())
                }
            }))
            .await;

            let QueryEvent {
                newest_event,
                found_on_relays,
                relays_without_event,
            } = QueryEvent::find(&newest_event, &pubkeys, &this, &found_on_relays)
                .await
                .context("re-query")?;
            if newest_event_id == newest_event.id {
                let broadcasted_to_new_relays = found_on_relays
                    .len()
                    .saturating_sub(found_on_relays_before_broadcasting);
                log::info!(
                    "event {newest_event_id} was accepted by {broadcasted_to_new_relays} relays \
                     (now it's available on {} of {} relays)",
                    found_on_relays.len(),
                    found_on_relays
                        .len()
                        .saturating_add(relays_without_event.len()),
                );
            } else {
                if retry <= NEWEST_EVENT_ATTEMPTS {
                    log::warn!(
                        "event {newest_event_id} was accepted but we've found newer event {}, \
                         retrying {retry}/{NEWEST_EVENT_ATTEMPTS}",
                        newest_event.id
                    );

                    Box::pin(Self::handle_event(
                        this,
                        newest_event,
                        found_on_relays,
                        retry + 1,
                    ))
                    .await?;
                } else {
                    log::error!(
                        "event {newest_event_id} was accepted, we've found newer event {} on \
                         {found_on_relays:?}, but we're out of attempts, not going to broadcast it",
                        newest_event.id
                    );
                }

                return Ok(());
            }

            Self::ignore_failing_relays_without_our_events(
                this.clone(),
                relays_without_event,
                Some(&event),
            )
            .await;
        }
        Ok(())
    }

    async fn ignore_failing_relays_without_our_events(
        this: Arc<Self>,
        relays_without_event: IndexSet<RelayUrl>,
        event: Option<&Event>,
    ) {
        join_all(relays_without_event.into_iter().map(async |relay_url| {
            let permit = this.relays_failure_budget.acquire().await;
            log::debug!("checking {relay_url} after failure");
            let relay = this
                .nostr_client
                .relay(&relay_url)
                .await?
                .context("relay")?;
            if relay.status() == RelayStatus::Banned || {
                this.facts
                    .read()
                    .await
                    .seen_relay_info_after_failure
                    .contains(&relay_url)
            } {
                return Ok(());
            }

            {
                this.facts
                    .write()
                    .await
                    .seen_relay_info_after_failure
                    .insert(relay_url.clone());
            }

            let connect_timeout = this.args.connect_timeout.0;
            let connected_relay = tokio::spawn({
                async move {
                    relay.wait_for_connection(connect_timeout).await;
                    relay
                }
            });

            log::debug!("discovering relay info for {relay_url}");
            let mut has_limitation = false;
            let mut has_requirements = false;
            let mut has_info_from_discovery = false;

            if let Some(relay_discovery) = this
                .nostr_client
                .fetch_events(
                    this.filter_in_update_interval_with_age(WEEK_SECS)
                        .limit(1)
                        .kind(EventKind::RelayDiscovery)
                        .identifier(relay_url.as_str()),
                )
                .timeout(this.args.request_timeout.0)
                .await
                .ok()
                .and_then(|i| i.first_owned())
            {
                let requirements = relay_discovery
                    .tags
                    .into_iter()
                    .filter_map(|t| Nip66Tag::parse(t.into_iter()).ok())
                    .filter_map(|t| match t {
                        Nip66Tag::Requirement(requirement) => Some(requirement),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                log::debug!("relay {relay_url} has requirements {requirements:?}");
                has_limitation = requirements
                    .iter()
                    .any(|t| ["auth", "payment"].contains(&t.as_str()));

                let info_from_discovery =
                    RelayInformationDocument::from_json(&relay_discovery.content);
                log::debug!("discovered relay info for {relay_url}: {info_from_discovery:?}");

                if !has_limitation {
                    has_limitation = has_publish_limitation(&info_from_discovery);
                }

                has_requirements = !requirements.is_empty();
                has_info_from_discovery = info_from_discovery.is_ok();
            }

            if !has_limitation && !has_requirements && !has_info_from_discovery {
                let relay = connected_relay.await?;
                if relay.status() != RelayStatus::Connected {
                    log::debug!("requesting relay info for {relay_url}");
                    let mut url = relay_url.as_str().parse::<Url>()?;
                    url.set_scheme(match url.scheme() {
                        "ws" => "http",
                        "wss" => "https",
                        _ => ah::bail!("unexpected scheme"),
                    })
                    .map_err(|e| ah::anyhow!("{e:?}"))?;

                    let info = this
                        .http_client
                        .get(url)
                        .header(header::ACCEPT, APPLICATION_NOSTR_JSON)
                        .send()
                        .await;
                    match info {
                        Err(e) => {
                            let text = format!("{e:?}");
                            if FATAL_CONNECTION_ERRORS.iter().any(|i| text.contains(i)) {
                                this.force_block(&relay_url, &text).await;
                                return Ok(());
                            } else {
                                log::debug!(
                                    "failed to retrieve relay info for {relay_url}: {text}"
                                );
                            }
                        },
                        Ok(info) if info.status() == reqwest::StatusCode::OK => {
                            let bytes = info.bytes().await?;
                            let info_from_nip11 =
                                serde_json::from_slice::<RelayInformationDocument>(&bytes);
                            log::debug!(
                                "retrieved relay info for {relay_url}: {info_from_nip11:?}"
                            );
                            has_limitation = has_publish_limitation(&info_from_nip11);
                        },
                        Ok(info) => {
                            let code = info.status();
                            this.force_block(&relay_url, &format!("unexpected status code {code}"))
                                .await;
                        },
                    }
                }
            }

            if has_limitation {
                this.block_if_no_events_with_same_author(&relay_url, event)
                    .await?;
            }

            drop(permit);
            Ok(())
        }))
        .await;
    }

    async fn block_if_no_events_with_same_author(
        &self,
        relay_url: &RelayUrl,
        event: Option<&Event>,
    ) -> ah::Result<()> {
        let mut authors: IndexSet<PublicKey> = self.args.pubkeys.clone().unwrap_or_default().0;
        if let Some(event) = event {
            authors.insert(event.pubkey);
        }

        if authors.is_empty() {
            return Ok(());
        }

        let filter = Filter::new().limit(1).authors(authors);
        let mut filters = vec![filter.clone()];
        if let Some(event) = event {
            filters.push(filter.kind(event.kind));
        }

        let relay = self
            .nostr_client
            .relay(relay_url)
            .await?
            .context("relay_second_attempt")?;
        relay.wait_for_connection(self.args.connect_timeout.0).await;

        let found_event_with_same_author = relay
            .fetch_events(filters)
            .timeout(self.args.request_timeout.0)
            .await
            .ok()
            .and_then(|i| i.first_owned())
            .is_some();

        if found_event_with_same_author {
            self.facts
                .write()
                .await
                .found_relevant_event
                .put(relay_url.clone(), ());
        } else {
            self.force_block(relay_url, "relay is limited and has no relevant events")
                .await;
        }
        Ok(())
    }

    fn filter_in_update_interval_with_age(&self, age_secs: u64) -> Filter {
        let interval = self.args.update_interval.0.as_secs();
        let now = Timestamp::now().as_secs();
        Filter::new()
            .since(Timestamp::from_secs(
                now.saturating_sub(interval).saturating_sub(age_secs),
            ))
            .until(Timestamp::from_secs(now.saturating_add(interval)))
    }

    async fn spawn_handle_relay_error(this: Arc<Self>, err: RelayError, relay_url: RelayUrl) {
        tokio::spawn(async move {
            match err {
                RelayError::RelayMessage(text) => {
                    for reason in ["auth-required", "blocked", "restricted"] {
                        if text.contains(reason) {
                            this.block(&relay_url, &text).await;
                            break;
                        }
                    }
                },
                RelayError::NotConnected => {
                    Self::ignore_failing_relays_without_our_events(this, [relay_url].into(), None)
                        .await;
                },
                _ => {
                    log::debug!("relay {relay_url} error: {err:?}");
                },
            }
            Ok::<_, ah::Error>(())
        });
    }

    async fn add_relay(&self, url: &RelayUrl) {
        log::debug!("adding relay {url}");
        let _ = self.nostr_client.add_relay(url).reconnect(false).await;
    }

    async fn remove_relay(&self, url: &RelayUrl) {
        log::debug!("removing relay {url}");
        let _ = self.nostr_client.remove_relay(url).force().await;
    }

    async fn block(&self, relay_url: &RelayUrl, reason: &str) {
        let has_gossip = self.args.no_gossip_discovery || self.policy.is_gossip(relay_url).await;
        if !has_gossip {
            self.force_block(relay_url, reason).await;
        }
    }

    async fn force_block(&self, relay_url: &RelayUrl, reason: &str) {
        log::debug!("blocking {relay_url} due to {reason}");
        let mut lock = self.facts.write().await;
        lock.found_relevant_event.pop(relay_url);
        lock.seen_relay_info_after_failure.remove(relay_url);
        self.policy.block_relay(relay_url).await;
        drop(lock);
    }

    pub(crate) async fn client_relays(&self) -> IndexSet<RelayUrl> {
        self.nostr_client.relays().await.into_keys().collect()
    }

    pub(crate) async fn banned_client_relays(&self) -> IndexSet<RelayUrl> {
        self.nostr_client
            .relays()
            .await
            .values()
            .filter(|i| i.status() == RelayStatus::Banned)
            .map(|i| i.url().clone())
            .collect()
    }

    // TODO
    pub(crate) fn maybe_can_connect_to_tor(&self) -> bool {
        self.args.tor_proxy.is_some() || self.args.proxy.is_some()
    }
}

impl RelaysAndSenders {
    pub(crate) fn new(args: &Broadcastr) -> ah::Result<Self> {
        let relay_lists = Arc::new(RwLock::new(RelayLists::default()));
        let (azzamo_block_pubkeys_sender, azzamo_block_pubkeys_receiver) =
            watch::channel(HashSet::default());

        let policy = InnerPolicy::new(args, relay_lists.clone(), azzamo_block_pubkeys_receiver);

        let relay_limits = RelayLimits {
            events: RelayEventLimits {
                max_size: Some(args.max_msg_size as u32),
                max_num_tags: Some(args.max_tags),
                max_num_tags_per_kind: HashMap::from([(EventKind::ContactList, Some(u16::MAX))]),
                ..Default::default()
            },
            ..Default::default()
        };

        let nostr_client = NostrClient::builder()
            // event signing is not supported
            .automatic_authentication(false)
            .gossip_config(GossipConfig {
                limits: GossipRelayLimits {
                    read_relays_per_user: 0,
                    write_relays_per_user: 0,
                    hint_relays_per_user: 0,
                    most_used_relays_per_user: 0,
                    nip17_relays: 0,
                },
                ..Default::default()
            })
            .relay_limits(relay_limits)
            .max_relays(args.max_relays)
            .proxy(Proxy::custom({
                let tor_proxy = args.tor_proxy;
                let proxy = args.proxy;
                move |relay_url| {
                    if relay_url.is_localhost() || relay_url.is_local_addr() {
                        None
                    } else if relay_url.is_onion() {
                        tor_proxy
                    } else {
                        proxy
                    }
                }
            }))
            .ban_relay_on_mismatch(true)
            .admit_policy(policy.clone())
            .build();

        let http_client = proxied_client_builder(args)?
            .pool_max_idle_per_host(0)
            .default_headers(
                [(header::CONNECTION, "close".parse()?)]
                    .into_iter()
                    .collect(),
            )
            .build()?;

        let relays = Arc::new(Relays {
            nostr_client,
            http_client,
            args: args.clone(),
            policy: Arc::new(Policy::new(policy, args)),
            seen_pubkeys: Arc::new(Mutex::new(LruCache::new(MAX_SEEN_AUTHORS))),
            facts: RwLock::new(RelayFacts {
                seen_relay_info_after_failure: Default::default(),
                found_relevant_event: if let Some(max_relays) = args.max_relays {
                    LruCache::new(max_relays)
                } else {
                    LruCache::unbounded()
                },
            }),
            relays_failure_budget: Semaphore::const_new(MAX_CONCURRENT_FAILURE_CHECKS),
        });

        Ok(Self {
            relays,
            azzamo_block_pubkeys_sender,
        })
    }
}

impl QueryEvent {
    pub(crate) async fn find(
        event: &Event,
        pubkeys: &HashSet<PublicKey>,
        relays: &Relays,
        found_on_relays: &IndexSet<RelayUrl>,
    ) -> ah::Result<Self> {
        let args = &relays.args;
        let nostr_client = &relays.nostr_client;
        let read_write = relays.policy.read_write_for(pubkeys, event.kind).await;

        let now = Timestamp::now().as_secs();
        let until = Timestamp::from_secs(now.saturating_add(args.update_interval.0.as_secs()));

        let (newest_event, found_on_relays): (Event, IndexSet<RelayUrl>) =
            join_all(nostr_client.relays().await.into_iter().map({
                let read_write = read_write.clone();
                move |(relay_url, relay)| {
                    let read_write = read_write.clone();
                    async move {
                        if relay.status() == RelayStatus::Banned
                            || !read_write.contains(&relay_url)
                            || found_on_relays.contains(&relay_url)
                        {
                            return None;
                        }

                        relay.wait_for_connection(args.connect_timeout.0).await;

                        let filter = Filter::new()
                            .author(event.pubkey)
                            .kind(event.kind)
                            .since(event.created_at)
                            .until(until)
                            .limit(1);
                        let filter = if event.kind.is_addressable()
                            && let Some(identifier) = event.tags.identifier()
                        {
                            filter.identifier(identifier)
                        } else if event.kind.is_replaceable() {
                            filter
                        } else {
                            filter.id(event.id)
                        };

                        match relay
                            .fetch_events(filter.clone())
                            .timeout(args.request_timeout.0)
                            .await
                        {
                            Ok(events) if !events.is_empty() => events
                                .into_iter()
                                .filter(|e| filter.match_event(e, MatchEventOptions::default()))
                                .max_by_key(|e| e.created_at)
                                .map(|e| (e, relay_url)),
                            Ok(_) => None,
                            Err(e) => {
                                log::debug!("cannot query relay {relay_url}: {e}");
                                None
                            },
                        }
                    }
                }
            }))
            .await
            .into_iter()
            .flatten()
            .chunk_by(|(e, _)| e.clone())
            .into_iter()
            .max_by_key(|(e, _)| e.created_at)
            .map(|(newest_event, event_to_relay_urls)| {
                let same = event.id == newest_event.id;
                (
                    newest_event,
                    event_to_relay_urls
                        .into_iter()
                        .map(|(_, u)| u)
                        .chain(if same {
                            Either::Left(found_on_relays.iter().cloned())
                        } else {
                            Either::Right(iter::empty())
                        })
                        .collect::<IndexSet<RelayUrl>>(),
                )
            })
            .unwrap_or_else(|| (event.clone(), found_on_relays.clone()));

        // some relays were possibly banned and removed, retrieving them again
        let relays_without_event = read_write.sub(&found_on_relays);

        Ok(Self {
            newest_event,
            found_on_relays,
            relays_without_event,
        })
    }
}

impl RelayListCreatedAt {
    pub fn new(value: Option<u64>) -> Self {
        Self(value.map(Timestamp::from_secs))
    }

    pub fn to_u64(self) -> u64 {
        self.0.map(|i| i.as_secs()).unwrap_or_default()
    }
}

fn elapsed(start: Instant) -> humantime::Duration {
    humantime::Duration::from(start.elapsed())
}
