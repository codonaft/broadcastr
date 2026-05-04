use super::{Broadcastr, retry_with_backoff_endless};
use crate::{
    Policy,
    nostr_utils::has_publish_limitation,
    policy::InnerPolicy,
    proxied_client_builder,
    relay_lists::{GossipRelayLists, RelayLists},
};
use anyhow::{self as ah, Context};
use futures::{StreamExt, future::join_all};
use nostr::{
    Alphabet, Event, Filter, Kind as EventKind, PublicKey, RelayUrl, TagStandard, Timestamp,
    event::TagKind, filter::MatchEventOptions, nips::nip11::RelayInformationDocument, serde_json,
    util::JsonUtil,
};
use nostr_sdk::{
    client::{Client as NostrClient, Connection, GossipConfig, GossipRelayLimits},
    relay::{
        Error as RelayError, RelayCapabilities, RelayEventLimits, RelayLimits, RelayStatus,
        ReqExitPolicy,
    },
};
use reqwest::{Client as HttpClient, Url};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    ops::Sub,
    sync::Arc,
    time::Instant,
};
use tokio::{
    sync::{RwLock, watch},
    time,
};

const MAX_GOSSIP_RELAYS: usize = 3;
const WEEK_SECS: u64 = 7 * 24 * 60 * 60;
const FATAL_CONNECTION_ERRORS: [&str; 7] = [
    "dns error",
    "InvalidCertificate",
    "ExpiredContext",
    "UnrecognisedName",
    "NotValidForNameContext",
    "tls handshake eof",
    "0.0.0.0:443",
];

#[derive(Debug)]
pub(crate) struct Relays {
    pub nostr_client: NostrClient,
    pub http_client: HttpClient,
    pub args: Broadcastr,
    pub policy: Arc<Policy>,
    pub seen_relay_info_after_failure: RwLock<HashSet<RelayUrl>>,
}

pub(crate) struct RelaysAndSenders {
    pub relays: Arc<Relays>,
    pub azzamo_block_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
}

#[derive(Debug)]
struct QueryEvent {
    found_on_relays: HashSet<RelayUrl>,
    relays_without_event: HashSet<RelayUrl>,
}

impl Relays {
    pub(crate) async fn updater(this: Arc<Self>) -> ah::Result<()> {
        let mut initialized = false;
        let mut interval = time::interval(this.args.update_interval.0);
        loop {
            interval.tick().await;
            retry_with_backoff_endless(this.args.clone(), || {
                let this = this.clone();
                async move {
                    if let Err(e) = Self::update_relays(&this).await {
                        log::error!("failed to update relays: {e}");
                    }
                    Self::update_connections(&this).await;
                    Self::update_subscriptions(this, initialized).await?;
                    Ok(())
                }
            })
            .await?;
            initialized = true;
        }
    }

    async fn update_relays(this: &Arc<Self>) -> ah::Result<()> {
        log::info!("updating relays");

        let RelayLists {
            read_write,
            read,
            block,
            gossip,
        } = RelayLists::new(this).await?;

        if read_write.is_empty() && read.is_empty() && !block.is_empty() {
            let relay_lists = this.policy.relay_lists();
            let mut write = relay_lists.write().await;
            *write = RelayLists {
                read_write,
                read,
                block: Default::default(),
                gossip,
            };
            return Err(ah::anyhow!("all relays are blocked"));
        }

        for i in &block {
            let _ = this.nostr_client.remove_relay(i).force().await;
        }

        let gossip = GossipRelayLists::fetch(this, &block).await?;
        for i in gossip.write.iter().take(MAX_GOSSIP_RELAYS) {
            let _ = this
                .nostr_client
                .add_relay(i)
                .capabilities(RelayCapabilities::WRITE)
                .await;
        }
        for i in gossip.read.iter().take(MAX_GOSSIP_RELAYS) {
            let _ = this
                .nostr_client
                .add_relay(i)
                .capabilities(RelayCapabilities::READ)
                .await;
        }

        for i in &read {
            let _ = this
                .nostr_client
                .add_relay(i)
                .capabilities(RelayCapabilities::READ)
                .await;
        }

        for i in &read_write {
            let _ = this
                .nostr_client
                .add_relay(i)
                .capabilities(RelayCapabilities::READ | RelayCapabilities::WRITE)
                .await;
        }

        {
            let relay_lists = this.policy.relay_lists();
            let mut write = relay_lists.write().await;
            *write = RelayLists {
                read_write,
                read,
                block,
                gossip,
            };
        }

        log::debug!("finished updating relays");
        Ok(())
    }

    async fn update_connections(this: &Arc<Self>) {
        log::info!("updating connections");
        let start = Instant::now();
        this.nostr_client
            .connect()
            .and_wait(this.args.connect_timeout.0)
            .await;
        let elapsed = elapsed(start);

        let client_relays = this.nostr_client.relays().await;
        let connected_relays = client_relays
            .values()
            .filter(|i| i.status().is_connected())
            .count();

        let blocked_relays = this
            .policy
            .blocked_relays()
            .await
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>();
        log::info!(
            "currently connected to {connected_relays}/{} relays, blocked relays {}",
            client_relays.len(),
            blocked_relays.len(),
        );
        log::debug!("reconnected in {elapsed}, blocked relays: {blocked_relays:?}");
    }

    async fn update_subscriptions(this: Arc<Self>, initialized: bool) -> ah::Result<()> {
        let mut futures = vec![];
        let timeout = this.args.update_interval.0;
        let policy = ReqExitPolicy::WaitDurationAfterEOSE(timeout);

        if this.args.subscribe
            && let (Some(pubkeys), Some(kinds)) =
                (this.args.pubkeys.clone(), this.args.kinds.clone())
        {
            let this = this.clone();
            futures.push(tokio::spawn(async move {
                let filter = this.filter_in_update_interval_with_age(0).kinds(kinds.0);
                let filters = [
                    filter.clone().authors(pubkeys.0.iter().copied()),
                    filter.pubkeys(pubkeys.0),
                ];
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
                                log::debug!(
                                    "received broadcastable event {event_id} from subscription"
                                );
                                let _ =
                                    Self::spawn_handle_event(this.clone(), event, None, true).await;
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

        let pool_has_empty_space = if let Some(max) = this.args.max_relays {
            this.nostr_client.relays().await.len() < max.get()
        } else {
            true
        };

        if !this.args.no_nip66_discovery && pool_has_empty_space {
            futures.push(tokio::spawn(async move {
                let filter = this
                    .filter_in_update_interval_with_age(if initialized { 0 } else { WEEK_SECS })
                    .kind(EventKind::RelayDiscovery);
                let mut stream = this
                    .nostr_client
                    .stream_events(filter)
                    .timeout(timeout)
                    .policy(policy)
                    .await
                    .context("relay_discovery")?;

                let mut discovered = 0;
                let relay_lists: RelayLists = { this.policy.relay_lists().read().await.clone() };
                while let Some((stream_relay_url, stream_event)) = stream.next().await {
                    match stream_event {
                        Ok(event) => {
                            if event.kind == EventKind::RelayDiscovery
                                && !this.args.no_nip66_discovery
                                && let Some(Ok(url)) = event.tags.identifier().map(RelayUrl::parse)
                                && !relay_lists.contains(&url)
                            {
                                log::debug!("discovered relay {url}");
                                let _ = this
                                    .nostr_client
                                    .add_relay(url)
                                    .capabilities(
                                        RelayCapabilities::READ | RelayCapabilities::WRITE,
                                    )
                                    .await;
                                discovered += 1;
                            }
                        },
                        Err(e) => {
                            Self::spawn_handle_relay_error(this.clone(), e, stream_relay_url).await;
                        },
                    }
                }

                log::info!("discovered {discovered} new relays");
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
        log::info!("closed all subscriptions after {}", elapsed(start));
        result.map_err(ah::Error::from)
    }

    pub(crate) async fn spawn_handle_event(
        this: Arc<Self>,
        event: Event,
        ip: Option<IpAddr>,
        silent: bool,
    ) -> ah::Result<()> {
        let result = this.policy.check(&event, ip).await;
        if let Err(e) = &result {
            let event_id = event.id;
            if !silent {
                log::error!("event {event_id} not accepted: {e}");
            }
            return result;
        }

        tokio::spawn(async move {
            if let Err(e) = Self::handle_event(this, event).await {
                log::error!("failed to handle a message: {e}");
            }
        });

        Ok(())
    }

    async fn handle_event(this: Arc<Self>, event: Event) -> ah::Result<()> {
        let event_id = event.id;
        let QueryEvent {
            found_on_relays,
            relays_without_event,
        } = QueryEvent::find(&event, &this).await.context("query")?;

        let found_on_relays_before_broadcasting = found_on_relays.len();
        if relays_without_event.is_empty() {
            ah::bail!(
                "already found the event {event_id} on all of the \
                 {found_on_relays_before_broadcasting} relays, not going to broadcast it",
            );
        } else {
            let found_message = if found_on_relays_before_broadcasting > 0 {
                format!("found event {event_id} on {found_on_relays_before_broadcasting} relays, ")
            } else {
                "".to_string()
            };
            log::info!(
                "{found_message}broadcasting to {} relays (of all of the {} relays)",
                relays_without_event.len(),
                found_on_relays_before_broadcasting.saturating_add(relays_without_event.len()),
            );

            if let Err(e) = this
                .nostr_client
                .send_event(&event)
                .to(relays_without_event)
                .await
            {
                this.policy.forget(event_id).await;
                log::error!("failed to broadcast event {event_id}: {e}");
            } else {
                let QueryEvent {
                    found_on_relays,
                    relays_without_event,
                } = QueryEvent::find(&event, &this).await.context("re-query")?;
                let broadcasted_to_new_relays = found_on_relays
                    .len()
                    .saturating_sub(found_on_relays_before_broadcasting);
                log::info!(
                    "event {event_id} was accepted by {broadcasted_to_new_relays} relays (now \
                     it's available on {} of {} relays)",
                    found_on_relays.len(),
                    found_on_relays
                        .len()
                        .saturating_add(relays_without_event.len()),
                );
                Self::ignore_failing_relays_without_our_events(
                    this,
                    relays_without_event,
                    Some(&event),
                )
                .await;
            }
        }
        Ok(())
    }

    async fn ignore_failing_relays_without_our_events(
        this: Arc<Self>,
        relays_without_event: HashSet<RelayUrl>,
        event: Option<&Event>,
    ) {
        join_all(relays_without_event.into_iter().map(async |relay_url| {
            let relay = this
                .nostr_client
                .relay(&relay_url)
                .await?
                .context("relay")?;
            if relay.status() == RelayStatus::Banned || {
                this.seen_relay_info_after_failure
                    .read()
                    .await
                    .contains(&relay_url)
            } {
                return Ok(());
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
                {
                    this.seen_relay_info_after_failure
                        .write()
                        .await
                        .insert(relay_url.clone());
                }

                let requirements = relay_discovery
                    .tags
                    .filter_standardized(TagKind::single_letter(Alphabet::R, true))
                    .filter_map(|t| match t {
                        TagStandard::RelayRequirement(requirement) => Some(requirement),
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
                    log::debug!("relay {relay_url} possibly failing");

                    if this.args.no_nip11_requests {
                        this.force_block(&relay_url, "possible fatal connection failure")
                            .await?;
                        return Ok(());
                    }

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
                        .header(reqwest::header::ACCEPT, "application/nostr+json")
                        .send()
                        .await;
                    match info {
                        Err(e) => {
                            let text = format!("{e:?}");
                            if FATAL_CONNECTION_ERRORS.iter().any(|i| text.contains(i)) {
                                this.force_block(&relay_url, &text).await?;
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
                                .await?;
                        },
                    }
                }
            }

            if has_limitation {
                this.block_if_no_events_with_same_author(&relay_url, event)
                    .await?;
            }
            Ok(())
        }))
        .await;
    }

    async fn block_if_no_events_with_same_author(
        &self,
        relay_url: &RelayUrl,
        event: Option<&Event>,
    ) -> ah::Result<()> {
        let mut authors: HashSet<PublicKey> = self.args.pubkeys.clone().unwrap_or_default().0;
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

        if !found_event_with_same_author {
            self.force_block(relay_url, "relay is limited and has no relevant events")
                .await?;
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
        tokio::spawn(async {
            match err {
                RelayError::RelayMessage(text) => {
                    for reason in ["auth-required", "blocked", "restricted"] {
                        if text.contains(reason) {
                            this.block(&relay_url, &text).await?;
                            break;
                        }
                    }
                },
                RelayError::NotConnected => {
                    Self::ignore_failing_relays_without_our_events(this, [relay_url].into(), None)
                        .await;
                },
                _ => {
                    log::debug!("relay {relay_url} answered {err:?}");
                },
            }
            Ok::<_, ah::Error>(())
        });
    }

    async fn block(&self, relay_url: &RelayUrl, reason: &str) -> ah::Result<()> {
        let has_gossip = self.args.no_gossip_discovery || self.policy.is_gossip(relay_url).await;
        if !has_gossip {
            log::debug!("blocking {relay_url} due to {reason}");
            self.policy.block_relay(relay_url).await;
        }
        Ok(())
    }

    async fn force_block(&self, relay_url: &RelayUrl, reason: &str) -> ah::Result<()> {
        log::debug!("force blocking {relay_url} due to {reason}");
        self.policy.block_relay(relay_url).await;
        Ok(())
    }
}

impl RelaysAndSenders {
    pub(crate) fn new(args: &Broadcastr, connection: Connection) -> ah::Result<Self> {
        let relay_lists = Arc::new(RwLock::new(RelayLists::default()));
        let seen_relay_info_after_failure = RwLock::new(HashSet::default());
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
            .connection(connection)
            .ban_relay_on_mismatch(true)
            .admit_policy(policy.clone())
            .build();

        let http_client = proxied_client_builder(args)?.tcp_keepalive(None).build()?;

        let relays = Arc::new(Relays {
            nostr_client,
            http_client,
            args: args.clone(),
            policy: Arc::new(Policy::new(policy, args)),
            seen_relay_info_after_failure,
        });

        Ok(Self {
            relays,
            azzamo_block_pubkeys_sender,
        })
    }
}

impl QueryEvent {
    pub(crate) async fn find(event: &Event, relays: &Relays) -> ah::Result<Self> {
        let args = &relays.args;
        let nostr_client = &relays.nostr_client;
        let event_id = event.id;
        let found_on_relays = join_all(
            nostr_client
                .relays()
                .with_capabilities(RelayCapabilities::READ | RelayCapabilities::WRITE)
                .await
                .into_iter()
                .map(|(relay_url, relay)| async move {
                    if relay.status() == RelayStatus::Banned {
                        return None;
                    }

                    relay.wait_for_connection(args.connect_timeout.0).await;
                    let filter = Filter::new().id(event_id).limit(1);
                    match relay
                        .fetch_events(filter)
                        .timeout(args.request_timeout.0)
                        .await
                    {
                        Ok(events)
                            if !events.is_empty() && events.iter().any(|i| i.id == event_id) =>
                        {
                            Some(relay_url)
                        },
                        Ok(_) => None,
                        Err(e) => {
                            log::debug!("cannot query relay {relay_url}: {e}");
                            None
                        },
                    }
                }),
        )
        .await
        .into_iter()
        .flatten()
        .collect::<HashSet<RelayUrl>>();

        // some relays were possibly banned and removed, retrieving them again
        let relay_urls: HashSet<RelayUrl> = nostr_client.relays().await.into_keys().collect();
        let relays_without_event = relay_urls.sub(&found_on_relays);

        Ok(Self {
            found_on_relays,
            relays_without_event,
        })
    }
}

fn elapsed(start: Instant) -> humantime::Duration {
    humantime::Duration::from(start.elapsed())
}
