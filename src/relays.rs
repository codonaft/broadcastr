use super::{Broadcastr, retry_with_backoff_endless};
use crate::{
    Policy, normalize_url, nostr_helpers::has_publish_limitation, policy::InnerPolicy,
    proxied_client_builder, relay_lists::RelayLists,
};
use anyhow::{self as ah, Context};
use futures::{StreamExt, future::join_all};
use nostr::{
    Alphabet, Event, EventId, Filter, Kind as EventKind, PublicKey, RelayUrl, TagStandard,
    Timestamp, event::TagKind, nips::nip11::RelayInformationDocument, serde_json, util::JsonUtil,
};
use nostr_sdk::{
    client::{Client as NostrClient, Connection, GossipConfig, GossipRelayLimits},
    relay::{RelayCapabilities, RelayEventLimits, RelayLimits, RelayStatus, ReqExitPolicy},
};
use reqwest::Url;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    ops::Sub,
    sync::Arc,
    time::Instant,
};
use tokio::{
    sync::{Mutex, RwLock, watch},
    time,
};

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
    pub args: Broadcastr,
    pub policy: Arc<Policy>,
    pub seen_relay_info_after_failure: RwLock<HashSet<Url>>,
    pub nip66_discovered: Mutex<HashSet<Url>>,
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
        let mut interval = time::interval(this.args.update_interval.0);
        loop {
            interval.tick().await;
            retry_with_backoff_endless(this.args.clone(), || {
                let this = this.clone();
                async move {
                    let result = Self::update_relays(&this).await;
                    if let Err(e) = &result {
                        log::error!("failed to update relays: {e}");
                    }
                    Self::update_connections(&this).await;
                    Self::spawn_relays_discovery(this.clone());
                    Self::update_subscription(this).await?;
                    Ok(result?)
                }
            })
            .await?;
        }
    }

    async fn update_relays(this: &Arc<Self>) -> ah::Result<()> {
        log::info!("updating relays");

        let discovery_flag = if this.args.no_gossip_discovery {
            RelayCapabilities::NONE
        } else {
            RelayCapabilities::DISCOVERY
        };
        let read_capabilities = discovery_flag | RelayCapabilities::READ;
        let read_write_capabilities = read_capabilities | RelayCapabilities::WRITE;

        let RelayLists {
            read_write,
            read,
            block,
            nip66_discovered,
            client_relays,
        } = RelayLists::new(this).await?;

        if !nip66_discovered.is_empty() {
            let discovered = nip66_discovered
                .iter()
                .map(|i| i.as_str())
                .collect::<Vec<_>>();
            log::info!("discovered new relays {discovered:?}");
        }

        if read_write.is_empty() && read.is_empty() && !block.is_empty() {
            let mut writer = this.policy.policy.block_relays.write().await;
            *writer = Default::default();
            return Err(ah::anyhow!("all relays are blocked"));
        }

        {
            let mut writer = this.policy.policy.block_relays.write().await;
            *writer = block.clone();
        }

        for i in &block {
            let url = RelayUrl::parse(i.as_str())?;
            if client_relays.contains(&url) {
                let _ = this.nostr_client.remove_relay(url).force().await;
            }
        }

        for i in &read_write {
            this.nostr_client
                .add_relay(RelayUrl::parse(i.as_str())?)
                .capabilities(read_write_capabilities)
                .await?;
        }

        for i in &read {
            let url = RelayUrl::parse(i.as_str())?;
            if let Some(relay) = this.nostr_client.relay(&url).await.ok().flatten() {
                relay.capabilities().remove(RelayCapabilities::WRITE);
            }
            this.nostr_client
                .add_relay(url)
                .capabilities(read_capabilities)
                .await?;
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
        let disconnected_relays = client_relays
            .iter()
            .filter(|(_, relay)| !relay.status().is_connected())
            .map(|(url, _)| url.to_string())
            .collect::<Vec<_>>();
        {
            let blocked_relays = this.policy.policy.block_relays.read().await;
            log::info!(
                "currently connected to {connected_relays}/{} relays, disconnected from {}, {} \
                 are blocked",
                client_relays.len(),
                disconnected_relays.len(),
                blocked_relays.len(),
            );
            log::debug!("reconnection took {elapsed}, blocked relays: {blocked_relays:?}");
        };
    }

    fn spawn_relays_discovery(this: Arc<Self>) {
        if this.args.no_nip66_discovery {
            return;
        }

        tokio::spawn(async move {
            log::info!("discovering relays");
            let start = Instant::now();
            let timeout = this.args.update_interval.0;
            let mut stream = this
                .nostr_client
                .stream_events(
                    this.filter_in_update_interval(WEEK_SECS)
                        .kind(EventKind::RelayDiscovery),
                )
                .timeout(timeout)
                .policy(ReqExitPolicy::WaitDurationAfterEOSE(timeout))
                .await?;

            let mut discovered = HashSet::<Url>::default();
            while let Some((_, event)) = stream.next().await {
                if let Ok(event) = event {
                    if let Some(Ok(url)) =
                        event.tags.identifier().map(|i| normalize_url(i.parse()?))
                    {
                        log::debug!("discovering relay {url}");
                        discovered.insert(url);
                    }
                } else {
                    break;
                }
            }

            {
                this.nip66_discovered.lock().await.extend(discovered);
            }

            log::info!("discovering finished after {}", elapsed(start));
            Ok::<_, ah::Error>(())
        });
    }

    async fn update_subscription(this: Arc<Self>) -> ah::Result<()> {
        if !this.args.subscribe {
            return Ok(());
        }

        log::info!("updating subscription");
        if let (Some(pubkeys), Some(kinds)) =
            (this.args.pubkeys.clone(), this.args.event_kinds.clone())
        {
            let filter = this.filter_in_update_interval(0).kinds(kinds.0);
            let filters = [
                filter.clone().authors(pubkeys.0.clone()),
                filter.pubkeys(pubkeys.0),
            ];

            log::debug!("subscribing {filters:?}");
            let start = Instant::now();

            let timeout = this.args.update_interval.0;
            let mut stream = this
                .nostr_client
                .stream_events(filters)
                .timeout(timeout)
                .policy(ReqExitPolicy::WaitDurationAfterEOSE(timeout))
                .await?;

            while let Some((_, event)) = stream.next().await {
                let event = event?;
                log::debug!("received event {} from subscription", event.id);
                let _ = Self::spawn_handle_event(this.clone(), event, None, true).await;
            }

            log::info!("closed all subscriptions after {}", elapsed(start));
        }

        Ok(())
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
        } = QueryEvent::find(event_id, &this.args, &this.nostr_client)
            .await
            .context("query")?;

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
                .to(&relays_without_event)
                .await
            {
                this.policy.forget(event_id).await;
                log::error!("failed to broadcast event {event_id}: {e}");
            } else {
                let QueryEvent {
                    found_on_relays,
                    relays_without_event,
                } = QueryEvent::find(event_id, &this.args, &this.nostr_client)
                    .await
                    .context("re-query")?;
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
                Self::ignore_failing_relays_without_our_events(this, relays_without_event, event)
                    .await;
            }
        }
        Ok(())
    }

    async fn ignore_failing_relays_without_our_events(
        this: Arc<Self>,
        relays_without_event: HashSet<RelayUrl>,
        event: Event,
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
                    .contains(&relay_url.clone().into())
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
                    this.filter_in_update_interval(WEEK_SECS)
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
                        .insert(relay_url.clone().into());
                }

                log::debug!("discovered relay info {relay_discovery:?}");

                let requirements = event
                    .tags
                    .filter_standardized(TagKind::single_letter(Alphabet::R, true))
                    .filter_map(|t| match t {
                        TagStandard::RelayRequirement(requirement) => Some(requirement),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                log::debug!("relay {relay_url} requirements {requirements:?}");
                has_limitation = requirements
                    .iter()
                    .any(|t| ["auth", "payment"].contains(&t.as_str()));

                let info_from_discovery =
                    RelayInformationDocument::from_json(&relay_discovery.content);

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
                        this.policy
                            .block(&relay_url, "possible fatal connection failure")
                            .await?;
                        return Ok(());
                    }

                    let mut url = relay_url.as_str().parse::<Url>()?;
                    url.set_scheme(match url.scheme() {
                        "ws" => "http",
                        "wss" => "https",
                        _ => ah::bail!("unexpected scheme"),
                    })
                    .map_err(|e| ah::anyhow!("{e:?}"))?;

                    let client = proxied_client_builder(&url, &this.args)?
                        .tcp_keepalive(None)
                        .build()?;

                    let info = client
                        .get(url)
                        .header(reqwest::header::ACCEPT, "application/nostr+json")
                        .send()
                        .await;
                    match info {
                        Err(e) => {
                            let text = format!("{e:?}");
                            log::debug!("failed to retrieve relay info for {relay_url}: {text}");
                            if FATAL_CONNECTION_ERRORS.iter().any(|i| text.contains(i)) {
                                this.policy
                                    .block(&relay_url, "fatal connection failure")
                                    .await?;
                                return Ok(());
                            }
                        },
                        Ok(info) if info.status() == reqwest::StatusCode::OK => {
                            let bytes = info.bytes().await?;
                            let info_from_nip11 =
                                serde_json::from_slice::<RelayInformationDocument>(&bytes);
                            has_limitation = has_publish_limitation(&info_from_nip11);
                        },
                        Ok(info) => {
                            let code = info.status();
                            this.policy
                                .block(&relay_url, &format!("unexpected status code {code}"))
                                .await?;
                        },
                    }
                }
            }

            if has_limitation {
                this.block_if_no_events_with_same_author(relay_url, &event)
                    .await?;
            }
            Ok(())
        }))
        .await;
    }

    async fn block_if_no_events_with_same_author(
        &self,
        relay_url: RelayUrl,
        event: &Event,
    ) -> ah::Result<()> {
        let mut authors: HashSet<PublicKey> = self.args.pubkeys.clone().unwrap_or_default().0;
        authors.insert(event.pubkey);
        let filter = Filter::new().limit(1).authors(authors);
        let filters = [filter.clone(), filter.kind(event.kind)];

        let relay = self
            .nostr_client
            .relay(&relay_url)
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
            self.policy
                .block(&relay_url, "relay is limited and has no relevant events")
                .await?;
        }
        Ok(())
    }

    fn filter_in_update_interval(&self, age_secs: u64) -> Filter {
        let interval = self.args.update_interval.0.as_secs();
        let now = Timestamp::now().as_secs();
        Filter::new()
            .since(Timestamp::from_secs(
                now.saturating_sub(interval).saturating_sub(age_secs),
            ))
            .until(Timestamp::from_secs(now.saturating_add(interval)))
    }
}

impl RelaysAndSenders {
    pub(crate) fn new(args: &Broadcastr, connection: Connection) -> ah::Result<Self> {
        let block_relays = Arc::new(RwLock::new(HashSet::default()));
        let seen_relay_info_after_failure = RwLock::new(HashSet::default());
        let (azzamo_block_pubkeys_sender, azzamo_block_pubkeys_receiver) =
            watch::channel(HashSet::default());

        let policy = InnerPolicy::new(args, block_relays.clone(), azzamo_block_pubkeys_receiver);

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
                limits: if args.no_gossip_discovery {
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
            .max_relays(args.max_relays)
            .connection(connection)
            .ban_relay_on_mismatch(true)
            .admit_policy(policy.clone())
            .build();
        let policy = Arc::new(Policy::new(policy, args));

        let relays = Arc::new(Relays {
            nostr_client: nostr_client.clone(),
            args: args.clone(),
            policy: policy.clone(),
            seen_relay_info_after_failure,
            nip66_discovered: Mutex::new(Default::default()),
        });

        Ok(Self {
            relays,
            azzamo_block_pubkeys_sender,
        })
    }
}

impl QueryEvent {
    pub(crate) async fn find(
        event_id: EventId,
        args: &Broadcastr,
        nostr_client: &NostrClient,
    ) -> ah::Result<Self> {
        let relays = nostr_client.relays().await;
        let relay_urls: HashSet<RelayUrl> = relays.keys().cloned().collect();
        let found_on_relays: HashSet<RelayUrl> =
            join_all(relays.into_iter().map(|(relay_url, relay)| async move {
                if relay.status() == RelayStatus::Banned {
                    return None;
                }

                let filter = Filter::new().id(event_id).limit(1);
                match relay
                    .fetch_events(filter)
                    .timeout(args.request_timeout.0)
                    .await
                {
                    Ok(events) if !events.is_empty() && events.iter().any(|i| i.id == event_id) => {
                        Some(relay_url)
                    },
                    Ok(_) => None,
                    Err(e) => {
                        log::debug!("cannot query relay {relay_url}: {e}");
                        None
                    },
                }
            }))
            .await
            .into_iter()
            .flatten()
            .collect();
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
