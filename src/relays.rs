use super::{Broadcastr, retry_with_backoff_endless};
use crate::{Policy, normalize_url, relay_lists::RelayLists};
use anyhow::{self as ah, Context};
use futures::{StreamExt, future::join_all};
use nostr::{
    Event, EventId, Filter, Kind as EventKind, RelayUrl, Timestamp,
    event::TagKind,
    key::PublicKey,
    nips::nip11::{Limitation, RelayInformationDocument},
    util::JsonUtil,
};
use nostr_sdk::{
    client::Client as NostrClient,
    relay::{RelayCapabilities, RelayStatus, ReqExitPolicy},
};
use reqwest::Url;
use std::{borrow::Cow, collections::HashSet, net::IpAddr, ops::Sub, sync::Arc, time::Instant};
use tokio::{
    sync::{Mutex, RwLock},
    time,
};

const RELAY_DISCOVERY: EventKind = EventKind::Custom(30166); // TODO: contribute?

#[derive(Debug)]
pub(crate) struct Relays {
    pub nostr_client: NostrClient,
    pub args: Broadcastr,
    pub policy: Arc<Policy>,
    pub seen_relay_info: RwLock<HashSet<Url>>,
    pub nip66_discovered: Mutex<HashSet<Url>>,
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

        let discovery_flag = if this.args.no_gossip {
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
        } = RelayLists::new(&this).await?;

        if !nip66_discovered.is_empty() {
            log::info!("discovered new relays {nip66_discovered:?}");
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
            .and_wait(this.args.connection_timeout.0)
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
        let blocked_relays = { this.policy.policy.block_relays.read().await };
        log::info!(
            "currently connected to {connected_relays}/{} relays, disconnected from {}, {} are \
             blocked",
            client_relays.len(),
            disconnected_relays.len(),
            blocked_relays.len(),
        );
        log::debug!("reconnection took {elapsed}, blocked relays: {blocked_relays:?}");
    }

    fn spawn_relays_discovery(this: Arc<Self>) {
        if this.args.no_nip66 {
            return;
        }

        tokio::spawn(async move {
            log::info!("discovering relays");
            let start = Instant::now();
            let mut stream = this
                .nostr_client
                .stream_events(Filter::new().kind(RELAY_DISCOVERY))
                .timeout(this.args.update_interval.0)
                .policy(ReqExitPolicy::WaitDurationAfterEOSE(
                    this.args.update_interval.0,
                ))
                .await?;

            let mut discovered = HashSet::<Url>::default();
            while let Some((_, Ok(event))) = stream.next().await {
                if let Some(Ok(url)) = event.tags.identifier().map(|i| normalize_url(i.parse()?)) {
                    log::debug!("discovering relay {url}");
                    discovered.insert(url);
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
            let now = Timestamp::now().as_secs();
            let interval = this.args.update_interval.0.as_secs();
            let filter = Filter::new()
                .since(Timestamp::from_secs(now.saturating_sub(interval)))
                .until(Timestamp::from_secs(now.saturating_add(interval)))
                .kinds(kinds.0);
            let filters = [
                filter.clone().authors(pubkeys.0.clone()),
                filter.pubkeys(pubkeys.0),
            ];

            log::debug!("subscribing {filters:?}");
            let start = Instant::now();

            let mut stream = this
                .nostr_client
                .stream_events(filters.clone())
                .timeout(this.args.update_interval.0)
                .policy(ReqExitPolicy::WaitDurationAfterEOSE(
                    this.args.update_interval.0,
                ))
                .await?;

            while let Some((_, Ok(event))) = stream.next().await {
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
        if !this.args.detect_failing_relays {
            return;
        }

        join_all(relays_without_event.into_iter().map(async |relay_url| {
            let relay = this
                .nostr_client
                .relay(&relay_url)
                .await?
                .context("relay")?;
            if relay.status() == RelayStatus::Banned || { this.seen_relay_info.read().await }
                .contains(&relay_url.clone().into())
            {
                return Ok(());
            }

            let connected_relay = tokio::spawn({
                let connection_timeout = this.args.connection_timeout.0;
                async move {
                    relay.wait_for_connection(connection_timeout).await;
                    relay
                }
            });

            log::debug!("checking relay info of {relay_url}");
            let mut has_limitation = false;
            if let Some(relay_discovery) = this
                .nostr_client
                .fetch_events(
                    Filter::new()
                        .limit(1)
                        .kind(RELAY_DISCOVERY)
                        .identifier(relay_url.as_str()),
                )
                .timeout(this.args.request_timeout.0)
                .await
                .ok()
                .and_then(|i| i.first_owned())
            {
                {
                    this.seen_relay_info
                        .write()
                        .await
                        .insert(relay_url.clone().into());
                }

                log::debug!("discovered relay info {relay_discovery:?}");

                let tags = event
                    .tags
                    .filter(TagKind::Custom(Cow::Borrowed("R")))
                    .flat_map(|t| t.content());
                dbg!(tags.collect::<Vec<_>>()); // TODO

                let mut tags = event
                    .tags
                    .filter(TagKind::Custom(Cow::Borrowed("R")))
                    .flat_map(|t| t.content());
                has_limitation = tags.any(|t| ["auth", "payment"].contains(&t));

                if !has_limitation
                    && let Ok(info) = RelayInformationDocument::from_json(&relay_discovery.content)
                {
                    if let Some(Limitation {
                        auth_required,
                        payment_required,
                        restricted_writes,
                        ..
                    }) = info.limitation
                    {
                        has_limitation = auth_required.unwrap_or_default()
                            || payment_required.unwrap_or_default()
                            || restricted_writes.unwrap_or_default()
                    }
                }
            }

            if !has_limitation {
                return Ok(());
            }

            let mut authors: HashSet<PublicKey> = this.args.pubkeys.clone().unwrap_or_default().0;
            authors.insert(event.pubkey);

            let filter = Filter::new().limit(1).authors(authors);
            let filters = [filter.clone(), filter.kind(event.kind)];

            let relay = connected_relay.await?;
            let found_event_with_same_author = relay
                .fetch_events(filters)
                .timeout(this.args.request_timeout.0)
                .await
                .ok()
                .and_then(|i| i.first_owned()) // TODO: extract?
                .is_some();

            if !found_event_with_same_author {
                log::debug!(
                    "blocking {relay_url} due to relay is limited and has no relevant events"
                );
                {
                    this.policy
                        .policy
                        .block_relays
                        .write()
                        .await
                        .insert(relay_url.into());
                }
                return Ok(());
            }
            Ok::<_, ah::Error>(())
        }))
        .await;
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
