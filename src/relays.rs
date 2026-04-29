use super::{Broadcastr, retry_with_backoff_endless};
use crate::{Policy, proxied_client_builder, relay_lists::RelayLists, retry_with_backoff};
use anyhow::{self as ah, Context};
use backoff as bf;
use futures::{
    StreamExt,
    future::{join_all, try_join_all},
};
use nostr::{
    Event, EventId, Filter, Kind as EventKind, RelayUrl, Timestamp,
    event::TagKind,
    filter::MatchEventOptions,
    key::PublicKey,
    nips::nip11::{Limitation, RelayInformationDocument},
    util::JsonUtil,
};
use nostr_sdk::{
    client::Client as NostrClient,
    prelude::ConnectionMode,
    relay::{Relay, RelayCapabilities, RelayOptions, RelayStatus, ReqExitPolicy},
};
use reqwest::Url;
use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fs::File,
    net::IpAddr,
    ops::Sub,
    sync::Arc,
    time::Instant,
};
use tokio::{
    sync::{RwLock, watch},
    time,
};

const RELAY_DISCOVERY: EventKind = EventKind::Custom(30166);

#[derive(Debug)]
struct QueryEvent {
    found_on_relays: HashSet<RelayUrl>,
    relays_without_event: HashSet<RelayUrl>,
}

// TODO
/*pub(crate) struct RelaysUpdater {
    block_relays: &Arc<RwLock<HashSet<Url>>>,
    seen_nip11: &Arc<RwLock<HashSet<Url>>>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    policy: &Arc<Policy>,
}*/

pub(crate) async fn updater(
    block_relays: &Arc<RwLock<HashSet<Url>>>,
    seen_nip11: &Arc<RwLock<HashSet<Url>>>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    policy: &Arc<Policy>,
) -> ah::Result<()> {
    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        retry_with_backoff_endless(args.clone(), || {
            let block_relays = block_relays.clone();
            let args = args.clone();
            let nostr_client = nostr_client.clone();
            async move {
                let result = update_relays(block_relays.clone(), &args, &nostr_client).await;
                if let Err(e) = &result {
                    log::error!("failed to update relays: {e}");
                }

                update_connections(&args, &nostr_client).await;
                update_subscription(
                    args,
                    nostr_client,
                    policy.clone(),
                    block_relays.clone(),
                    seen_nip11.clone(),
                )
                .await?;

                Ok(result?)
            }
        })
        .await?;
    }
}

async fn update_relays(
    block_relays: Arc<RwLock<HashSet<Url>>>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
) -> ah::Result<()> {
    log::info!("updating relays");

    let discovery_flag = if args.no_gossip {
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
        client_relays,
    } = RelayLists::new(args, nostr_client).await?;

    // TODO

    {
        let mut writer = block_relays.write().await;
        *writer = block.clone();
    }

    for i in &block {
        let url = RelayUrl::parse(i.as_str())?;
        if client_relays.contains(&url) {
            let _ = nostr_client.force_remove_relay(url).await;
        }
    }

    for i in &read_write {
        nostr_client
            .add_relay(RelayUrl::parse(i.as_str())?)
            .capabilities(read_write_capabilities)
            .await?;
    }

    for i in &read {
        let url = RelayUrl::parse(i.as_str())?;
        if let Some(relay) = nostr_client.relay(&url).await.ok().flatten() {
            relay.capabilities().remove(RelayCapabilities::WRITE);
        }
        nostr_client
            .add_relay(url)
            .capabilities(read_capabilities)
            .await?;
    }

    log::debug!("finished updating relays");
    Ok(())
}

async fn update_connections(args: &Broadcastr, nostr_client: &NostrClient) {
    log::info!("updating connections");
    let start = Instant::now();
    nostr_client
        .connect()
        .and_wait(args.connection_timeout.0)
        .await;
    let elapsed = humantime::Duration::from(start.elapsed());

    let client_relays = nostr_client.relays().await;
    let connected_relays = client_relays
        .values()
        .filter(|i| i.status().is_connected())
        .count();
    let disconnected_relays = client_relays
        .iter()
        .filter(|(_, relay)| !relay.status().is_connected())
        .map(|(url, _)| url.to_string())
        .collect::<Vec<_>>();
    let failing_relays = client_relays
        .values()
        .filter(|i| i.status() == RelayStatus::Banned)
        .count();
    log::info!(
        "currently connected to {connected_relays}/{} relays, disconnected from {}, \
         {failing_relays} are failing",
        client_relays.len(),
        disconnected_relays.len(),
    );
    log::debug!("reconnection took {elapsed}, disconnected relays: {disconnected_relays:?}");
    // TODO: blocked relays
}

async fn update_subscription(
    args: Broadcastr,
    nostr_client: NostrClient,
    policy: Arc<Policy>,
    block_relays: Arc<RwLock<HashSet<Url>>>,
    seen_nip11: Arc<RwLock<HashSet<Url>>>,
) -> ah::Result<()> {
    if !args.subscribe {
        return Ok(());
    }

    log::info!("updating subscription");
    if let (Some(pubkeys), Some(kinds)) = (args.pubkeys.clone(), args.event_kinds.clone()) {
        let now = Timestamp::now().as_secs();
        let interval = args.update_interval.0.as_secs();
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

        let mut stream = nostr_client
            .stream_events(filters.clone())
            .timeout(args.update_interval.0)
            .policy(ReqExitPolicy::WaitDurationAfterEOSE(args.update_interval.0))
            .await?;

        while let Some((_, event)) = stream.next().await {
            let event = event?;
            log::debug!("received event {} from subscription", event.id);
            let _ = spawn_handle_event(
                &args,
                &nostr_client,
                event,
                None,
                policy.clone(),
                block_relays.clone(),
                seen_nip11.clone(),
                true,
            )
            .await;
        }

        let elapsed = humantime::Duration::from(start.elapsed());
        log::info!("closed all subscriptions after {elapsed}");
    }

    Ok(())
}

pub(crate) async fn spawn_handle_event(
    args: &Broadcastr,
    nostr_client: &NostrClient,
    event: Event,
    ip: Option<IpAddr>,
    policy: Arc<Policy>,
    block_relays: Arc<RwLock<HashSet<Url>>>,
    seen_nip11: Arc<RwLock<HashSet<Url>>>,
    silent: bool,
) -> ah::Result<()> {
    let result = policy.check(&event, ip).await;
    if let Err(e) = &result {
        let event_id = event.id;
        if !silent {
            log::error!("event {event_id} not accepted: {e}");
        }
        return result;
    }

    let args = args.clone();
    let nostr_client = nostr_client.clone();
    let policy = policy.clone();
    let block_relays = block_relays.clone();
    let seen_nip11 = seen_nip11.clone();
    tokio::spawn(async move {
        if let Err(e) =
            handle_event(event, args, nostr_client, policy, block_relays, seen_nip11).await
        {
            log::error!("failed to handle a message: {e}");
        }
    });

    Ok(())
}

async fn handle_event(
    event: Event,
    args: Broadcastr,
    nostr_client: NostrClient,
    policy: Arc<Policy>,
    block_relays: Arc<RwLock<HashSet<Url>>>,
    seen_nip11: Arc<RwLock<HashSet<Url>>>,
) -> ah::Result<()> {
    let event_id = event.id;
    let QueryEvent {
        found_on_relays,
        relays_without_event,
    } = QueryEvent::find(event_id, &args, &nostr_client)
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

        if let Err(e) = nostr_client
            .send_event(&event)
            .to(&relays_without_event)
            .await
        {
            policy.forget(event_id).await;
            log::error!("failed to broadcast event {event_id}: {e}");
        } else {
            // TODO: nostr_client.sync().await?;
            let QueryEvent {
                found_on_relays,
                relays_without_event,
            } = QueryEvent::find(event_id, &args, &nostr_client)
                .await
                .context("re-query")?;
            let broadcasted_to_new_relays = found_on_relays
                .len()
                .saturating_sub(found_on_relays_before_broadcasting);
            log::info!(
                "event {event_id} was accepted by {broadcasted_to_new_relays} relays (now it's \
                 available on {} of {} relays)",
                found_on_relays.len(),
                found_on_relays
                    .len()
                    .saturating_add(relays_without_event.len()),
            );
            ignore_failing_relays_without_our_events(
                relays_without_event,
                args,
                nostr_client,
                block_relays,
                seen_nip11,
                event,
            )
            .await;
        }
    }
    Ok(())
}

async fn ignore_failing_relays_without_our_events(
    relays_without_event: HashSet<RelayUrl>,
    args: Broadcastr,
    nostr_client: NostrClient,
    block_relays: Arc<RwLock<HashSet<Url>>>,
    seen_nip11: Arc<RwLock<HashSet<Url>>>,
    event: Event,
) {
    if !args.detect_failing_relays {
        return;
    }

    join_all(relays_without_event.into_iter().map(async |relay_url| {
        let relay = nostr_client.relay(&relay_url).await?.context("relay")?;
        if relay.status() == RelayStatus::Banned || { seen_nip11.read().await }
            .contains(&relay_url.clone().into())
        {
            return Ok(());
        }

        let connected_relay = tokio::spawn(async move {
            relay.wait_for_connection(args.connection_timeout.0).await;
            relay
        });

        let mut has_limitation = false;
        if let Some(relay_discovery) = nostr_client
            .fetch_events(Filter::new().limit(1).kind(RELAY_DISCOVERY))
            .timeout(args.request_timeout.0)
            .await
            .ok()
            .and_then(|i| i.first_owned())
        {
            {
                seen_nip11.write().await.insert(relay_url.clone().into());
            }

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

        let mut authors: HashSet<PublicKey> = args.pubkeys.clone().unwrap_or_default().0;
        authors.insert(event.pubkey);

        let filter = Filter::new().limit(1).authors(authors);
        let filters = [filter.clone(), filter.kind(event.kind)];

        let relay = connected_relay.await?;
        let found_event_with_same_author = relay
            .fetch_events(filters)
            .timeout(args.request_timeout.0)
            .await
            .ok()
            .and_then(|i| i.first_owned())
            .is_some();

        if !found_event_with_same_author {
            log::debug!("ignore {relay_url} due to relay is limited and has no relevant events");
            {
                block_relays.write().await.insert(relay_url.into());
            }
            return Ok(());
        }
        Ok::<_, ah::Error>(())
    }))
    .await;
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
