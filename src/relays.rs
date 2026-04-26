use super::{Broadcastr, normalize_url, retry_with_backoff};
use crate::Policy;
use anyhow::{self as ah, Context, bail};
use futures::{
    StreamExt,
    future::{join_all, try_join_all},
};
use nostr_relay_pool::{
    RelayServiceFlags, RelayStatus,
    relay::{FlagCheck, ReqExitPolicy},
};
use nostr_sdk::{
    Client as NostrClient, Event, EventId, Filter, RelayUrl, Timestamp,
    filter::MatchEventOptions,
    nips::nip11::{Limitation, RelayInformationDocument},
    serde_json,
};
use reqwest::{ClientBuilder, Url};
use std::{
    collections::HashSet,
    fs::File,
    net::IpAddr,
    ops::Sub,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::watch, time};

#[derive(Debug)]
struct QueryEvent {
    found_on_relays: HashSet<RelayUrl>,
    relays_without_event: HashSet<RelayUrl>,
}

pub(crate) async fn updater(
    blocked_relays_sender: watch::Sender<HashSet<Url>>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    policy: &Arc<Policy>,
) -> ah::Result<()> {
    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        retry_with_backoff(args.clone(), || {
            let blocked_relays_sender = blocked_relays_sender.clone();
            let args = args.clone();
            let nostr_client = nostr_client.clone();
            async {
                let result = update_relays(blocked_relays_sender, &args, &nostr_client).await;
                if let Err(e) = &result {
                    log::error!("failed to update relays: {e}");
                }
                update_connections(&args, &nostr_client).await;
                update_subscription(args, nostr_client, policy.clone()).await?;
                Ok(result?)
            }
        })
        .await?;
    }
}

async fn update_relays(
    blocked_relays_sender: watch::Sender<HashSet<Url>>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
) -> ah::Result<()> {
    log::debug!("updating relays");
    let request_timeout = args.request_timeout.0;
    let online_relays = tokio::spawn({
        let relays = args.relays.0.clone();
        async move { parse_or_fetch_relays(relays, request_timeout).await }
    });
    let blocked_relays = parse_or_fetch_relays(
        args.blocked_relays.clone().map(|i| i.0).unwrap_or_default(),
        request_timeout,
    )
    .await?;

    blocked_relays_sender.send(blocked_relays.clone())?;
    let online_relays = online_relays.await??;

    let all_relays = online_relays.sub(&blocked_relays);
    for i in &all_relays {
        nostr_client.add_relay(i).await?;
    }

    let outdated_relays = all_relays.sub(
        &nostr_client
            .relays()
            .await
            .into_keys()
            .map(|i| normalize_url(i.as_str().parse()?))
            .collect::<ah::Result<HashSet<Url>>>()?,
    );
    for i in &outdated_relays {
        log::info!("removing outdated relay {i}");
        let _ = nostr_client.remove_relay(i).await;
    }
    log::debug!("finished updating relays");

    let client_relays = nostr_client.relays().await;
    debug_assert_eq!(
        client_relays.len(),
        all_relays.len() - outdated_relays.len()
    );
    Ok(())
}

async fn parse_or_fetch_relays(
    relays_or_relays_lists: HashSet<Url>,
    request_timeout: Duration,
) -> ah::Result<HashSet<Url>> {
    let futures = relays_or_relays_lists
        .into_iter()
        .map(async |uri| -> ah::Result<_> {
            let result = if ["wss", "ws"].contains(&uri.scheme()) {
                vec![uri.to_string()]
            } else if uri.scheme() == "file" {
                serde_json::from_reader(File::open(uri.path())?)
                    .map_err(|e| ah::anyhow!(r#"{}, expected format: ["ws://a","wss://b"]"#, e))?
            } else if ["https", "http"].contains(&uri.scheme()) {
                ClientBuilder::new()
                    .timeout(request_timeout)
                    .build()?
                    .get(uri.as_ref())
                    .send()
                    .await?
                    .json::<Vec<String>>()
                    .await?
            } else {
                ah::bail!("unexpected relay item {uri}");
            }
            .into_iter()
            .map(|i| normalize_url(i.parse()?));
            log::debug!("fetched {} relays from {uri}", result.len());
            Ok(result)
        });

    let result = try_join_all(futures)
        .await?
        .into_iter()
        .flatten()
        .collect::<ah::Result<HashSet<Url>>>()?;
    Ok(result)
}

async fn update_connections(args: &Broadcastr, nostr_client: &NostrClient) {
    let start = Instant::now();
    nostr_client.connect().await;
    nostr_client
        .wait_for_connection(args.connection_timeout.0)
        .await;
    let elapsed = humantime::Duration::from(start.elapsed());

    let client_relays = nostr_client.relays().await;
    let connected_relays = client_relays.values().filter(|i| i.is_connected()).count();
    let disconnected_relays = client_relays
        .iter()
        .filter(|(_, relay)| !relay.is_connected())
        .map(|(url, _)| url.to_string())
        .collect::<Vec<_>>();
    log::info!(
        "currently connected to {connected_relays}/{} relays, disconnected from {}",
        client_relays.len(),
        disconnected_relays.len(),
    );
    log::debug!("reconnection took {elapsed}, disconnected relays: {disconnected_relays:?}");
}

async fn update_subscription(
    args: Broadcastr,
    nostr_client: NostrClient,
    policy: Arc<Policy>,
) -> ah::Result<()> {
    if !args.subscribe {
        return Ok(());
    }

    tokio::spawn(async move {
        if let (Some(allowed_pubkeys), Some(allowed_kinds)) =
            (args.allowed_pubkeys.clone(), args.allowed_kinds.clone())
        {
            let now = Timestamp::now().as_secs();
            let interval = args.update_interval.0.as_secs();
            let filter = Filter::new()
                .since(Timestamp::from_secs(now.saturating_sub(interval)))
                .until(Timestamp::from_secs(now.saturating_add(interval)))
                .kinds(allowed_kinds.0);
            let filters = [
                filter.clone().authors(allowed_pubkeys.0.clone()),
                filter.pubkeys(allowed_pubkeys.0),
            ];

            log::debug!("subscribing {filters:?}");
            let start = Instant::now();

            let pool = nostr_client.pool();
            let mut stream = pool
                .stream_events_from(
                    pool.relays_with_flag(RelayServiceFlags::READ, FlagCheck::All)
                        .await
                        .keys(),
                    filters.clone(),
                    args.update_interval.0,
                    ReqExitPolicy::WaitDurationAfterEOSE(args.update_interval.0),
                )
                .await?;

            while let Some(event) = stream.next().await {
                if filters
                    .iter()
                    .any(|i| i.match_event(&event, MatchEventOptions::default()))
                {
                    log::debug!("received event {} from subscription", event.id);
                    let _ =
                        spawn_handle_event(&args, &nostr_client, event, None, policy.clone(), true)
                            .await;
                }
            }

            let elapsed = humantime::Duration::from(start.elapsed());
            log::info!("closed all subscriptions after {elapsed}");
        }
        Ok::<_, ah::Error>(())
    })
    .await??;

    Ok(())
}

pub(crate) async fn spawn_handle_event(
    args: &Broadcastr,
    nostr_client: &NostrClient,
    event: Event,
    ip: Option<IpAddr>,
    policy: Arc<Policy>,
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
    tokio::spawn(async move {
        if let Err(e) = handle_event(event, args, nostr_client, policy).await {
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
            .send_event_to(&relays_without_event, &event)
            .await
        {
            policy.forget(event_id).await;
            log::error!("failed to broadcast event {event_id}: {e}");
        } else {
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
            ignore_relays_without_our_events(args, nostr_client, relays_without_event).await;
        }
    }
    Ok(())
}

async fn ignore_relays_without_our_events(
    args: Broadcastr,
    nostr_client: NostrClient,
    relays_without_event: HashSet<RelayUrl>,
) {
    join_all(relays_without_event.into_iter().map(async |relay_url| {
        let relay = nostr_client.relay(&relay_url).await?;
        if relay.status() == RelayStatus::Banned {
            return Ok(());
        }

        let client = ClientBuilder::new().timeout(args.request_timeout.0).build();
        let mut url = relay_url.as_str().parse::<Url>()?;
        url.set_scheme(match url.scheme() {
            "ws" => "http",
            "wss" => "https",
            _ => bail!("unexpected scheme"),
        })
        .map_err(|e| ah::anyhow!("{e:?}"))?;
        let info = client?
            .get(url)
            .header(reqwest::header::ACCEPT, "application/nostr+json")
            .send()
            .await?
            .json::<RelayInformationDocument>()
            .await
            .map_err(|e| ah::anyhow!("{e:?}"))?;

        if let Some(Limitation {
            auth_required: Some(true),
            ..
        }) = info.limitation
        {
            log::debug!("ignore {relay_url} due to auth requirement");
            relay.ban();
        }

        if let (
            Some(Limitation {
                payment_required: Some(true),
                ..
            }),
            Some(allowed_pubkeys),
        ) = (info.limitation, &args.allowed_pubkeys)
        {
            let filter = Filter::new().authors(allowed_pubkeys.0.clone()).limit(1);
            let found = match nostr_client
                .fetch_events_from([&relay_url], filter, args.request_timeout.0)
                .await
            {
                Ok(events)
                    if !events.is_empty()
                        && events.iter().any(|i| allowed_pubkeys.0.contains(&i.pubkey)) =>
                {
                    true
                },
                Ok(_) => false,
                Err(e) => {
                    log::debug!("cannot query relay {relay_url}: {e}");
                    false
                },
            };

            if !found {
                log::debug!("ignore {relay_url} due to payment requirement and no events found");
                relay.ban();
            }
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
        let relay_urls: HashSet<RelayUrl> = nostr_client.relays().await.keys().cloned().collect();
        let found_on_relays: HashSet<RelayUrl> =
            join_all(relay_urls.clone().into_iter().map(|relay_url| async move {
                let filter = Filter::new().ids([event_id]).limit(1);
                match nostr_client
                    .fetch_events_from([&relay_url], filter, args.request_timeout.0)
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
