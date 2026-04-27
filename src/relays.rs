use super::{Broadcastr, normalize_url, retry_with_backoff_endless};
use crate::{Policy, retry_with_backoff};
use anyhow::{self as ah, Context};
use backoff as bf;
use futures::{
    StreamExt,
    future::{join_all, try_join_all},
};
use nostr_relay_pool::{
    Relay, RelayServiceFlags, RelayStatus,
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
    dont_ignore_relays: &Arc<RwLock<HashSet<RelayUrl>>>,
) -> ah::Result<()> {
    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        retry_with_backoff_endless(args.clone(), || {
            let blocked_relays_sender = blocked_relays_sender.clone();
            let args = args.clone();
            let nostr_client = nostr_client.clone();
            async {
                let result = update_relays(blocked_relays_sender, &args, &nostr_client).await;
                if let Err(e) = &result {
                    log::error!("failed to update relays: {e}");
                }

                if args.detect_failing_relays {
                    tokio::spawn({
                        let initialized_relays = nostr_client
                            .relays()
                            .await
                            .into_iter()
                            .filter(|(_, relay)| relay.status() == RelayStatus::Initialized)
                            .collect::<HashMap<_, _>>();
                        let args = args.clone();
                        async move { maybe_ignore_failing_relays(initialized_relays, &args).await }
                    });
                }

                update_connections(&args, &nostr_client).await;
                update_subscription(
                    args,
                    nostr_client,
                    policy.clone(),
                    dont_ignore_relays.clone(),
                )
                .await?;

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
    log::info!("updating relays");
    let online_relays = tokio::spawn({
        let relays = args.relays.0.clone();
        let args = args.clone();
        async move { parse_or_fetch_relays(relays, &args).await }
    });
    let blocked_relays = parse_or_fetch_relays(
        args.blocked_relays.clone().map(|i| i.0).unwrap_or_default(),
        args,
    )
    .await?;

    blocked_relays_sender.send(blocked_relays.clone())?;
    let online_relays = online_relays.await??;

    let client_relays = nostr_client.relays().await;
    let failing_relays = client_relays
        .values()
        .filter(|i| i.status() == RelayStatus::Banned)
        .map(|i| normalize_url(i.url().as_str().parse()?))
        .collect::<ah::Result<HashSet<Url>>>()?;
    let all_relays = online_relays.sub(&blocked_relays);
    for i in &all_relays.sub(&failing_relays) {
        nostr_client.add_relay(i).await?;
    }

    let outdated_relays = nostr_client
        .relays()
        .await
        .into_keys()
        .map(|i| normalize_url(i.as_str().parse()?))
        .collect::<ah::Result<HashSet<Url>>>()?
        .sub(&all_relays);
    for i in &outdated_relays {
        log::info!("removing outdated relay {i}");
        let _ = nostr_client.remove_relay(i).await;
    }
    log::debug!("finished updating relays");
    Ok(())
}

async fn parse_or_fetch_relays(
    relays_or_relays_lists: HashSet<Url>,
    args: &Broadcastr,
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
                    .connect_timeout(args.connection_timeout.0)
                    .timeout(args.request_timeout.0)
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
    log::info!("updating connections");
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
}

async fn maybe_ignore_failing_relays(
    initialized_relays: HashMap<RelayUrl, Relay>,
    args: &Broadcastr,
) {
    if initialized_relays.is_empty() {
        return;
    }

    log::info!("detecting failing relays");
    let start = Instant::now();

    join_all(
        initialized_relays
            .clone()
            .into_iter()
            .map(|(relay_url, relay)| {
                retry_with_backoff(args, move || {
                    let args = args.clone();
                    let relay_url = relay_url.clone();
                    let relay = relay.clone();
                    async move {
                        get_relay_info_or_ignore_relay(&args, &relay_url, &relay).await?;
                        Ok(())
                    }
                })
            }),
    )
    .await;

    let elapsed = humantime::Duration::from(start.elapsed());
    let failing = initialized_relays
        .values()
        .filter(|i| i.status() == RelayStatus::Banned)
        .count();
    log::info!("detecting failing relays took {elapsed}, {failing} relays are failing");
}

async fn update_subscription(
    args: Broadcastr,
    nostr_client: NostrClient,
    policy: Arc<Policy>,
    dont_ignore_relays: Arc<RwLock<HashSet<RelayUrl>>>,
) -> ah::Result<()> {
    if !args.subscribe {
        return Ok(());
    }

    log::info!("updating subscription");
    if let (Some(allowed_pubkeys), Some(allowed_kinds)) =
        (args.allow_pubkeys.clone(), args.allow_kinds.clone())
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
                let _ = spawn_handle_event(
                    &args,
                    &nostr_client,
                    event,
                    None,
                    policy.clone(),
                    dont_ignore_relays.clone(),
                    true,
                )
                .await;
            }
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
    dont_ignore_relays: Arc<RwLock<HashSet<RelayUrl>>>,
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
    let dont_ignore_relays = dont_ignore_relays.clone();
    tokio::spawn(async move {
        if let Err(e) = handle_event(event, args, nostr_client, policy, dont_ignore_relays).await {
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
    dont_ignore_relays: Arc<RwLock<HashSet<RelayUrl>>>,
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
            ignore_failing_relays_without_our_events(
                args,
                nostr_client,
                relays_without_event,
                dont_ignore_relays,
            )
            .await;
        }
    }
    Ok(())
}

async fn ignore_failing_relays_without_our_events(
    args: Broadcastr,
    nostr_client: NostrClient,
    relays_without_event: HashSet<RelayUrl>,
    dont_ignore_relays: Arc<RwLock<HashSet<RelayUrl>>>,
) {
    let dont_ignore = { dont_ignore_relays.read().await };

    join_all(
        relays_without_event
            .into_iter()
            .filter(|relay_url| !dont_ignore.contains(relay_url))
            .map(async |relay_url| {
                let relay = nostr_client.relay(&relay_url).await?;
                if relay.status() == RelayStatus::Banned {
                    return Ok(());
                }

                let info = get_relay_info_or_ignore_relay(&args, &relay_url, &relay)
                    .await
                    .map_err(|e| ah::anyhow!("{e:?}"))?;

                // TODO: restricted_writes
                if let Some(Limitation {
                    auth_required: Some(true),
                    ..
                }) = info.limitation
                {
                    log::debug!("ignore {relay_url} due to auth requirement");
                    relay.ban();
                    return Ok(());
                }

                if let (
                    Some(Limitation {
                        payment_required: Some(true),
                        ..
                    }),
                    Some(allowed_pubkeys),
                ) = (info.limitation, &args.allow_pubkeys)
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
                        log::debug!(
                            "ignore {relay_url} due to payment requirement and no events found"
                        );
                        relay.ban();
                        return Ok(());
                    }
                }

                {
                    dont_ignore_relays.write().await.insert(relay_url);
                }
                Ok::<_, ah::Error>(())
            }),
    )
    .await;
}

async fn get_relay_info_or_ignore_relay(
    args: &Broadcastr,
    relay_url: &RelayUrl,
    relay: &Relay,
) -> Result<RelayInformationDocument, bf::Error<ah::Error>> {
    let client = ClientBuilder::new()
        .connect_timeout(args.connection_timeout.0)
        .timeout(args.request_timeout.0)
        .tcp_keepalive(None)
        .build()
        .map_err(|e| bf::Error::permanent(ah::anyhow!("{e:?}")))?;

    let mut url = relay_url
        .as_str()
        .parse::<Url>()
        .map_err(|e| bf::Error::permanent(ah::anyhow!("{e:?}")))?;
    url.set_scheme(match url.scheme() {
        "ws" => "http",
        "wss" => "https",
        _ => return Err(bf::Error::permanent(ah::anyhow!("unexpected scheme"))),
    })
    .map_err(|e| bf::Error::permanent(ah::anyhow!("{e:?}")))?;

    log::debug!("retrieving relay info for {relay_url}");

    let info = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/nostr+json")
        .send()
        .await;

    if let Err(e) = &info {
        let text = format!("{e:?}");
        log::debug!("failed to retrieve relay info for {relay_url}: {text}");
        if [
            "dns error",
            "InvalidCertificate",
            "ExpiredContext",
            "UnrecognisedName",
            "NotValidForNameContext",
            "tls handshake eof",
            "0.0.0.0:443",
        ]
        .iter()
        .any(|i| text.contains(i))
        {
            log::info!("ignore {relay_url}");
            relay.ban();
            return Err(bf::Error::permanent(ah::anyhow!("{e:?}")));
        } else {
            return Err(bf::Error::transient(ah::anyhow!("{e:?}")));
        }
    }

    log::debug!("parsing info for {relay_url}");

    let result = info
        .map_err(|e| bf::Error::permanent(ah::anyhow!("{e:?}")))?
        .json::<RelayInformationDocument>()
        .await
        .map_err(|e| bf::Error::permanent(ah::anyhow!("{e:?}")));

    log::debug!("finished parsing for {relay_url}");

    result
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
