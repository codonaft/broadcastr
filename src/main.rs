use anyhow as ah;
use argh::FromArgs;
use backoff::{self as bf, ExponentialBackoff, ExponentialBackoffBuilder};
use futures::{
    FutureExt, SinkExt, StreamExt, TryFutureExt,
    future::{join_all, try_join_all},
};
use futures_util::stream::SplitSink;
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use nonzero_ext::*;
use nostr_relay_pool::{
    RelayLimits,
    relay::{constants::MAX_EVENT_SIZE, limits::RelayEventLimits},
};
use nostr_sdk::{
    Alphabet, Client as NostrClient, ClientMessage, Event, EventId, Filter, JsonUtil,
    Kind as EventKind, Options, PublicKey, RelayMessage, RelayUrl, SingleLetterTag, SubscriptionId,
    Tag,
    client::{Connection, ConnectionTarget},
    prelude::{AdmitPolicy, AdmitStatus, PolicyError},
    serde_json,
    util::BoxedFuture,
};
use reqwest::{ClientBuilder, Url};
use serde::{Deserialize, de::DeserializeOwned};
use std::{
    borrow::Cow,
    collections::HashSet,
    fs::File,
    net::SocketAddr,
    ops::Sub,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
    time,
};
use tokio_tungstenite::{WebSocketStream, accept_async_with_config, tungstenite::Message};
use tungstenite::protocol::WebSocketConfig;

const MAX_EVENTS_BY_ID: Quota = Quota::per_hour(nonzero!(3u32));
const MIN_SIZE: usize = 128;

#[derive(FromArgs, Clone, Debug)]
#[argh(help_triggers("-h", "--help"))]
/// Broadcast nostr events to other relays
struct Broadcastr {
    /// the listener ws address (e.g. "ws://localhost:8080")
    #[argh(option)]
    listen: Url,

    /// API endpoints/files with relay list
    /// (comma-separated, e.g. "https://api.nostr.watch/v1/online,file:///path/to/relays-in-array.json")
    #[argh(option)]
    relay_sources: Urls,

    /// relays ignore-list
    /// (comma-separated, e.g. "wss://nostr.mutinywallet.com,ws://1.2.3.4:9000");
    /// put public URL to your broadcastr here to avoid loops
    #[argh(option)]
    blocked_relays: Option<Urls>,

    /// connect to tor onion relays using socks5 proxy
    /// (e.g. "127.0.0.1:9050")
    #[argh(option)]
    tor_proxy: Option<SocketAddr>,

    /// connect to all relays using socks5 proxy
    #[argh(option)]
    proxy: Option<SocketAddr>,

    /// pow difficulty limit (NIP-13)
    #[argh(option)]
    min_pow: Option<u8>,

    /// authors or mentioned authors (comma-separated hex/bech32/NIP-21 allow-list)
    #[argh(option)]
    allowed_pubkeys: Option<PublicKeys>,

    /// limit event kinds with
    /// (comma-separated allow-list, e.g "0,1,3,5,6,7,4550,34550")
    #[argh(option)]
    allowed_kinds: Option<EventKinds>,

    /// don't discover additional relays from user profiles
    #[argh(switch)]
    disable_gossip: bool,

    /// don't use spam.nostr.band for spam filtering
    #[argh(switch)]
    disable_spam_nostr_band: bool,

    /// relays and spam-lists update interval (default is 15m)
    #[argh(option, default = "DurationArg(Duration::from_secs(15 * 60))")]
    update_interval: DurationArg,

    /// max update backoff interval (default is 5m)
    #[argh(option, default = "DurationArg(Duration::from_secs(5 * 60))")]
    max_backoff_interval: DurationArg,

    /// connection timeout (default is 15s)
    #[argh(option, default = "DurationArg(Duration::from_secs(15))")]
    connection_timeout: DurationArg,

    /// request timeout (default is 10s)
    #[argh(option, default = "DurationArg(Duration::from_secs(10))")]
    request_timeout: DurationArg,

    /// max incoming connections per listener IP address
    #[argh(option, default = "1024")]
    tcp_backlog: i32,

    /// event message size
    #[argh(option, default = "MAX_EVENT_SIZE as usize")]
    max_msg_size: usize,

    /// ws frame size
    #[argh(option, default = "(MAX_EVENT_SIZE as usize * 4)")]
    max_frame_size: usize,
}

#[derive(Debug, Clone, Default)]
struct Urls(HashSet<Url>);

#[derive(Debug, Clone, Default)]
struct PublicKeys(HashSet<PublicKey>);

#[derive(Debug, Clone, Default)]
struct EventKinds(HashSet<EventKind>);

#[derive(Debug, Clone)]
struct DurationArg(Duration);

#[derive(Debug)]
struct QueryEvent {
    found_on_relays: HashSet<RelayUrl>,
    relays_without_event: HashSet<RelayUrl>,
}

#[derive(Debug)]
struct BroadcastedEvent {
    event_id: EventId,
    found_on_relays_before_broadcasting: usize,
}

type RateLimitEvents = RateLimiter<EventId, DefaultKeyedStateStore<EventId>, DefaultClock>;

#[derive(Debug, Clone)]
struct Policy {
    blocked_relays: HashSet<RelayUrl>,
    allowed_pubkeys: HashSet<PublicKey>,
    allowed_kinds: HashSet<EventKind>,
    min_pow: Option<u8>,
    spam_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
    spam_events_receiver: watch::Receiver<HashSet<EventId>>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ah::Result<()> {
    env_logger::init();
    let args: Broadcastr = argh::from_env();
    if args.proxy.is_some() && args.tor_proxy.is_some() {
        ah::bail!("ambiguous proxy arguments");
    }
    if let Some(size) = [
        args.tcp_backlog as usize,
        args.max_msg_size,
        args.max_frame_size,
    ]
    .into_iter()
    .filter(|i| *i < MIN_SIZE)
    .next()
    {
        ah::bail!("{size} is too small");
    }

    let relay_limits = RelayLimits {
        events: RelayEventLimits {
            max_size: Some(args.max_msg_size as u32),
            ..Default::default()
        },
        ..Default::default()
    };

    let ws_message_size = args.max_msg_size * 4;
    let ws_config = WebSocketConfig::default()
        .max_write_buffer_size(
            WebSocketConfig::default()
                .write_buffer_size
                .saturating_add(ws_message_size),
        )
        .max_message_size(Some(ws_message_size))
        .max_frame_size(Some(args.max_frame_size as usize));

    let mut opts = Options::new()
        .gossip(!args.disable_gossip)
        .relay_limits(relay_limits);
    let mut connection: Connection = Connection::new();
    opts = if let Some(proxy) = args.proxy {
        connection = connection.proxy(proxy);
        opts.connection(connection.target(ConnectionTarget::All))
    } else if let Some(tor_proxy) = args.tor_proxy {
        connection = connection.proxy(tor_proxy);
        opts.connection(connection.target(ConnectionTarget::Onion))
    } else {
        opts
    };

    let blocked_relays = args
        .blocked_relays
        .iter()
        .flat_map(|r| r.0.iter())
        .cloned()
        .map(normalize_url)
        .collect::<ah::Result<HashSet<Url>>>()?;

    let (spam_pubkeys_sender, spam_pubkeys_receiver) = watch::channel(HashSet::default());
    let (spam_events_sender, spam_events_receiver) = watch::channel(HashSet::default());

    let policy = Policy {
        blocked_relays: blocked_relays
            .iter()
            .map(|i| Ok(i.as_str().parse()?))
            .collect::<ah::Result<_>>()?,
        allowed_pubkeys: args.allowed_pubkeys.clone().unwrap_or_default().0,
        allowed_kinds: args.allowed_kinds.clone().unwrap_or_default().0,
        min_pow: args.min_pow,
        spam_pubkeys_receiver,
        spam_events_receiver,
    };
    let nostr_client = NostrClient::builder()
        .opts(opts)
        .admit_policy(policy.clone())
        .build();
    let policy = Arc::new(policy);

    let limit_events_by_id = Arc::new(RateLimiter::keyed(MAX_EVENTS_BY_ID));
    let listeners = new_listeners(&args).await?.into_iter().map(|listener| {
        serve(
            listener,
            ws_config,
            &args,
            &nostr_client,
            &limit_events_by_id,
            &policy,
        )
        .boxed()
    });

    if let Err(e) = try_join_all(
        [
            relays_updater(blocked_relays, &args, &nostr_client).boxed(),
            spam_lists_updater(&args, spam_pubkeys_sender, spam_events_sender).boxed(),
        ]
        .into_iter()
        .chain(listeners),
    )
    .await
    {
        log::error!("fatal {e}");
    }

    nostr_client.shutdown().await;
    log::info!("exiting");
    Ok(())
}

async fn serve(
    listener: TcpListener,
    ws_config: WebSocketConfig,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    limit_events_by_id: &Arc<RateLimitEvents>,
    policy: &Arc<Policy>,
) -> ah::Result<()> {
    loop {
        match listener.accept().await {
            Ok((stream, _client_addr)) => {
                tokio::spawn(
                    handle_ws_connection(
                        stream,
                        ws_config,
                        args.clone(),
                        nostr_client.clone(),
                        limit_events_by_id.clone(),
                        policy.clone(),
                    )
                    .map_err(move |e| {
                        log::info!("failed to handle connection from client: {e}");
                    }),
                );
            },
            Err(e) => {
                log::info!("failed to accept connection from client: {e}");
            },
        }
    }
}

async fn new_listeners(args: &Broadcastr) -> ah::Result<Vec<TcpListener>> {
    let mut result = vec![];
    for listen_addr in args.listen.socket_addrs(|| None)? {
        let domain = match listen_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;

        if listen_addr.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        socket.bind(&listen_addr.into())?;
        socket.listen(args.tcp_backlog)?;

        let std_listener: std::net::TcpListener = socket.into();
        std_listener.set_nonblocking(true)?;
        let listener = TcpListener::from_std(std_listener)?;

        log::info!("listening on {listen_addr}");
        result.push(listener);
    }
    Ok(result)
}

async fn handle_ws_connection(
    stream: TcpStream,
    ws_config: WebSocketConfig,
    args: Broadcastr,
    nostr_client: NostrClient,
    limit_events_by_id: Arc<RateLimitEvents>,
    policy: Arc<Policy>,
) -> ah::Result<()> {
    let ws_stream = accept_async_with_config(stream, Some(ws_config)).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    let mut broadcasted_events = vec![];
    if let Ok(Some(Ok(Message::Text(text)))) =
        time::timeout(args.request_timeout.0, ws_receiver.next()).await
    {
        match ClientMessage::from_json(&text) {
            Ok(client_message) => {
                handle_client_message(
                    client_message,
                    &mut broadcasted_events,
                    &mut ws_sender,
                    &args,
                    &nostr_client,
                    limit_events_by_id,
                    policy,
                )
                .await;
            },
            Err(e) => {
                log::debug!("failed to parse client message: {e}");
            },
        }
    } else {
        return Ok(());
    }

    for BroadcastedEvent {
        event_id,
        found_on_relays_before_broadcasting,
    } in broadcasted_events
    {
        let QueryEvent {
            found_on_relays,
            relays_without_event,
        } = QueryEvent::find(event_id, &args, &nostr_client).await?;

        let broadcasted_to_new_relays = found_on_relays
            .len()
            .saturating_sub(found_on_relays_before_broadcasting);

        ok(
            event_id,
            broadcasted_to_new_relays > 0,
            format!(
                "published to {broadcasted_to_new_relays} relays (now it's available on {} of {} \
                 relays)",
                found_on_relays.len(),
                found_on_relays
                    .len()
                    .saturating_add(relays_without_event.len()),
            ),
            &mut ws_sender,
        )
        .await;
    }

    ws_sender.close().await?;
    log::debug!("closed connection with client");
    Ok(())
}

async fn handle_client_message(
    client_message: ClientMessage<'_>,
    broadcasted_events: &mut Vec<BroadcastedEvent>,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    limit_events_by_id: Arc<RateLimitEvents>,
    policy: Arc<Policy>,
) {
    use ClientMessage::*;
    match client_message {
        Event(event) => {
            let event_id = event.id;
            match handle_event(
                event,
                args,
                ws_sender,
                nostr_client,
                limit_events_by_id,
                policy,
            )
            .await
            {
                Ok(Some(broadcasted_event)) => {
                    broadcasted_events.push(broadcasted_event);
                },
                Ok(None) => (),
                Err(e) => {
                    ok(
                        event_id,
                        false,
                        format!("failed to handle a message: {e}"),
                        ws_sender,
                    )
                    .await
                },
            }
        },
        Close(subscription_id) => closed(subscription_id, "close", ws_sender).await,
        Auth(event) => ok(event.id, false, "unexpected message", ws_sender).await,
        Req {
            subscription_id, ..
        }
        | ReqMultiFilter {
            subscription_id, ..
        }
        | Count {
            subscription_id, ..
        } => closed(subscription_id, "message is unsupported", ws_sender).await,
        NegOpen {
            subscription_id, ..
        }
        | NegMsg {
            subscription_id, ..
        }
        | NegClose {
            subscription_id, ..
        } => neg_err(subscription_id, "message is unsupported", ws_sender).await,
    }
}

async fn handle_event(
    event: Cow<'_, Event>,
    args: &Broadcastr,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    nostr_client: &NostrClient,
    limit_events_by_id: Arc<RateLimitEvents>,
    policy: Arc<Policy>,
) -> ah::Result<Option<BroadcastedEvent>> {
    check_policy(&event, &policy).await?;

    let event_id = event.id;
    if limit_events_by_id.check_key(&event_id).is_err() {
        ah::bail!("rate-limit: too many attempts to transmit the same event");
    }
    log::debug!("received event {event_id}");

    let QueryEvent {
        found_on_relays,
        relays_without_event,
    } = QueryEvent::find(event_id, args, nostr_client).await?;

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
        let info = format!(
            "{found_message}broadcasting to {} relays (of all of the {} relays)",
            relays_without_event.len(),
            found_on_relays_before_broadcasting.saturating_add(relays_without_event.len()),
        );
        notice(info, ws_sender).await;

        if let Err(e) = nostr_client
            .send_event_to(&relays_without_event, &event)
            .await
        {
            log::error!("failed to broadcast event {event_id}: {e}");
        } else {
            return Ok(Some(BroadcastedEvent {
                event_id,
                found_on_relays_before_broadcasting,
            }));
        }
    }
    Ok(None)
}

impl AdmitPolicy for Policy {
    fn admit_connection<'a>(
        &'a self,
        url: &'a RelayUrl,
    ) -> BoxedFuture<'a, Result<AdmitStatus, PolicyError>> {
        Box::pin(async move {
            let result = if self.blocked_relays.contains(url) {
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
            if let Some(min_pow) = self.min_pow {
                if !event.check_pow(min_pow) {
                    return Ok(AdmitStatus::Rejected {
                        reason: Some(format!("unexpected pow < {min_pow}")),
                    });
                }
            }

            if !self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(&event.kind) {
                Ok(AdmitStatus::Rejected {
                    reason: Some(format!("unexpected kind {}", event.kind)),
                })
            } else if !self.allowed_pubkeys.is_empty()
                && self.allowed_pubkeys.contains(&event.pubkey)
            {
                Ok(AdmitStatus::Success)
            } else {
                let event_mentions_allowed_pubkeys = event
                    .tags
                    .iter()
                    .flat_map(mentioned_pubkey)
                    .any(|i| self.allowed_pubkeys.contains(&i));

                if !self.allowed_pubkeys.is_empty() && !event_mentions_allowed_pubkeys {
                    return Ok(AdmitStatus::Rejected {
                        reason: Some("unexpected author or mentioned public key".to_string()),
                    });
                }

                if self.spam_pubkeys_receiver.borrow().contains(&event.pubkey)
                    || self.spam_events_receiver.borrow().contains(&event.id)
                {
                    return Ok(AdmitStatus::Rejected {
                        reason: Some("listed on spam.nostr.band".to_string()),
                    });
                }

                Ok(AdmitStatus::Success)
            }
        })
    }
}

async fn relays_updater(
    blocked_relays: HashSet<Url>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
) -> ah::Result<()> {
    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        bf::future::retry(backoff(args), || {
            let blocked_relays = blocked_relays.clone();
            let args = args.clone();
            let nostr_client = nostr_client.clone();
            async move {
                let result = update_relays(blocked_relays, &args, &nostr_client).await;
                if let Err(e) = &result {
                    log::error!("failed to update relays: {e}");
                }
                update_connections(args, nostr_client).await;
                Ok(result?)
            }
        })
        .await?;
    }
}

async fn spam_lists_updater(
    args: &Broadcastr,
    spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
    spam_events_sender: watch::Sender<HashSet<EventId>>,
) -> ah::Result<()> {
    if args.disable_spam_nostr_band {
        return Ok(());
    }

    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        if let Err(e) = update_spam_lists(
            args.clone(),
            spam_pubkeys_sender.clone(),
            spam_events_sender.clone(),
        )
        .await
        {
            log::error!("failed to update spam lists: {e}");
        }
    }
}

async fn update_spam_lists(
    args: Broadcastr,
    spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
    spam_events_sender: watch::Sender<HashSet<EventId>>,
) -> ah::Result<()> {
    #[derive(Deserialize, Debug)]
    struct Pubkeys {
        cluster_pubkeys: Vec<ClusterPubkeys>,
    }

    #[derive(Deserialize, Debug)]
    struct Events {
        cluster_events: Vec<ClusterEvents>,
    }

    #[derive(Deserialize, Debug)]
    struct ClusterPubkeys {
        pubkeys: Vec<PublicKey>,
    }

    #[derive(Deserialize, Debug)]
    struct ClusterEvents {
        events: Vec<EventId>,
    }

    impl From<Pubkeys> for HashSet<PublicKey> {
        fn from(value: Pubkeys) -> Self {
            value
                .cluster_pubkeys
                .into_iter()
                .flat_map(|i| i.pubkeys)
                .collect()
        }
    }

    impl From<Events> for HashSet<EventId> {
        fn from(value: Events) -> Self {
            value
                .cluster_events
                .into_iter()
                .flat_map(|i| i.events)
                .collect()
        }
    }

    join_all([
        fetch_spam_list::<Pubkeys, PublicKey>(args.clone(), spam_pubkeys_sender, "pubkeys"),
        fetch_spam_list::<Events, EventId>(args, spam_events_sender, "events"),
    ])
    .await
    .into_iter()
    .flatten()
    .collect::<ah::Result<Vec<()>>>()?;

    Ok(())
}

fn fetch_spam_list<Input: DeserializeOwned, Output>(
    args: Broadcastr,
    output: watch::Sender<HashSet<Output>>,
    view: &'static str,
) -> JoinHandle<ah::Result<()>>
where
    HashSet<Output>: From<Input>,
    Output: Send + Sync + 'static,
{
    tokio::spawn(bf::future::retry(backoff(&args), move || {
        let output = output.clone();
        async move {
            let url = Url::parse_with_params(
                "https://spam.nostr.band/spam_api?method=get_current_spam",
                &[("view", view)],
            )
            .map_err(|e| bf::Error::transient(e.into()))?;
            let items: HashSet<_> = async move {
                ClientBuilder::new()
                    .timeout(args.request_timeout.0)
                    .build()?
                    .get(url)
                    .send()
                    .await?
                    .json::<Input>()
                    .await
            }
            .await
            .map_err(|e| bf::Error::transient(e.into()))?
            .into();

            log::info!("spam.nostr.band: fetched {} {view}", items.len());
            output
                .send(items)
                .map_err(|e| bf::Error::transient(e.into()))?;
            Result::<_, bf::Error<anyhow::Error>>::Ok(())
        }
    }))
}

async fn update_relays(
    blocked_relays: HashSet<Url>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
) -> ah::Result<()> {
    log::debug!("updating relays");
    let online_relays = try_join_all(args.relay_sources.0.iter().map(
        async |uri| -> ah::Result<_> {
            let result = if ["https", "http"].contains(&uri.scheme()) {
                ClientBuilder::new()
                    .timeout(args.request_timeout.0)
                    .build()?
                    .get(uri.as_ref())
                    .send()
                    .await?
                    .json::<Vec<String>>()
                    .await?
            } else {
                serde_json::from_reader(File::open(uri.path())?)
                    .map_err(|e| ah::anyhow!(r#"{}, expected format: ["ws://a","wss://b"]"#, e))?
            }
            .into_iter()
            .map(|i| normalize_url(i.parse()?));
            log::info!("fetched {} relays from {uri}", result.len());
            Ok(result)
        },
    ))
    .await?
    .into_iter()
    .flatten()
    .collect::<ah::Result<HashSet<Url>>>()?;

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

async fn update_connections(args: Broadcastr, nostr_client: NostrClient) {
    let start = Instant::now();
    nostr_client.connect().await;
    nostr_client
        .wait_for_connection(args.connection_timeout.0)
        .await;
    let client_relays = nostr_client.relays().await;
    let connected_relays = client_relays.values().filter(|i| i.is_connected()).count();
    let disconnected_relays = client_relays
        .iter()
        .filter(|(_, relay)| !relay.is_connected())
        .map(|(url, _)| url.to_string())
        .collect::<Vec<_>>();
    let elapsed = humantime::Duration::from(start.elapsed());
    log::info!(
        "currently connected to {connected_relays}/{} relays, disconnected from \
         {disconnected_relays:?}, reconnection took {elapsed}",
        client_relays.len(),
    );
}

impl QueryEvent {
    async fn find(
        event_id: EventId,
        args: &Broadcastr,
        nostr_client: &NostrClient,
    ) -> ah::Result<Self> {
        let relay_urls: HashSet<RelayUrl> = nostr_client.relays().await.keys().cloned().collect();
        let found_on_relays: HashSet<RelayUrl> =
            join_all(relay_urls.iter().cloned().map(|relay_url| async move {
                let filter = Filter::new().ids([event_id]).limit(1);
                match nostr_client
                    .fetch_events_from([&relay_url], filter, args.request_timeout.0)
                    .await
                {
                    Ok(events) if events.is_empty() => None,
                    Ok(_) => Some(relay_url),
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

fn normalize_url(mut url: Url) -> ah::Result<Url> {
    let mut path_segments: Vec<String> = url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    while let Some(last_segment) = path_segments.last() {
        if last_segment.is_empty() {
            path_segments.pop();
        } else {
            break;
        }
    }

    url.set_path(&path_segments.join("/"));
    Ok(url)
}

async fn ok<S: AsRef<str>>(
    event_id: EventId,
    status: bool,
    message: S,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) {
    let message = message.as_ref();
    log::debug!("ok: {message}");
    let _ = send_relay_message(
        RelayMessage::Ok {
            event_id,
            status,
            message: Cow::Borrowed(message),
        },
        ws_sender,
    )
    .await;
}

async fn notice<S: AsRef<str>>(
    message: S,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) {
    let message = message.as_ref();
    log::debug!("notice: {message}");
    let _ = send_relay_message(RelayMessage::Notice(Cow::Borrowed(message)), ws_sender).await;
}

async fn closed<S: AsRef<str>>(
    subscription_id: Cow<'_, SubscriptionId>,
    message: S,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) {
    let message = message.as_ref();
    log::debug!("closed: {message}");
    let _ = send_relay_message(
        RelayMessage::Closed {
            subscription_id,
            message: Cow::Borrowed(message),
        },
        ws_sender,
    )
    .await;
}

async fn neg_err<S: AsRef<str>>(
    subscription_id: Cow<'_, SubscriptionId>,
    message: S,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) {
    let _ = send_relay_message(
        RelayMessage::NegErr {
            subscription_id,
            message: Cow::Borrowed(message.as_ref()),
        },
        ws_sender,
    )
    .await;
}

async fn send_relay_message(
    message: RelayMessage<'_>,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) -> ah::Result<()> {
    let text = Message::Text(serde_json::to_string(&message)?.into());
    ws_sender.send(text).await?;
    Ok(())
}

fn mentioned_pubkey(tag: &Tag) -> Option<PublicKey> {
    if tag.single_letter_tag() == Some(SingleLetterTag::lowercase(Alphabet::P)) {
        if let Some(pubkey) = tag.content() {
            return pubkey.parse().ok();
        }
    }
    None
}

async fn check_policy(event: &Event, policy: &Arc<Policy>) -> ah::Result<()> {
    if let AdmitStatus::Rejected {
        reason: Some(reason),
    } = policy
        .admit_event(&"ws://unknown".parse()?, &SubscriptionId::generate(), event)
        .await?
    {
        ah::bail!("{}", reason);
    }
    Ok(())
}

fn backoff(args: &Broadcastr) -> ExponentialBackoff {
    ExponentialBackoffBuilder::new()
        .with_max_elapsed_time(None)
        .with_max_interval(args.max_backoff_interval.0)
        .build()
}

impl FromStr for Urls {
    type Err = String;

    fn from_str(urls: &str) -> Result<Self, Self::Err> {
        urls.split(',')
            .map(|i| {
                let url = i.parse::<Url>().map_err(|e| e.to_string())?;
                normalize_url(url).map_err(|e| e.to_string())
            })
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl FromStr for PublicKeys {
    type Err = String;

    fn from_str(urls: &str) -> Result<Self, Self::Err> {
        urls.split(',')
            .map(|i| i.parse::<PublicKey>().map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl FromStr for EventKinds {
    type Err = String;

    fn from_str(urls: &str) -> Result<Self, Self::Err> {
        urls.split(',')
            .map(|i| i.parse::<EventKind>().map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()
            .map(Self)
    }
}

impl FromStr for DurationArg {
    type Err = String;

    fn from_str(duration: &str) -> Result<Self, Self::Err> {
        let result = humantime::Duration::from_str(duration)
            .map_err(|e| e.to_string())?
            .into();
        Ok(Self(result))
    }
}
