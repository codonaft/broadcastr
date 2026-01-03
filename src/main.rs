mod nostr;
mod relays;
mod spam;

use anyhow as ah;
use argh::FromArgs;
use backoff::{
    self as bf, ExponentialBackoff, ExponentialBackoffBuilder, Notify,
    future::{Retry, Sleeper},
};
use futures::{FutureExt, TryFutureExt, future::try_join_all};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use log::LevelFilter;
use nonzero_ext::*;
use nostr::PolicyWithSenders;
use nostr_relay_pool::{RelayLimits, relay::limits::RelayEventLimits};
use nostr_sdk::{
    Client as NostrClient, ClientOptions, EventId, JsonUtil, PublicKey,
    client::{
        Connection, ConnectionTarget,
        options::{GossipOptions, GossipRelayLimits},
    },
    nips::nip11::RelayInformationDocument,
};
use reqwest::Url;
use rustls::crypto;
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tungstenite::protocol::WebSocketConfig;

const MAX_EVENTS_BY_ID: Quota = Quota::per_hour(nonzero!(3u32));
const MIN_SIZE: usize = 128;

#[derive(FromArgs, Clone, Debug)]
#[argh(help_triggers("-h", "--help"))]
/// Broadcast Nostr events to other relays
struct Broadcastr {
    /// the listener ws URI (e.g. "ws://localhost:8080")
    #[argh(option)]
    listen: Url,

    /// relays or relay-list URIs
    /// (comma-separated, e.g. "https://codonaft.com/relays.json,file:///path/to/relays-in-array.json,ws://1.2.3.4:5678")
    #[argh(option)]
    relays: Urls,

    /// same, but for ignored relays;
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
    allowed_pubkeys: Option<nostr::PublicKeys>,

    /// disallow mentions (of the allowed authors) by others (default is false)
    #[argh(switch)]
    disable_mentions: bool,

    /// limit events by author (default is 5)
    #[argh(option, default = "nonzero!(5u32)")]
    max_events_by_author_per_min: NonZeroU32,

    /// limit events by IP (default is 50)
    #[argh(option, default = "nonzero!(50u32)")]
    max_events_by_ip_per_min: NonZeroU32,

    /// limit event kinds with
    /// (comma-separated allow-list, e.g "0,1,3,5,6,7,4550,34550")
    #[argh(option)]
    allowed_kinds: Option<nostr::EventKinds>,

    /// don't discover additional relays from user profiles
    #[argh(switch)]
    disable_gossip: bool,

    /// don't use spam.nostr.band for spam filtering
    #[argh(switch)]
    disable_spam_nostr_band: bool,

    /// don't use azzamo.net for spam filtering
    #[argh(switch)]
    disable_azzamo: bool,

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

    /// log level (default is info)
    #[argh(option, default = "LevelFilter::Info")]
    log_level: LevelFilter,

    /// max incoming connections per listener IP address
    #[argh(option, default = "1024")]
    tcp_backlog: i32,

    /// event message size
    #[argh(option, default = "70 * 1024")]
    max_msg_size: usize,

    /// ws frame size
    #[argh(option, default = "4 * 70 * 1024")]
    max_frame_size: usize,
}

#[derive(Debug)]
struct RateLimits {
    events_by_author: RateLimitBy<PublicKey>,
    events_by_id: RateLimitBy<EventId>,
    events_by_ip: RateLimitBy<IpAddr>,
}

type RateLimitBy<I> = RateLimiter<I, DefaultKeyedStateStore<I>, DefaultClock>;

#[derive(Debug, Clone, Default)]
struct Urls(HashSet<Url>);

#[derive(Debug, Clone)]
struct DurationArg(Duration);

#[tokio::main(flavor = "current_thread")]
async fn main() -> ah::Result<()> {
    let args: Broadcastr = argh::from_env();
    TermLogger::init(
        args.log_level,
        simplelog::Config::default(),
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )?;

    log::info!("starting {:#?}", args);

    let _ = crypto::CryptoProvider::install_default(crypto::ring::default_provider());

    if args.proxy.is_some() && args.tor_proxy.is_some() {
        ah::bail!("ambiguous proxy arguments");
    }
    if let Some(size) = [
        args.tcp_backlog as usize,
        args.max_msg_size,
        args.max_frame_size,
    ]
    .into_iter()
    .find(|i| *i < MIN_SIZE)
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

    let mut opts = ClientOptions::new()
        .gossip(GossipOptions {
            limits: if args.disable_gossip {
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
        })
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

    let PolicyWithSenders {
        policy,
        blocked_relays_sender,
        spam_pubkeys_sender,
        spam_events_sender,
        azzamo_blocked_pubkeys_sender,
    } = nostr::PolicyWithSenders::new(&args)?;
    let nostr_client = NostrClient::builder()
        .opts(opts)
        .admit_policy(policy.clone())
        .build();
    let policy = Arc::new(policy);

    let rate_limits = Arc::new(RateLimits {
        events_by_author: RateLimiter::keyed(Quota::per_minute(args.max_events_by_author_per_min)),
        events_by_id: RateLimiter::keyed(MAX_EVENTS_BY_ID),
        events_by_ip: RateLimiter::keyed(Quota::per_minute(args.max_events_by_ip_per_min)),
    });
    let listeners = new_listeners(&args).await?.into_iter().map(|listener| {
        serve(
            listener,
            ws_config,
            &args,
            &nostr_client,
            &rate_limits,
            &policy,
        )
        .boxed()
    });

    if let Err(e) = try_join_all(
        [
            relays::updater(blocked_relays_sender, &args, &nostr_client).boxed(),
            spam::spam_nostr_band_updater(&args, spam_pubkeys_sender, spam_events_sender).boxed(),
            spam::azzamo_updater(&args, azzamo_blocked_pubkeys_sender).boxed(),
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
    rate_limits: &Arc<RateLimits>,
    policy: &Arc<nostr::Policy>,
) -> ah::Result<()> {
    let relay_info = {
        let body = RelayInformationDocument {
            name: Some("broadcastr".to_string()),
            software: Some("git+https://github.com/codonaft/broadcastr".to_string()),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            icon: Some("https://codonaft.com/assets/favicon-32x32.png".to_string()),
            ..Default::default()
        }
        .as_json();
        let length = body.len();
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \
             {length}\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n{body}"
        )
    };

    loop {
        match listener.accept().await {
            Ok((stream, _client_addr)) => {
                tokio::spawn(
                    nostr::handle_ws_connection(
                        stream,
                        ws_config,
                        args.clone(),
                        nostr_client.clone(),
                        rate_limits.clone(),
                        policy.clone(),
                        relay_info.clone(),
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

        #[cfg(unix)]
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

fn retry_with_backoff<F, Fut>(
    args: Broadcastr,
    f: F,
) -> Retry<impl Sleeper, ExponentialBackoff, impl Notify<ah::Error>, F, Fut>
where
    Fut: Future<Output = Result<(), bf::Error<ah::Error>>> + Send,
    F: Fn() -> Fut + Send,
{
    let backoff = ExponentialBackoffBuilder::new()
        .with_max_elapsed_time(None)
        .with_max_interval(args.max_backoff_interval.0)
        .build();
    bf::future::retry(backoff, f)
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

impl FromStr for DurationArg {
    type Err = String;

    fn from_str(duration: &str) -> Result<Self, Self::Err> {
        let result = humantime::Duration::from_str(duration)
            .map_err(|e| e.to_string())?
            .into();
        Ok(Self(result))
    }
}
