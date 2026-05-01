mod nostr_helpers;
mod policy;
mod relay_lists;
mod relays;
mod spam;

use crate::relays::Relays;
use anyhow as ah;
use argh::FromArgs;
use backoff::{
    self as bf, ExponentialBackoff, ExponentialBackoffBuilder, Notify,
    future::{Retry, Sleeper},
};
use const_format::concatcp;
use core::num::NonZeroUsize;
use futures::{FutureExt, TryFutureExt, future::try_join_all};
use git_version::git_version;
use log::LevelFilter;
use nonzero_ext::*;
use nostr::{JsonUtil, nips::nip11::RelayInformationDocument, types::Host};
use nostr_sdk::client::{Connection, ConnectionTarget};
use policy::{ClientAndPolicy, Policy};
use reqwest::{ClientBuilder, Proxy, Url};
use rustls::crypto;
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use std::{
    collections::HashSet, net::SocketAddr, num::NonZeroU32, str::FromStr, sync::Arc, time::Duration,
};
use tokio::{net::TcpListener, sync::Mutex};
use tokio_graceful_shutdown::{SubsystemBuilder, SubsystemHandle, Toplevel};
use tungstenite::protocol::WebSocketConfig;

pub(crate) const UPDATE_INTERVAL: Duration = Duration::from_secs(15 * 60);

const MIN_SIZE: usize = 128;

#[derive(FromArgs, Clone, Debug)]
#[argh(help_triggers("-h", "--help"))]
/// Broadcast Nostr events to other relays
struct Broadcastr {
    /// the listener ws URI (e.g. "ws://localhost:8080")
    #[argh(option)]
    listen: Url,

    /// relays or dynamically refreshable relay-list URIs
    /// (comma-separated, e.g. "https://codonaft.com/relays.json,file:///path/to/relays-in-array.json,ws://1.2.3.4:5678")
    #[argh(option)]
    relays: Option<Urls>,

    /// same, but for read-only relays; overrides entries of the write relays
    #[argh(option)]
    read_relays: Option<Urls>,

    /// same, but for ignored relays;
    /// put public URL to your broadcastr here to avoid loops
    #[argh(option)]
    block_relays: Option<Urls>,

    /// limit the connection pool
    #[argh(option)]
    max_relays: Option<NonZeroUsize>,

    /// connect to tor onion relays using socks5 proxy
    /// (e.g. "127.0.0.1:9050")
    #[argh(option)]
    tor_proxy: Option<SocketAddr>,

    /// make all connections using socks5 proxy
    #[argh(option)]
    proxy: Option<SocketAddr>,

    /// allow authors or mentioned authors only (comma-separated hex/bech32/NIP-21 allow-list)
    #[argh(option)]
    pubkeys: Option<nostr_helpers::PublicKeys>,

    /// disallow mentions (of the allowed authors) by others
    #[argh(switch)]
    no_mentions: bool,

    /// allow some event kinds only
    /// (comma-separated allow-list, e.g "0,1,3,5,6,7,4550,34550")
    #[argh(option)]
    event_kinds: Option<nostr_helpers::EventKinds>,

    /// subscribe and automatically distribute events of the allowed authors and event kinds
    #[argh(switch)]
    subscribe: bool,

    /// limit events by author (default is 5)
    #[argh(option, default = "nonzero!(5u32)")]
    max_events_by_author_per_min: NonZeroU32,

    /// limit events by IP (default is 50)
    #[argh(option, default = "nonzero!(50u32)")]
    max_events_by_ip_per_min: NonZeroU32,

    /// pow difficulty limit (NIP-13)
    #[argh(option)]
    min_pow: Option<u8>,

    /// don't discover additional relays from user profiles
    #[argh(switch)]
    no_gossip: bool,

    /// don't discover additional relays (NIP-66)
    #[argh(switch)]
    no_nip66: bool,

    /// don't use azzamo.net for spam filtering
    #[argh(switch)]
    no_azzamo: bool,

    /// aggressively detect relays that can't receive relevant events
    /// (may save some bandwidth in the long run but will consume more CPU, especially on start)
    #[argh(switch)]
    detect_failing_relays: bool,

    /// relays and spam-lists update interval (default is 15m)
    #[argh(option, default = "DurationArg(UPDATE_INTERVAL)")]
    update_interval: DurationArg,

    /// max update backoff interval (default is 5m)
    #[argh(option, default = "DurationArg(Duration::from_secs(5 * 60))")]
    max_backoff_interval: DurationArg,

    /// connection timeout (default is 15s)
    #[argh(option, default = "DurationArg(Duration::from_secs(15))")]
    connect_timeout: DurationArg,

    /// request timeout (default is 10s)
    #[argh(option, default = "DurationArg(Duration::from_secs(10))")]
    request_timeout: DurationArg,

    /// log level (default is info)
    #[argh(option, default = "LevelFilter::Info")]
    log_level: LevelFilter,

    /// max tags allowed for non kind 3 events (default is 32)
    #[argh(option, default = "32")]
    max_tags: u16,

    /// event message size
    #[argh(option, default = "70 * 1024")]
    max_msg_size: usize,

    /// max incoming connections per listener IP address
    #[argh(option, default = "1024")]
    tcp_backlog: i32,

    /// ws frame size
    #[argh(option, default = "4 * 70 * 1024")]
    max_frame_size: usize,
}

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

    if args.relays.is_none() && args.read_relays.is_none() {
        ah::bail!("either --relays or --read-relays is required");
    }

    if args.subscribe && (args.pubkeys.is_none() || args.event_kinds.is_none()) {
        ah::bail!("--pubkeys and --kinds are required for --subscribe");
    }

    if args.update_interval.0 < args.connect_timeout.0 + args.request_timeout.0 {
        ah::bail!("--update-interval should be greater than --connect-timeout + --request-timeout");
    }

    if args.no_mentions && args.pubkeys.is_none() {
        ah::bail!("--pubkeys is required for --no-mentions");
    }

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

    let ws_message_size = args.max_msg_size * 4;
    let ws_config = WebSocketConfig::default()
        .max_write_buffer_size(
            WebSocketConfig::default()
                .write_buffer_size
                .saturating_add(ws_message_size),
        )
        .max_message_size(Some(ws_message_size))
        .max_frame_size(Some(args.max_frame_size as usize));

    let connection = Connection::new();
    let connection = if let Some(proxy) = args.proxy {
        connection.proxy(proxy).target(ConnectionTarget::All)
    } else if let Some(tor_proxy) = args.tor_proxy {
        connection.proxy(tor_proxy).target(ConnectionTarget::Onion)
    } else {
        connection
    };

    let ClientAndPolicy {
        nostr_client,
        policy,
        seen_relay_info_after_failure,
        azzamo_block_pubkeys_sender,
    } = ClientAndPolicy::new(&args, connection)?;

    let relays = Arc::new(Relays {
        nostr_client: nostr_client.clone(),
        args: args.clone(),
        policy: policy.clone(),
        seen_relay_info_after_failure,
        nip66_discovered: Mutex::new(Default::default()),
    });

    Toplevel::new({
        async move |s: &mut SubsystemHandle| {
            s.start(SubsystemBuilder::new("shutdown", {
                let nostr_client = nostr_client.clone();
                async move |subsys: &mut SubsystemHandle| {
                    subsys.on_shutdown_requested().await;
                    nostr_client.shutdown().await;
                    log::info!("exiting");
                    Ok::<_, ah::Error>(())
                }
            }));
            s.start(SubsystemBuilder::new(
                "main",
                async move |subsys: &mut SubsystemHandle| {
                    let relays = relays.clone();
                    let listeners = new_listeners(&args).await?.into_iter().map({
                        let relays = relays.clone();
                        move |listener| serve(listener, ws_config, relays.clone()).boxed()
                    });

                    if let Err(e) = try_join_all(
                        [
                            async {
                                subsys.on_shutdown_requested().await;
                                ah::bail!("shutdown");
                            }
                            .boxed(),
                            Relays::updater(relays).boxed(),
                            spam::azzamo_updater(&args, azzamo_block_pubkeys_sender).boxed(),
                        ]
                        .into_iter()
                        .chain(listeners),
                    )
                    .await
                    {
                        log::error!("{e}");
                    }
                    Ok::<_, ah::Error>(())
                },
            ));
        }
    })
    .catch_signals()
    .handle_shutdown_requests(Duration::from_millis(4000))
    .await?;
    Ok(())
}

async fn serve(
    listener: TcpListener,
    ws_config: WebSocketConfig,
    relays: Arc<Relays>,
) -> ah::Result<()> {
    let relay_info = {
        let body = RelayInformationDocument {
            name: Some("broadcastr".to_string()),
            software: Some("git+https://github.com/codonaft/broadcastr".to_string()),
            version: Some(concatcp!(env!("CARGO_PKG_VERSION"), '-', git_version!()).to_string()),
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
                    nostr_helpers::handle_ws_connection(
                        stream,
                        ws_config,
                        relays.clone(),
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

fn proxied_client_builder(url: &Url, args: &Broadcastr) -> ah::Result<ClientBuilder> {
    let client = ClientBuilder::new()
        .connect_timeout(args.connect_timeout.0)
        .timeout(args.request_timeout.0);
    let client = if let Some(proxy) = args.proxy {
        client.proxy(Proxy::all(format!("socks5h://{proxy}")).map_err(ah::Error::from)?)
    } else if let Some(tor_proxy) = args.tor_proxy
        && let Some(Host::Domain(relay_host)) = url.host()
        && relay_host.ends_with(".onion")
    {
        client.proxy(Proxy::all(format!("socks5h://{tor_proxy}")).map_err(ah::Error::from)?)
    } else {
        client
    };
    Ok(client)
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

fn retry_with_backoff_endless<F, Fut>(
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
