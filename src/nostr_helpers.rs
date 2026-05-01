use crate::relays::Relays;
use anyhow as ah;
use anyhow::Context;
use futures::{SinkExt, StreamExt};
use futures_util::stream::SplitSink;
use httparse::Status;
use nostr::{
    ClientMessage, EventId, JsonUtil, Kind as EventKind, PublicKey, RelayMessage, SubscriptionId,
    nips::nip11::{Limitation, RelayInformationDocument},
    serde_json,
};
use reqwest::header;
use std::{borrow::Cow, collections::HashSet, net::IpAddr, str::FromStr, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config, tungstenite::Message};
use tungstenite::{
    handshake::server::{Request, Response},
    protocol::WebSocketConfig,
};

#[derive(Debug, Clone, Default)]
pub(crate) struct PublicKeys(pub HashSet<PublicKey>);

#[derive(Debug, Clone, Default)]
pub(crate) struct EventKinds(pub HashSet<EventKind>);

#[derive(Default, Debug)]
struct ParsedHttpHeaders {
    ws: bool,
    ip: Option<IpAddr>,
}

pub(crate) async fn handle_ws_connection(
    mut stream: TcpStream,
    ws_config: WebSocketConfig,
    relays: Arc<Relays>,
    relay_info: String,
) -> ah::Result<()> {
    let ParsedHttpHeaders { ws, ip } = parse_http_headers(&stream).await;
    if !ws {
        stream.write_all(relay_info.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    log::debug!("detected ws connection");

    let value = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        .parse()
        .context("header value")?;

    // false positive?
    #[allow(clippy::result_large_err)]
    let ws_stream = accept_hdr_async_with_config(
        stream,
        |_: &Request, mut response: Response| {
            response.headers_mut().insert(header::VARY, value);
            Ok(response)
        },
        Some(ws_config),
    )
    .await
    .context("accept_async_with_config")?;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();
    while let Some(Ok(Message::Text(text))) = ws_receiver.next().await {
        match ClientMessage::from_json(&text) {
            Ok(client_message) => {
                handle_client_message(client_message, ip, &mut ws_sender, relays.clone()).await;
            },
            Err(e) => {
                log::debug!("failed to parse client message: {e}");
                break;
            },
        }
    }

    let _ = ws_sender
        .close()
        .await
        .context("ws_sender.close")
        .map_err(|e| log::error!("{e}"));
    log::debug!("closed connection with client");
    Ok(())
}

async fn parse_http_headers(stream: &TcpStream) -> ParsedHttpHeaders {
    let mut buffer = [0u8; 1024];
    let _ = stream.peek(&mut buffer).await;

    let mut result = ParsedHttpHeaders::default();
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    if let Ok(Status::Partial) = request.parse(&buffer) {
        log::error!("too many request headers");
    }

    for i in request.headers {
        if i.name.is_empty() {
            break;
        }
        let header = i.name.to_lowercase();
        let header = header.trim();
        if header.contains("sec-websocket") {
            result.ws = true;
        } else if ["x-forwarded-for", "x-real-ip"].contains(&header)
            && let Some(value) = str::from_utf8(i.value)
                .ok()
                .and_then(|v| v.split(',').next())
        {
            result.ip = value.trim().parse().ok();
        }
    }

    log::debug!("parsed headers {:?}", result);
    result
}

async fn handle_client_message(
    client_message: ClientMessage<'_>,
    ip: Option<IpAddr>,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    relays: Arc<Relays>,
) {
    use ClientMessage::*;
    match client_message {
        Event(event) => {
            let event = event.into_owned();
            let event_id = event.id;
            let (success, message) =
                match Relays::spawn_handle_event(relays, event, ip, false).await {
                    Ok(()) => (true, "".to_string()),
                    Err(e) => (false, format!("{e}")),
                };
            ok(event_id, success, &message, ws_sender).await;
        },
        Close(subscription_id) => closed(subscription_id, "close", ws_sender).await,
        Auth(event) => ok(event.id, false, "unexpected message", ws_sender).await,
        Req {
            subscription_id, ..
        } => eose(subscription_id, ws_sender).await,
        Count {
            subscription_id, ..
        } => count(subscription_id, ws_sender).await,
        NegOpen {
            subscription_id, ..
        }
        | NegMsg {
            subscription_id, ..
        }
        | NegClose {
            subscription_id, ..
        } => neg_err(subscription_id, "unexpected message", ws_sender).await,
    }
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

async fn eose(
    subscription_id: Cow<'_, SubscriptionId>,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) {
    log::debug!("eose");
    let _ = send_relay_message(RelayMessage::EndOfStoredEvents(subscription_id), ws_sender).await;
}

async fn count(
    subscription_id: Cow<'_, SubscriptionId>,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
) {
    log::debug!("count");
    let _ = send_relay_message(
        RelayMessage::Count {
            subscription_id,
            count: 0,
        },
        ws_sender,
    )
    .await;
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
    let text = Message::Text(
        serde_json::to_string(&message)
            .context("relay_message")?
            .into(),
    );
    ws_sender.send(text).await.context("ws_sender.send")?;
    ws_sender.flush().await?;
    Ok(())
}

pub(crate) fn has_publish_limitation(
    info_from_discovery: &Result<RelayInformationDocument, serde_json::Error>,
) -> bool {
    if let Ok(info) = info_from_discovery
        && let Some(Limitation {
            auth_required,
            payment_required,
            restricted_writes,
            ..
        }) = info.limitation
    {
        auth_required.unwrap_or_default()
            || payment_required.unwrap_or_default()
            || restricted_writes.unwrap_or_default()
    } else {
        false
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
