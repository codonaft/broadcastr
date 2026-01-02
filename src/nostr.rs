use super::Broadcastr;
use crate::RateLimits;
use anyhow as ah;
use anyhow::Context;
use futures::{SinkExt, StreamExt, future::join_all};
use futures_util::stream::SplitSink;
use nostr_sdk::{
    Alphabet, Client as NostrClient, ClientMessage, Event, EventId, Filter, JsonUtil,
    Kind as EventKind, PublicKey, RelayMessage, RelayUrl, SingleLetterTag, SubscriptionId, Tag,
    prelude::{AdmitPolicy, AdmitStatus, PolicyError},
    serde_json,
    util::BoxedFuture,
};
use reqwest::{Url, header};
use std::{borrow::Cow, collections::HashSet, ops::Sub, str::FromStr, sync::Arc};
use tokio::{io::AsyncWriteExt, net::TcpStream, sync::watch};
use tokio_tungstenite::{WebSocketStream, accept_hdr_async_with_config, tungstenite::Message};
use tungstenite::{
    handshake::server::{Request, Response},
    protocol::WebSocketConfig,
};

#[derive(Debug, Clone)]
pub struct Policy {
    allowed_pubkeys: HashSet<PublicKey>,
    disable_mentions: bool,
    allowed_kinds: HashSet<EventKind>,
    min_pow: Option<u8>,
    blocked_relays_receiver: watch::Receiver<HashSet<Url>>,
    spam_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
    spam_events_receiver: watch::Receiver<HashSet<EventId>>,
    azzamo_blocked_pubkeys_receiver: watch::Receiver<HashSet<PublicKey>>,
}

pub(crate) struct PolicyWithSenders {
    pub policy: Policy,
    pub blocked_relays_sender: watch::Sender<HashSet<Url>>,
    pub spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
    pub spam_events_sender: watch::Sender<HashSet<EventId>>,
    pub azzamo_blocked_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PublicKeys(pub HashSet<PublicKey>);

#[derive(Debug, Clone, Default)]
pub(crate) struct EventKinds(pub HashSet<EventKind>);

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

pub(crate) async fn handle_ws_connection(
    mut stream: TcpStream,
    ws_config: WebSocketConfig,
    args: Broadcastr,
    nostr_client: NostrClient,
    rate_limits: Arc<RateLimits>,
    policy: Arc<Policy>,
    relay_info: String,
) -> ah::Result<()> {
    if !is_ws(&stream).await {
        stream.write_all(relay_info.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    log::debug!("detected ws connection");

    let value = "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
        .parse()
        .context("header value")?;
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
                let broadcasted = handle_client_message(
                    client_message,
                    &mut ws_sender,
                    &args,
                    &nostr_client,
                    rate_limits.clone(),
                    policy.clone(),
                )
                .await;

                if let Some(BroadcastedEvent {
                    event_id,
                    found_on_relays_before_broadcasting,
                }) = broadcasted
                {
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
                        "event {event_id} was accepted by {broadcasted_to_new_relays} relays (now \
                         it's available on {} of {} relays)",
                        found_on_relays.len(),
                        found_on_relays
                            .len()
                            .saturating_add(relays_without_event.len()),
                    );
                }
            },
            Err(e) => {
                log::debug!("failed to parse client message: {e}");
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

async fn is_ws(stream: &TcpStream) -> bool {
    let mut buffer = [0u8; 1024];
    let n = match stream.peek(&mut buffer).await {
        Ok(n) => n,
        Err(_) => {
            return false;
        },
    };

    if n == 0 {
        return false;
    }

    let request = String::from_utf8_lossy(&buffer[..n]);
    log::debug!("request {request}");
    request.to_lowercase().contains("sec-websocket")
}

async fn handle_client_message(
    client_message: ClientMessage<'_>,
    ws_sender: &mut SplitSink<WebSocketStream<TcpStream>, Message>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    rate_limits: Arc<RateLimits>,
    policy: Arc<Policy>,
) -> Option<BroadcastedEvent> {
    use ClientMessage::*;
    match client_message {
        Event(event) => {
            let event_id = event.id;

            ok(event_id, true, "", ws_sender).await;

            match handle_event(event, args, nostr_client, rate_limits, policy).await {
                Ok(Some(broadcasted_event)) => return Some(broadcasted_event),
                Ok(None) => (),
                Err(e) => log::error!("failed to handle a message: {e}"),
            }
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
    None
}

async fn handle_event(
    event: Cow<'_, Event>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
    rate_limits: Arc<RateLimits>,
    policy: Arc<Policy>,
) -> ah::Result<Option<BroadcastedEvent>> {
    policy.check_event(&event)?;

    let event_id = event.id;
    if rate_limits
        .events_by_author
        .check_key(&event.pubkey)
        .is_err()
    {
        ah::bail!("rate-limit: too many attempts to transmit event by the same author");
    }
    if rate_limits.events_by_id.check_key(&event_id).is_err() {
        ah::bail!("rate-limit: too many attempts to transmit the same event");
    }
    log::debug!("received event {event_id}");

    let QueryEvent {
        found_on_relays,
        relays_without_event,
    } = QueryEvent::find(event_id, args, nostr_client)
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
            let blocked_relays = self
                .blocked_relays_receiver
                .borrow()
                .iter()
                .map(|i| i.as_str().parse().map_err(PolicyError::backend))
                .collect::<Result<HashSet<RelayUrl>, PolicyError>>()?;

            let result = if blocked_relays.contains(url) {
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
            if let Err(e) = self.check_event(event) {
                return Ok(AdmitStatus::Rejected {
                    reason: Some(format!("{e}")),
                });
            }
            Ok(AdmitStatus::Success)
        })
    }
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
    Ok(())
}

fn mentioned_pubkey(tag: &Tag) -> Option<PublicKey> {
    if tag.single_letter_tag() == Some(SingleLetterTag::lowercase(Alphabet::P))
        && let Some(pubkey) = tag.content()
    {
        return pubkey.parse().ok();
    }
    None
}

impl PolicyWithSenders {
    pub(crate) fn new(args: &Broadcastr) -> ah::Result<Self> {
        let (blocked_relays_sender, blocked_relays_receiver) = watch::channel(HashSet::default());
        let (spam_pubkeys_sender, spam_pubkeys_receiver) = watch::channel(HashSet::default());
        let (spam_events_sender, spam_events_receiver) = watch::channel(HashSet::default());
        let (azzamo_blocked_pubkeys_sender, azzamo_blocked_pubkeys_receiver) =
            watch::channel(HashSet::default());
        let policy = Policy {
            allowed_pubkeys: args.allowed_pubkeys.clone().unwrap_or_default().0,
            disable_mentions: args.disable_mentions,
            allowed_kinds: args.allowed_kinds.clone().unwrap_or_default().0,
            min_pow: args.min_pow,
            blocked_relays_receiver,
            spam_pubkeys_receiver,
            spam_events_receiver,
            azzamo_blocked_pubkeys_receiver,
        };

        if policy.disable_mentions && policy.allowed_pubkeys.is_empty() {
            ah::bail!(
                "--disable-mentions does nothing if --allowed-pubkeys is not set; perhaps you \
                 forgot to set the --allowed-pubkeys"
            );
        }

        Ok(Self {
            policy,
            blocked_relays_sender,
            spam_pubkeys_sender,
            spam_events_sender,
            azzamo_blocked_pubkeys_sender,
        })
    }
}

impl Policy {
    fn check_event(&self, event: &Event) -> ah::Result<()> {
        if let Some(min_pow) = self.min_pow
            && !event.check_pow(min_pow)
        {
            ah::bail!("unexpected pow < {min_pow}");
        }

        if !self.allowed_kinds.is_empty() && !self.allowed_kinds.contains(&event.kind) {
            ah::bail!("unexpected kind {}", event.kind);
        } else if !self.allowed_pubkeys.is_empty() {
            if self.allowed_pubkeys.contains(&event.pubkey) {
                return Ok(());
            }

            if self.disable_mentions {
                ah::bail!("unexpected author");
            } else if !self.mentions_allowed_pubkeys(event) {
                ah::bail!("unexpected author or mentioned public key");
            }
        }

        if self.is_spam(event) {
            ah::bail!("listed on spam.nostr.band");
        }
        Ok(())
    }

    fn mentions_allowed_pubkeys(&self, event: &Event) -> bool {
        event
            .tags
            .iter()
            .flat_map(mentioned_pubkey)
            .any(|i| self.allowed_pubkeys.contains(&i))
    }

    fn is_spam(&self, event: &Event) -> bool {
        self.spam_pubkeys_receiver.borrow().contains(&event.pubkey)
            || self.spam_events_receiver.borrow().contains(&event.id)
            || self
                .azzamo_blocked_pubkeys_receiver
                .borrow()
                .contains(&event.pubkey)
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
