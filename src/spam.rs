use crate::relays::EventMetadata;
use crate::{Broadcastr, backoff, now, proxied_client_builder, relays::Relays};
use anyhow as ah;
use anyhow::{Context, bail};
use backon::Retryable;
use futures::future::try_join_all;
use nostr::event::EventId;
use nostr::types::Timestamp;
use nostr::{
    Event, Filter, Kind as EventKind, PublicKey,
    event::tag::TagCodec,
    nips::{
        nip05::{Nip05Address, verify_from_raw_json},
        nip10::Nip10Tag,
    },
    serde_json,
};
use reqwest::Client as HttpClient;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{sync::watch, time, time::sleep};

const QUARANTINE_TIME: Duration = Duration::from_hours(1);

pub(crate) async fn check_possible_spam(event: &Event, relays: Arc<Relays>) -> ah::Result<()> {
    let (parent_event_metadata, parent_event_id) = {
        let facts = relays.facts.read().await;
        if let Some(yes) = facts.possible_spammers.peek(&event.pubkey).copied() {
            return if yes {
                Err(ah::anyhow!("{} is possibly a spammer", event.pubkey))
            } else {
                Ok(())
            };
        }

        if let Some(Nip10Tag::Event { id, .. }) = event
            .tags
            .iter()
            .cloned()
            .filter_map(|t| Nip10Tag::parse(t).ok())
            .filter(|t| t.is_reply())
            .next()
        {
            (facts.events_metadata.get(&id).copied(), Some(id))
        } else {
            (None, None)
        }
    };

    let result = check_possible_spam_inner(
        event,
        parent_event_metadata,
        parent_event_id,
        relays.clone(),
    )
    .await;

    {
        let mut lock = relays.facts.write().await;
        lock.possible_spammers.put(event.pubkey, result.is_err());
    }

    result
}

async fn check_possible_spam_inner(
    event: &Event,
    parent_event_metadata: Option<EventMetadata>,
    parent_event_id: Option<EventId>,
    relays: Arc<Relays>,
) -> ah::Result<()> {
    let followed = {
        relays
            .facts
            .read()
            .await
            .author_to_contact_list
            .values()
            .any(|(i, _)| i.contains(&event.pubkey))
    };
    if followed {
        log::debug!("{} followed by allowed author(s)", event.pubkey);
        return Ok(());
    }

    let created_at = Duration::from_secs(event.created_at.as_secs());

    let interval = relays.args.update_interval.0;
    let until = Timestamp::from_secs(now().saturating_add(interval).as_secs()); // TODO

    if let Some(parent_event_id) = parent_event_id {
        let parent_event_metadata = if let Some(parent_event_metadata) = parent_event_metadata {
            parent_event_metadata
        } else {
            log::info!("looking for parent event {parent_event_id}");
            let parent_event_metadata = relays
                .nostr_client
                .fetch_events(Filter::new().id(parent_event_id).limit(1).until(until))
                .timeout(relays.args.request_timeout.0)
                .await
                .ok()
                .and_then(|i| i.first().map(EventMetadata::new))
                .context("parent_event")?;

            {
                let mut lock = relays.facts.write().await;
                lock.events_metadata
                    .insert(parent_event_id, parent_event_metadata);
            }

            parent_event_metadata
        };

        let response_time = created_at.saturating_sub(Duration::from_secs(
            parent_event_metadata.created_at.as_secs(),
        ));
        if response_time > parent_event_metadata.time_to_read {
            bail!("too fast response, possibly an automatic reply");
        }
    }

    let age = now().saturating_sub(created_at);
    if age < QUARANTINE_TIME {
        let time = QUARANTINE_TIME.saturating_sub(age);
        log::info!("putting {} on quarantine for {time:?}", event.id);
        sleep(time).await;
        return Box::pin(check_possible_spam(event, relays)).await;
    }

    // TODO: if event author is mentioned by a trusted spam detector bot in their generated replies - spam

    let nip05_verification = tokio::spawn({
        let pubkey = event.pubkey;
        let relays = relays.clone();
        async move {
            let permit = relays.http_client_budget.acquire().await;
            let metadata = relays
                .nostr_client
                .fetch_events(
                    Filter::new()
                        .author(pubkey)
                        .kind(EventKind::Metadata)
                        .limit(1)
                        .until(until),
                )
                .timeout(relays.args.request_timeout.0)
                .await
                .ok()
                .and_then(|i| i.into_iter().max_by_key(|e| e.created_at));
            let address =
                serde_json::from_str::<serde_json::Value>(&metadata.context("metadata")?.content)?
                    .get("nip05")
                    .and_then(|i| i.as_str())
                    .map(Nip05Address::parse)
                    .context("nip05 address")?;
            let address = address?;
            let nip05_json = relays
                .http_client
                .get(address.url().as_str())
                .send()
                .await?
                .text()
                .await?;
            drop(permit);
            if !verify_from_raw_json(&pubkey, &address, &nip05_json)? {
                bail!("{pubkey} NIP-05 verification failed");
            }
            Ok(())
        }
    });

    let has_non_reply_posts = tokio::spawn({
        let pubkey = event.pubkey;
        async move {
            let has_posts = relays
                .nostr_client
                .fetch_events(
                    Filter::new()
                        .author(pubkey)
                        .kinds([EventKind::TextNote, EventKind::Comment])
                        .limit(50)
                        .until(until),
                )
                .timeout(relays.args.request_timeout.0)
                .await
                .into_iter()
                .flat_map(|i| i.into_iter())
                .find(|e| {
                    let nip10_tags = e
                        .tags
                        .clone()
                        .into_iter()
                        .map(Nip10Tag::parse)
                        .filter_map(Result::ok)
                        .collect::<Vec<_>>();
                    match &nip10_tags[..] {
                        [] => true,
                        [tag] => !tag.is_reply(),
                        _ => false,
                    }
                })
                .is_some();
            if !has_posts {
                bail!("{pubkey} might be a reply spammer");
            }
            Ok(())
        }
    });

    try_join_all([nip05_verification, has_non_reply_posts]).await?;
    Ok(())
}

pub(crate) async fn run_azzamo(
    args: &Broadcastr,
    spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
) -> ah::Result<()> {
    if args.no_azzamo {
        return Ok(());
    }

    let client = proxied_client_builder(args)?.build()?;
    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        if let Err(e) =
            update_azzamo_blocked_pubkeys(spam_pubkeys_sender.clone(), args, client.clone()).await
        {
            log::error!("failed to update azzamo blocked pubkeys: {e}");
        }
    }
}

async fn update_azzamo_blocked_pubkeys(
    output: watch::Sender<HashSet<PublicKey>>,
    args: &Broadcastr,
    client: HttpClient,
) -> ah::Result<()> {
    let fetch = move || {
        let output = output.clone();
        let client = client.clone();
        async move {
            let items = async {
                let result = client
                    .get("https://ban-api.azzamo.net/public/blocked/pubkeys")
                    .send()
                    .await?
                    .json::<HashSet<_>>()
                    .await?;
                Ok::<_, ah::Error>(result)
            }
            .await?;

            log::debug!("azzamo: fetched {}", items.len());
            output.send(items)?;
            Ok(())
        }
    };
    fetch.retry(backoff(args)).await
}
