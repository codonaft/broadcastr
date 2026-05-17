use crate::{Broadcastr, backoff, nostr_utils, now, proxied_client_builder, relays::Relays};
use anyhow as ah;
use anyhow::{Context, bail};
use backon::Retryable;
use futures::future::try_join_all;
use indexmap::IndexSet;
use itertools::Itertools;
use nostr::{
    Event, Filter, Kind as EventKind, PublicKey,
    event::tag::TagCodec,
    filter::{Alphabet, SingleLetterTag},
    nips::{
        nip05::{Nip05Address, verify_from_raw_json},
        nip10::Nip10Tag,
    },
    serde_json,
    types::Timestamp,
};
use reqwest::Client as HttpClient;
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::{sync::watch, time, time::sleep};

const QUARANTINE_TIME: Duration = Duration::from_hours(2);
const MIN_TIME_BETWEEN_POSTS_BY_STRANGER: Duration = Duration::from_mins(3);

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

pub(crate) async fn check_stranger(
    stranger_event: &Event,
    authors: &IndexSet<PublicKey>,
    relays: Arc<Relays>,
) -> ah::Result<()> {
    let NeighoringEvents { parent, child } =
        NeighoringEvents::fetch(stranger_event, authors, relays.clone()).await?;

    let allowed_author = if let Some(parent_event) = parent {
        log::info!(
            "stranger {} responded to allowed author {} with event {}",
            stranger_event.pubkey,
            parent_event.pubkey,
            stranger_event.id,
        );

        let response_time = stranger_event.created_at - parent_event.created_at;
        let response_time = Duration::from_secs(response_time.as_secs());

        if response_time < time_to_read(&parent_event) {
            bail!(
                "stranger {} responded with {} too fast, possibly it's an automated reply",
                stranger_event.pubkey,
                stranger_event.id
            );
        }
        parent_event.pubkey
    } else if let Some(child_event) = child {
        log::info!(
            "allowed author {} responded to stranger {} with event {}",
            child_event.pubkey,
            stranger_event.pubkey,
            child_event.id
        );
        child_event.pubkey
    } else {
        bail!(
            "stranger event {} has no connection with allowed authors",
            stranger_event.id
        );
    };

    let followed = {
        relays
            .facts
            .read()
            .await
            .author_to_contact_list
            .get(&allowed_author)
            .map(|(contacts, _)| contacts.contains(&stranger_event.pubkey))
            .unwrap_or_default()
    };

    if followed {
        log::debug!(
            "{} followed by allowed author {}",
            stranger_event.pubkey,
            allowed_author
        );

        {
            let mut lock = relays.facts.write().await;
            lock.possible_spammers.put(stranger_event.pubkey, false);
        }

        return Ok(());
    }

    check_sanity(stranger_event, relays).await
}

struct NeighoringEvents {
    parent: Option<Event>,
    child: Option<Event>,
}

impl NeighoringEvents {
    async fn fetch(
        stranger_event: &Event,
        authors: &IndexSet<PublicKey>,
        relays: Arc<Relays>,
    ) -> ah::Result<Self> {
        let interval = relays.args.update_interval.0;
        let until = Timestamp::from_secs(now().saturating_add(interval).as_secs()); // TODO

        let filter = Filter::new().authors(authors.clone()).until(until);
        let filter = if let Some(nostr_utils::EventKinds(kinds)) = relays.args.kinds.clone() {
            filter.kinds(kinds)
        } else {
            filter
        };

        let parent = tokio::spawn({
            let stranger_event = stranger_event.clone();
            let filter = filter.clone();
            let relays = relays.clone();
            let authors = authors.clone();
            async move {
                if let Some(Nip10Tag::Event {
                    id: parent_event_id,
                    public_key,
                    ..
                }) = stranger_event
                    .tags
                    .iter()
                    .cloned()
                    .filter_map(|t| Nip10Tag::parse(t).ok())
                    .find(|t| t.is_reply())
                    && public_key.map(|p| authors.contains(&p)).unwrap_or(true)
                {
                    log::debug!(
                        "finding parent event {parent_event_id} of {}",
                        stranger_event.id
                    );
                    relays
                        .nostr_client
                        .fetch_events(filter.clone().id(parent_event_id))
                        .timeout(relays.args.request_timeout.0)
                        .await
                        .ok()
                        .and_then(|i| i.first_owned())
                } else {
                    None
                }
            }
        });

        let child = relays
            .nostr_client
            .fetch_events(
                filter
                    .pubkey(stranger_event.pubkey)
                    .event(stranger_event.id)
                    .since(stranger_event.created_at + 1),
            )
            .timeout(relays.args.request_timeout.0)
            .await
            .ok()
            .into_iter()
            .flatten()
            .chunk_by(|e| e.pubkey)
            .into_iter()
            .flat_map(|(_, events)| events.into_iter().min_by_key(|e| e.created_at).into_iter())
            .next();

        let parent = parent.await?;
        Ok(Self { parent, child })
    }
}

pub(crate) async fn check_sanity(stranger_event: &Event, relays: Arc<Relays>) -> ah::Result<()> {
    log::debug!("sanity check for {}", stranger_event.id);
    {
        let facts = relays.facts.read().await;
        if let Some(yes) = facts
            .possible_spammers
            .peek(&stranger_event.pubkey)
            .copied()
        {
            return if yes {
                ah::bail!("{} is possibly a spammer", stranger_event.pubkey);
            } else {
                Ok(())
            };
        }
    }

    let age = Duration::from_secs((Timestamp::now() - stranger_event.created_at).as_secs()); // TODO
    if age < QUARANTINE_TIME {
        let time = QUARANTINE_TIME.saturating_sub(age);
        log::info!("putting {} on quarantine for {time:?}", stranger_event.id);
        sleep(time).await;
    }

    let interval = relays.args.update_interval.0;
    let until = Timestamp::from_secs(now().saturating_add(interval).as_secs()); // TODO

    let sane_non_reply_posts = tokio::spawn({
        let pubkey = stranger_event.pubkey;
        let relays = relays.clone();
        async move {
            // false positive
            #[allow(clippy::mutable_key_type)]
            let posts = relays
                .nostr_client
                .fetch_events(
                    Filter::new()
                        .author(pubkey)
                        .kinds([EventKind::TextNote, EventKind::Comment])
                        .limit(200)
                        .until(until),
                )
                .timeout(relays.args.request_timeout.0)
                .await
                .into_iter()
                .flat_map(|i| i.into_iter())
                .collect::<HashSet<Event>>();

            let non_replies = posts
                .into_iter()
                .filter(|e| {
                    let nip10_tags = e
                        .tags
                        .clone()
                        .into_iter()
                        .map(Nip10Tag::parse)
                        .filter_map(Result::ok)
                        .collect_vec();
                    match &nip10_tags[..] {
                        [] => true,
                        [tag] => !tag.is_reply(),
                        _ => false,
                    }
                })
                .collect_vec();
            if non_replies.len() < 5 {
                bail!("{pubkey} has too few non-reply posts");
            }

            let deltas = non_replies
                .iter()
                .map(|e| e.created_at)
                .sorted()
                .tuple_windows()
                .map(|(a, b)| (b - a).as_secs())
                .collect_vec();
            let dt = Duration::from_secs(approximate_percentile(0.9, deltas));
            log::debug!("{pubkey} posts mostly a non-reply post per {dt:?}");
            if dt < MIN_TIME_BETWEEN_POSTS_BY_STRANGER {
                bail!("{pubkey} posts too often");
            }
            Ok(())
        }
    });

    let nip05_verification = tokio::spawn({
        let pubkey = stranger_event.pubkey;
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

    let stranger_event_reported_by_moderator = tokio::spawn({
        let stranger_event = stranger_event.clone();
        let relays = relays.clone();
        async move {
            if let Some(moderators) = &relays.args.moderators {
                let filter = Filter::new()
                    .authors(moderators.0.clone())
                    .kind(EventKind::Reporting)
                    .pubkey(stranger_event.pubkey)
                    .limit(1)
                    .since(stranger_event.created_at + 1)
                    .until(until);
                let event_id_hex = stranger_event.id.to_hex();
                let report = relays
                    .nostr_client
                    .fetch_events(
                        ["spam", "scam"]
                            .into_iter()
                            .map(|report_type| {
                                filter.clone().custom_tags(
                                    SingleLetterTag::lowercase(Alphabet::E),
                                    [event_id_hex.clone(), report_type.to_string()],
                                )
                            })
                            .collect_vec(),
                    )
                    .timeout(relays.args.request_timeout.0)
                    .await
                    .ok()
                    .and_then(|i| i.first_owned());
                if let Some(report) = report {
                    bail!("{} was reported by {}", stranger_event.id, report.pubkey);
                }
            }
            Ok(())
        }
    });

    let result = try_join_all([
        sane_non_reply_posts,
        nip05_verification,
        stranger_event_reported_by_moderator,
    ])
    .await
    .map(|_| ());

    {
        let mut lock = relays.facts.write().await;
        lock.possible_spammers
            .put(stranger_event.pubkey, result.is_err());
    }

    Ok(result?)
}

fn time_to_read(event: &Event) -> Duration {
    Duration::from_secs_f64(event.content.len() as f64 * 0.04)
}

fn approximate_percentile<T: Copy>(p_normalized: f64, sorted_data: Vec<T>) -> T {
    debug_assert!(!sorted_data.is_empty());
    let index = ((sorted_data.len() as f64 * p_normalized).ceil() as usize).saturating_sub(1);
    sorted_data[index]
}
