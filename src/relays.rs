use super::{Broadcastr, backoff, normalize_url};
use anyhow as ah;
use backoff::{self as bf};
use futures::future::try_join_all;
use nostr_sdk::{Client as NostrClient, serde_json};
use reqwest::{ClientBuilder, Url};
use std::{collections::HashSet, fs::File, ops::Sub, time::Instant};
use tokio::time;

pub(crate) async fn updater(
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
            log::debug!("fetched {} relays from {uri}", result.len());
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
        log::debug!("removing outdated relay {i}");
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
    log::debug!(
        "currently connected to {connected_relays}/{} relays, disconnected from {}",
        client_relays.len(),
        disconnected_relays.len(),
    );
    log::trace!("reconnection took {elapsed}, disconnected relays: {disconnected_relays:?}");
}
