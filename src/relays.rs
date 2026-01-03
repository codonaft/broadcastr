use super::{Broadcastr, normalize_url, retry_with_backoff};
use anyhow as ah;
use futures::future::try_join_all;
use nostr_sdk::{Client as NostrClient, serde_json};
use reqwest::{ClientBuilder, Url};
use std::{
    collections::HashSet,
    fs::File,
    ops::Sub,
    time::{Duration, Instant},
};
use tokio::{sync::watch, time};

pub(crate) async fn updater(
    blocked_relays_sender: watch::Sender<HashSet<Url>>,
    args: &Broadcastr,
    nostr_client: &NostrClient,
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
                update_connections(args, nostr_client).await;
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

async fn update_connections(args: Broadcastr, nostr_client: NostrClient) {
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
