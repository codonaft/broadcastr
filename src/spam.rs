use super::{Broadcastr, retry_with_backoff_endless};
use crate::proxied_client_builder;
use anyhow as ah;
use backoff::{self as bf};
use nostr::PublicKey;
use reqwest::Client as HttpClient;
use std::collections::HashSet;
use tokio::{sync::watch, task::JoinHandle, time};

pub(crate) async fn azzamo_updater(
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
            update_azzamo_blocked_pubkeys(spam_pubkeys_sender.clone(), args.clone(), client.clone())
                .await
        {
            log::error!("failed to update azzamo blocked pubkeys: {e}");
        }
    }
}

fn update_azzamo_blocked_pubkeys(
    output: watch::Sender<HashSet<PublicKey>>,
    args: Broadcastr,
    client: HttpClient,
) -> JoinHandle<ah::Result<()>> {
    let fetch = move || {
        let output = output.clone();
        let client = client.clone();
        async move {
            let items = async {
                Ok(client
                    .get("https://ban-api.azzamo.net/public/blocked/pubkeys")
                    .send()
                    .await?
                    .json::<HashSet<_>>()
                    .await?)
            }
            .await
            .map_err(bf::Error::transient)?;

            log::debug!("azzamo: fetched {}", items.len());
            output
                .send(items)
                .map_err(|e| bf::Error::transient(e.into()))?;
            Ok(())
        }
    };
    tokio::spawn(retry_with_backoff_endless(args, fetch))
}
