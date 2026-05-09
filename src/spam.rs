use crate::{Broadcastr, backoff, proxied_client_builder};
use anyhow as ah;
use backon::Retryable;
use nostr::PublicKey;
use reqwest::Client as HttpClient;
use std::collections::HashSet;
use tokio::{sync::watch, time};

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
