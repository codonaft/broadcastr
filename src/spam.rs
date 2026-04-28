use super::{Broadcastr, retry_with_backoff_endless};
use crate::proxied_client_builder;
use anyhow as ah;
use backoff::{self as bf};
use nostr_sdk::PublicKey;
use reqwest::Url;
use std::collections::HashSet;
use tokio::{sync::watch, task::JoinHandle, time};

pub(crate) async fn azzamo_updater(
    args: &Broadcastr,
    spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
) -> ah::Result<()> {
    if args.disable_azzamo {
        return Ok(());
    }

    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        if let Err(e) =
            update_azzamo_blocked_pubkeys(args.clone(), spam_pubkeys_sender.clone()).await
        {
            log::error!("failed to update azzamo blocked pubkeys: {e}");
        }
    }
}

fn update_azzamo_blocked_pubkeys(
    args: Broadcastr,
    output: watch::Sender<HashSet<PublicKey>>,
) -> JoinHandle<ah::Result<()>> {
    let args = args.clone();
    let fetch = {
        let args = args.clone();
        move || {
            let args = args.clone();
            let output = output.clone();
            async move {
                let url = Url::parse("https://ban-api.azzamo.net/public/blocked/pubkeys")
                    .map_err(|e| bf::Error::permanent(e.into()))?;
                let client = proxied_client_builder(&url, &args);
                let items = async {
                    Ok(client?
                        .build()?
                        .get(url)
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
        }
    };
    tokio::spawn(retry_with_backoff_endless(args, fetch))
}
