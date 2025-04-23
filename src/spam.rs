use super::{Broadcastr, backoff};
use anyhow as ah;
use backoff::{self as bf};
use futures::future::join_all;
use nostr_sdk::{EventId, PublicKey};
use reqwest::{ClientBuilder, Url};
use serde::{Deserialize, de::DeserializeOwned};
use std::collections::HashSet;
use tokio::{sync::watch, task::JoinHandle, time};

pub(crate) async fn updater(
    args: &Broadcastr,
    spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
    spam_events_sender: watch::Sender<HashSet<EventId>>,
) -> ah::Result<()> {
    if args.disable_spam_nostr_band {
        return Ok(());
    }

    let mut interval = time::interval(args.update_interval.0);
    loop {
        interval.tick().await;
        if let Err(e) = update_lists(
            args.clone(),
            spam_pubkeys_sender.clone(),
            spam_events_sender.clone(),
        )
        .await
        {
            log::error!("failed to update spam lists: {e}");
        }
    }
}

async fn update_lists(
    args: Broadcastr,
    spam_pubkeys_sender: watch::Sender<HashSet<PublicKey>>,
    spam_events_sender: watch::Sender<HashSet<EventId>>,
) -> ah::Result<()> {
    #[derive(Deserialize, Debug)]
    struct Pubkeys {
        cluster_pubkeys: Vec<ClusterPubkeys>,
    }

    #[derive(Deserialize, Debug)]
    struct Events {
        cluster_events: Vec<ClusterEvents>,
    }

    #[derive(Deserialize, Debug)]
    struct ClusterPubkeys {
        pubkeys: Vec<PublicKey>,
    }

    #[derive(Deserialize, Debug)]
    struct ClusterEvents {
        events: Vec<EventId>,
    }

    impl From<Pubkeys> for HashSet<PublicKey> {
        fn from(value: Pubkeys) -> Self {
            value
                .cluster_pubkeys
                .into_iter()
                .flat_map(|i| i.pubkeys)
                .collect()
        }
    }

    impl From<Events> for HashSet<EventId> {
        fn from(value: Events) -> Self {
            value
                .cluster_events
                .into_iter()
                .flat_map(|i| i.events)
                .collect()
        }
    }

    join_all([
        fetch_list::<Pubkeys, PublicKey>(args.clone(), spam_pubkeys_sender, "pubkeys"),
        fetch_list::<Events, EventId>(args, spam_events_sender, "events"),
    ])
    .await
    .into_iter()
    .flatten()
    .collect::<ah::Result<Vec<()>>>()?;

    Ok(())
}

fn fetch_list<Input: DeserializeOwned, Output>(
    args: Broadcastr,
    output: watch::Sender<HashSet<Output>>,
    view: &'static str,
) -> JoinHandle<ah::Result<()>>
where
    HashSet<Output>: From<Input>,
    Output: Send + Sync + 'static,
{
    tokio::spawn(bf::future::retry(backoff(&args), move || {
        let output = output.clone();
        async move {
            let url = Url::parse_with_params(
                "https://spam.nostr.band/spam_api?method=get_current_spam",
                &[("view", view)],
            )
            .map_err(|e| bf::Error::transient(e.into()))?;
            let items: HashSet<_> = async move {
                ClientBuilder::new()
                    .timeout(args.request_timeout.0)
                    .build()?
                    .get(url)
                    .send()
                    .await?
                    .json::<Input>()
                    .await
            }
            .await
            .map_err(|e| bf::Error::transient(e.into()))?
            .into();

            log::debug!("spam.nostr.band: fetched {} {view}", items.len());
            output
                .send(items)
                .map_err(|e| bf::Error::transient(e.into()))?;
            Result::<_, bf::Error<ah::Error>>::Ok(())
        }
    }))
}
