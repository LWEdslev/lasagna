use crate::pippi::peer::Peer;
use crate::pippi::Message;
use crate::pippi::MessageContent;
use crate::pippi::Result;
use crate::pippi::MAX_PEERS;
use rand::Rng;
use std::collections::HashSet;

pub trait MessageHandlingStrategy: Clone + Send + Sync + 'static {
    fn handle_message(
        peer: &Peer<impl MessageHandlingStrategy>,
        message: Message,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Clone)]
pub struct DefaultMessageHandlingStrategy;

impl MessageHandlingStrategy for DefaultMessageHandlingStrategy {
    async fn handle_message(
        peer: &Peer<impl MessageHandlingStrategy>,
        message: Message,
    ) -> Result<()> {
        let from = message.from;
        use crate::pippi::MessageContent::*;

        if let Some(id) = message.uuid {
            if peer.flooding_set.contains(&id).await {
                return Ok(());
            } // already handled and relayed
            peer.flooding_set.add(id).await;
        }

        match message.content {
            App(ref app_message) => {
                peer.app_message(app_message.clone()).await;
            }
            Contact => (),
            AddMe => {
                let mut inner_peerset = peer.peerset.inner.write().await; // we need to lock it here to avoid race conditions
                let number_of_peers = inner_peerset.len();

                let available_peer = if number_of_peers >= MAX_PEERS {
                    let random_peer = inner_peerset.random_from_dynamic().unwrap();
                    inner_peerset.remove(&random_peer);

                    let message = Message::new_direct_message(
                        &peer.address,
                        MessageContent::IDroppedYou(from),
                    );
                    peer.send_to(&message, &random_peer).await.unwrap();

                    Some(random_peer)
                } else {
                    None
                };

                inner_peerset.insert(from);

                drop(inner_peerset);

                let message = Message::new_direct_message(
                    &peer.address,
                    MessageContent::AddMeAccepted(available_peer),
                );
                peer.send_to(&message, &from).await?;
            }
            IDroppedYou(available_peer) => {
                peer.establish_contact(&available_peer).await.unwrap();
                peer.peerset.replace(from, available_peer).await;
            }
            AddMeAccepted(available_peer) => {
                if let Some(available_peer) = available_peer {
                    peer.establish_contact(&available_peer).await.unwrap();
                    peer.peerset.add_peer(available_peer).await;
                }
            }
            PeersetRelayRequest { origin, counter } => {
                if counter == 0 {
                    peer.establish_contact(&origin).await.unwrap();
                    let peerset = peer.peerset.get_copy().await;
                    let message = Message::new_direct_message(
                        &peer.address,
                        MessageContent::PeersetResponse(peerset),
                    );
                    peer.send_to(&message, &origin).await.unwrap();
                } else {
                    let inner_peerset = peer.peerset.inner.read().await;
                    let inner_without_origin = {
                        let mut t = inner_peerset.get_copy();
                        t.remove(&origin);
                        t
                    };
                    if inner_without_origin.is_empty() {
                        return Ok(());
                    }
                    let random_index = rand::thread_rng().gen_range(0..inner_without_origin.len());
                    let random_peer = inner_without_origin.iter().nth(random_index).unwrap();
                    let message = Message::new_direct_message(
                        &peer.address,
                        MessageContent::PeersetRelayRequest {
                            origin,
                            counter: counter - 1,
                        },
                    );
                    drop(inner_peerset);
                    peer.send_to(&message, random_peer).await?;
                }
            }
            PeersetResponse(ref other_peerset) => {
                let mut inner_peerset = peer.peerset.inner.write().await;
                if inner_peerset.len() >= MAX_PEERS - 1 {
                    return Ok(());
                }
                let copy = inner_peerset.get_copy();
                let mut difference: HashSet<_> = other_peerset.difference(&copy).collect();
                difference.remove(&peer.address);
                if difference.is_empty() {
                    return Ok(());
                }

                let random_index = rand::thread_rng().gen_range(0..difference.len());
                let random_peer = *(*difference.iter().nth(random_index).unwrap());

                inner_peerset.insert(random_peer);

                let message = Message::new_direct_message(&peer.address, MessageContent::AddMe);
                peer.establish_contact(&random_peer).await.unwrap();
                peer.send_to(&message, &random_peer).await.unwrap();

                drop(inner_peerset);
            }
            Heartbeat => {
                peer.heartbeat.update(from).await;
            }
        }

        if message.is_flood() {
            peer.broadcast_to_peerset(message).await;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct LoggingMessageHandlingStrategy;

impl MessageHandlingStrategy for LoggingMessageHandlingStrategy {
    async fn handle_message(
        peer: &Peer<impl MessageHandlingStrategy>,
        message: Message,
    ) -> Result<()> {
        println!(
            "{} got {:?} from {}",
            peer.address, message.content, message.from
        );
        DefaultMessageHandlingStrategy::handle_message(peer, message).await
    }
}
