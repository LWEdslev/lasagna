use std::net::SocketAddr;

use crate::{
    block::Block,
    blockchain::Blockchain,
    pippi::{message_handling::DefaultMessageHandlingStrategy, peer::Peer, PippiError},
    transaction::Transaction,
    ExternalMessage, Error,
};
use tokio::sync::mpsc::Sender;

use crate::ClientMessage;

struct NetworkActor {
    seed_addr: SocketAddr,
    peer: Peer<DefaultMessageHandlingStrategy>,
}

impl NetworkActor {
    /// If we are the seed node set seed_addr = addr
    async fn new(
        seed_addr: SocketAddr,
        addr: SocketAddr,
        sending_channel: Sender<ClientMessage>,
    ) -> Result<Self, PippiError> {
        let peer = Peer::new(addr, sending_channel)?;
        if addr != seed_addr {
            peer.join_network(&seed_addr).await?;
        }
        Ok(Self { seed_addr, peer })
    }

    async fn handle_message(&mut self, msg: NetworkActorMessage) {
        use NetworkActorMessage::*;
        match msg {
            RequestBootstrap => {
                self.peer
                    .send_direct_client_message(
                        self.seed_addr,
                        ExternalMessage::BootstrapReqFrom(self.peer.address),
                    )
                    .await;
            }
            BroadcastBlock(block) => {
                self.peer
                    .flood(ExternalMessage::BroadcastBlock(block))
                    .await;
            }
            Bootstrap(to, blockchain) => {
                self.peer
                    .send_direct_client_message(to, ExternalMessage::Bootstrap(blockchain))
                    .await;
            }
            BroadcastTransaction(t) => {
                self.peer
                    .flood(ExternalMessage::BroadcastTransaction(t))
                    .await;
            }
        }
    }
}

enum NetworkActorMessage {
    RequestBootstrap,
    BroadcastBlock(Block),
    BroadcastTransaction(Transaction),
    Bootstrap(SocketAddr, Blockchain),
}

#[derive(Clone)]
pub struct NetworkHandle {
    sender: Sender<NetworkActorMessage>,
}

impl NetworkHandle {
    /// If we are creating the network set seed_addr = addr
    pub fn new(seed_addr: SocketAddr, addr: SocketAddr, client_tx: Sender<ClientMessage>) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(100);
        tokio::spawn(async move {
            let mut actor = NetworkActor::new(seed_addr, addr, client_tx).await.unwrap();
            while let Some(msg) = receiver.recv().await {
                actor.handle_message(msg).await
            }
        });

        Self { sender }
    }

    pub async fn request_bootstrap(&self) -> crate::Result<()> {
        self.sender
            .send(NetworkActorMessage::RequestBootstrap)
            .await
            .map_err(|_| Error::NetworkError)
    }

    pub async fn broadcast_block(&self, block: Block) -> crate::Result<()> {
        self.sender
            .send(NetworkActorMessage::BroadcastBlock(block))
            .await
            .map_err(|_| Error::NetworkError)
    }

    pub async fn send_bootstraping_message_to(
        &self,
        to: SocketAddr,
        blockchain: Blockchain,
    ) -> crate::Result<()> {
        self.sender
            .send(NetworkActorMessage::Bootstrap(to, blockchain))
            .await
            .map_err(|_| Error::NetworkError)
    }

    pub async fn broadcast_transaction(
        &self,
        transaction: crate::transaction::Transaction,
    ) -> crate::Result<()> {
        self.sender
            .send(NetworkActorMessage::BroadcastTransaction(transaction))
            .await
            .map_err(|_| Error::NetworkError)
    }
}
