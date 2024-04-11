use std::net::SocketAddr;

use crate::pippi::{message_handling::DefaultMessageHandlingStrategy, peer::Peer, PippiError};
use tokio::sync::mpsc::Sender;

use crate::ClientMessage;

struct NetworkActor {
    sending_channel: Sender<ClientMessage>,
    peer: Peer<DefaultMessageHandlingStrategy>,
}

impl NetworkActor {
    fn new(seed_addr: SocketAddr, addr: SocketAddr, sending_channel: Sender<ClientMessage>) -> Result<Self, PippiError> {
        let peer = Peer::new(addr, sending_channel.clone())?;
        Ok(Self {
            peer,
            sending_channel,
        })
    }
}

enum NetworkActorMessage {

}

#[derive(Clone)]
pub struct NetworkHandle {
    sender: Sender<NetworkActorMessage>,
}

impl NetworkHandle {
    pub fn new(client_tx: Sender<ClientMessage>, addr: SocketAddr) -> Self {
        todo!()
    }
}