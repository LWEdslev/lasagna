use std::{collections::HashSet, net::SocketAddr};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ClientMessage, ExternalMessage};

pub(crate) mod connectionmap;
pub(crate) mod flooding_set_actor;
pub(crate) mod heartbeat;
pub mod message_handling;
pub mod network_analysis;
pub mod peer;
pub(crate) mod peerset;
pub(crate) mod reading_actor;
pub(crate) mod writing_actor;

const MAX_PEERS: usize = 10;
const PEER_WALK_DEPTH: u32 = 30;
const MESSAGE_LIFETIME: u128 = 2_000;

const THROTTLE_MESSAGES: u32 = 30; // we only handle 10 messages per second per connection
const THROTTLE_PERIOD: u128 = 1_000;

const MAX_CONNECTIONS: usize = 1000; // max connections we can have in our connection-map

#[derive(Debug, thiserror::Error)]
pub enum PippiError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Reading actor error")]
    ReadingActorError,
    #[error("Writing actor error")]
    WritingActorError,
    #[error("actor reply oneshot error {0}")]
    RecvActorError(#[from] tokio::sync::oneshot::error::RecvError),
    #[error("Not found")]
    NotFound,
    #[error("Heartbeat actor error")]
    HeartbeatError,
    #[error("actor send error")]
    ActorSendError,
    #[error("actor recv error")]
    ActorRecvError,
}

pub type Result<T> = std::result::Result<T, PippiError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BootstrapData {
    pub peers: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum MessageContent {
    Contact,
    AddMe,
    IDroppedYou(SocketAddr),
    AddMeAccepted(Option<SocketAddr>),
    PeersetRelayRequest { origin: SocketAddr, counter: u32 },
    PeersetResponse(HashSet<SocketAddr>),
    App(ExternalMessage),
    Heartbeat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    uuid: Option<Uuid>,
    content: MessageContent,
    from: SocketAddr,
}

impl Message {
    pub(crate) fn new_flood_message(from: &SocketAddr, content: MessageContent) -> Self {
        Self {
            uuid: Some(Uuid::new_v4()),
            content,
            from: *from,
        }
    }

    pub(crate) fn new_direct_message(from: &SocketAddr, content: MessageContent) -> Self {
        Self {
            uuid: None,
            content,
            from: *from,
        }
    }

    pub fn is_flood(&self) -> bool {
        self.uuid.is_some()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_string(&self)?
            .trim()
            .chars()
            .map(|c| c as _)
            .collect())
    }
}

fn get_unix_time() -> u128 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}
