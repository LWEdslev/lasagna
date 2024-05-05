use std::{collections::HashMap, net::SocketAddr};

use tokio::sync::oneshot;

pub const HEARTBEAT: u64 = 2_000;
const DEAD: u128 = 6_200;

struct HeartbeatActor {
    map: HashMap<SocketAddr, u128>,
}

impl HeartbeatActor {
    fn update(&mut self, peer: SocketAddr) {
        let timestamp = crate::pippi::get_unix_time();
        self.map.insert(peer, timestamp);
    }

    fn take_dead(&mut self) -> Vec<SocketAddr> {
        let curr_time = crate::pippi::get_unix_time();
        
        self
            .map
            .clone()
            .into_iter()
            .filter(|&(_peer, ts)| (ts + DEAD < curr_time)).map(|(peer, _ts)| {
                    self.map.remove_entry(&peer);
                    peer
                })
            .collect()
    }

    async fn handle_message(&mut self, msg: HeartbeatActorMessage) {
        match msg {
            HeartbeatActorMessage::Update(peer) => self.update(peer),
            HeartbeatActorMessage::TakeDead(reply_to) => reply_to.send(self.take_dead()).unwrap(),
        }
    }
}

enum HeartbeatActorMessage {
    Update(SocketAddr),
    TakeDead(oneshot::Sender<Vec<SocketAddr>>),
}

#[derive(Clone)]
pub struct HeartbeatHandle {
    sender: tokio::sync::mpsc::Sender<HeartbeatActorMessage>,
}

impl HeartbeatHandle {
    pub fn new() -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(100);
        tokio::spawn(async move {
            let mut actor = HeartbeatActor {
                map: HashMap::new(),
            };
            while let Some(msg) = receiver.recv().await {
                actor.handle_message(msg).await;
            }
        });
        Self { sender }
    }

    pub async fn update(&self, peer: SocketAddr) {
        self.sender
            .send(HeartbeatActorMessage::Update(peer))
            .await
            .unwrap();
    }

    pub async fn take_dead(&self) -> Vec<SocketAddr> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(HeartbeatActorMessage::TakeDead(sender))
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time;

    #[tokio::test]
    async fn heartbeat() {
        let handle = HeartbeatHandle::new();
        let peer = "127.0.0.1:8080".parse().unwrap();
        handle.update(peer).await;
        time::sleep(Duration::from_millis(DEAD as u64 + 5)).await;
        let deads = handle.take_dead().await;
        assert_eq!(deads.len(), 1);

        time::sleep(Duration::from_millis(DEAD as u64 + 5)).await;
        let deads = handle.take_dead().await;
        assert_eq!(deads.len(), 0);
    }

    #[tokio::test]
    async fn heartbeat_multiple() {
        let handle = HeartbeatHandle::new();
        let peer = "127.0.0.1:8080".parse().unwrap();
        let peer2 = "127.0.0.1:8081".parse().unwrap();
        handle.update(peer).await;
        handle.update(peer2).await;
        time::sleep(Duration::from_millis(DEAD as u64 + 5)).await;
        let deads = handle.take_dead().await;
        assert_eq!(deads.len(), 2);
    }

    #[tokio::test]
    async fn heartbeat_multiple_async() {
        let handle = HeartbeatHandle::new();
        let peer = "127.0.0.1:8080".parse().unwrap();
        let peer2 = "127.0.0.1:8081".parse().unwrap();
        handle.update(peer).await;
        time::sleep(Duration::from_millis(DEAD as u64 / 2 + 5)).await;
        handle.update(peer2).await;
        time::sleep(Duration::from_millis(DEAD as u64 / 2 + 5)).await;
        let deads = handle.take_dead().await;
        assert_eq!(deads.len(), 1);
        time::sleep(Duration::from_millis(DEAD as u64 / 2 + 5)).await;
        let deads = handle.take_dead().await;
        assert_eq!(deads.len(), 1);
        time::sleep(Duration::from_millis(DEAD as u64 / 2 + 5)).await;
        let deads = handle.take_dead().await;
        assert_eq!(deads.len(), 0);
    }
}
