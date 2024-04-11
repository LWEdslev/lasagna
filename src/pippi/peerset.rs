use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use rand::Rng;
use tokio::sync::RwLock;

use crate::pippi::MAX_PEERS;

const STATIC_SET_SIZE: usize = MAX_PEERS / 2;

#[derive(Clone)]
pub struct PeersetInner {
    static_set: HashSet<SocketAddr>,
    dynamic_set: HashSet<SocketAddr>,
}

impl PeersetInner {
    fn empty() -> Self {
        Self {
            static_set: HashSet::new(),
            dynamic_set: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.static_set.len() + self.dynamic_set.len()
    }

    pub fn contains(&self, peer: &SocketAddr) -> bool {
        self.static_set.contains(peer) || self.dynamic_set.contains(peer)
    }

    pub fn insert(&mut self, peer: SocketAddr) {
        if self.contains(&peer) {
            return;
        }
        if self.static_set.len() >= STATIC_SET_SIZE {
            self.dynamic_set.insert(peer);
        } else {
            self.static_set.insert(peer);
        }
    }

    pub fn remove(&mut self, peer: &SocketAddr) {
        if self.static_set.remove(peer) {
            self.update()
        };
        self.dynamic_set.remove(peer);
    }

    pub fn replace(&mut self, to_add: SocketAddr, to_remove: &SocketAddr) {
        self.remove(to_remove);
        self.insert(to_add);
    }

    pub fn update(&mut self) {
        if self.static_set.len() < STATIC_SET_SIZE && !self.dynamic_set.is_empty() {
            let from_dyn = *self.dynamic_set.iter().next().unwrap();
            assert!(self.dynamic_set.remove(&from_dyn));
            self.static_set.insert(from_dyn);
        }
    }

    pub fn get_copy(&self) -> HashSet<SocketAddr> {
        self.dynamic_set.union(&self.static_set).cloned().collect()
    }

    pub fn random_from_dynamic(&self) -> Option<SocketAddr> {
        if self.dynamic_set.is_empty() {
            return None;
        };
        let random_index = rand::thread_rng().gen_range(0..self.dynamic_set.len());
        let random_peer = self
            .dynamic_set
            .iter()
            .nth(random_index)
            .expect("unreachable");
        Some(*random_peer)
    }
}

#[derive(Clone)]
pub struct Peerset {
    pub inner: Arc<RwLock<PeersetInner>>,
}

impl Peerset {
    pub fn empty() -> Self {
        Self {
            inner: Arc::new(RwLock::new(PeersetInner::empty())),
        }
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn add_peer(&self, peer: SocketAddr) {
        let mut inner = self.inner.write().await;
        if inner.len() < MAX_PEERS {
            inner.insert(peer);
        }
    }

    pub async fn replace(&self, to_remove: SocketAddr, to_add: SocketAddr) {
        let mut inner = self.inner.write().await;
        inner.remove(&to_remove);
        inner.insert(to_add);
    }

    pub async fn remove(&self, peer: &SocketAddr) {
        self.inner.write().await.remove(peer);
    }

    pub async fn get_copy(&self) -> HashSet<SocketAddr> {
        self.inner.read().await.get_copy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn add_len() {
        let set = Peerset::empty();
        assert_eq!(set.len().await, 0);
        let p1 = "127.0.0.1:8080".parse().unwrap();
        set.add_peer(p1).await;
        assert_eq!(set.len().await, 1);
    }

    #[tokio::test]
    async fn replace() {
        let set = Peerset::empty();
        let p1 = "127.0.0.1:8080".parse().unwrap();
        let p2 = "127.0.0.1:8081".parse().unwrap();
        set.add_peer(p1).await;
        set.replace(p1, p2).await;
        assert_eq!(set.len().await, 1);
        assert!(set.get_copy().await.contains(&p2));
    }
}
