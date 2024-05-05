use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use tokio::sync::RwLock;

use crate::pippi::writing_actor::WritingActorHandle;

use super::reading_actor::ReadingActorHandle;

#[derive(Debug, Clone)]
pub struct ConnectionMap {
    inner: Arc<RwLock<HashMap<SocketAddr, (ReadingActorHandle, WritingActorHandle)>>>,
}

impl Default for ConnectionMap {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionMap {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, key: SocketAddr, value: (ReadingActorHandle, WritingActorHandle)) {
        self.inner.write().await.insert(key, value);
    }

    pub async fn get(&self, key: &SocketAddr) -> Option<(ReadingActorHandle, WritingActorHandle)> {
        self.inner.read().await.get(key).cloned()
    }

    pub async fn remove(
        &self,
        key: &SocketAddr,
    ) -> Option<(ReadingActorHandle, WritingActorHandle)> {
        self.inner.write().await.remove(key)
    }

    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    pub async fn keys(&self) -> Vec<SocketAddr> {
        self.inner.read().await.keys().copied().collect()
    }

    pub(crate) async fn shutdown(&self) -> crate::pippi::Result<()> {
        let keys = self.keys().await;
        for key in keys {
            let (reading_actor, writing_actor) = self.remove(&key).await.unwrap();
            reading_actor.kill().await?;
            writing_actor.kill().await?;
        }
        Ok(())
    }

    // this is better than combining the other functions since this maintains the lock through the process
    pub async fn insert_if_not_present(
        &self,
        key: SocketAddr,
        value: (ReadingActorHandle, WritingActorHandle),
    ) {
        let mut inner = self.inner.write().await;
        inner.entry(key).or_insert(value);
    }
}
