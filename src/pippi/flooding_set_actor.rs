use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use tokio::{sync::RwLock, task::JoinHandle};
use uuid::Uuid;

use crate::pippi::MESSAGE_LIFETIME;

struct FloodingSetInner {
    queue: VecDeque<(Uuid, u128)>, // we can binary search on the timestamp so we can find all messages that are too old
    set: HashSet<Uuid>,            // we can check for existance in constant time
}

impl FloodingSetInner {
    /// O(1)
    fn add(&mut self, id: Uuid) {
        if self.set.insert(id) {
            let t = crate::pippi::get_unix_time();
            self.queue.push_front((id, t));
        }
    }

    /// O(1)
    fn contains(&self, id: &Uuid) -> bool {
        self.set.contains(id)
    }

    /// O(n)
    fn remove_all_dead(&mut self) {
        let target_time = crate::pippi::get_unix_time() - MESSAGE_LIFETIME; // all messages older than this are dead
        let r = self.queue.binary_search_by(|(_, time)| {
            // O(log(n))
            target_time.cmp(time)
        });
        let youngest_dead_i = match r {
            Ok(i) => i,
            Err(i) => i,
        };

        let deads = self.queue.split_off(youngest_dead_i);

        for (dead, _) in deads.into_iter() {
            self.set.remove(&dead); // O(1) done n times so O(n)
        }
    }
}

#[derive(Clone)]
pub struct FloodingSetHandle {
    inner: Arc<RwLock<FloodingSetInner>>,
    _delete_handle: Arc<JoinHandle<()>>,
}

impl Default for FloodingSetHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl FloodingSetHandle {
    pub fn new() -> Self {
        let inner = FloodingSetInner {
            queue: VecDeque::new(),
            set: HashSet::new(),
        };
        let inner = Arc::new(RwLock::new(inner));

        let handle = {
            let inner = inner.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(1_000)).await;
                    inner.write().await.remove_all_dead();
                }
            })
        };

        let handle = Arc::new(handle);

        Self {
            inner,
            _delete_handle: handle,
        }
    }

    pub async fn add(&self, id: Uuid) {
        self.inner.write().await.add(id);
    }

    pub async fn contains(&self, id: &Uuid) -> bool {
        self.inner.read().await.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auto_remove() {
        let set = FloodingSetHandle::new();
        let id = Uuid::new_v4();
        set.inner.write().await.add(id);
        assert!(set.inner.read().await.contains(&id));
        tokio::time::sleep(Duration::from_millis(MESSAGE_LIFETIME as u64 + 10)).await;
        assert!(!set.inner.read().await.contains(&id));
    }

    #[tokio::test]
    async fn only_some_are_removed() {
        let set = FloodingSetHandle::new();
        let id = Uuid::new_v4();
        set.inner.write().await.add(id);
        assert!(set.inner.read().await.contains(&id));
        tokio::time::sleep(Duration::from_millis(MESSAGE_LIFETIME as u64 / 2)).await;
        set.inner.write().await.add(Uuid::new_v4());
        tokio::time::sleep(Duration::from_millis(MESSAGE_LIFETIME as u64 / 2 + 10)).await;
        assert!(!set.inner.read().await.contains(&id));
    }

    #[tokio::test]
    async fn inner_test() {
        let mut inner = FloodingSetInner {
            queue: VecDeque::new(),
            set: HashSet::new(),
        };
        let id = Uuid::new_v4();
        inner.add(id);
        inner.add(Uuid::new_v4());
        assert!(inner.contains(&id));
        tokio::time::sleep(Duration::from_millis(MESSAGE_LIFETIME as u64 + 10)).await;
        inner.remove_all_dead();
        assert!(!inner.contains(&id));
    }
}
