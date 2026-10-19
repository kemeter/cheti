//! Teardown of challenge material that survives cancellation.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

type CleanupFn<T> = Arc<dyn Fn(T) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Tracks what a solver has put in place and must take down.
///
/// The solver calls [`run`](Self::run) on every path it controls. If the
/// solving future is dropped first (a caller-side `timeout`, a `select!`, a
/// shutdown), whatever is still pending is cleaned up from `Drop` on a task
/// spawned on the current Tokio runtime. That task is best-effort: it does not
/// run if there is no runtime, or if the runtime shuts down before it does.
pub(crate) struct CleanupGuard<T: Clone + Send + 'static> {
    pending: Vec<T>,
    cleanup: CleanupFn<T>,
}

impl<T: Clone + Send + 'static> CleanupGuard<T> {
    pub(crate) fn new<F, Fut>(cleanup: F) -> Self
    where
        F: Fn(T) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self {
            pending: Vec::new(),
            cleanup: Arc::new(move |item| Box::pin(cleanup(item))),
        }
    }

    pub(crate) fn push(&mut self, item: T) {
        self.pending.push(item);
    }

    pub(crate) fn pending(&self) -> &[T] {
        &self.pending
    }

    /// Cleans up every pending item, in order. An item leaves the list only
    /// once its cleanup has completed, so a drop in the middle hands the
    /// in-flight item and the rest over to `Drop`.
    pub(crate) async fn run(&mut self) {
        while let Some(item) = self.pending.first().cloned() {
            (self.cleanup)(item).await;
            self.pending.remove(0);
        }
    }
}

impl<T: Clone + Send + 'static> Drop for CleanupGuard<T> {
    fn drop(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let pending = std::mem::take(&mut self.pending);
        let cleanup = self.cleanup.clone();
        runtime.spawn(async move {
            for item in pending {
                cleanup(item).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Duration;

    use super::*;

    fn recording_guard() -> (CleanupGuard<u32>, Arc<Mutex<Vec<u32>>>) {
        let cleaned = Arc::new(Mutex::new(Vec::new()));
        let sink = cleaned.clone();
        let guard = CleanupGuard::new(move |item: u32| {
            let sink = sink.clone();
            async move { sink.lock().unwrap().push(item) }
        });
        (guard, cleaned)
    }

    #[tokio::test]
    async fn run_cleans_every_item_in_order_and_empties_the_guard() {
        let (mut guard, cleaned) = recording_guard();
        guard.push(1);
        guard.push(2);
        guard.run().await;
        assert!(guard.pending().is_empty());
        drop(guard);
        tokio::task::yield_now().await;
        assert_eq!(*cleaned.lock().unwrap(), vec![1, 2]);
    }

    #[tokio::test]
    async fn dropping_with_pending_items_spawns_their_cleanup() {
        let (mut guard, cleaned) = recording_guard();
        guard.push(7);
        guard.push(8);
        drop(guard);
        tokio::time::timeout(Duration::from_secs(1), async {
            while cleaned.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("spawned cleanup did not run");
        assert_eq!(*cleaned.lock().unwrap(), vec![7, 8]);
    }

    #[test]
    fn dropping_outside_a_runtime_does_not_panic() {
        let (mut guard, cleaned) = recording_guard();
        guard.push(1);
        drop(guard);
        assert!(cleaned.lock().unwrap().is_empty());
    }
}
