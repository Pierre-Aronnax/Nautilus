#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::Mutex;
    use mdns::BackoffState;
    /// Helper struct to mock the backoff manager.
    struct MockBackoff {
        state: Mutex<BackoffState>,
        advertise_interval: AtomicU64,
        query_interval: AtomicU64,
    }

    impl MockBackoff {
        /// Create a new MockBackoff instance with default settings.
        fn new() -> Self {
            Self {
                state: Mutex::new(BackoffState::Normal),
                advertise_interval: AtomicU64::new(5),
                query_interval: AtomicU64::new(5),
            }
        }

        /// Simulate the adjust_backoff_state function behavior.
        async fn adjust_backoff_state(&self) {
            let state = self.state.lock().await;
            let current_advertise = self.advertise_interval.load(Ordering::Relaxed);
            let current_query = self.query_interval.load(Ordering::Relaxed);

            match *state {
                BackoffState::Normal => {
                    self.advertise_interval.store(5, Ordering::Relaxed);
                    self.query_interval.store(5, Ordering::Relaxed);
                }
                BackoffState::Backoff => {
                    let new_advertise = (current_advertise as f64 * 1.5).min(60.0) as u64;
                    let new_query = (current_query as f64 * 1.5).min(60.0) as u64;
                    self.advertise_interval.store(new_advertise, Ordering::Relaxed);
                    self.query_interval.store(new_query, Ordering::Relaxed);
                }
                BackoffState::Recovery => {
                    let new_advertise = (current_advertise as f64 / 1.5).max(5.0) as u64;
                    let new_query = (current_query as f64 / 1.5).max(5.0) as u64;
                    self.advertise_interval.store(new_advertise, Ordering::Relaxed);
                    self.query_interval.store(new_query, Ordering::Relaxed);
                }
                BackoffState::Stable => {
                    self.advertise_interval.store(10, Ordering::Relaxed);
                    self.query_interval.store(10, Ordering::Relaxed);
                }
            }

            // Ensure query interval never exceeds 2x advertise interval
            let adjusted_query = self.query_interval.load(Ordering::Relaxed);
            let adjusted_advertise = self.advertise_interval.load(Ordering::Relaxed);
            if adjusted_query > 2 * adjusted_advertise {
                self.query_interval
                    .store(2 * adjusted_advertise, Ordering::Relaxed);
            }
        }
    }

    /// ✅ Test that the initial state is `Normal` with correct default intervals.
    #[tokio::test]
    async fn test_initial_state() {
        let backoff = MockBackoff::new();
        let state = backoff.state.lock().await;

        assert_eq!(*state, BackoffState::Normal);
        assert_eq!(backoff.advertise_interval.load(Ordering::Relaxed), 5);
        assert_eq!(backoff.query_interval.load(Ordering::Relaxed), 5);
    }

    /// ✅ Test transition from `Normal` to `Backoff` and verify interval increase.
    #[tokio::test]
    async fn test_normal_to_backoff() {
        let backoff = MockBackoff::new();

        {
            let mut state = backoff.state.lock().await;
            *state = BackoffState::Backoff; // Simulate entering Backoff state
        }

        backoff.adjust_backoff_state().await;

        assert!(backoff.advertise_interval.load(Ordering::Relaxed) > 5);
        assert!(backoff.query_interval.load(Ordering::Relaxed) > 5);
    }

    /// ✅ Test transition from `Backoff` to `Recovery` and verify interval decrease.
    #[tokio::test]
    async fn test_backoff_to_recovery() {
        let backoff = MockBackoff::new();

        {
            let mut state = backoff.state.lock().await;
            *state = BackoffState::Backoff; // Enter Backoff first
        }

        backoff.adjust_backoff_state().await;

        {
            let mut state = backoff.state.lock().await;
            *state = BackoffState::Recovery; // Move to Recovery
        }

        backoff.adjust_backoff_state().await;

        assert!(backoff.advertise_interval.load(Ordering::Relaxed) < 60);
        assert!(backoff.query_interval.load(Ordering::Relaxed) < 60);
    }

    /// ✅ Test transition from `Recovery` to `Stable`.
    #[tokio::test]
    async fn test_recovery_to_stable() {
        let backoff = MockBackoff::new();

        {
            let mut state = backoff.state.lock().await;
            *state = BackoffState::Recovery; // Start in Recovery state
        }

        backoff.adjust_backoff_state().await;

        {
            let mut state = backoff.state.lock().await;
            *state = BackoffState::Stable; // Move to Stable
        }

        backoff.adjust_backoff_state().await;

        assert_eq!(backoff.advertise_interval.load(Ordering::Relaxed), 10);
        assert_eq!(backoff.query_interval.load(Ordering::Relaxed), 10);
    }

    /// ✅ Ensure the query interval never exceeds 2x the advertise interval.
    #[tokio::test]
    async fn test_query_interval_limit() {
        let backoff = MockBackoff::new();

        {
            let mut state = backoff.state.lock().await;
            *state = BackoffState::Backoff;
        }

        backoff.advertise_interval.store(10, Ordering::Relaxed);
        backoff.query_interval.store(30, Ordering::Relaxed); // Set too high on purpose

        backoff.adjust_backoff_state().await;

        let adjusted_query = backoff.query_interval.load(Ordering::Relaxed);
        let adjusted_advertise = backoff.advertise_interval.load(Ordering::Relaxed);

        assert!(adjusted_query <= 2 * adjusted_advertise);
    }
}
