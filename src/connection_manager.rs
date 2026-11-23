//! Direct connection admission control.
//!
//! The first architectural extraction from ws.rs: one scheduler owns how many
//! direct TCP/TLS handshakes can run, with a dedicated background quota so
//! pool preconnects cannot occupy every slot needed by real client sessions.
//! This does NOT change destinations, routing or transport protocols.

use once_cell::sync::Lazy;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub const MAX_PARALLEL_DIRECT_WS: usize = 4;
pub const MAX_BACKGROUND_DIRECT_WS: usize = 2;
pub const CLIENT_QUEUE_TIMEOUT: Duration = Duration::from_millis(1000);
pub const BACKGROUND_QUEUE_TIMEOUT: Duration = Duration::from_millis(2500);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialPurpose {
    Client,
    BackgroundPool,
}

impl DialPurpose {
    pub fn label(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::BackgroundPool => "pool",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Busy,
    Closed,
}

pub struct DialPermit {
    _global: OwnedSemaphorePermit,
    _background: Option<OwnedSemaphorePermit>,
}

pub struct ConnectionScheduler {
    global: Arc<Semaphore>,
    background: Arc<Semaphore>,
}

impl ConnectionScheduler {
    pub fn new(total: usize, background: usize) -> Self {
        assert!(total > 0 && background > 0 && background < total);
        Self {
            global: Arc::new(Semaphore::new(total)),
            background: Arc::new(Semaphore::new(background)),
        }
    }

    /// The same queue budget applies to both permits combined.
    /// Cancelled waiters do not consume permits; the RAII guard releases both.
    pub async fn acquire(
        &self,
        purpose: DialPurpose,
        max_wait: Duration,
    ) -> Result<DialPermit, AdmissionError> {
        let started = Instant::now();
        let background = if purpose == DialPurpose::BackgroundPool {
            let permit = tokio::time::timeout(
                max_wait,
                Arc::clone(&self.background).acquire_owned(),
            ).await;
            match permit {
                Ok(Ok(p)) => Some(p),
                Ok(Err(_)) => return Err(AdmissionError::Closed),
                Err(_) => return Err(AdmissionError::Busy),
            }
        } else {
            None
        };

        let remain = max_wait.saturating_sub(started.elapsed());
        let global = tokio::time::timeout(
            remain,
            Arc::clone(&self.global).acquire_owned(),
        ).await;
        let global = match global {
            Ok(Ok(p)) => p,
            Ok(Err(_)) => return Err(AdmissionError::Closed),
            Err(_) => return Err(AdmissionError::Busy),
        };

        Ok(DialPermit {
            _global: global,
            _background: background,
        })
    }

    pub fn available_global(&self) -> usize {
        self.global.available_permits()
    }
}

pub static DIRECT_SCHEDULER: Lazy<ConnectionScheduler> = Lazy::new(|| {
    ConnectionScheduler::new(MAX_PARALLEL_DIRECT_WS, MAX_BACKGROUND_DIRECT_WS)
});

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn background_pool_cannot_exhaust_client_capacity() {
        let scheduler = ConnectionScheduler::new(4, 2);
        let budget = Duration::from_millis(100);
        let _p1 = scheduler.acquire(DialPurpose::BackgroundPool, budget).await.unwrap();
        let _p2 = scheduler.acquire(DialPurpose::BackgroundPool, budget).await.unwrap();
        assert!(matches!(
            scheduler.acquire(DialPurpose::BackgroundPool, Duration::from_millis(15)).await,
            Err(AdmissionError::Busy)
        ));
        let _c1 = scheduler.acquire(DialPurpose::Client, budget).await.unwrap();
        let _c2 = scheduler.acquire(DialPurpose::Client, budget).await.unwrap();
        assert_eq!(scheduler.available_global(), 0);
    }

    #[tokio::test]
    async fn dropping_permits_restores_capacity() {
        let scheduler = ConnectionScheduler::new(3, 1);
        {
            let _p = scheduler
                .acquire(DialPurpose::BackgroundPool, Duration::from_millis(100))
                .await.unwrap();
            assert_eq!(scheduler.available_global(), 2);
        }
        assert_eq!(scheduler.available_global(), 3);
    }

    #[tokio::test]
    async fn client_saturation_is_not_a_network_timeout() {
        let scheduler = ConnectionScheduler::new(2, 1);
        let budget = Duration::from_millis(100);
        let _a = scheduler.acquire(DialPurpose::Client, budget).await.unwrap();
        let _b = scheduler.acquire(DialPurpose::Client, budget).await.unwrap();
        assert!(matches!(
            scheduler.acquire(DialPurpose::Client, Duration::from_millis(15)).await,
            Err(AdmissionError::Busy)
        ));
    }
}
