//! Policy for keeping speculative pool dial work bounded on slow networks.
//! The protocol and route selection stay unchanged.

pub const MAX_POOL_REFILL_BATCH: usize = 2;
pub const POOL_BACKOFF_START_SECS: f64 = 5.0;

pub fn refill_batch_size(needed: usize) -> usize {
    needed.min(MAX_POOL_REFILL_BATCH)
}

pub fn refill_backoff_secs(failures: u32, configured_max: f64) -> f64 {
    let shift = failures.saturating_sub(1).min(12);
    (POOL_BACKOFF_START_SECS * 2_f64.powi(shift as i32)).min(configured_max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refill_is_bounded_even_when_pool_is_empty() {
        assert_eq!(refill_batch_size(0), 0);
        assert_eq!(refill_batch_size(1), 1);
        assert_eq!(refill_batch_size(4), 2);
        assert_eq!(refill_batch_size(16), 2);
    }

    #[test]
    fn failed_refill_backs_off_and_caps() {
        assert_eq!(refill_backoff_secs(1, 120.0), 5.0);
        assert_eq!(refill_backoff_secs(2, 120.0), 10.0);
        assert_eq!(refill_backoff_secs(3, 120.0), 20.0);
        assert_eq!(refill_backoff_secs(6, 120.0), 120.0);
        assert_eq!(refill_backoff_secs(100, 120.0), 120.0);
    }
}
