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

/// Time limit for reusing an *idle* websocket. We cannot safely probe
/// the TLS stream with an application read: it might consume live relay data.
/// A short media lifetime reduces the stale-socket window without touching
/// active media sessions or sending extra protocol frames.
pub const MEDIA_IDLE_REUSE_MAX_SECS: f64 = 8.0;
pub const REGULAR_IDLE_REUSE_MAX_SECS: f64 = 45.0;

pub fn idle_reuse_max_secs(is_media: bool) -> f64 {
    if is_media { MEDIA_IDLE_REUSE_MAX_SECS } else { REGULAR_IDLE_REUSE_MAX_SECS }
}

pub fn pool_entry_reusable(age_secs: f64, is_media: bool, locally_closed: bool) -> bool {
    !locally_closed && age_secs.is_finite() &&
        age_secs >= 0.0 && age_secs < idle_reuse_max_secs(is_media)
}

/// Separate short upstream failures from normal/complete transfers.
/// This is a diagnostic heuristic, NOT proof of a stale pooled socket.
pub fn early_upstream_close(elapsed_secs: f64, down_bytes: i64, close_reason: &str) -> bool {
    elapsed_secs.is_finite()
        && elapsed_secs >= 0.0
        && elapsed_secs < 2.0
        && down_bytes < 64
        && (close_reason.starts_with("upstream: io:")
            || close_reason.starts_with("upstream: remote_close:")
            || close_reason == "upstream: send_failed")
}

/// Never treat local saturation as a remote failure. The caller stores only
/// confirmed network timeout cooldowns; this function checks expiry.
pub fn target_cooldown_remaining_secs(now: f64, until: Option<f64>) -> f64 {
    until.map(|u| (u - now).max(0.0)).unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_media_expires_before_regular_and_closed_is_never_reused() {
        assert!(pool_entry_reusable(5.0, true, false));
        assert!(!pool_entry_reusable(11.4, true, false));
        assert!(pool_entry_reusable(11.4, false, false));
        assert!(!pool_entry_reusable(1.0, false, true));
        assert!(!pool_entry_reusable(f64::NAN, true, false));
    }

    #[test]
    fn early_eof_detector_does_not_flag_useful_transfers_or_normal_close() {
        assert!(early_upstream_close(0.1, 24, "upstream: io:UnexpectedEof:os=None"));
        assert!(!early_upstream_close(0.4, 148901, "upstream: io:ConnectionReset"));
        assert!(!early_upstream_close(0.1, 24, "normal"));
        assert!(!early_upstream_close(2.1, 24, "upstream: io:UnexpectedEof"));
    }

    #[test]
    fn target_cooldown_is_time_limited() {
        assert_eq!(target_cooldown_remaining_secs(100.0, Some(130.0)), 30.0);
        assert_eq!(target_cooldown_remaining_secs(140.0, Some(130.0)), 0.0);
        assert_eq!(target_cooldown_remaining_secs(140.0, None), 0.0);
    }

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
