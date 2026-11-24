//! Experimental Cloudflare media retry guard.
//! Limits repeated unsuccessful media attempts without affecting ordinary CF.
//! A tiny, short-lived upstream session is only a heuristic for a failed route.

use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

pub const MEDIA_CF_CONCURRENT_PER_DC: usize = 2;
pub const MEDIA_CF_COOLDOWN_START_SECS: f64 = 30.0;
pub const MEDIA_CF_COOLDOWN_MAX_SECS: f64 = 120.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateReject {
    Saturated,
    Cooldown,
}

#[derive(Default)]
struct Slot {
    active: usize,
    consecutive_failures: u32,
    cooldown_until: f64,
}

#[derive(Default)]
pub struct MediaCfGate {
    slots: Mutex<HashMap<i32, Slot>>,
    generation: AtomicU64,
}

pub static MEDIA_CF_GATE: Lazy<MediaCfGate> = Lazy::new(MediaCfGate::default);

pub fn suspicious_media_cf_end(elapsed: f64, down_bytes: i64, close_reason: &str) -> bool {
    if !elapsed.is_finite() || elapsed < 0.0 || down_bytes < 0 {
        return false;
    }
    // A short and almost-empty session is suspicious even when its close is
    // reported as normal. Keep this existing conservative heuristic.
    let early_empty = elapsed < 5.0 && down_bytes < 1024 &&
        (close_reason.starts_with("upstream:") || close_reason == "normal");

    // On mobile, a CF media socket may remain open for 20-30 seconds, receive
    // only a MTProto header, then die with an EOF. Time alone must not mark it
    // healthy: the diagnostic trace showed 1291 bytes in 25 seconds before EOF.
    // A long *normal* idle close is not classified as failure here.
    let upstream_eof = close_reason.starts_with("upstream: io:UnexpectedEof") ||
        close_reason.starts_with("upstream: io:ConnectionReset");
    early_empty || (upstream_eof && down_bytes < 4096)
}

pub fn cooldown_seconds(failures: u32) -> f64 {
    let shift = failures.saturating_sub(1).min(8);
    (MEDIA_CF_COOLDOWN_START_SECS * 2_f64.powi(shift as i32))
        .min(MEDIA_CF_COOLDOWN_MAX_SECS)
}

impl MediaCfGate {
    pub fn acquire(&self, dc: i32, now: f64) -> Result<MediaCfPermit<'_>, (GateReject, u64)> {
        let mut states = self.slots.lock();
        let slot = states.entry(dc).or_default();
        if now < slot.cooldown_until {
            return Err((GateReject::Cooldown, ((slot.cooldown_until - now) * 1000.0) as u64));
        }
        if slot.active >= MEDIA_CF_CONCURRENT_PER_DC {
            return Err((GateReject::Saturated, 0));
        }
        slot.active += 1;
        Ok(MediaCfPermit {
            gate: self,
            dc,
            generation: self.generation.load(Ordering::SeqCst),
            completed: false,
        })
    }

    pub fn reset(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.slots.lock().clear();
    }
}

pub struct MediaCfPermit<'a> {
    gate: &'a MediaCfGate,
    dc: i32,
    generation: u64,
    completed: bool,
}

impl MediaCfPermit<'_> {
    /// Returns the new cooldown, in seconds. Success clears prior failures.
    pub fn finish(&mut self, now: f64, failed: bool) -> f64 {
        if self.completed { return 0.0; }
        self.completed = true;
        if self.generation != self.gate.generation.load(Ordering::SeqCst) {
            return 0.0;
        }
        let mut slots = self.gate.slots.lock();
        let state = slots.entry(self.dc).or_default();
        if failed {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            let cooldown = cooldown_seconds(state.consecutive_failures);
            state.cooldown_until = state.cooldown_until.max(now + cooldown);
            cooldown
        } else {
            state.consecutive_failures = 0;
            state.cooldown_until = 0.0;
            0.0
        }
    }
}

impl Drop for MediaCfPermit<'_> {
    fn drop(&mut self) {
        if self.generation != self.gate.generation.load(Ordering::SeqCst) {
            return;
        }
        let mut slots = self.gate.slots.lock();
        if let Some(state) = slots.get_mut(&self.dc) {
            state.active = state.active.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_short_session_is_only_heuristic() {
        assert!(suspicious_media_cf_end(0.1, 24, "upstream: io:UnexpectedEof"));
        assert!(!suspicious_media_cf_end(0.3, 500000, "upstream: io:ConnectionReset"));
        assert!(suspicious_media_cf_end(10.0, 24, "upstream: io:UnexpectedEof"));
        assert!(suspicious_media_cf_end(25.5, 1291, "upstream: io:UnexpectedEof:os=None"));
        assert!(!suspicious_media_cf_end(26.0, 1532, "normal"));
        assert!(!suspicious_media_cf_end(25.5, 70000, "upstream: io:UnexpectedEof:os=None"));
        assert!(!suspicious_media_cf_end(f64::NAN, 0, "upstream: io:UnexpectedEof"));
    }

    #[test]
    fn cooldown_is_exponential_and_bounded() {
        assert_eq!(cooldown_seconds(1), 30.0);
        assert_eq!(cooldown_seconds(2), 60.0);
        assert_eq!(cooldown_seconds(3), 120.0);
        assert_eq!(cooldown_seconds(10), 120.0);
    }

    #[test]
    fn limits_simultaneous_media_attempts_per_dc() {
        let gate = MediaCfGate::default();
        let a = gate.acquire(2, 10.0).unwrap();
        let b = gate.acquire(2, 10.0).unwrap();
        assert!(matches!(gate.acquire(2, 10.0), Err((GateReject::Saturated, 0))));
        let _other_dc = gate.acquire(4, 10.0).unwrap();
        drop(a);
        let _third = gate.acquire(2, 11.0).unwrap();
        drop(b);
    }

    #[test]
    fn failure_cools_off_new_attempts_and_reset_clears_gate() {
        let gate = MediaCfGate::default();
        let mut permit = gate.acquire(2, 10.0).unwrap();
        assert_eq!(permit.finish(11.0, true), 30.0);
        drop(permit);
        assert!(matches!(gate.acquire(2, 15.0), Err((GateReject::Cooldown, _))));
        gate.reset();
        assert!(gate.acquire(2, 15.0).is_ok());
    }

    #[test]
    fn successful_attempt_resets_failure_history() {
        let gate = MediaCfGate::default();
        let mut p = gate.acquire(2, 0.0).unwrap();
        p.finish(1.0, true);
        drop(p);
        let mut good = gate.acquire(2, 32.0).unwrap();
        good.finish(33.0, false);
        drop(good);
        let mut bad = gate.acquire(2, 34.0).unwrap();
        assert_eq!(bad.finish(35.0, true), 30.0);
    }
}
