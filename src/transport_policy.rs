//! Failure classification separated from transport/routing implementation.
//! A saturated *local* admission queue must not damage remote DC reputation.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectFailure {
    LocalCapacity,
    NetworkTimeout,
    AllRedirects,
    RemoteFailure,
}

impl DirectFailure {
    pub fn classify(
        locally_busy: bool,
        timed_out: bool,
        saw_redirect: bool,
        all_redirects: bool,
    ) -> Self {
        if locally_busy {
            return Self::LocalCapacity;
        }
        if timed_out {
            return Self::NetworkTimeout;
        }
        if saw_redirect && all_redirects {
            return Self::AllRedirects;
        }
        Self::RemoteFailure
    }

    pub fn penalize_dc(self) -> bool {
        matches!(self, Self::NetworkTimeout | Self::RemoteFailure)
    }

    pub fn penalize_ip(self) -> bool {
        matches!(self, Self::NetworkTimeout)
    }

    pub fn blacklist_for_redirect(self) -> bool {
        matches!(self, Self::AllRedirects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_queue_exhaustion_never_creates_cooldown() {
        let failure = DirectFailure::classify(true, false, false, false);
        assert_eq!(failure, DirectFailure::LocalCapacity);
        assert!(!failure.penalize_ip());
        assert!(!failure.penalize_dc());
        assert!(!failure.blacklist_for_redirect());
    }

    #[test]
    fn observed_network_timeout_uses_network_penalty() {
        let failure = DirectFailure::classify(false, true, false, true);
        assert_eq!(failure, DirectFailure::NetworkTimeout);
        assert!(failure.penalize_dc());
        assert!(failure.penalize_ip());
    }

    #[test]
    fn only_redirects_trigger_redirect_blacklist() {
        let failure = DirectFailure::classify(false, false, true, true);
        assert!(failure.blacklist_for_redirect());
        assert!(!failure.penalize_dc());
        assert!(!failure.penalize_ip());
    }

    #[test]
    fn busy_after_redirect_is_not_an_all_redirect_result() {
        let failure = DirectFailure::classify(true, false, true, false);
        assert_eq!(failure, DirectFailure::LocalCapacity);
    }

    #[test]
    fn non_redirect_error_gets_dc_but_no_ip_penalty() {
        let failure = DirectFailure::classify(false, false, true, false);
        assert_eq!(failure, DirectFailure::RemoteFailure);
        assert!(failure.penalize_dc());
        assert!(!failure.penalize_ip());
    }
}
