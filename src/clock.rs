//! Injectable time.
//!
//! Everything in the library that depends on "how much time has passed"
//! (keepalive pings, dead-link detection, round-trip measurement) reads time
//! through the [`Clock`] trait instead of calling `Instant::now()` directly.
//! Production uses [`SystemClock`]. Tests can use [`ManualClock`] and move
//! time by hand, so a 30-second dead-link timeout is tested in microseconds
//! and deterministically (no sleeps, no flaky timing under CPU load).
//!
//! Time here is MONOTONIC and relative: a [`Duration`] since an arbitrary
//! origin. It is never a wall-clock date, so nothing in the protocol can
//! depend on the two peers' clocks agreeing, and a user changing their system
//! date cannot break liveness detection.
//!
//! What is deliberately NOT injected: the handshake timeout is enforced by
//! the OS socket read timeout (a kernel facility, not library code), and
//! randomness (see NOTES.md: RNG injection stays out of the public API
//! because a predictable RNG is a security hole, not a convenience).

use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A source of monotonic time and of waiting.
pub trait Clock: Send + Sync + Debug {
    /// Monotonic time since this clock's origin. Never goes backwards.
    fn now(&self) -> Duration;
    /// Wait roughly `d`. Background threads call this between checks.
    fn sleep(&self, d: Duration);
}

/// The real clock: [`Instant`] and [`std::thread::sleep`].
#[derive(Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub fn new() -> Self {
        SystemClock {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// A clock that only moves when told to, for tests.
///
/// `sleep` does NOT advance it: it yields for one real millisecond so a
/// polling background thread does not spin a core, then returns. The thread
/// therefore re-checks its conditions promptly after you call
/// [`ManualClock::advance`].
#[derive(Debug, Default)]
pub struct ManualClock {
    nanos: AtomicU64,
}

impl ManualClock {
    pub fn new() -> Arc<Self> {
        Arc::new(ManualClock::default())
    }

    /// Move time forward by `d`.
    pub fn advance(&self, d: Duration) {
        self.nanos.fetch_add(d.as_nanos() as u64, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
    fn sleep(&self, _d: Duration) {
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_moves_only_when_advanced() {
        let c = ManualClock::new();
        assert_eq!(c.now(), Duration::ZERO);
        c.sleep(Duration::from_secs(100));
        assert_eq!(c.now(), Duration::ZERO);
        c.advance(Duration::from_secs(5));
        assert_eq!(c.now(), Duration::from_secs(5));
    }

    #[test]
    fn system_clock_is_monotonic() {
        let c = SystemClock::new();
        let a = c.now();
        c.sleep(Duration::from_millis(2));
        assert!(c.now() > a);
    }
}
