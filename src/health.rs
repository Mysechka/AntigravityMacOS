//! Whether a route is worth sending traffic down right now.
//!
//! Every route this tool can take goes through some third party, and third
//! parties fail: on 2026-08-25 the relay accepted tunnels for an hour and cut
//! every one of them at the handshake. A route that cannot be told to stand
//! aside fails *every* request, because past `200 Connection Established` there
//! is no way back for a connection already handed to a client.
//!
//! So each route carries one of these. Two failures in a row bench it, the bench
//! doubles while it stays down, and a probe on the warm loop - never a user's
//! request - decides when it comes back.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many failures in a row it takes. Two, not one: a single failure is
/// ordinary, and a route that drops one connection in fifty is still the best
/// one available.
const DUD_LIMIT: u32 = 2;
/// The first bench. Short, because the alternative route is slower, not broken.
const FIRST_BENCH: Duration = Duration::from_secs(5 * 60);
/// How many times it may double. 5 → up to 160 minutes.
const DOUBLINGS: u32 = 5;

/// Health of one route.
///
/// Lives in a `static`, so everything here is `const`-constructible and locks
/// are taken one at a time and released immediately - this is consulted on the
/// path of every connection.
pub struct Health {
    label: &'static str,
    duds: Mutex<u32>,
    benched: Mutex<Option<(Instant, Duration)>>,
    streak: Mutex<u32>,
}

impl Health {
    pub const fn new(label: &'static str) -> Self {
        Health {
            label,
            duds: Mutex::new(0),
            benched: Mutex::new(None),
            streak: Mutex::new(0),
        }
    }

    /// True while this route is being left alone.
    ///
    /// Also lifts an expired bench, so the check and the expiry are one step and
    /// cannot disagree.
    pub fn is_benched(&self) -> bool {
        match self.benched.lock() {
            Ok(mut benched) => match *benched {
                Some((at, dur)) if at.elapsed() < dur => true,
                Some(_) => {
                    *benched = None;
                    false
                }
                None => false,
            },
            // A poisoned lock must not take a working route away.
            Err(_) => false,
        }
    }

    /// Records how one attempt went.
    ///
    /// While benched nothing is counted: attempts already in flight when the
    /// bench landed keep failing afterwards, and counting those escalated a
    /// seconds-long flap into a twenty-minute outage once already. Only
    /// `revive` and `probe_failed` speak while a route is down.
    pub fn note(&self, worked: bool) {
        if self.is_benched() {
            return;
        }
        let Ok(mut duds) = self.duds.lock() else {
            return;
        };
        if worked {
            *duds = 0;
            drop(duds);
            self.clear_streak();
            return;
        }
        *duds += 1;
        if *duds < DUD_LIMIT {
            return;
        }
        *duds = 0;
        drop(duds);
        self.bench();
    }

    /// Same as a failed attempt, but allowed to speak while already benched -
    /// this is how a route that is still down keeps its bench growing without a
    /// user's request being spent to find out.
    pub fn probe_failed(&self) {
        if self.is_benched() {
            self.bench();
        } else {
            self.note(false);
        }
    }

    fn bench(&self) {
        let mut how_long = FIRST_BENCH;
        if let Ok(mut streak) = self.streak.lock() {
            *streak = streak.saturating_add(1);
            how_long = FIRST_BENCH * 2u32.saturating_pow(streak.saturating_sub(1).min(DOUBLINGS));
        }
        let before = match self.benched.lock() {
            Ok(mut benched) => benched.replace((Instant::now(), how_long)),
            Err(_) => None,
        };
        // Once per change, not once per probe. The bench stops doubling at the
        // maximum, so a route that is simply gone - a proxy the user configured
        // and no longer runs - otherwise writes the same line every probe pass
        // forever, and the log is the one place a real fault has to be visible.
        if before.map(|(_, was)| was) == Some(how_long) {
            return;
        }
        crate::dns_forwarder::log_proxy(&format!(
            "{} отложен на {} мин — не отвечает; трафик идёт другим путём",
            self.label,
            how_long.as_secs() / 60
        ));
    }

    /// Puts the route back in use. One good probe is enough: it is evidence the
    /// route works *now*, which is the only thing a bench was ever guessing at.
    pub fn revive(&self, why: &str) {
        let was = match self.benched.lock() {
            Ok(mut benched) => benched.take().is_some(),
            Err(_) => false,
        };
        if let Ok(mut duds) = self.duds.lock() {
            *duds = 0;
        }
        self.clear_streak();
        if was {
            crate::dns_forwarder::log_proxy(&format!("{} снова в работе — {}", self.label, why));
        }
    }

    fn clear_streak(&self) {
        if let Ok(mut streak) = self.streak.lock() {
            *streak = 0;
        }
    }

    #[cfg(test)]
    fn bench_length(&self) -> Option<Duration> {
        self.benched.lock().ok().and_then(|b| b.map(|(_, d)| d))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static T: Health = Health::new("тест");

    /// The whole contract, in the order it actually happens: one failure is
    /// tolerated, two are not, a burst that follows changes nothing, a probe
    /// that still fails lengthens it, and one success ends it.
    ///
    /// A single test, because these share process-wide state and two of them
    /// running in parallel would fight over it - the same trap the answer-cache
    /// tests fell into.
    #[test]
    fn a_route_is_benched_after_two_failures_and_comes_back_on_one_success() {
        T.revive("reset");

        T.note(false);
        assert!(!T.is_benched(), "one failure is ordinary");
        T.note(false);
        assert!(T.is_benched(), "two in a row bench it");
        let first = T.bench_length().expect("benched");
        assert_eq!(first, FIRST_BENCH);

        // Attempts still in flight when the bench landed.
        for _ in 0..6 {
            T.note(false);
        }
        assert_eq!(
            T.bench_length(),
            Some(first),
            "a burst must not lengthen the bench"
        );

        // A probe that finds it still down does lengthen it.
        T.probe_failed();
        assert!(T.bench_length().expect("still benched") > first);

        T.revive("a probe got through");
        assert!(!T.is_benched());
        T.note(false);
        assert!(!T.is_benched(), "the streak was cleared with the bench");
    }
}
