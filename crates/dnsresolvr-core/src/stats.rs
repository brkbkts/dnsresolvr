//! Summary statistics for a batch of probe results.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Summary {
    pub total: usize,
    pub successes: usize,
    pub min: Duration,
    pub max: Duration,
    pub mean: Duration,
    pub p50: Duration,
    pub p90: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub stddev: Duration,
}

/// Below this many successful samples the 99th percentile is just the maximum.
pub const P99_MIN_SAMPLES: usize = 100;

impl Summary {
    /// False when every query failed; the latency fields are then all zero.
    pub fn has_samples(&self) -> bool {
        self.successes > 0
    }

    /// p99, or `None` when there are too few samples for it to mean anything.
    pub fn p99_if_meaningful(&self) -> Option<Duration> {
        (self.successes >= P99_MIN_SAMPLES).then_some(self.p99)
    }

    pub fn reliability(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.successes as f64 / self.total as f64
        }
    }
}

/// Build a summary from successful RTTs and a total (successes + failures) count.
///
/// Returns `None` only when nothing was attempted. An endpoint where every
/// query failed still gets a summary, with 0% reliability and zeroed latencies.
pub fn summarize(mut rtts: Vec<Duration>, total: usize) -> Option<Summary> {
    if total == 0 {
        return None;
    }
    if rtts.is_empty() {
        let z = Duration::ZERO;
        return Some(Summary {
            total,
            successes: 0,
            min: z,
            max: z,
            mean: z,
            p50: z,
            p90: z,
            p95: z,
            p99: z,
            stddev: z,
        });
    }
    rtts.sort_unstable();
    let successes = rtts.len();
    let min = *rtts.first().unwrap();
    let max = *rtts.last().unwrap();

    let sum_nanos: u128 = rtts.iter().map(|d| d.as_nanos()).sum();
    let mean_nanos = sum_nanos / successes as u128;
    let mean = Duration::from_nanos(mean_nanos as u64);

    let variance_nanos_sq: u128 = rtts
        .iter()
        .map(|d| {
            let diff = d.as_nanos() as i128 - mean_nanos as i128;
            (diff * diff) as u128
        })
        .sum::<u128>()
        / successes as u128;
    let stddev = Duration::from_nanos((variance_nanos_sq as f64).sqrt() as u64);

    Some(Summary {
        total,
        successes,
        min,
        max,
        mean,
        p50: percentile(&rtts, 0.50),
        p90: percentile(&rtts, 0.90),
        p95: percentile(&rtts, 0.95),
        p99: percentile(&rtts, 0.99),
        stddev,
    })
}

/// Nearest-rank percentile. `q` in [0.0, 1.0].
fn percentile(sorted: &[Duration], q: f64) -> Duration {
    debug_assert!(!sorted.is_empty());
    let q = q.clamp(0.0, 1.0);
    let rank = (q * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    sorted[idx]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(ms: u64) -> Duration {
        Duration::from_millis(ms)
    }

    #[test]
    fn percentiles_on_100_samples() {
        let rtts: Vec<Duration> = (1..=100).map(d).collect();
        let s = summarize(rtts, 100).unwrap();
        assert_eq!(s.min, d(1));
        assert_eq!(s.max, d(100));
        assert_eq!(s.p50, d(50));
        assert_eq!(s.p90, d(90));
        assert_eq!(s.p95, d(95));
        assert_eq!(s.p99, d(99));
    }

    #[test]
    fn reliability_counts_total() {
        let s = summarize(vec![d(5), d(6), d(7)], 10).unwrap();
        assert_eq!(s.total, 10);
        assert_eq!(s.successes, 3);
        assert!((s.reliability() - 0.3).abs() < 1e-9);
    }

    #[test]
    fn all_failures_report_zero_reliability() {
        let s = summarize(Vec::new(), 8).unwrap();
        assert!(!s.has_samples());
        assert_eq!(s.reliability(), 0.0);
        assert!(summarize(Vec::new(), 0).is_none());
    }

    #[test]
    fn p99_hidden_for_small_samples() {
        let small = summarize((1..=40).map(d).collect(), 40).unwrap();
        assert!(small.p99_if_meaningful().is_none());
        let large = summarize((1..=100).map(d).collect(), 100).unwrap();
        assert_eq!(large.p99_if_meaningful(), Some(d(99)));
    }
}
