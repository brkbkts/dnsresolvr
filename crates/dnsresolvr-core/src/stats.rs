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
    pub p95: Duration,
    pub p99: Duration,
    pub stddev: Duration,
}

impl Summary {
    pub fn reliability(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.successes as f64 / self.total as f64
        }
    }
}

/// Build a summary from successful RTTs and a total (successes + failures) count.
pub fn summarize(mut rtts: Vec<Duration>, total: usize) -> Option<Summary> {
    if rtts.is_empty() {
        return None;
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
        let rtts: Vec<Duration> = (1..=100).map(|n| d(n)).collect();
        let s = summarize(rtts, 100).unwrap();
        assert_eq!(s.min, d(1));
        assert_eq!(s.max, d(100));
        assert_eq!(s.p50, d(50));
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
}
