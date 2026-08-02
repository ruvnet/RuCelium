//! `OutageBuffer` — gateway store-and-forward with duplicate-free replay
//! (ADR-264 §5 responsibility 7, §14 criteria 2–3).
//!
//! While the uplink is down the gateway pushes normalized samples here. On
//! restore, [`OutageBuffer::drain`] replays them in deterministic
//! `(node_id, sequence)` order. The dedup index is part of the serialized
//! form, so a gateway restart (serialize → deserialize) never reintroduces a
//! sample it already buffered.

use rumycelium_core::EnvSample;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Store-and-forward log a gateway fills while its uplink is down.
///
/// Duplicate suppression uses the stable sample dedup key
/// `(node_id, sequence)` (ADR-264 §14 criterion 3). The `seen` index is
/// retained across [`drain`](OutageBuffer::drain) calls and across
/// serialization, so replayed wire packets after a restart are still dropped.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OutageBuffer {
    /// Buffered samples, in arrival order.
    samples: Vec<EnvSample>,
    /// Every `(node_id, sequence)` key ever pushed — the dedup state.
    seen: BTreeSet<(u64, u32)>,
}

impl OutageBuffer {
    /// Create an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        OutageBuffer::default()
    }

    /// Buffer a sample. Returns `false` (dropped) when the sample's
    /// `(node_id, sequence)` key has already been buffered — including keys
    /// seen before a serialize/deserialize restart cycle.
    pub fn push(&mut self, sample: EnvSample) -> bool {
        if !self.seen.insert(sample.dedup_key()) {
            return false;
        }
        self.samples.push(sample);
        true
    }

    /// Number of samples currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether no samples are currently buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Remove and return all buffered samples in `(node_id, sequence)` order
    /// (deterministic replay order). The dedup index is deliberately *not*
    /// cleared: a key that was drained is still a duplicate if it arrives
    /// again.
    pub fn drain(&mut self) -> Vec<EnvSample> {
        let mut out = std::mem::take(&mut self.samples);
        out.sort_by_key(EnvSample::dedup_key);
        out
    }

    /// Serialize the whole buffer — samples *and* dedup state — so it
    /// survives a gateway restart.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Restore a buffer previously produced by
    /// [`to_json`](OutageBuffer::to_json).
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::sample;

    #[test]
    fn push_drops_duplicates() {
        let mut buf = OutageBuffer::new();
        assert!(buf.push(sample(1, 1, 1_000, 20.0)));
        assert!(buf.push(sample(1, 2, 2_000, 20.5)));
        // Same (node_id, sequence), even with different payload: dropped.
        assert!(!buf.push(sample(1, 1, 9_000, 99.0)));
        assert_eq!(buf.len(), 2);
        assert!(!buf.is_empty());
    }

    #[test]
    fn drain_is_ordered_and_empties() {
        let mut buf = OutageBuffer::new();
        buf.push(sample(2, 5, 5_000, 1.0));
        buf.push(sample(1, 9, 4_000, 2.0));
        buf.push(sample(1, 3, 3_000, 3.0));
        let drained = buf.drain();
        let keys: Vec<(u64, u32)> = drained.iter().map(EnvSample::dedup_key).collect();
        assert_eq!(keys, vec![(1, 3), (1, 9), (2, 5)]);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn dedup_state_survives_restart() {
        let mut buf = OutageBuffer::new();
        buf.push(sample(1, 1, 1_000, 20.0));
        buf.push(sample(1, 2, 2_000, 21.0));
        let json = buf.to_json().unwrap();

        // Gateway restarts: restore from disk.
        let mut restored = OutageBuffer::from_json(&json).unwrap();
        assert_eq!(restored.len(), 2);
        // Replayed wire packets with already-buffered keys are dropped.
        assert!(!restored.push(sample(1, 1, 1_000, 20.0)));
        assert!(!restored.push(sample(1, 2, 2_000, 21.0)));
        // New keys still flow.
        assert!(restored.push(sample(1, 3, 3_000, 22.0)));

        // Drain after restore contains zero duplicates.
        let drained = restored.drain();
        let mut keys: Vec<(u64, u32)> = drained.iter().map(EnvSample::dedup_key).collect();
        let n = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), n);
        assert_eq!(keys, vec![(1, 1), (1, 2), (1, 3)]);

        // Even after draining, previously seen keys stay duplicates.
        assert!(!restored.push(sample(1, 3, 3_000, 22.0)));
    }
}
