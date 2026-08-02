//! `ObservationStore` — the durable, segmented, append-only sample log with
//! a persistent dedup index and retention enforcement (ADR-265 §3).

use crate::segment::{list_segments, read_segment, segment_file_name, SegmentInfo};
use crate::{AppendOutcome, StoreError};
use rucelium_core::EnvSample;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Observation segment file prefix (`obs-NNNNNN.jsonl`).
const PREFIX: &str = "obs";

/// Store health counters and sizes.
///
/// `records` / `segments` / `bytes_on_disk` describe current on-disk state;
/// the `*_total` counters count operations since this handle was opened.
/// `bytes_on_disk` is approximate: it is the sum of segment sizes as
/// maintained at the last open-scan, append, or retention pass — the store
/// does not re-stat files on every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StoreStats {
    /// Unique records currently stored on disk.
    pub records: u64,
    /// Number of live segment files.
    pub segments: u64,
    /// Samples appended since open.
    pub appended_total: u64,
    /// Duplicate appends rejected since open.
    pub duplicates_total: u64,
    /// Records deleted by retention since open.
    pub retention_deleted_total: u64,
    /// Approximate sum of segment file sizes in bytes.
    pub bytes_on_disk: u64,
}

/// One live segment: public metadata plus its tracked byte size.
struct SegmentState {
    info: SegmentInfo,
    bytes: u64,
}

/// Durable append-only store for [`EnvSample`]s.
///
/// Samples live on disk as one JSON line each, in zero-padded segment files
/// `obs-NNNNNN.jsonl` of at most `segment_max_records` records. Only the
/// dedup keys (`(node_id, sequence)`) and per-segment metadata are held in
/// memory — replay always reads from disk, so it is deterministic across
/// restarts. See the crate docs for the v0.1 durability, torn-tail, and
/// retention design notes.
pub struct ObservationStore {
    dir: PathBuf,
    segment_max_records: usize,
    /// Every dedup key ever appended — kept even after retention (crate docs).
    seen: BTreeSet<(u64, u32)>,
    segments: Vec<SegmentState>,
    next_segment_index: u64,
    appended_total: u64,
    duplicates_total: u64,
    retention_deleted_total: u64,
}

fn parse_sample(line: &str) -> Result<EnvSample, String> {
    serde_json::from_str(line).map_err(|e| e.to_string())
}

impl ObservationStore {
    /// Open (or create) a store at `dir`, scanning existing `obs-*.jsonl`
    /// segments in lexicographic order to rebuild the dedup index and
    /// segment metadata.
    ///
    /// Crash recovery: an unparsable **final** line of the **final** segment
    /// is truncated away (torn write); a malformed line anywhere else is
    /// [`StoreError::Corrupt`]. A `segment_max_records` of `0` is treated
    /// as `1`.
    pub fn open(dir: &Path, segment_max_records: usize) -> Result<Self, StoreError> {
        fs::create_dir_all(dir)?;
        let listed = list_segments(dir, PREFIX)?;
        let n = listed.len();
        let mut seen = BTreeSet::new();
        let mut segments = Vec::with_capacity(n);
        let mut next_segment_index = 0u64;
        for (i, (name, index)) in listed.into_iter().enumerate() {
            let repair_torn_tail = i + 1 == n;
            let (records, bytes) =
                read_segment(&dir.join(&name), &name, repair_torn_tail, parse_sample)?;
            let mut info = SegmentInfo::empty(name);
            for s in &records {
                seen.insert(s.dedup_key());
                info.records += 1;
                info.min_measured_ns = info.min_measured_ns.min(s.measured_ns);
                info.max_measured_ns = info.max_measured_ns.max(s.measured_ns);
            }
            segments.push(SegmentState { info, bytes });
            next_segment_index = index + 1;
        }
        Ok(ObservationStore {
            dir: dir.to_path_buf(),
            segment_max_records: segment_max_records.max(1),
            seen,
            segments,
            next_segment_index,
            appended_total: 0,
            duplicates_total: 0,
            retention_deleted_total: 0,
        })
    }

    /// Append a sample, deduplicating by [`EnvSample::dedup_key`].
    ///
    /// The sample is validated first (invalid → [`StoreError::Core`]). A new
    /// segment starts when the current one holds `segment_max_records`. The
    /// write is flushed to the OS after each append; v0.1 deliberately does
    /// not fsync (crate docs).
    pub fn append(&mut self, sample: &EnvSample) -> Result<AppendOutcome, StoreError> {
        sample
            .validate()
            .map_err(|e| StoreError::Core(e.to_string()))?;
        let key = sample.dedup_key();
        if self.seen.contains(&key) {
            self.duplicates_total += 1;
            return Ok(AppendOutcome::Duplicate);
        }
        let roll = match self.segments.last() {
            None => true,
            Some(s) => s.info.records >= self.segment_max_records,
        };
        if roll {
            let name = segment_file_name(PREFIX, self.next_segment_index);
            self.next_segment_index += 1;
            self.segments.push(SegmentState {
                info: SegmentInfo::empty(name),
                bytes: 0,
            });
        }
        let line = serde_json::to_string(sample).map_err(|e| StoreError::Core(e.to_string()))?;
        let seg = self.segments.last_mut().expect("segment exists after roll");
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(&seg.info.name))?;
        file.write_all(line.as_bytes())?;
        file.write_all(b"\n")?;
        file.flush()?;
        self.seen.insert(key);
        seg.info.records += 1;
        seg.info.min_measured_ns = seg.info.min_measured_ns.min(sample.measured_ns);
        seg.info.max_measured_ns = seg.info.max_measured_ns.max(sample.measured_ns);
        seg.bytes += line.len() as u64 + 1;
        self.appended_total += 1;
        Ok(AppendOutcome::Appended)
    }

    /// Number of unique records currently stored on disk. After retention
    /// this can be smaller than the dedup index, whose keys are kept forever.
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments.iter().map(|s| s.info.records).sum()
    }

    /// Whether no records are currently stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Live segment file names, sorted.
    #[must_use]
    pub fn segments(&self) -> Vec<String> {
        self.segments.iter().map(|s| s.info.name.clone()).collect()
    }

    /// Per-segment metadata, in segment order.
    #[must_use]
    pub fn segment_infos(&self) -> Vec<SegmentInfo> {
        self.segments.iter().map(|s| s.info.clone()).collect()
    }

    /// Full deterministic replay: every stored sample, in append order,
    /// read back from disk (the store caches only dedup keys, never
    /// payloads).
    pub fn iter(&self) -> Result<Vec<EnvSample>, StoreError> {
        let mut out = Vec::with_capacity(self.len());
        for seg in &self.segments {
            let (records, _) = read_segment(
                &self.dir.join(&seg.info.name),
                &seg.info.name,
                false,
                parse_sample,
            )?;
            out.extend(records);
        }
        Ok(out)
    }

    /// The last `limit` records, in append order.
    pub fn recent(&self, limit: usize) -> Result<Vec<EnvSample>, StoreError> {
        let mut all = self.iter()?;
        let skip = all.len().saturating_sub(limit);
        Ok(all.split_off(skip))
    }

    /// Delete whole segments whose newest measurement has expired:
    /// `max_measured_ns + retention_ns <= now_ns`. Returns the number of
    /// records deleted.
    ///
    /// Segment-level deletion is the deliberate design: expired data is
    /// dropped by removing whole files — cheap, and no segment is ever
    /// rewritten. The current (last) segment is never deleted. Dedup keys of
    /// deleted records are retained (crate docs), so an expired sample
    /// replayed later is still a duplicate.
    pub fn enforce_retention(&mut self, now_ns: u64, retention_ns: u64) -> Result<u64, StoreError> {
        let mut deleted = 0u64;
        let mut i = 0;
        while i + 1 < self.segments.len() {
            let seg = &self.segments[i];
            if seg.info.max_measured_ns.saturating_add(retention_ns) <= now_ns {
                fs::remove_file(self.dir.join(&seg.info.name))?;
                deleted += seg.info.records as u64;
                self.segments.remove(i);
            } else {
                i += 1;
            }
        }
        self.retention_deleted_total += deleted;
        Ok(deleted)
    }

    /// Current counters and sizes (see [`StoreStats`] for exact semantics).
    #[must_use]
    pub fn stats(&self) -> StoreStats {
        StoreStats {
            records: self.len() as u64,
            segments: self.segments.len() as u64,
            appended_total: self.appended_total,
            duplicates_total: self.duplicates_total,
            retention_deleted_total: self.retention_deleted_total,
            bytes_on_disk: self.segments.iter().map(|s| s.bytes).sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{sample, temp_dir};

    #[test]
    fn append_iter_round_trips_in_order_and_rejects_duplicates() {
        let dir = temp_dir("roundtrip");
        let mut store = ObservationStore::open(&dir, 100).unwrap();
        let samples = [
            sample(1, 1, 1_000, 20.0),
            sample(2, 1, 2_000, 21.0),
            sample(1, 2, 3_000, 22.0),
        ];
        for s in &samples {
            assert_eq!(store.append(s).unwrap(), AppendOutcome::Appended);
        }
        // Same key, different payload: still a duplicate.
        assert_eq!(
            store.append(&sample(1, 1, 9_000, 99.0)).unwrap(),
            AppendOutcome::Duplicate
        );
        assert_eq!(store.len(), 3);
        assert!(!store.is_empty());
        assert_eq!(store.iter().unwrap(), samples.to_vec());
        assert_eq!(store.recent(2).unwrap(), samples[1..].to_vec());
        let stats = store.stats();
        assert_eq!(stats.appended_total, 3);
        assert_eq!(stats.duplicates_total, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_sample_is_a_core_error() {
        let dir = temp_dir("invalid");
        let mut store = ObservationStore::open(&dir, 100).unwrap();
        let mut bad = sample(1, 1, 1_000, 20.0);
        bad.quality = 2.0;
        assert!(matches!(store.append(&bad), Err(StoreError::Core(_))));
        assert!(store.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn segments_roll_over_at_max_records() {
        let dir = temp_dir("rollover");
        let mut store = ObservationStore::open(&dir, 3).unwrap();
        for seq in 1..=7 {
            store
                .append(&sample(1, seq, u64::from(seq) * 1_000, 20.0))
                .unwrap();
        }
        assert_eq!(
            store.segments(),
            vec!["obs-000000.jsonl", "obs-000001.jsonl", "obs-000002.jsonl"]
        );
        let infos = store.segment_infos();
        assert_eq!(
            infos.iter().map(|i| i.records).collect::<Vec<_>>(),
            vec![3, 3, 1]
        );
        assert_eq!(infos[0].min_measured_ns, 1_000);
        assert_eq!(infos[0].max_measured_ns, 3_000);
        assert_eq!(infos[2].min_measured_ns, 7_000);
        assert_eq!(infos[2].max_measured_ns, 7_000);
        // Replay stays ordered across segment boundaries.
        let seqs: Vec<u32> = store.iter().unwrap().iter().map(|s| s.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4, 5, 6, 7]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reopen_recovers_index_and_metadata() {
        let dir = temp_dir("reopen");
        let mut store = ObservationStore::open(&dir, 3).unwrap();
        for seq in 1..=5 {
            store
                .append(&sample(1, seq, u64::from(seq) * 1_000, 20.0))
                .unwrap();
        }
        let len = store.len();
        let segments = store.segments();
        let infos = store.segment_infos();
        drop(store);

        let mut reopened = ObservationStore::open(&dir, 3).unwrap();
        assert_eq!(reopened.len(), len);
        assert_eq!(reopened.segments(), segments);
        assert_eq!(reopened.segment_infos(), infos);
        // Dedup survives restart.
        assert_eq!(
            reopened.append(&sample(1, 3, 3_000, 20.0)).unwrap(),
            AppendOutcome::Duplicate
        );
        // New keys still flow, into the correct next segment.
        assert_eq!(
            reopened.append(&sample(1, 6, 6_000, 20.0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(reopened.len(), 6);
        assert_eq!(
            reopened.segments(),
            vec!["obs-000000.jsonl", "obs-000001.jsonl"]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn torn_tail_is_truncated_on_open() {
        let dir = temp_dir("torn");
        let mut store = ObservationStore::open(&dir, 100).unwrap();
        for seq in 1..=5 {
            store
                .append(&sample(1, seq, u64::from(seq) * 1_000, 20.0))
                .unwrap();
        }
        drop(store);
        // Simulate a crash mid-write: garbage bytes, no trailing newline.
        let path = dir.join("obs-000000.jsonl");
        let clean_len = fs::metadata(&path).unwrap().len();
        let mut f = fs::OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"half").unwrap();
        drop(f);

        let mut reopened = ObservationStore::open(&dir, 100).unwrap();
        assert_eq!(reopened.len(), 5);
        assert_eq!(reopened.iter().unwrap().len(), 5);
        // The file was truncated back to the last complete record.
        assert_eq!(fs::metadata(&path).unwrap().len(), clean_len);
        assert!(!fs::read_to_string(&path).unwrap().contains("half"));
        // The store keeps working after repair.
        assert_eq!(
            reopened.append(&sample(1, 6, 6_000, 20.0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(reopened.iter().unwrap().len(), 6);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_middle_line_names_segment_and_line() {
        let dir = temp_dir("corrupt");
        let mut store = ObservationStore::open(&dir, 100).unwrap();
        for seq in 1..=3 {
            store
                .append(&sample(1, seq, u64::from(seq) * 1_000, 20.0))
                .unwrap();
        }
        drop(store);
        let path = dir.join("obs-000000.jsonl");
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect();
        lines[1] = "not json".into();
        fs::write(&path, lines.join("\n") + "\n").unwrap();

        let err = ObservationStore::open(&dir, 100).map(|_| ()).unwrap_err();
        match err {
            StoreError::Corrupt { segment, line, .. } => {
                assert_eq!(segment, "obs-000000.jsonl");
                assert_eq!(line, 2);
            }
            other => panic!("expected Corrupt, got {other}"),
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn retention_deletes_expired_segments_but_never_the_last() {
        let dir = temp_dir("retention");
        let mut store = ObservationStore::open(&dir, 2).unwrap();
        // seg0: 1000, 2000 | seg1: 5000, 6000 | seg2: 9000
        for (seq, measured) in [(1, 1_000), (2, 2_000), (3, 5_000), (4, 6_000), (5, 9_000)] {
            store.append(&sample(1, seq, measured, 20.0)).unwrap();
        }
        assert_eq!(store.segments().len(), 3);

        // 2000 + 1000 <= 3000: only seg0 has expired.
        assert_eq!(store.enforce_retention(3_000, 1_000).unwrap(), 2);
        assert_eq!(
            store.segments(),
            vec!["obs-000001.jsonl", "obs-000002.jsonl"]
        );
        let measured: Vec<u64> = store
            .iter()
            .unwrap()
            .iter()
            .map(|s| s.measured_ns)
            .collect();
        assert_eq!(measured, vec![5_000, 6_000, 9_000]);
        assert!(!dir.join("obs-000000.jsonl").exists());

        // Far future: everything expired, but the last segment survives.
        assert_eq!(store.enforce_retention(u64::MAX, 0).unwrap(), 2);
        assert_eq!(store.segments(), vec!["obs-000002.jsonl"]);
        assert_eq!(store.len(), 1);
        assert_eq!(store.stats().retention_deleted_total, 4);

        // Dedup keys outlive retention: an expired sample is still a dup.
        assert_eq!(
            store.append(&sample(1, 1, 1_000, 20.0)).unwrap(),
            AppendOutcome::Duplicate
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stats_serialize_to_json() {
        let dir = temp_dir("stats");
        let mut store = ObservationStore::open(&dir, 100).unwrap();
        store.append(&sample(1, 1, 1_000, 20.0)).unwrap();
        store.append(&sample(1, 1, 1_000, 20.0)).unwrap();
        let json = serde_json::to_value(store.stats()).unwrap();
        assert_eq!(json["records"], 1);
        assert_eq!(json["segments"], 1);
        assert_eq!(json["appended_total"], 1);
        assert_eq!(json["duplicates_total"], 1);
        assert_eq!(json["retention_deleted_total"], 0);
        assert!(json["bytes_on_disk"].as_u64().unwrap() > 0);
        fs::remove_dir_all(&dir).unwrap();
    }
}
