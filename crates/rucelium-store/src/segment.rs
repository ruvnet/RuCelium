//! Segment file machinery shared by [`crate::ObservationStore`] and
//! [`crate::EventStore`]: naming, directory scan, and line-oriented reads
//! with torn-tail repair.

use crate::StoreError;
use serde::Serialize;
use std::fs;
use std::path::Path;

/// In-memory metadata for one on-disk segment file, rebuilt on open and
/// updated on append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SegmentInfo {
    /// Segment file name (e.g. `obs-000002.jsonl`).
    pub name: String,
    /// Number of records in the segment.
    pub records: usize,
    /// Smallest `measured_ns` in the segment (`u64::MAX` while empty).
    pub min_measured_ns: u64,
    /// Largest `measured_ns` in the segment (`0` while empty).
    pub max_measured_ns: u64,
}

impl SegmentInfo {
    /// An empty segment about to receive its first record.
    pub(crate) fn empty(name: String) -> Self {
        SegmentInfo {
            name,
            records: 0,
            min_measured_ns: u64::MAX,
            max_measured_ns: 0,
        }
    }
}

/// Segment file name for `index`: `{prefix}-{index:06}.jsonl`. Zero-padding
/// to six digits keeps lexicographic order equal to numeric order for up to
/// a million segments — far beyond any v0.1 deployment.
pub(crate) fn segment_file_name(prefix: &str, index: u64) -> String {
    format!("{prefix}-{index:06}.jsonl")
}

/// List `{prefix}-NNNNNN.jsonl` files in `dir` as `(name, index)`, sorted
/// lexicographically by name. Non-matching files are ignored.
pub(crate) fn list_segments(dir: &Path, prefix: &str) -> Result<Vec<(String, u64)>, StoreError> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some(index) = parse_segment_index(name, prefix) {
            out.push((name.to_string(), index));
        }
    }
    out.sort();
    Ok(out)
}

/// Parse the numeric index out of `{prefix}-NNNNNN.jsonl`; `None` when the
/// name does not match the pattern.
fn parse_segment_index(name: &str, prefix: &str) -> Option<u64> {
    let digits = name
        .strip_prefix(prefix)?
        .strip_prefix('-')?
        .strip_suffix(".jsonl")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Read one segment file, parsing each line with `parse`. Returns the parsed
/// records and the file's size in bytes after any repair.
///
/// With `repair_torn_tail` set (open-time recovery of the *last* segment
/// only), an unparsable **final** line is treated as a crash-torn write: the
/// file is truncated to just before it and the scan succeeds. Any other
/// malformed line — and any malformed line when `repair_torn_tail` is unset
/// — is [`StoreError::Corrupt`] with a 1-based line number.
pub(crate) fn read_segment<T, F>(
    path: &Path,
    name: &str,
    repair_torn_tail: bool,
    parse: F,
) -> Result<(Vec<T>, u64), StoreError>
where
    F: Fn(&str) -> Result<T, String>,
{
    let bytes = fs::read(path)?;
    let mut records = Vec::new();
    let mut offset = 0usize;
    let mut line_no = 0usize;
    while offset < bytes.len() {
        line_no += 1;
        let end = bytes[offset..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |p| offset + p);
        let parsed = std::str::from_utf8(&bytes[offset..end])
            .map_err(|e| e.to_string())
            .and_then(&parse);
        match parsed {
            Ok(record) => records.push(record),
            Err(reason) => {
                // Final line iff nothing follows it but (at most) its '\n'.
                let is_final_line = end + 1 >= bytes.len();
                if repair_torn_tail && is_final_line {
                    let file = fs::OpenOptions::new().write(true).open(path)?;
                    file.set_len(offset as u64)?;
                    return Ok((records, offset as u64));
                }
                return Err(StoreError::Corrupt {
                    segment: name.to_string(),
                    line: line_no,
                    reason,
                });
            }
        }
        offset = end + 1;
    }
    Ok((records, bytes.len() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_zero_padded() {
        assert_eq!(segment_file_name("obs", 0), "obs-000000.jsonl");
        assert_eq!(segment_file_name("evt", 42), "evt-000042.jsonl");
    }

    #[test]
    fn index_parsing_rejects_foreign_names() {
        assert_eq!(parse_segment_index("obs-000007.jsonl", "obs"), Some(7));
        assert_eq!(parse_segment_index("obs-000007.jsonl", "evt"), None);
        assert_eq!(parse_segment_index("obs-x7.jsonl", "obs"), None);
        assert_eq!(parse_segment_index("obs-.jsonl", "obs"), None);
        assert_eq!(parse_segment_index("obs-000007.tmp", "obs"), None);
    }
}
