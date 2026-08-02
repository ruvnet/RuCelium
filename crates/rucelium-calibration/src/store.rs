//! Calibration record store with anchor-rooted lineage verification
//! (ADR-264 §12 items 1–3).

use crate::error::CalibrationError;
use rucelium_core::{CalibrationRecord, SensorModality};
use std::collections::BTreeMap;

/// Whether a lineage root with this method counts as anchored: only records
/// produced at the factory or directly against a reference-grade anchor
/// station may terminate a chain (ADR-264 §12 items 1–3).
fn is_anchored_method(method: &str) -> bool {
    method == "factory" || method == "anchor_reference"
}

/// An in-memory store of [`CalibrationRecord`]s keyed by `calibration_id`,
/// enforcing anchor-rooted lineage at insert time and on demand via
/// [`CalibrationStore::verify_lineage`].
///
/// Records are immutable once inserted — a duplicate `calibration_id` is
/// rejected rather than overwritten, because rewriting calibration history
/// would be exactly the silent correction ADR-264 §12 item 6 forbids.
#[derive(Debug, Clone, Default)]
pub struct CalibrationStore {
    records: BTreeMap<u32, CalibrationRecord>,
}

impl CalibrationStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of records in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the store holds no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Insert a record after validating it structurally
    /// ([`CalibrationRecord::validate`]) and against the lineage rules:
    /// a `parent_id` must already exist in the store, and a root record
    /// (`parent_id: None`) must use an anchored method (`factory` or
    /// `anchor_reference`). Duplicate ids are rejected.
    pub fn insert(&mut self, record: CalibrationRecord) -> Result<(), CalibrationError> {
        record.validate()?;
        if self.records.contains_key(&record.calibration_id) {
            return Err(CalibrationError::Core(rucelium_core::EnvError::Invalid(
                format!(
                    "calibration id {} already exists; records are immutable",
                    record.calibration_id
                ),
            )));
        }
        match record.parent_id {
            Some(parent) => {
                if !self.records.contains_key(&parent) {
                    return Err(CalibrationError::BrokenLineage {
                        id: record.calibration_id,
                        missing_parent: parent,
                    });
                }
            }
            None => {
                if !is_anchored_method(&record.method) {
                    return Err(CalibrationError::UnanchoredRoot(record.calibration_id));
                }
            }
        }
        self.records.insert(record.calibration_id, record);
        Ok(())
    }

    /// Look up a record by id.
    #[must_use]
    pub fn get(&self, id: u32) -> Option<&CalibrationRecord> {
        self.records.get(&id)
    }

    /// Walk the parent chain from `id` to its root and return the visited ids
    /// root-last (`[id, parent, …, root]`).
    ///
    /// Fails with [`CalibrationError::UnknownRecord`] if `id` is absent,
    /// [`CalibrationError::BrokenLineage`] if an ancestor's parent is missing,
    /// [`CalibrationError::LineageCycle`] if the chain revisits a record, and
    /// [`CalibrationError::UnanchoredRoot`] if the root's method is not
    /// anchored (ADR-264 §12 items 1–3).
    pub fn verify_lineage(&self, id: u32) -> Result<Vec<u32>, CalibrationError> {
        let mut chain: Vec<u32> = Vec::new();
        let mut current = id;
        loop {
            if chain.contains(&current) {
                return Err(CalibrationError::LineageCycle(current));
            }
            let Some(record) = self.records.get(&current) else {
                return match chain.last() {
                    None => Err(CalibrationError::UnknownRecord(current)),
                    Some(&child) => Err(CalibrationError::BrokenLineage {
                        id: child,
                        missing_parent: current,
                    }),
                };
            };
            chain.push(current);
            match record.parent_id {
                Some(parent) => current = parent,
                None => {
                    if !is_anchored_method(&record.method) {
                        return Err(CalibrationError::UnanchoredRoot(current));
                    }
                    return Ok(chain);
                }
            }
        }
    }

    /// The newest (highest `created_ns`, ties broken by highest id) record for
    /// `node_id` + `modality` that has not expired at `now_ns` and whose
    /// lineage verifies. `None` when no such record exists.
    #[must_use]
    pub fn active_for(
        &self,
        node_id: u64,
        modality: SensorModality,
        now_ns: u64,
    ) -> Option<&CalibrationRecord> {
        self.records
            .values()
            .filter(|r| {
                r.node_id == node_id
                    && r.modality == modality
                    && !r.is_expired(now_ns)
                    && self.verify_lineage(r.calibration_id).is_ok()
            })
            .max_by_key(|r| (r.created_ns, r.calibration_id))
    }

    /// Test-only backdoor that bypasses all checks, used to forge broken
    /// stores (e.g. lineage cycles) that `insert` correctly refuses to build.
    #[cfg(test)]
    pub(crate) fn insert_unchecked(&mut self, record: CalibrationRecord) {
        self.records.insert(record.calibration_id, record);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rucelium_core::calibration::Q16_ONE;

    fn record(id: u32, method: &str, parent_id: Option<u32>, created_ns: u64) -> CalibrationRecord {
        CalibrationRecord {
            calibration_id: id,
            node_id: 7,
            modality: SensorModality::Weather,
            method: method.into(),
            reference_station: Some("anchor-01".into()),
            parent_id,
            created_ns,
            expires_ns: created_ns + 1_000_000,
            scale_q16: Q16_ONE,
            offset_q16: 0,
            uncertainty_q16: Q16_ONE / 10,
            data_hash: "sha256:cal".into(),
            signature_hex: None,
            signer_pubkey_hex: None,
        }
    }

    #[test]
    fn anchor_rooted_chain_inserts_and_verifies_root_last() {
        let mut store = CalibrationStore::new();
        store
            .insert(record(1, "anchor_reference", None, 1_000))
            .unwrap();
        store
            .insert(record(2, "colocation", Some(1), 2_000))
            .unwrap();
        store
            .insert(record(3, "colocation", Some(2), 3_000))
            .unwrap();
        assert_eq!(store.len(), 3);
        assert!(!store.is_empty());
        assert_eq!(store.verify_lineage(3).unwrap(), vec![3, 2, 1]);
        assert_eq!(store.verify_lineage(1).unwrap(), vec![1]);
    }

    #[test]
    fn missing_parent_is_rejected_at_insert() {
        let mut store = CalibrationStore::new();
        let err = store
            .insert(record(2, "colocation", Some(99), 2_000))
            .unwrap_err();
        assert_eq!(
            err,
            CalibrationError::BrokenLineage {
                id: 2,
                missing_parent: 99
            }
        );
        assert!(store.get(2).is_none());
    }

    #[test]
    fn unanchored_root_is_rejected() {
        let mut store = CalibrationStore::new();
        let err = store
            .insert(record(1, "colocation", None, 1_000))
            .unwrap_err();
        assert_eq!(err, CalibrationError::UnanchoredRoot(1));
        // Factory roots are fine.
        store.insert(record(1, "factory", None, 1_000)).unwrap();
    }

    #[test]
    fn invalid_record_and_duplicate_id_are_rejected() {
        let mut store = CalibrationStore::new();
        let mut bad = record(1, "factory", None, 1_000);
        bad.scale_q16 = 0;
        assert!(matches!(store.insert(bad), Err(CalibrationError::Core(_))));
        store.insert(record(1, "factory", None, 1_000)).unwrap();
        assert!(matches!(
            store.insert(record(1, "factory", None, 2_000)),
            Err(CalibrationError::Core(_))
        ));
    }

    #[test]
    fn unknown_record_and_forged_dangling_parent() {
        let mut store = CalibrationStore::new();
        assert_eq!(
            store.verify_lineage(42).unwrap_err(),
            CalibrationError::UnknownRecord(42)
        );
        // Forge a record whose parent vanished (insert would refuse this).
        store.insert_unchecked(record(5, "colocation", Some(4), 1_000));
        assert_eq!(
            store.verify_lineage(5).unwrap_err(),
            CalibrationError::BrokenLineage {
                id: 5,
                missing_parent: 4
            }
        );
    }

    #[test]
    fn forged_cycle_reports_lineage_cycle() {
        let mut store = CalibrationStore::new();
        store.insert_unchecked(record(10, "colocation", Some(11), 1_000));
        store.insert_unchecked(record(11, "colocation", Some(10), 1_000));
        assert_eq!(
            store.verify_lineage(10).unwrap_err(),
            CalibrationError::LineageCycle(10)
        );
        // Self-loop is also a cycle.
        store.insert_unchecked(record(12, "colocation", Some(12), 1_000));
        assert_eq!(
            store.verify_lineage(12).unwrap_err(),
            CalibrationError::LineageCycle(12)
        );
    }

    #[test]
    fn forged_unanchored_root_fails_verification() {
        let mut store = CalibrationStore::new();
        store.insert_unchecked(record(20, "colocation", None, 1_000));
        store.insert_unchecked(record(21, "colocation", Some(20), 2_000));
        assert_eq!(
            store.verify_lineage(21).unwrap_err(),
            CalibrationError::UnanchoredRoot(20)
        );
    }

    #[test]
    fn active_for_picks_newest_non_expired_with_valid_lineage() {
        let mut store = CalibrationStore::new();
        // Old but long-lived.
        store
            .insert(record(1, "anchor_reference", None, 1_000))
            .unwrap();
        // Newest, but expires early.
        let mut short = record(2, "colocation", Some(1), 3_000);
        short.expires_ns = 4_000;
        store.insert(short).unwrap();
        // Middle age, long-lived.
        store
            .insert(record(3, "colocation", Some(1), 2_000))
            .unwrap();

        // Before record 2 expires it wins (newest created_ns).
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 3_500)
                .unwrap()
                .calibration_id,
            2
        );
        // After it expires, record 3 (created 2_000) beats record 1.
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 5_000)
                .unwrap()
                .calibration_id,
            3
        );
        // Wrong node or modality: nothing.
        assert!(store
            .active_for(8, SensorModality::Weather, 3_500)
            .is_none());
        assert!(store
            .active_for(7, SensorModality::SoilMoisture, 3_500)
            .is_none());
        // Broken lineage disqualifies even a fresh record.
        store.insert_unchecked(record(9, "colocation", Some(999), 4_000));
        assert_eq!(
            store
                .active_for(7, SensorModality::Weather, 4_500)
                .unwrap()
                .calibration_id,
            3
        );
    }
}
