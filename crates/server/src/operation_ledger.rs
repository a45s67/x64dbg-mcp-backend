use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum Admission {
    Started,
    InFlight,
    Completed(Value),
    Unknown,
    Conflict,
    Capacity,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("operation ledger capacity and TTL must be non-zero")]
    InvalidConfiguration,
    #[error("operation ledger lock is poisoned")]
    Poisoned,
    #[error("operation ID was not admitted")]
    NotFound,
}

#[derive(Debug)]
pub struct OperationLedger {
    max_entries: usize,
    ttl: Duration,
    entries: Mutex<HashMap<Uuid, Entry>>,
}

#[derive(Debug)]
struct Entry {
    fingerprint: String,
    status: Status,
    touched: Instant,
}

#[derive(Debug)]
enum Status {
    InFlight,
    Completed(Value),
    Unknown,
}

impl OperationLedger {
    /// Creates a bounded mutation operation ledger.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::InvalidConfiguration`] for a zero capacity or TTL.
    pub fn new(max_entries: usize, ttl: Duration) -> Result<Self, LedgerError> {
        if max_entries == 0 || ttl.is_zero() {
            return Err(LedgerError::InvalidConfiguration);
        }
        Ok(Self {
            max_entries,
            ttl,
            entries: Mutex::new(HashMap::with_capacity(max_entries)),
        })
    }

    /// Admits a mutation once or returns its previously observed state.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Poisoned`] if another thread panicked while holding
    /// the ledger lock.
    pub fn begin(&self, operation_id: Uuid, fingerprint: String) -> Result<Admission, LedgerError> {
        let now = Instant::now();
        let mut entries = self.entries.lock().map_err(|_| LedgerError::Poisoned)?;
        entries.retain(|_, entry| {
            matches!(entry.status, Status::InFlight) || now.duration_since(entry.touched) < self.ttl
        });

        if let Some(entry) = entries.get_mut(&operation_id) {
            entry.touched = now;
            if entry.fingerprint != fingerprint {
                return Ok(Admission::Conflict);
            }
            return Ok(match &entry.status {
                Status::InFlight => Admission::InFlight,
                Status::Completed(value) => Admission::Completed(value.clone()),
                Status::Unknown => Admission::Unknown,
            });
        }
        if entries.len() >= self.max_entries {
            return Ok(Admission::Capacity);
        }
        entries.insert(
            operation_id,
            Entry {
                fingerprint,
                status: Status::InFlight,
                touched: now,
            },
        );
        Ok(Admission::Started)
    }

    /// Records the callback-confirmed result of an admitted mutation.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NotFound`] for an operation that was never admitted,
    /// or [`LedgerError::Poisoned`] when the lock is poisoned.
    pub fn complete(&self, operation_id: Uuid, result: Value) -> Result<(), LedgerError> {
        self.set_status(operation_id, Status::Completed(result))
    }

    /// Marks an admitted mutation as having an ambiguous outcome without retrying.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NotFound`] for an operation that was never admitted,
    /// or [`LedgerError::Poisoned`] when the lock is poisoned.
    pub fn mark_unknown(&self, operation_id: Uuid) -> Result<(), LedgerError> {
        self.set_status(operation_id, Status::Unknown)
    }

    /// Removes an in-flight admission that was proven not to have crossed the
    /// transport boundary. The fingerprint prevents abandoning another call's
    /// operation if the identifier was concurrently reused.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::NotFound`] unless the exact operation is still
    /// in flight, or [`LedgerError::Poisoned`] when the lock is poisoned.
    pub fn abandon_unstarted(
        &self,
        operation_id: Uuid,
        fingerprint: &str,
    ) -> Result<(), LedgerError> {
        let mut entries = self.entries.lock().map_err(|_| LedgerError::Poisoned)?;
        let removable = entries.get(&operation_id).is_some_and(|entry| {
            entry.fingerprint == fingerprint && matches!(entry.status, Status::InFlight)
        });
        if !removable {
            return Err(LedgerError::NotFound);
        }
        entries.remove(&operation_id);
        Ok(())
    }

    fn set_status(&self, operation_id: Uuid, status: Status) -> Result<(), LedgerError> {
        let mut entries = self.entries.lock().map_err(|_| LedgerError::Poisoned)?;
        let entry = entries
            .get_mut(&operation_id)
            .ok_or(LedgerError::NotFound)?;
        entry.status = status;
        entry.touched = Instant::now();
        Ok(())
    }
}

/// Produces a stable ledger fingerprint from a tool name and validated arguments.
///
/// # Errors
///
/// Returns a JSON serialization error if the arguments cannot be encoded.
pub fn fingerprint(method: &str, arguments: &Value) -> Result<String, serde_json::Error> {
    serde_json::to_string(&(method, arguments))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn ledger(capacity: usize) -> OperationLedger {
        OperationLedger::new(capacity, Duration::from_secs(600)).unwrap()
    }

    #[test]
    fn completion_is_replayed_without_reexecution() {
        let ledger = ledger(8);
        let id = Uuid::new_v4();
        let key =
            fingerprint("memory.write", &json!({"address":"0x1000","data_hex":"90"})).unwrap();
        assert_eq!(ledger.begin(id, key.clone()).unwrap(), Admission::Started);
        assert_eq!(ledger.begin(id, key.clone()).unwrap(), Admission::InFlight);
        ledger.complete(id, json!({"bytes_written":1})).unwrap();
        assert_eq!(
            ledger.begin(id, key).unwrap(),
            Admission::Completed(json!({"bytes_written":1}))
        );
    }

    #[test]
    fn ambiguous_mutation_stays_unknown_and_is_not_restarted() {
        let ledger = ledger(8);
        let id = Uuid::new_v4();
        let key = fingerprint("debugger.resume", &json!({"operation_id":id})).unwrap();
        assert_eq!(ledger.begin(id, key.clone()).unwrap(), Admission::Started);
        ledger.mark_unknown(id).unwrap();
        assert_eq!(ledger.begin(id, key).unwrap(), Admission::Unknown);
    }

    #[test]
    fn reused_id_with_different_arguments_is_a_conflict() {
        let ledger = ledger(8);
        let id = Uuid::new_v4();
        assert_eq!(
            ledger.begin(id, "first".to_owned()).unwrap(),
            Admission::Started
        );
        assert_eq!(
            ledger.begin(id, "second".to_owned()).unwrap(),
            Admission::Conflict
        );
    }

    #[test]
    fn capacity_is_hard_bounded_without_evicting_inflight_work() {
        let ledger = ledger(1);
        assert_eq!(
            ledger.begin(Uuid::new_v4(), "one".to_owned()).unwrap(),
            Admission::Started
        );
        assert_eq!(
            ledger.begin(Uuid::new_v4(), "two".to_owned()).unwrap(),
            Admission::Capacity
        );
    }

    #[test]
    fn unstarted_admission_can_be_safely_released() {
        let ledger = ledger(1);
        let id = Uuid::new_v4();
        let key = "not-dispatched".to_owned();
        assert_eq!(ledger.begin(id, key.clone()).unwrap(), Admission::Started);
        ledger.abandon_unstarted(id, &key).unwrap();
        assert_eq!(ledger.begin(id, key).unwrap(), Admission::Started);
    }

    #[test]
    fn unknown_admission_cannot_be_abandoned() {
        let ledger = ledger(1);
        let id = Uuid::new_v4();
        let key = "dispatched".to_owned();
        assert_eq!(ledger.begin(id, key.clone()).unwrap(), Admission::Started);
        ledger.mark_unknown(id).unwrap();
        assert_eq!(
            ledger.abandon_unstarted(id, &key),
            Err(LedgerError::NotFound)
        );
        assert_eq!(ledger.begin(id, key).unwrap(), Admission::Unknown);
    }
}
