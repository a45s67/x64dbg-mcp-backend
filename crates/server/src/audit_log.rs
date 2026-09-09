//! Best-effort persistent JSONL audit storage for tool traffic and debugger events.

use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        mpsc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Value, json};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::adapter::ToolError;

pub const ROTATE_BYTES: u64 = 5 * 1024 * 1024;
const QUEUE_RECORDS: usize = 256;
const MAX_QUEUED_BYTES: usize = 64 * 1024 * 1024;
const MAX_CURSORS: usize = 512;

pub struct AuditLog {
    sender: Option<mpsc::SyncSender<Vec<u8>>>,
    store: Option<Arc<Mutex<Store>>>,
    counters: Arc<Counters>,
    backend: String,
    instance_id: Uuid,
    secrets: Vec<String>,
    unavailable: Option<&'static str>,
    event_sender: broadcast::Sender<BrokerEvent>,
}

#[derive(Clone)]
struct BrokerEvent {
    value: Value,
}

pub struct EventWait {
    receiver: broadcast::Receiver<BrokerEvent>,
}

#[derive(Default)]
struct Counters {
    queued_bytes: AtomicUsize,
    dropped: AtomicU64,
    written: AtomicU64,
    errors: AtomicU64,
    healthy: AtomicBool,
    event_connected: AtomicBool,
}

#[derive(Clone)]
struct Segment {
    id: Uuid,
    path: PathBuf,
    length: u64,
}

#[derive(Clone)]
struct Cursor {
    segments: Vec<Segment>,
    index: usize,
    offset: u64,
    partial: bool,
}

struct Store {
    _lock: File,
    directory: PathBuf,
    file: File,
    segments: Vec<Segment>,
    backups: usize,
    rotate_bytes: u64,
    recovered_bytes: u64,
    oversize_records: u64,
    cursors: HashMap<Uuid, Cursor>,
    cursor_order: VecDeque<Uuid>,
    successors: HashMap<(Uuid, u64, u64), Uuid>,
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn failure(code: &'static str, message: &'static str) -> ToolError {
    ToolError::new(code, message, true, false, json!({}))
}

impl AuditLog {
    /// Creates an explicitly unavailable store while keeping diagnostic tools usable.
    #[must_use]
    pub fn disabled(backend: &str, instance_id: Uuid, reason: &'static str) -> Arc<Self> {
        let (event_sender, _) = broadcast::channel(1024);
        Arc::new(Self {
            sender: None,
            store: None,
            counters: Arc::new(Counters::default()),
            backend: backend.to_owned(),
            instance_id,
            secrets: Vec::new(),
            unavailable: Some(reason),
            event_sender,
        })
    }

    /// Opens a backend-owned log directory. Failure disables logging, not debugging.
    #[must_use]
    pub fn open(
        directory: &Path,
        backend: &str,
        instance_id: Uuid,
        backups: usize,
        secrets: Vec<String>,
    ) -> Arc<Self> {
        Self::open_with_limit(
            directory,
            backend,
            instance_id,
            backups,
            secrets,
            ROTATE_BYTES,
        )
    }

    fn open_with_limit(
        directory: &Path,
        backend: &str,
        instance_id: Uuid,
        backups: usize,
        secrets: Vec<String>,
        rotate_bytes: u64,
    ) -> Arc<Self> {
        let counters = Arc::new(Counters::default());
        let (event_sender, _) = broadcast::channel(1024);
        let (sender, store, unavailable) = match Store::open(directory, backups, rotate_bytes) {
            Ok(store) => {
                let store = Arc::new(Mutex::new(store));
                let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(QUEUE_RECORDS);
                let writer_store = Arc::clone(&store);
                let writer_counters = Arc::clone(&counters);
                counters.healthy.store(true, Ordering::Relaxed);
                let spawned = std::thread::Builder::new()
                    .name("x64dbg-mcp-audit".to_owned())
                    .spawn(move || writer_loop(receiver, &writer_store, &writer_counters));
                if spawned.is_ok() {
                    (Some(sender), Some(store), None)
                } else {
                    (None, Some(store), Some("WRITER_UNAVAILABLE"))
                }
            }
            Err(_) => (None, None, Some("LOG_STORE_UNAVAILABLE")),
        };
        let log = Arc::new(Self {
            sender,
            store,
            counters,
            backend: backend.to_owned(),
            instance_id,
            secrets,
            unavailable,
            event_sender,
        });
        log.record(
            "backend_started",
            json!({"durability":"best_effort","payload_policy":"full_except_transport_credentials"}),
        );
        log
    }

    pub fn record(&self, kind: &str, payload: Value) {
        let Some(sender) = &self.sender else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let session_id = payload.get("session_id").cloned().unwrap_or(Value::Null);
        let mut record = json!({
            "schema_version": 1,
            "kind": kind,
            "timestamp_unix_ms": now_ms(),
            "backend": self.backend,
            "instance_id": self.instance_id,
            "session_id": session_id,
            "payload": payload
        });
        self.scrub(&mut record);
        let Ok(mut line) = serde_json::to_vec(&record) else {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        line.push(b'\n');
        let length = line.len();
        if self
            .counters
            .queued_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |queued| {
                queued
                    .checked_add(length)
                    .filter(|total| *total <= MAX_QUEUED_BYTES)
            })
            .is_err()
        {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if sender.try_send(line).is_err() {
            self.counters
                .queued_bytes
                .fetch_sub(length, Ordering::Relaxed);
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn scrub(&self, value: &mut Value) {
        match value {
            Value::String(text) => {
                for secret in &self.secrets {
                    if !secret.is_empty() {
                        *text = text.replace(secret, "[REDACTED]");
                    }
                }
            }
            Value::Array(values) => {
                for value in values {
                    self.scrub(value);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    if matches!(
                        key.to_ascii_lowercase().as_str(),
                        "authorization" | "bearer_token" | "nonce" | "ipc_nonce"
                    ) {
                        *value = Value::String("[REDACTED]".to_owned());
                    } else {
                        self.scrub(value);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    pub fn event_connected(&self, connected: bool) {
        self.counters
            .event_connected
            .store(connected, Ordering::Relaxed);
        self.record("event_transport", json!({"connected":connected}));
    }

    /// Persists and publishes one authenticated native callback event.
    pub fn publish_event(&self, event: Value) {
        self.record("native_event", event.clone());
        let _ = self.event_sender.send(BrokerEvent { value: event });
    }

    /// Subscribes before the caller obtains a native event-sequence barrier.
    #[must_use]
    pub fn arm_event_wait(&self) -> EventWait {
        EventWait {
            receiver: self.event_sender.subscribe(),
        }
    }

    /// Waits for a future native event without occupying the request IPC stream.
    ///
    /// # Errors
    /// Returns a structured timeout, cancellation, transport, or overflow error.
    pub async fn wait_event(
        &self,
        mut wait: EventWait,
        arguments: &Value,
        after_sequence: u64,
        session_id: &str,
    ) -> Result<Value, ToolError> {
        let types = arguments
            .get("types")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let timeout_ms = arguments
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5000);
        let receive = async {
            loop {
                match wait.receiver.recv().await {
                    Ok(event) => {
                        let kind = event.value.get("type").and_then(Value::as_str);
                        if kind == Some("gap") {
                            continue;
                        }
                        let event_session = event.value.get("session_id").and_then(Value::as_str);
                        if event_session != Some(session_id) {
                            if kind == Some("process_created") {
                                return Err(ToolError::new(
                                    "CANCELLED",
                                    "debuggee session changed while waiting for an event",
                                    true,
                                    false,
                                    json!({}),
                                ));
                            }
                            continue;
                        }
                        let sequence = event.value.get("sequence").and_then(Value::as_u64);
                        if sequence.is_none_or(|sequence| sequence <= after_sequence) {
                            continue;
                        }
                        if types.is_empty()
                            || kind.is_some_and(|kind| types.iter().any(|item| item == kind))
                        {
                            return Ok(json!({
                                "session_id": event.value.get("session_id"),
                                "latest_sequence": event.value.get("sequence"),
                                "event": event.value
                            }));
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        return Err(ToolError::new(
                            "INTERNAL",
                            "native event wait overflowed",
                            true,
                            false,
                            json!({"skipped":skipped}),
                        ));
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(ToolError::new(
                            "PLUGIN_UNAVAILABLE",
                            "native event transport closed",
                            true,
                            true,
                            json!({}),
                        ));
                    }
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_millis(timeout_ms), receive)
            .await
            .map_err(|_| {
                ToolError::new(
                    "TIMEOUT",
                    "no matching debugger event was observed",
                    true,
                    true,
                    json!({}),
                )
            })?
    }

    #[must_use]
    pub fn status(&self) -> Value {
        let store = self.store.as_ref().and_then(|store| store.lock().ok());
        json!({
            "state": {
                "enabled": self.sender.is_some(),
                "healthy": self.sender.is_some() && self.counters.healthy.load(Ordering::Relaxed)
            },
            "backend": self.backend,
            "instance_id": self.instance_id,
            "diagnostic_code": self.unavailable,
            "written_records": self.counters.written.load(Ordering::Relaxed),
            "dropped_records": self.counters.dropped.load(Ordering::Relaxed),
            "write_errors": self.counters.errors.load(Ordering::Relaxed),
            "queued_bytes": self.counters.queued_bytes.load(Ordering::Relaxed),
            "event_stream_connected": self.counters.event_connected.load(Ordering::Relaxed),
            "rotation_bytes": store.as_ref().map_or(ROTATE_BYTES, |store| store.rotate_bytes),
            "backup_count": store.as_ref().map(|store| store.backups),
            "recovered_tail_bytes": store.as_ref().map_or(0, |store| store.recovered_bytes),
            "oversize_records": store.as_ref().map_or(0, |store| store.oversize_records),
            "segments": store.as_ref().map(|store| store.segments.iter()
                .map(|segment| json!({"segment_id":segment.id,"bytes":segment.length}))
                .collect::<Vec<_>>()),
            "durability": "best_effort; queued records may be lost on crash; counters are per backend instance"
        })
    }

    /// Reads only store-owned files through bounded process-local snapshot cursors.
    ///
    /// # Errors
    /// Returns a structured error for unavailable storage, invalid input, expired
    /// cursors, or failed reads.
    pub fn read(&self, arguments: &Value) -> Result<Value, ToolError> {
        let object = arguments
            .as_object()
            .ok_or_else(|| failure("INVALID_ARGUMENT", "arguments must be an object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "cursor" | "limit" | "max_bytes"))
        {
            return Err(failure("INVALID_ARGUMENT", "unknown log reader field"));
        }
        let limit = optional_bounded(object.get("limit"), 50, 1, 100, "invalid log record limit")?;
        let budget = optional_bounded(
            object.get("max_bytes"),
            65_536,
            1024,
            262_144,
            "invalid log byte limit",
        )?;
        let store = self
            .store
            .as_ref()
            .ok_or_else(|| failure("LOG_STORE_UNAVAILABLE", "audit store is unavailable"))?;
        let mut store = store
            .lock()
            .map_err(|_| failure("LOG_STORE_UNAVAILABLE", "audit store is unavailable"))?;
        let mut source_cursor = None;
        let mut cursor = if let Some(value) = object.get("cursor") {
            let id = value
                .as_str()
                .filter(|value| value.len() <= 512)
                .and_then(|value| Uuid::parse_str(value).ok())
                .ok_or_else(|| failure("CURSOR_EXPIRED", "invalid or expired audit cursor"))?;
            source_cursor = Some(id);
            store
                .cursors
                .get(&id)
                .cloned()
                .ok_or_else(|| failure("CURSOR_EXPIRED", "invalid or expired audit cursor"))?
        } else {
            Cursor {
                segments: store.segments.clone(),
                index: 0,
                offset: 0,
                partial: false,
            }
        };
        advance_empty_segments(&mut cursor);
        if cursor.index == cursor.segments.len() {
            return Ok(empty_read());
        }
        let segment = cursor.segments[cursor.index].clone();
        let current = store
            .segments
            .iter()
            .find(|candidate| candidate.id == segment.id)
            .ok_or_else(|| failure("CURSOR_EXPIRED", "snapshot segment has rotated out"))?;
        let mut file = File::open(&current.path)
            .map_err(|_| failure("LOG_READ_FAILED", "audit segment could not be read"))?;
        file.seek(SeekFrom::Start(cursor.offset))
            .map_err(|_| failure("LOG_READ_FAILED", "audit segment could not be read"))?;
        let count = usize::try_from(budget.min(segment.length - cursor.offset))
            .map_err(|_| failure("LOG_READ_FAILED", "audit byte range is invalid"))?;
        let mut bytes = vec![0; count];
        file.read_exact(&mut bytes)
            .map_err(|_| failure("LOG_READ_FAILED", "audit segment could not be read"))?;
        let valid = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => return Err(failure("LOG_READ_FAILED", "audit segment is not UTF-8")),
        };
        bytes.truncate(valid);
        let mut completed_records = 0_u64;
        let mut last_boundary = None;
        for (index, byte) in bytes.iter().enumerate() {
            if *byte == b'\n' {
                completed_records += 1;
                last_boundary = Some(index + 1);
                if completed_records == limit {
                    break;
                }
            }
        }
        if let Some(end) = last_boundary {
            bytes.truncate(end);
        }
        let starts_mid_record = cursor.partial;
        let ends_mid_record = bytes.last() != Some(&b'\n');
        let offset = cursor.offset;
        cursor.offset += u64::try_from(bytes.len()).unwrap_or(0);
        cursor.partial = ends_mid_record;
        advance_empty_segments(&mut cursor);
        let complete = cursor.index == cursor.segments.len();
        let next_cursor = if complete {
            None
        } else if let Some(existing) = source_cursor
            .and_then(|source| store.successors.get(&(source, limit, budget)).copied())
            .filter(|successor| store.cursors.contains_key(successor))
        {
            Some(existing)
        } else {
            let id = Uuid::new_v4();
            store.cursors.insert(id, cursor);
            store.cursor_order.push_back(id);
            if let Some(source) = source_cursor {
                store.successors.insert((source, limit, budget), id);
            }
            while store.cursor_order.len() > MAX_CURSORS {
                if let Some(expired) = store.cursor_order.pop_front() {
                    store.cursors.remove(&expired);
                    store.successors.retain(|(source, _, _), successor| {
                        *source != expired && *successor != expired
                    });
                }
            }
            Some(id)
        };
        let text = String::from_utf8(bytes)
            .map_err(|_| failure("LOG_READ_FAILED", "audit segment is not UTF-8"))?;
        Ok(json!({
            "text": text,
            "encoding": "utf8_jsonl",
            "bytes": text.len(),
            "completed_records": completed_records,
            "segment_id": segment.id,
            "offset": offset,
            "starts_mid_record": starts_mid_record,
            "ends_mid_record": ends_mid_record,
            "partial_record": starts_mid_record || ends_mid_record,
            "next_cursor": next_cursor,
            "complete": complete
        }))
    }

    pub async fn flush(&self, deadline: std::time::Duration) {
        let _ = tokio::time::timeout(deadline, async {
            while self.counters.queued_bytes.load(Ordering::Relaxed) != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await;
    }
}

fn optional_bounded(
    value: Option<&Value>,
    default: u64,
    minimum: u64,
    maximum: u64,
    message: &'static str,
) -> Result<u64, ToolError> {
    value.map_or(Ok(default), |value| {
        value
            .as_u64()
            .filter(|value| (minimum..=maximum).contains(value))
            .ok_or_else(|| failure("INVALID_ARGUMENT", message))
    })
}

fn advance_empty_segments(cursor: &mut Cursor) {
    while cursor.index < cursor.segments.len()
        && cursor.offset == cursor.segments[cursor.index].length
    {
        cursor.index += 1;
        cursor.offset = 0;
        cursor.partial = false;
    }
}

fn empty_read() -> Value {
    json!({"text":"","encoding":"utf8_jsonl","bytes":0,"completed_records":0,
        "partial_record":false,"next_cursor":null,"complete":true})
}

fn writer_loop(receiver: mpsc::Receiver<Vec<u8>>, store: &Mutex<Store>, counters: &Counters) {
    let mut reported_drops = 0;
    for line in receiver {
        let length = line.len();
        let result = store
            .lock()
            .map_err(|_| io::Error::other("audit store lock poisoned"))
            .and_then(|mut store| {
                let dropped = counters.dropped.load(Ordering::Relaxed);
                if dropped != reported_drops {
                    let mut gap = serde_json::to_vec(&json!({
                        "schema_version": 1,
                        "kind": "audit_gap",
                        "timestamp_unix_ms": now_ms(),
                        "dropped_total": dropped,
                        "dropped_since_previous": dropped - reported_drops
                    }))?;
                    gap.push(b'\n');
                    store.append(&gap)?;
                    reported_drops = dropped;
                }
                store.append(&line)
            });
        counters.queued_bytes.fetch_sub(length, Ordering::Relaxed);
        if result.is_ok() {
            counters.written.fetch_add(1, Ordering::Relaxed);
        } else {
            counters.errors.fetch_add(1, Ordering::Relaxed);
            counters.dropped.fetch_add(1, Ordering::Relaxed);
            counters.healthy.store(false, Ordering::Relaxed);
        }
    }
}

impl Store {
    fn open(directory: &Path, backups: usize, rotate_bytes: u64) -> io::Result<Self> {
        fs::create_dir_all(directory)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(directory.join("writer.lock"))?;
        lock.try_lock().map_err(io::Error::other)?;
        let mut segments = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(id) = name
                .strip_prefix("audit.")
                .and_then(|name| name.strip_suffix(".jsonl"))
                .and_then(|name| Uuid::parse_str(name).ok())
            else {
                continue;
            };
            segments.push(Segment {
                id,
                path: entry.path(),
                length: entry.metadata()?.len(),
            });
        }
        segments.sort_by_key(|segment| {
            fs::metadata(&segment.path)
                .and_then(|metadata| metadata.modified())
                .ok()
        });
        let active_path = directory.join("audit.jsonl");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&active_path)?;
        let original_length = file.metadata()?.len();
        let valid_length = complete_tail_length(&mut file, original_length)?;
        file.set_len(valid_length)?;
        file.seek(SeekFrom::Start(0))?;
        let read_length = usize::try_from(valid_length.min(1024)).map_err(io::Error::other)?;
        let mut header = vec![0; read_length];
        file.read_exact(&mut header)?;
        if let Some(end) = header.iter().position(|byte| *byte == b'\n') {
            header.truncate(end);
        }
        let active_id = serde_json::from_slice::<Value>(&header)
            .ok()
            .and_then(|value| {
                value
                    .get("segment_id")?
                    .as_str()
                    .and_then(|id| Uuid::parse_str(id).ok())
            })
            .unwrap_or_else(Uuid::new_v4);
        file.seek(SeekFrom::End(0))?;
        segments.push(Segment {
            id: active_id,
            path: active_path,
            length: valid_length,
        });
        let mut store = Self {
            _lock: lock,
            directory: directory.to_owned(),
            file,
            segments,
            backups,
            rotate_bytes,
            recovered_bytes: original_length - valid_length,
            oversize_records: 0,
            cursors: HashMap::new(),
            cursor_order: VecDeque::new(),
            successors: HashMap::new(),
        };
        if valid_length == 0 {
            store.write_header()?;
        }
        store.prune()?;
        Ok(store)
    }

    fn write_header(&mut self) -> io::Result<()> {
        let segment = self
            .segments
            .last_mut()
            .ok_or_else(|| io::Error::other("missing active audit segment"))?;
        let line = format!(
            "{}\n",
            json!({"kind":"segment","segment_id":segment.id,"timestamp_unix_ms":now_ms()})
        );
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        segment.length = u64::try_from(line.len()).map_err(io::Error::other)?;
        Ok(())
    }

    fn prune(&mut self) -> io::Result<()> {
        while self.segments.len() > self.backups + 1 {
            fs::remove_file(&self.segments[0].path)?;
            self.segments.remove(0);
        }
        Ok(())
    }

    fn append(&mut self, line: &[u8]) -> io::Result<()> {
        let active = self
            .segments
            .last()
            .ok_or_else(|| io::Error::other("missing active audit segment"))?;
        let line_length = u64::try_from(line.len()).map_err(io::Error::other)?;
        if active.length + line_length > self.rotate_bytes && active.length > 256 {
            self.file.sync_data()?;
            let backup_path = self.directory.join(format!("audit.{}.jsonl", active.id));
            fs::rename(&active.path, &backup_path)?;
            self.segments
                .last_mut()
                .ok_or_else(|| io::Error::other("missing active audit segment"))?
                .path = backup_path;
            let active_path = self.directory.join("audit.jsonl");
            self.file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&active_path)?;
            self.segments.push(Segment {
                id: Uuid::new_v4(),
                path: active_path,
                length: 0,
            });
            self.write_header()?;
            self.prune()?;
        }
        let start = self.file.stream_position()?;
        if let Err(error) = self
            .file
            .write_all(line)
            .and_then(|()| self.file.sync_data())
        {
            self.file.set_len(start)?;
            self.file.seek(SeekFrom::Start(start))?;
            return Err(error);
        }
        if line_length > self.rotate_bytes {
            self.oversize_records += 1;
        }
        self.segments
            .last_mut()
            .ok_or_else(|| io::Error::other("missing active audit segment"))?
            .length += line_length;
        Ok(())
    }
}

fn complete_tail_length(file: &mut File, length: u64) -> io::Result<u64> {
    if length == 0 {
        return Ok(0);
    }
    let mut end = length;
    let mut buffer = [0_u8; 8192];
    while end > 0 {
        let start = end.saturating_sub(buffer.len() as u64);
        file.seek(SeekFrom::Start(start))?;
        let count = usize::try_from(end - start).map_err(io::Error::other)?;
        file.read_exact(&mut buffer[..count])?;
        if let Some(last) = buffer[..count].iter().rposition(|byte| *byte == b'\n') {
            return Ok(start + u64::try_from(last).map_err(io::Error::other)? + 1);
        }
        end = start;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write, sync::Arc};

    use serde_json::{Value, json};
    use tokio::sync::broadcast;
    use uuid::Uuid;

    use super::{AuditLog, Counters, Store};

    struct TemporaryDirectory(std::path::PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("x64dbg-mcp-audit-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn local_log(store: Store) -> AuditLog {
        AuditLog {
            sender: None,
            store: Some(Arc::new(std::sync::Mutex::new(store))),
            counters: Arc::new(Counters::default()),
            backend: "test".to_owned(),
            instance_id: Uuid::nil(),
            secrets: vec!["super-secret-token".to_owned()],
            unavailable: None,
            event_sender: broadcast::channel(16).0,
        }
    }

    #[test]
    fn credentials_are_recursively_redacted() {
        let log = AuditLog {
            sender: None,
            store: None,
            counters: Arc::new(Counters::default()),
            backend: "test".to_owned(),
            instance_id: Uuid::nil(),
            secrets: vec!["super-secret-token".to_owned()],
            unavailable: None,
            event_sender: broadcast::channel(16).0,
        };
        let mut value = json!({
            "authorization":"Bearer super-secret-token",
            "nested":[{"nonce":"abc"},"prefix-super-secret-token-suffix"]
        });
        log.scrub(&mut value);
        assert_eq!(value["authorization"], "[REDACTED]");
        assert_eq!(value["nested"][0]["nonce"], "[REDACTED]");
        assert_eq!(value["nested"][1], "prefix-[REDACTED]-suffix");
    }

    #[test]
    fn rotation_retention_and_crash_tail_recovery_are_bounded() {
        let directory = TemporaryDirectory::new();
        {
            let mut store = Store::open(&directory.0, 2, 300).unwrap();
            for index in 0..12 {
                let line = format!(
                    "{}\n",
                    json!({"kind":"test","index":index,"data":"x".repeat(100)})
                );
                store.append(line.as_bytes()).unwrap();
            }
            assert!(store.segments.len() <= 3);
        }
        let active = directory.0.join("audit.jsonl");
        fs::OpenOptions::new()
            .append(true)
            .open(&active)
            .unwrap()
            .write_all(b"{incomplete")
            .unwrap();
        let store = Store::open(&directory.0, 2, 300).unwrap();
        assert_eq!(store.recovered_bytes, 11);
        assert!(store.segments.len() <= 3);
    }

    #[test]
    fn log_reader_chunks_large_utf8_records_without_invalid_text() {
        let directory = TemporaryDirectory::new();
        let mut store = Store::open(&directory.0, 2, 16 * 1024).unwrap();
        let line = format!(
            "{}\n",
            json!({"kind":"unicode","text":"\u{e9}".repeat(2_000)})
        );
        store.append(line.as_bytes()).unwrap();
        let log = local_log(store);
        let mut arguments = json!({"max_bytes":1024,"limit":100});
        let mut combined = String::new();
        let mut retried_cursor = false;
        loop {
            let result = log.read(&arguments).unwrap();
            if arguments.get("cursor").is_some() && !retried_cursor {
                assert_eq!(log.read(&arguments).unwrap(), result);
                retried_cursor = true;
            }
            let text = result["text"].as_str().unwrap();
            assert!(std::str::from_utf8(text.as_bytes()).is_ok());
            combined.push_str(text);
            if result["complete"] == Value::Bool(true) {
                break;
            }
            arguments["cursor"] = result["next_cursor"].clone();
        }
        assert!(combined.contains("\u{e9}\u{e9}\u{e9}"));
        assert!(retried_cursor);
        for line in combined.lines() {
            let _: Value = serde_json::from_str(line).unwrap();
        }
    }

    #[tokio::test]
    async fn event_wait_observes_only_future_events_and_cancels_on_new_session() {
        let log = AuditLog::disabled("test", Uuid::nil(), "test");
        log.event_connected(true);
        log.publish_event(json!({
            "type":"process_created","session_id":"session-1","sequence":1,
            "state_generation":1
        }));
        log.publish_event(json!({
            "type":"resumed","session_id":"session-1","sequence":2,
            "state_generation":2
        }));

        let future_log = Arc::clone(&log);
        let future_wait = log.arm_event_wait();
        let future = tokio::spawn(async move {
            future_log
                .wait_event(
                    future_wait,
                    &json!({"types":["resumed"],"timeout_ms":1000}),
                    2,
                    "session-1",
                )
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        log.publish_event(json!({
            "type":"resumed","session_id":"session-1","sequence":3,
            "state_generation":3
        }));
        let observed = future.await.unwrap().unwrap();
        assert_eq!(observed["event"]["sequence"], 3);

        let changed_log = Arc::clone(&log);
        let changed_wait = log.arm_event_wait();
        let changed = tokio::spawn(async move {
            changed_log
                .wait_event(
                    changed_wait,
                    &json!({"types":["paused"],"timeout_ms":1000}),
                    3,
                    "session-1",
                )
                .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        log.publish_event(json!({
            "type":"process_created","session_id":"session-2","sequence":4,
            "state_generation":4
        }));
        assert_eq!(changed.await.unwrap().unwrap_err().code, "CANCELLED");
    }
}
