use crate::models::{DbStats, ScanRecord, ScanSession};
use mimic_core::{MimicError, ScanResult};
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info};

pub struct MimicDb {
    conn: Mutex<Connection>,
}

impl MimicDb {
    pub fn open(path: &Path) -> Result<Self, MimicError> {
        let conn = Connection::open(path)
            .map_err(|e| MimicError::Engine(format!("failed to open database: {e}")))?;

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        info!(path = %path.display(), "database opened");
        Ok(db)
    }

    pub fn open_memory() -> Result<Self, MimicError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| MimicError::Engine(format!("failed to open in-memory db: {e}")))?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema()?;
        Ok(db)
    }

    /// Remove all scan records and sessions (keeps schema). Use at startup for a fresh state.
    pub fn clean(&self) -> Result<(), MimicError> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM scan_records", [])
            .map_err(|e| MimicError::Engine(format!("clean records failed: {e}")))?;
        conn.execute("DELETE FROM scan_sessions", [])
            .map_err(|e| MimicError::Engine(format!("clean sessions failed: {e}")))?;
        info!("database cleaned (all sessions and records removed)");
        Ok(())
    }

    fn init_schema(&self) -> Result<(), MimicError> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scan_sessions (
                id TEXT PRIMARY KEY,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                scan_path TEXT NOT NULL,
                total_files INTEGER DEFAULT 0,
                infected INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0,
                clean INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                total_bytes INTEGER DEFAULT 0,
                duration_ms INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_records (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                md5 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                threats_json TEXT NOT NULL DEFAULT '{}',
                scan_duration_us INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                error TEXT,
                FOREIGN KEY (session_id) REFERENCES scan_sessions(id)
            );

            CREATE INDEX IF NOT EXISTS idx_records_session ON scan_records(session_id);
            CREATE INDEX IF NOT EXISTS idx_records_sha256 ON scan_records(sha256);
            CREATE INDEX IF NOT EXISTS idx_records_verdict ON scan_records(verdict);
            ",
        )
        .map_err(|e| MimicError::Engine(format!("schema init failed: {e}")))?;
        debug!("database schema initialized");
        Ok(())
    }

    pub fn create_session(&self, scan_path: &str) -> Result<String, MimicError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scan_sessions (id, started_at, scan_path) VALUES (?1, ?2, ?3)",
            params![id, now, scan_path],
        )
        .map_err(|e| MimicError::Engine(format!("create session failed: {e}")))?;
        debug!(session_id = %id, "scan session created");
        Ok(id)
    }

    pub fn finish_session(
        &self,
        session_id: &str,
        total_files: u64,
        infected: u64,
        suspicious: u64,
        clean: u64,
        errors: u64,
        total_bytes: u64,
        duration_ms: u64,
    ) -> Result<(), MimicError> {
        let now = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE scan_sessions SET finished_at=?1, total_files=?2, infected=?3,
             suspicious=?4, clean=?5, errors=?6, total_bytes=?7, duration_ms=?8
             WHERE id=?9",
            params![now, total_files, infected, suspicious, clean, errors, total_bytes, duration_ms, session_id],
        )
        .map_err(|e| MimicError::Engine(format!("finish session failed: {e}")))?;
        Ok(())
    }

    pub fn insert_result(
        &self,
        session_id: &str,
        result: &ScanResult,
    ) -> Result<(), MimicError> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let verdict_str = result.scan_verdict.verdict.to_string();
        let threats_json = serde_json::to_string(&result.scan_verdict).unwrap_or_default();

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scan_records (id, session_id, path, sha256, md5, size_bytes,
             verdict, threats_json, scan_duration_us, scanned_at, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                session_id,
                result.path,
                result.sha256,
                result.md5,
                result.size_bytes,
                verdict_str,
                threats_json,
                result.scan_duration_us,
                now,
                result.error,
            ],
        )
        .map_err(|e| MimicError::Engine(format!("insert result failed: {e}")))?;
        Ok(())
    }

    pub fn get_sessions(&self, limit: u32) -> Result<Vec<ScanSession>, MimicError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, started_at, finished_at, scan_path, total_files, infected,
                 suspicious, clean, errors, total_bytes, duration_ms
                 FROM scan_sessions ORDER BY started_at DESC LIMIT ?1",
            )
            .map_err(|e| MimicError::Engine(format!("query sessions: {e}")))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(ScanSession {
                    id: row.get(0)?,
                    started_at: row.get(1)?,
                    finished_at: row.get(2)?,
                    scan_path: row.get(3)?,
                    total_files: row.get::<_, i64>(4)? as u64,
                    infected: row.get::<_, i64>(5)? as u64,
                    suspicious: row.get::<_, i64>(6)? as u64,
                    clean: row.get::<_, i64>(7)? as u64,
                    errors: row.get::<_, i64>(8)? as u64,
                    total_bytes: row.get::<_, i64>(9)? as u64,
                    duration_ms: row.get::<_, i64>(10)? as u64,
                })
            })
            .map_err(|e| MimicError::Engine(format!("query sessions: {e}")))?;

        let mut sessions = Vec::new();
        for row in rows {
            sessions.push(row.map_err(|e| MimicError::Engine(e.to_string()))?);
        }
        Ok(sessions)
    }

    pub fn get_session_records(
        &self,
        session_id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ScanRecord>, MimicError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, session_id, path, sha256, md5, size_bytes, verdict,
                 threats_json, scan_duration_us, scanned_at, error
                 FROM scan_records WHERE session_id=?1
                 ORDER BY scanned_at DESC LIMIT ?2 OFFSET ?3",
            )
            .map_err(|e| MimicError::Engine(format!("query records: {e}")))?;

        let rows = stmt
            .query_map(params![session_id, limit, offset], |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    path: row.get(2)?,
                    sha256: row.get(3)?,
                    md5: row.get(4)?,
                    size_bytes: row.get::<_, i64>(5)? as u64,
                    verdict: row.get(6)?,
                    threats_json: row.get(7)?,
                    scan_duration_us: row.get::<_, i64>(8)? as u64,
                    scanned_at: row.get(9)?,
                    error: row.get(10)?,
                })
            })
            .map_err(|e| MimicError::Engine(format!("query records: {e}")))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| MimicError::Engine(e.to_string()))?);
        }
        Ok(records)
    }

    pub fn get_records_by_verdict(
        &self,
        verdict: &str,
        limit: u32,
    ) -> Result<Vec<ScanRecord>, MimicError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, session_id, path, sha256, md5, size_bytes, verdict,
                 threats_json, scan_duration_us, scanned_at, error
                 FROM scan_records WHERE verdict=?1
                 ORDER BY scanned_at DESC LIMIT ?2",
            )
            .map_err(|e| MimicError::Engine(format!("query by verdict: {e}")))?;

        let rows = stmt
            .query_map(params![verdict, limit], |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    path: row.get(2)?,
                    sha256: row.get(3)?,
                    md5: row.get(4)?,
                    size_bytes: row.get::<_, i64>(5)? as u64,
                    verdict: row.get(6)?,
                    threats_json: row.get(7)?,
                    scan_duration_us: row.get::<_, i64>(8)? as u64,
                    scanned_at: row.get(9)?,
                    error: row.get(10)?,
                })
            })
            .map_err(|e| MimicError::Engine(format!("query by verdict: {e}")))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| MimicError::Engine(e.to_string()))?);
        }
        Ok(records)
    }

    pub fn search_by_hash(&self, hash: &str) -> Result<Vec<ScanRecord>, MimicError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT id, session_id, path, sha256, md5, size_bytes, verdict,
                 threats_json, scan_duration_us, scanned_at, error
                 FROM scan_records WHERE sha256=?1 OR md5=?1
                 ORDER BY scanned_at DESC",
            )
            .map_err(|e| MimicError::Engine(format!("search hash: {e}")))?;

        let rows = stmt
            .query_map(params![hash], |row| {
                Ok(ScanRecord {
                    id: row.get(0)?,
                    session_id: row.get(1)?,
                    path: row.get(2)?,
                    sha256: row.get(3)?,
                    md5: row.get(4)?,
                    size_bytes: row.get::<_, i64>(5)? as u64,
                    verdict: row.get(6)?,
                    threats_json: row.get(7)?,
                    scan_duration_us: row.get::<_, i64>(8)? as u64,
                    scanned_at: row.get(9)?,
                    error: row.get(10)?,
                })
            })
            .map_err(|e| MimicError::Engine(format!("search hash: {e}")))?;

        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(|e| MimicError::Engine(e.to_string()))?);
        }
        Ok(records)
    }

    pub fn get_stats(&self) -> Result<DbStats, MimicError> {
        let conn = self.conn.lock().unwrap();

        let total_sessions: i64 = conn
            .query_row("SELECT COUNT(*) FROM scan_sessions", [], |r| r.get(0))
            .unwrap_or(0);
        let total_files: i64 = conn
            .query_row("SELECT COUNT(*) FROM scan_records", [], |r| r.get(0))
            .unwrap_or(0);
        let total_infected: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_records WHERE verdict='INFECTED'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let total_suspicious: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scan_records WHERE verdict='SUSPICIOUS'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let total_bytes: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(size_bytes), 0) FROM scan_records",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let unique_hashes: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT sha256) FROM scan_records WHERE sha256 != ''",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let mut stmt = conn
            .prepare(
                "SELECT threats_json, COUNT(*) as cnt FROM scan_records
                 WHERE verdict IN ('INFECTED', 'SUSPICIOUS')
                 GROUP BY threats_json ORDER BY cnt DESC LIMIT 20",
            )
            .map_err(|e| MimicError::Engine(format!("stats query: {e}")))?;

        let top_threats: Vec<(String, u64)> = stmt
            .query_map([], |row| {
                let json: String = row.get(0)?;
                let cnt: i64 = row.get(1)?;
                Ok((json, cnt as u64))
            })
            .map_err(|e| MimicError::Engine(format!("stats query: {e}")))?
            .filter_map(|r| r.ok())
            .collect();

        Ok(DbStats {
            total_sessions: total_sessions as u64,
            total_files_scanned: total_files as u64,
            total_infected: total_infected as u64,
            total_suspicious: total_suspicious as u64,
            total_bytes_scanned: total_bytes as u64,
            unique_hashes: unique_hashes as u64,
            top_threats,
        })
    }
}
