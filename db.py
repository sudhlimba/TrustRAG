"""
TrustRAG Database Layer
Supports dual-mode operations: SQLite for zero-setup local dev and PostgreSQL for production.
Manages 'users' and 'audit_logs' tables.
"""

import os
import sqlite3
import hashlib
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import config

GENESIS_HASH = "GENESIS_BLOCK_00000000000000000000000000000000000000000000000000000000"

# Try to import psycopg2 if postgres is needed
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


_pg_pool = None


def is_postgres() -> bool:
    """Determine if PostgreSQL should be used."""
    return (config.DB_TYPE == "postgres" or bool(config.DATABASE_URL)) and PSYCOPG2_AVAILABLE


def get_connection():
    """Returns an active database connection based on configuration."""
    global _pg_pool
    if is_postgres():
        if _pg_pool is None:
            from psycopg2.pool import ThreadedConnectionPool
            _pg_pool = ThreadedConnectionPool(minconn=1, maxconn=10, dsn=config.DATABASE_URL)
        return _pg_pool.getconn()
    else:
        conn = sqlite3.connect(config.DB_SQLITE_PATH)
        conn.row_factory = sqlite3.Row  # Access columns by name
        return conn


def release_connection(conn, use_pg: bool):
    """Safely closes connection or returns it to the connection pool."""
    if use_pg and _pg_pool is not None:
        _pg_pool.putconn(conn)
    else:
        conn.close()


def _format_sql_for_engine(sql: str, use_postgres: bool) -> str:
    """
    Translates standard ? parameter placeholders into %s if using PostgreSQL.
    Safely ignores ? inside single-quoted string literals.
    """
    if use_postgres:
        import re
        parts = re.split(r"('(?:''|[^'])*')", sql)
        for i in range(0, len(parts), 2):
            parts[i] = parts[i].replace("?", "%s")
        return "".join(parts)
    return sql


def execute_write(sql: str, params: tuple = ()) -> int:
    """Executes an INSERT/UPDATE/DELETE query and returns the last row ID or affected rows."""
    use_pg = is_postgres()
    conn = get_connection()
    try:
        cur = conn.cursor()
        formatted_sql = _format_sql_for_engine(sql, use_pg)
        
        # Postgres lastrowid support: append RETURNING id for INSERT queries if not present
        trimmed = formatted_sql.strip()
        is_insert = trimmed.upper().startswith("INSERT")
        if use_pg and is_insert and "RETURNING" not in trimmed.upper():
            formatted_sql = trimmed.rstrip(";") + " RETURNING id;"
            cur.execute(formatted_sql, params)
            res = cur.fetchone()
            last_id = res[0] if res else 0
        else:
            cur.execute(formatted_sql, params)
            last_id = getattr(cur, "lastrowid", 0) or getattr(cur, "rowcount", 0)

        conn.commit()
        return last_id
    finally:
        release_connection(conn, use_pg)


def execute_read_one(sql: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
    """Executes a SELECT query and returns a single row as a dictionary."""
    use_pg = is_postgres()
    conn = get_connection()
    try:
        if use_pg:
            cur = conn.cursor(cursor_factory=RealDictCursor)
        else:
            cur = conn.cursor()

        formatted_sql = _format_sql_for_engine(sql, use_pg)
        cur.execute(formatted_sql, params)
        row = cur.fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        release_connection(conn, use_pg)


def execute_read_all(sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    """Executes a SELECT query and returns all matching rows as dictionaries."""
    use_pg = is_postgres()
    conn = get_connection()
    try:
        if use_pg:
            cur = conn.cursor(cursor_factory=RealDictCursor)
        else:
            cur = conn.cursor()

        formatted_sql = _format_sql_for_engine(sql, use_pg)
        cur.execute(formatted_sql, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        release_connection(conn, use_pg)


def init_db():
    """Initializes the database schema for users and audit_logs."""
    use_pg = is_postgres()
    conn = get_connection()
    try:
        cur = conn.cursor()

        if use_pg:
            # PostgreSQL Schema
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(64) NOT NULL,
                    clearance_level INT NOT NULL CHECK (clearance_level BETWEEN 1 AND 4),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    username VARCHAR(64) NOT NULL,
                    clearance_level INT NOT NULL,
                    prompt TEXT NOT NULL,
                    attack_detected BOOLEAN NOT NULL DEFAULT FALSE,
                    attack_reason TEXT,
                    chunks_retrieved_count INT DEFAULT 0,
                    response TEXT,
                    latency_ms INT DEFAULT 0,
                    prev_hash VARCHAR(64) DEFAULT 'GENESIS_BLOCK_00000000000000000000000000000000000000000000000000000000',
                    record_hash VARCHAR(64)
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_requests (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    role VARCHAR(64) NOT NULL,
                    requested_clearance INT NOT NULL CHECK (requested_clearance BETWEEN 1 AND 4),
                    justification TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by VARCHAR(64),
                    reviewed_at TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS clearance_escalation_requests (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    current_clearance INT NOT NULL,
                    requested_clearance INT NOT NULL CHECK (requested_clearance BETWEEN 1 AND 4),
                    justification TEXT,
                    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by VARCHAR(64),
                    reviewed_at TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS document_access_requests (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(64) NOT NULL,
                    document_name VARCHAR(255) NOT NULL,
                    document_clearance INT NOT NULL,
                    justification TEXT,
                    duration_hours INT NOT NULL DEFAULT 4,
                    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
                    requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by VARCHAR(64),
                    expires_at TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS inbox_notifications (
                    id SERIAL PRIMARY KEY,
                    recipient_username VARCHAR(64) NOT NULL,
                    sender_username VARCHAR(64) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    category VARCHAR(64) NOT NULL,
                    is_read BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
        else:
            # SQLite Schema
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    clearance_level INTEGER NOT NULL CHECK (clearance_level BETWEEN 1 AND 4),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    username TEXT NOT NULL,
                    clearance_level INTEGER NOT NULL,
                    prompt TEXT NOT NULL,
                    attack_detected INTEGER NOT NULL DEFAULT 0,
                    attack_reason TEXT,
                    chunks_retrieved_count INTEGER DEFAULT 0,
                    response TEXT,
                    latency_ms INTEGER DEFAULT 0,
                    prev_hash TEXT,
                    record_hash TEXT
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    requested_clearance INTEGER NOT NULL CHECK (requested_clearance BETWEEN 1 AND 4),
                    justification TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by TEXT,
                    reviewed_at DATETIME
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS clearance_escalation_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    current_clearance INTEGER NOT NULL,
                    requested_clearance INTEGER NOT NULL CHECK (requested_clearance BETWEEN 1 AND 4),
                    justification TEXT,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by TEXT,
                    reviewed_at DATETIME
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS document_access_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    document_name TEXT NOT NULL,
                    document_clearance INTEGER NOT NULL,
                    justification TEXT,
                    duration_hours INTEGER NOT NULL DEFAULT 4,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reviewed_by TEXT,
                    expires_at DATETIME
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS inbox_notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_username TEXT NOT NULL,
                    sender_username TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    category TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
            """)

            # Auto-migrate SQLite audit_logs columns & backfill hash chain if missing
            try:
                cur.execute("PRAGMA table_info(audit_logs)")
                col_names = [c[1] for c in cur.fetchall()]
                if "prev_hash" not in col_names:
                    cur.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")
                if "record_hash" not in col_names:
                    cur.execute("ALTER TABLE audit_logs ADD COLUMN record_hash TEXT")

                # Backfill cryptographic hash chain for any legacy unhashed records
                cur.execute("SELECT id, prev_hash, record_hash, username, clearance_level, prompt, attack_detected, attack_reason, chunks_retrieved_count, response FROM audit_logs ORDER BY id ASC")
                all_logs = cur.fetchall()
                running_h = GENESIS_HASH
                for row in all_logs:
                    l_id = row[0]
                    cur_rec_h = row[2]
                    if not cur_rec_h:
                        f_str = "1" if row[6] in (1, True, "1") else "0"
                        r_str = row[7] or ""
                        resp_str = row[9] or ""
                        payload = f"{running_h}|{row[3]}|{row[4]}|{row[5]}|{f_str}|{r_str}|{row[8]}|{resp_str}"
                        cur_rec_h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
                        cur.execute("UPDATE audit_logs SET prev_hash = ?, record_hash = ? WHERE id = ?", (running_h, cur_rec_h, l_id))
                    running_h = cur_rec_h
            except Exception as mig_err:
                print(f"[Migration Warning] audit_logs schema check: {mig_err}")


            # Auto-migrate SQLite user_requests if previously created with UNIQUE constraint
            try:
                cur.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='user_requests'")
                t_row = cur.fetchone()
                if t_row and "username TEXT UNIQUE NOT NULL" in t_row[0]:
                    cur.execute("ALTER TABLE user_requests RENAME TO user_requests_old")
                    cur.execute("""
                        CREATE TABLE user_requests (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT NOT NULL,
                            password_hash TEXT NOT NULL,
                            role TEXT NOT NULL,
                            requested_clearance INTEGER NOT NULL CHECK (requested_clearance BETWEEN 1 AND 4),
                            justification TEXT,
                            status TEXT NOT NULL DEFAULT 'PENDING',
                            requested_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            reviewed_by TEXT,
                            reviewed_at DATETIME
                        );
                    """)
                    cur.execute("""
                        INSERT INTO user_requests (id, username, password_hash, role, requested_clearance, justification, status, requested_at, reviewed_by, reviewed_at)
                        SELECT id, username, password_hash, role, requested_clearance, justification, status, requested_at, reviewed_by, reviewed_at FROM user_requests_old;
                    """)
                    cur.execute("DROP TABLE user_requests_old;")
            except Exception as mig_err:
                print(f"[Migration Warning] user_requests schema check: {mig_err}")

        conn.commit()
    finally:
        conn.close()


# ==============================================================================
# User CRUD Helpers
# ==============================================================================

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Fetches a user record by username."""
    sql = "SELECT id, username, password_hash, role, clearance_level, created_at FROM users WHERE username = ?"
    return execute_read_one(sql, (username,))


def create_user(username: str, password_hash: str, role: str, clearance_level: int) -> bool:
    """Inserts a new user into the database."""
    sql = """
        INSERT INTO users (username, password_hash, role, clearance_level)
        VALUES (?, ?, ?, ?)
    """
    try:
        execute_write(sql, (username, password_hash, role, clearance_level))
        return True
    except Exception as e:
        print(f"Error creating user {username}: {e}")
        return False


def get_all_users() -> List[Dict[str, Any]]:
    """Returns all users without sensitive password hashes."""
    sql = "SELECT id, username, role, clearance_level, created_at FROM users ORDER BY clearance_level ASC"
    return execute_read_all(sql)


def delete_user(username: str, reviewer_username: str) -> Tuple[bool, str]:
    """Permanently offboards and removes a user from active directory."""
    username = username.strip().lower()
    default_protected = ["exec_david", "hr_elena", "dev_sarah", "intern_bob", "alice_analyst"]
    if username in default_protected:
        return False, f"User '{username}' is a core system persona and cannot be deleted."

    user = get_user_by_username(username)
    if not user:
        return False, f"User '{username}' does not exist in directory."

    try:
        # Revoke any active document grants
        execute_write("DELETE FROM document_access_requests WHERE username = ?", (username,))
        # Remove user requests
        execute_write("DELETE FROM user_requests WHERE username = ?", (username,))
        # Remove notifications
        execute_write("DELETE FROM inbox_notifications WHERE recipient_username = ?", (username,))
        # Delete user
        execute_write("DELETE FROM users WHERE username = ?", (username,))

        log_audit_event(
            username=reviewer_username,
            clearance_level=4,
            prompt=f"[User Offboarding] Executive '{reviewer_username}' removed account '{username}' from enterprise directory",
            attack_detected=False,
            attack_reason=None,
            chunks_retrieved_count=0,
            response="User account purged and sessions terminated.",
            latency_ms=0
        )
        return True, f"Successfully offboarded and removed user '{username}'."
    except Exception as e:
        return False, f"Database error offboarding user: {e}"


def update_user_clearance(username: str, new_level: int, reviewer_username: str) -> Tuple[bool, str]:
    """Updates user clearance level directly."""
    username = username.strip().lower()
    user = get_user_by_username(username)
    if not user:
        return False, f"User '{username}' not found."
    if new_level not in [1, 2, 3, 4]:
        return False, "Clearance level must be between 1 and 4."

    try:
        execute_write("UPDATE users SET clearance_level = ? WHERE username = ?", (new_level, username))
        log_audit_event(
            username=reviewer_username,
            clearance_level=4,
            prompt=f"[Clearance Adjustment] Executive '{reviewer_username}' set '{username}' clearance to Level {new_level}",
            attack_detected=False,
            attack_reason=None,
            chunks_retrieved_count=0,
            response="Clearance adjusted.",
            latency_ms=0
        )
        create_notification(
            recipient_username=username,
            sender_username=reviewer_username,
            title="🛡️ Security Clearance Adjusted",
            message=f"Your security clearance was updated to Level {new_level} ({config.CLEARANCE_LEVELS[new_level]['name']}) by {reviewer_username}.",
            category="SECURITY"
        )
        return True, f"Updated '{username}' clearance to Level {new_level}."
    except Exception as e:
        return False, f"Database error updating clearance: {e}"


# ==============================================================================
# Audit Log Helpers
# ==============================================================================

def compute_audit_hash(
    prev_hash: str,
    username: str,
    clearance_level: int,
    prompt: str,
    attack_detected: Any,
    attack_reason: Optional[str],
    chunks_retrieved_count: int,
    response: Optional[str]
) -> str:
    """Computes a deterministic SHA-256 hash for tamper-proof audit log chaining."""
    flag_str = "1" if attack_detected in (1, True, "1") else "0"
    reason_str = attack_reason or ""
    resp_str = response or ""
    payload = f"{prev_hash}|{username}|{clearance_level}|{prompt}|{flag_str}|{reason_str}|{chunks_retrieved_count}|{resp_str}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_audit_event(
    username: str,
    clearance_level: int,
    prompt: str,
    attack_detected: bool,
    attack_reason: Optional[str] = None,
    chunks_retrieved_count: int = 0,
    response: Optional[str] = None,
    latency_ms: int = 0
) -> int:
    """Records an audit trail event with cryptographic SHA-256 hash-chaining."""
    last_log = execute_read_one("SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1")
    prev_hash = (last_log["record_hash"] if last_log and last_log.get("record_hash") else GENESIS_HASH)

    flag = True if attack_detected else False
    if not is_postgres():
        flag = 1 if attack_detected else 0

    record_hash = compute_audit_hash(
        prev_hash=prev_hash,
        username=username,
        clearance_level=clearance_level,
        prompt=prompt,
        attack_detected=flag,
        attack_reason=attack_reason,
        chunks_retrieved_count=chunks_retrieved_count,
        response=response
    )

    sql = """
        INSERT INTO audit_logs 
        (username, clearance_level, prompt, attack_detected, attack_reason, chunks_retrieved_count, response, latency_ms, prev_hash, record_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    return execute_write(sql, (
        username,
        clearance_level,
        prompt,
        flag,
        attack_reason,
        chunks_retrieved_count,
        response,
        latency_ms,
        prev_hash,
        record_hash
    ))


def get_audit_logs(limit: int = 200) -> List[Dict[str, Any]]:
    """Retrieves the most recent audit logs for security telemetry."""
    sql = "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?"
    return execute_read_all(sql, (limit,))


def verify_audit_log_integrity() -> Dict[str, Any]:
    """
    Validates the entire cryptographic SHA-256 hash chain of the audit ledger.
    Detects any unauthorized modification, deletion, or insertion of audit records.
    """
    sql = "SELECT id, timestamp, username, clearance_level, prompt, attack_detected, attack_reason, chunks_retrieved_count, response, prev_hash, record_hash FROM audit_logs ORDER BY id ASC"
    records = execute_read_all(sql)
    if not records:
        return {
            "is_valid": True,
            "verified_count": 0,
            "error_msg": None,
            "total_records": 0,
            "latest_hash": GENESIS_HASH
        }

    expected_prev = GENESIS_HASH
    for idx, rec in enumerate(records):
        rec_id = rec["id"]
        actual_prev = rec.get("prev_hash") or ""
        actual_hash = rec.get("record_hash") or ""

        # Verify chain linkage
        if actual_prev != expected_prev:
            return {
                "is_valid": False,
                "verified_count": idx,
                "error_msg": f"Broken Hash Chain at Record #{rec_id}: expected prev_hash '{expected_prev[:16]}...', found '{actual_prev[:16]}...'",
                "total_records": len(records),
                "tampered_id": rec_id
            }

        # Verify record content hash
        computed_hash = compute_audit_hash(
            prev_hash=actual_prev,
            username=rec["username"],
            clearance_level=rec["clearance_level"],
            prompt=rec["prompt"],
            attack_detected=rec["attack_detected"],
            attack_reason=rec["attack_reason"],
            chunks_retrieved_count=rec["chunks_retrieved_count"],
            response=rec["response"]
        )

        if computed_hash != actual_hash:
            return {
                "is_valid": False,
                "verified_count": idx,
                "error_msg": f"Cryptographic Signature Mismatch at Record #{rec_id}: Content was modified after insertion!",
                "total_records": len(records),
                "tampered_id": rec_id
            }

        expected_prev = actual_hash

    return {
        "is_valid": True,
        "verified_count": len(records),
        "error_msg": None,
        "total_records": len(records),
        "latest_hash": expected_prev
    }


def get_audit_summary() -> Dict[str, Any]:
    """Generates summary statistics of security queries and attacks."""
    total_queries_sql = "SELECT COUNT(*) as count FROM audit_logs"
    attacks_sql = "SELECT COUNT(*) as count FROM audit_logs WHERE attack_detected = 1 OR attack_detected = TRUE"
    
    total = execute_read_one(total_queries_sql)
    attacks = execute_read_one(attacks_sql)
    
    total_count = total["count"] if total else 0
    attack_count = attacks["count"] if attacks else 0
    
    return {
        "total_queries": total_count,
        "attacks_blocked": attack_count,
        "clean_queries": total_count - attack_count
    }


# ==============================================================================
# User Provisioning & Approval Helpers
# ==============================================================================

def submit_user_request(
    username: str,
    password_hash: str,
    role: str,
    requested_clearance: int,
    justification: str = ""
) -> Tuple[bool, str]:
    """Submits a new membership application requiring Executive approval."""
    username = username.strip().lower()
    existing_user = get_user_by_username(username)
    if existing_user:
        return False, f"Username '{username}' already exists in active directory."

    existing_req = execute_read_one("SELECT id, status FROM user_requests WHERE username = ? AND status = 'PENDING'", (username,))
    if existing_req:
        return False, f"A pending application for '{username}' is already awaiting Executive review."

    sql = """
        INSERT INTO user_requests (username, password_hash, role, requested_clearance, justification, status)
        VALUES (?, ?, ?, ?, ?, 'PENDING')
    """
    try:
        execute_write(sql, (username, password_hash, role, requested_clearance, justification))
        log_audit_event(
            username=username,
            clearance_level=requested_clearance,
            prompt=f"[Account Request] User '{username}' applied for Clearance Level {requested_clearance} ({role})",
            attack_detected=False,
            attack_reason=None,
            chunks_retrieved_count=0,
            response="Application submitted, pending Executive authorization.",
            latency_ms=0
        )
        return True, "Application submitted successfully! An Executive must approve your account before login."
    except Exception as e:
        return False, f"Database error: {e}"


def get_pending_user_requests() -> List[Dict[str, Any]]:
    """Fetches all pending user registration requests for Executive review."""
    sql = "SELECT id, username, role, requested_clearance, justification, requested_at, status FROM user_requests WHERE status = 'PENDING' ORDER BY id ASC"
    return execute_read_all(sql)


def approve_user_request(request_id: int, reviewer_username: str) -> bool:
    """Approves a pending user request, creates the active user, and logs the authorization."""
    req = execute_read_one("SELECT * FROM user_requests WHERE id = ?", (request_id,))
    if not req or req["status"] != "PENDING":
        return False

    # Create active user
    created = create_user(
        username=req["username"],
        password_hash=req["password_hash"],
        role=req["role"],
        clearance_level=req["requested_clearance"]
    )
    if not created:
        return False

    # Update request status
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    execute_write("UPDATE user_requests SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                  (reviewer_username, now_str, request_id))

    log_audit_event(
        username=reviewer_username,
        clearance_level=4,
        prompt=f"[User Approved] Executive '{reviewer_username}' approved account '{req['username']}' at Clearance Level {req['requested_clearance']}",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response="Account provisioned and active.",
        latency_ms=0
    )

    create_notification(
        recipient_username=req["username"],
        sender_username=reviewer_username,
        title="🟢 Account Authorized & Active",
        message=f"Executive {reviewer_username} authorized your account at Clearance Level {req['requested_clearance']} ({req['role']}). You may now log in.",
        category="ACCOUNT_APPROVED"
    )
    return True


def reject_user_request(request_id: int, reviewer_username: str, reason: str = "Executive authorization declined.") -> bool:
    """Rejects a user registration request."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    req = execute_read_one("SELECT * FROM user_requests WHERE id = ?", (request_id,))
    if not req:
        return False

    execute_write("UPDATE user_requests SET status = 'REJECTED', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
                  (reviewer_username, now_str, request_id))

    log_audit_event(
        username=reviewer_username,
        clearance_level=4,
        prompt=f"[User Rejected] Executive '{reviewer_username}' rejected application for '{req['username']}'",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response="Account request rejected.",
        latency_ms=0
    )

    create_notification(
        recipient_username=req["username"],
        sender_username=reviewer_username,
        title="🔴 Account Registration Rejected",
        message=f"Executive {reviewer_username} declined your membership request.\nNote: {reason}",
        category="ACCOUNT_REJECTED"
    )
    return True


# ==============================================================================
# Permanent Clearance Escalation Workflow Helpers
# ==============================================================================

def submit_clearance_escalation(
    username: str,
    current_clearance: int,
    requested_clearance: int,
    justification: str = ""
) -> Tuple[bool, str]:
    """Submits a permanent clearance level escalation request for Executive approval."""
    username = username.strip().lower()
    if requested_clearance <= current_clearance:
        return False, f"Requested clearance (Level {requested_clearance}) must be higher than your current clearance (Level {current_clearance})."

    existing_req = execute_read_one(
        "SELECT id FROM clearance_escalation_requests WHERE username = ? AND status = 'PENDING'",
        (username,)
    )
    if existing_req:
        return False, "You already have an active clearance escalation request awaiting Executive review."

    sql = """
        INSERT INTO clearance_escalation_requests (username, current_clearance, requested_clearance, justification, status)
        VALUES (?, ?, ?, ?, 'PENDING')
    """
    try:
        execute_write(sql, (username, current_clearance, requested_clearance, justification))
        log_audit_event(
            username=username,
            clearance_level=current_clearance,
            prompt=f"[Clearance Promotion Request] User '{username}' requested promotion from Level {current_clearance} to Level {requested_clearance}",
            attack_detected=False,
            attack_reason=None,
            chunks_retrieved_count=0,
            response="Clearance promotion request submitted for Executive review.",
            latency_ms=0
        )
        # Dispatch notification to all Level 4 Executives
        execs = execute_read_all("SELECT username FROM users WHERE clearance_level = 4")
        for ex in execs:
            create_notification(
                recipient_username=ex["username"],
                sender_username=username,
                title="⭐ Clearance Promotion Request",
                message=f"User '{username}' (Level {current_clearance}) has requested permanent promotion to Level {requested_clearance}.\nJustification: {justification}",
                category="PROMOTION_REQUEST"
            )
        return True, f"Clearance escalation to Level {requested_clearance} successfully submitted to Executive review!"
    except Exception as e:
        return False, f"Database error: {e}"


def get_pending_clearance_escalations() -> List[Dict[str, Any]]:
    """Retrieves all pending clearance escalation requests for Executive review."""
    sql = "SELECT * FROM clearance_escalation_requests WHERE status = 'PENDING' ORDER BY id ASC"
    return execute_read_all(sql)


def get_user_clearance_escalations(username: str) -> List[Dict[str, Any]]:
    """Retrieves clearance escalation request history for a specific user."""
    sql = "SELECT * FROM clearance_escalation_requests WHERE username = ? ORDER BY id DESC"
    return execute_read_all(sql, (username,))


def approve_clearance_escalation(request_id: int, reviewer_username: str) -> Tuple[bool, str]:
    """Approves a clearance escalation request and permanently updates the user's clearance level."""
    req = execute_read_one("SELECT * FROM clearance_escalation_requests WHERE id = ?", (request_id,))
    if not req:
        return False, "Clearance request not found."
    if req["status"] != "PENDING":
        return False, f"Request already resolved ({req['status']})."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_user = req["username"]
    new_level = req["requested_clearance"]

    # 1. Update request status
    execute_write(
        "UPDATE clearance_escalation_requests SET status = 'APPROVED', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
        (reviewer_username, now_str, request_id)
    )

    # 2. Update user's clearance_level in users table
    execute_write(
        "UPDATE users SET clearance_level = ? WHERE username = ?",
        (new_level, target_user)
    )

    # 3. Log audit event
    log_audit_event(
        username=reviewer_username,
        clearance_level=4,
        prompt=f"[Clearance Promotion Approved] Executive '{reviewer_username}' promoted '{target_user}' to Clearance Level {new_level}",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response=f"Clearance promotion approved permanently.",
        latency_ms=0
    )

    # 4. Notify user in inbox
    new_level_name = config.CLEARANCE_LEVELS.get(new_level, {}).get("name", f"Level {new_level}")
    create_notification(
        recipient_username=target_user,
        sender_username=reviewer_username,
        title="🎉 Clearance Promotion Approved!",
        message=f"Executive {reviewer_username} has approved your permanent clearance escalation. Your account has been promoted to Clearance Level {new_level} ({new_level_name}).",
        category="PROMOTION_APPROVED"
    )
    return True, f"Successfully promoted '{target_user}' to Clearance Level {new_level}!"


def reject_clearance_escalation(request_id: int, reviewer_username: str, reason: str = "") -> Tuple[bool, str]:
    """Rejects a clearance escalation request."""
    req = execute_read_one("SELECT * FROM clearance_escalation_requests WHERE id = ?", (request_id,))
    if not req:
        return False, "Clearance request not found."
    if req["status"] != "PENDING":
        return False, f"Request already resolved ({req['status']})."

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target_user = req["username"]

    execute_write(
        "UPDATE clearance_escalation_requests SET status = 'REJECTED', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
        (reviewer_username, now_str, request_id)
    )

    log_audit_event(
        username=reviewer_username,
        clearance_level=4,
        prompt=f"[Clearance Promotion Rejected] Request for '{target_user}' rejected by Executive '{reviewer_username}'. Reason: {reason}",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response="Clearance promotion rejected.",
        latency_ms=0
    )

    reason_suffix = f"\nNote: {reason}" if reason else ""
    create_notification(
        recipient_username=target_user,
        sender_username=reviewer_username,
        title="🔴 Clearance Promotion Request Declined",
        message=f"Your clearance escalation request to Level {req['requested_clearance']} was reviewed and declined by Executive {reviewer_username}.{reason_suffix}",
        category="PROMOTION_REJECTED"
    )
    return True, f"Rejected clearance escalation for '{target_user}'."



# ==============================================================================
# Just-In-Time (JIT) Temporary Document Access Helpers
# ==============================================================================

def submit_doc_access_request(
    username: str,
    document_name: str,
    document_clearance: int,
    justification: str,
    duration_hours: int = 4
) -> Tuple[bool, str]:
    """Submits a temporary document clearance grant request."""
    active_grants = get_user_active_doc_grants(username)
    for g in active_grants:
        if g["document_name"] == document_name:
            return False, f"You already have active authorized access to '{document_name}' until {g.get('expires_at')}."

    sql = """
        INSERT INTO document_access_requests 
        (username, document_name, document_clearance, justification, duration_hours, status)
        VALUES (?, ?, ?, ?, ?, 'PENDING')
    """
    try:
        execute_write(sql, (username, document_name, document_clearance, justification, duration_hours))
        log_audit_event(
            username=username,
            clearance_level=document_clearance,
            prompt=f"[JIT Request] User '{username}' requested {duration_hours}h access to '{document_name}' (Level {document_clearance})",
            attack_detected=False,
            attack_reason=None,
            chunks_retrieved_count=0,
            response="Pending clearance authority sign-off.",
            latency_ms=0
        )
        # Notify eligible reviewing authorities
        try:
            authorities = execute_read_all("SELECT username FROM users WHERE clearance_level >= ?", (document_clearance,))
            for auth_user in authorities:
                if auth_user["username"] != username:
                    create_notification(
                        recipient_username=auth_user["username"],
                        sender_username=username,
                        title=f"📥 JIT Access Request: {document_name}",
                        message=f"User '{username}' requested {duration_hours}h access to '{document_name}' (Level {document_clearance}).\nJustification: {justification or 'None'}",
                        category="NEW_REQUEST"
                    )
        except Exception:
            pass

        return True, f"Request for '{document_name}' submitted for clearance authority review."
    except Exception as e:
        return False, f"Database error: {e}"


def get_pending_doc_requests(approver_clearance: int) -> List[Dict[str, Any]]:
    """
    Returns pending document requests that the approver is authorized to grant.
    An approver with Level N can grant access to any document requiring Level <= N.
    """
    sql = """
        SELECT * FROM document_access_requests 
        WHERE status = 'PENDING' AND document_clearance <= ?
        ORDER BY id DESC
    """
    return execute_read_all(sql, (approver_clearance,))


def approve_doc_request(request_id: int, reviewer_username: str, duration_hours: Optional[int] = None) -> bool:
    """Grants time-limited access to a document and notifies requester."""
    from datetime import datetime, timedelta
    req = execute_read_one("SELECT * FROM document_access_requests WHERE id = ?", (request_id,))
    if not req or req["status"] != "PENDING":
        return False

    hours = duration_hours if duration_hours is not None else req.get("duration_hours", 4)
    now = datetime.now()
    expires_at = now + timedelta(hours=hours)
    expires_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")

    execute_write("""
        UPDATE document_access_requests 
        SET status = 'APPROVED', reviewed_by = ?, duration_hours = ?, expires_at = ?
        WHERE id = ?
    """, (reviewer_username, hours, expires_str, request_id))

    log_audit_event(
        username=reviewer_username,
        clearance_level=req["document_clearance"],
        prompt=f"[JIT Approved] '{reviewer_username}' granted {hours}h access to '{req['document_name']}' for '{req['username']}'",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response=f"Access valid until {expires_str}.",
        latency_ms=0
    )

    # Inbox notification to requester
    create_notification(
        recipient_username=req["username"],
        sender_username=reviewer_username,
        title=f"🟢 Access Approved: {req['document_name']}",
        message=f"Officer {reviewer_username} has approved {hours}h temporary access to '{req['document_name']}'. Valid until {expires_str}.",
        category="GRANT_APPROVED"
    )
    return True


def reject_doc_request(request_id: int, reviewer_username: str, reason: str = "Clearance authorization denied.") -> bool:
    """Denies a document access request and notifies requester."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    req = execute_read_one("SELECT * FROM document_access_requests WHERE id = ?", (request_id,))
    if not req:
        return False

    execute_write("UPDATE document_access_requests SET status = 'REJECTED', reviewed_by = ?, expires_at = ? WHERE id = ?",
                  (reviewer_username, now_str, request_id))

    log_audit_event(
        username=reviewer_username,
        clearance_level=req["document_clearance"],
        prompt=f"[JIT Denied] '{reviewer_username}' denied access to '{req['document_name']}' for '{req['username']}'. Reason: {reason}",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response="Access denied.",
        latency_ms=0
    )

    # Inbox notification to requester
    create_notification(
        recipient_username=req["username"],
        sender_username=reviewer_username,
        title=f"🔴 Access Request Denied: {req['document_name']}",
        message=f"Officer {reviewer_username} declined your access request for '{req['document_name']}'.\nNote: {reason}",
        category="REQUEST_DENIED"
    )
    return True


def revoke_doc_grant(request_id: int, reviewer_username: str, reason: str = "Early access termination by authority") -> bool:
    """
    Emergency Kill Switch: Immediately terminates an active JIT clearance grant.
    Sets status to 'REVOKED', expires_at to current timestamp, logs a high-priority audit event,
    and sends an urgent revocation alert to the requester's inbox.
    """
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    req = execute_read_one("SELECT * FROM document_access_requests WHERE id = ?", (request_id,))
    if not req or req["status"] != "APPROVED":
        return False

    execute_write("""
        UPDATE document_access_requests 
        SET status = 'REVOKED', expires_at = ?, reviewed_by = ?
        WHERE id = ?
    """, (now_str, reviewer_username, request_id))

    log_audit_event(
        username=reviewer_username,
        clearance_level=req["document_clearance"],
        prompt=f"[JIT Kill Switch] '{reviewer_username}' terminated active access to '{req['document_name']}' for '{req['username']}' early. Reason: {reason}",
        attack_detected=False,
        attack_reason=None,
        chunks_retrieved_count=0,
        response="Access immediately revoked via emergency kill switch.",
        latency_ms=0
    )

    create_notification(
        recipient_username=req["username"],
        sender_username=reviewer_username,
        title=f"🛑 Access Revoked Early: {req['document_name']}",
        message=f"Your temporary clearance grant to '{req['document_name']}' was terminated early by {reviewer_username}.\nReason: {reason}",
        category="GRANT_REVOKED"
    )
    return True


def direct_grant_doc_access(
    username: str,
    document_name: str,
    document_clearance: int,
    duration_hours: int,
    reviewer_username: str,
    reviewer_clearance: int
) -> Tuple[bool, str]:
    """Directly grants time-limited JIT access to a document by an authorized reviewer."""
    from datetime import datetime, timedelta
    username = username.strip().lower()
    user = get_user_by_username(username)
    if not user:
        return False, f"Target user '{username}' does not exist in the enterprise directory."
    if reviewer_clearance < document_clearance:
        return False, f"Unauthorized: Granting access to Level {document_clearance} files requires at least Level {document_clearance} clearance (you hold Level {reviewer_clearance})."

    now = datetime.now()
    expires_at = now + timedelta(hours=duration_hours)
    expires_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")

    # Clear prior active or pending requests for same doc to ensure clean state
    execute_write("DELETE FROM document_access_requests WHERE username = ? AND document_name = ?", (username, document_name))

    sql = """
        INSERT INTO document_access_requests 
        (username, document_name, document_clearance, justification, duration_hours, status, reviewed_by, expires_at)
        VALUES (?, ?, ?, ?, ?, 'APPROVED', ?, ?)
    """
    try:
        execute_write(sql, (username, document_name, document_clearance, f"Direct grant by {reviewer_username} via ChatOps Copilot", duration_hours, reviewer_username, expires_str))
        log_audit_event(
            username=reviewer_username,
            clearance_level=document_clearance,
            prompt=f"[JIT Direct Grant] '{reviewer_username}' granted {duration_hours}h access to '{document_name}' for '{username}'",
            attack_detected=False,
            attack_reason=None,
            chunks_retrieved_count=0,
            response=f"Access valid until {expires_str}.",
            latency_ms=0
        )
        create_notification(
            recipient_username=username,
            sender_username=reviewer_username,
            title=f"🟢 JIT Access Granted: {document_name}",
            message=f"Authority {reviewer_username} granted you {duration_hours}h access to '{document_name}'. Valid until {expires_str}.",
            category="GRANT_APPROVED"
        )
        return True, f"Successfully granted {duration_hours}h access to '{document_name}' for user '{username}' (active until {expires_str})."
    except Exception as e:
        return False, f"Database error granting access: {e}"


def revoke_doc_grant_by_user_doc(
    username: str,
    document_name: str,
    reviewer_username: str,
    reviewer_clearance: int,
    reason: str = "Early access termination by authority"
) -> Tuple[bool, str]:
    """Revokes active JIT grant for a specified user and document."""
    username = username.strip().lower()
    grants = get_user_active_doc_grants(username)
    target_grant = None
    clean_target = document_name.strip().lower()
    for g in grants:
        if clean_target in g["document_name"].lower() or g["document_name"].lower() in clean_target:
            target_grant = g
            break
    if not target_grant:
        return False, f"No active, unexpired grant found for user '{username}' matching '{document_name}'."

    if reviewer_clearance < target_grant["document_clearance"]:
        return False, f"Unauthorized: Revoking access to Level {target_grant['document_clearance']} files requires Level {target_grant['document_clearance']}+ clearance."

    success = revoke_doc_grant(target_grant["id"], reviewer_username, reason)
    if success:
        return True, f"Successfully terminated active grant for '{target_grant['document_name']}' assigned to '{username}'."
    return False, "Failed to revoke document grant."


def get_all_active_doc_grants(reviewer_clearance: int = 4) -> List[Dict[str, Any]]:
    """Returns all currently active grants within the authority's clearance tier for monitoring and revocation."""
    sql = """
        SELECT * FROM document_access_requests 
        WHERE status = 'APPROVED' AND document_clearance <= ?
        ORDER BY id DESC
    """
    rows = execute_read_all(sql, (reviewer_clearance,))
    active = []
    now = datetime.now()
    for r in rows:
        exp_val = r.get("expires_at")
        if exp_val:
            try:
                if isinstance(exp_val, datetime):
                    exp_dt = exp_val
                else:
                    exp_dt = datetime.strptime(str(exp_val), "%Y-%m-%d %H:%M:%S")

                if exp_dt > now:
                    time_remaining = exp_dt - now
                    hours_rem = int(time_remaining.total_seconds() // 3600)
                    mins_rem = int((time_remaining.total_seconds() % 3600) // 60)
                    r["time_remaining_str"] = f"{hours_rem}h {mins_rem}m"
                    active.append(r)
            except Exception:
                pass
    return active


def get_user_active_doc_grants(username: str) -> List[Dict[str, Any]]:
    """Returns all currently valid, non-expired document grants for a user."""
    from datetime import datetime
    sql = "SELECT * FROM document_access_requests WHERE username = ? AND status = 'APPROVED'"
    rows = execute_read_all(sql, (username,))
    
    active_grants = []
    now = datetime.now()
    for r in rows:
        exp_val = r.get("expires_at")
        if exp_val:
            try:
                if isinstance(exp_val, datetime):
                    exp_dt = exp_val
                else:
                    exp_dt = datetime.strptime(str(exp_val), "%Y-%m-%d %H:%M:%S")

                if exp_dt > now:
                    time_remaining = exp_dt - now
                    hours_rem = int(time_remaining.total_seconds() // 3600)
                    mins_rem = int((time_remaining.total_seconds() % 3600) // 60)
                    r["time_remaining_str"] = f"{hours_rem}h {mins_rem}m"
                    active_grants.append(r)
            except Exception:
                pass
    return active_grants


def get_user_doc_requests(username: str) -> List[Dict[str, Any]]:
    """Returns all document access requests submitted by a user."""
    sql = "SELECT * FROM document_access_requests WHERE username = ? ORDER BY id DESC"
    return execute_read_all(sql, (username,))


def has_active_doc_access(username: str, document_name: str) -> bool:
    """Checks if a user has an active, unexpired grant for a specific document."""
    grants = get_user_active_doc_grants(username)
    return any(g["document_name"] == document_name for g in grants)


# ==============================================================================
# Inbox & Notifications Helpers
# ==============================================================================

def create_notification(
    recipient_username: str,
    sender_username: str,
    title: str,
    message: str,
    category: str = "INFO"
) -> int:
    """Dispatches a notification ticket into the user's inbox."""
    sql = """
        INSERT INTO inbox_notifications (recipient_username, sender_username, title, message, category, is_read)
        VALUES (?, ?, ?, ?, ?, 0)
    """
    return execute_write(sql, (recipient_username, sender_username, title, message, category))


def get_user_notifications(username: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches notifications for a user, newest first."""
    sql = "SELECT * FROM inbox_notifications WHERE recipient_username = ? ORDER BY id DESC LIMIT ?"
    return execute_read_all(sql, (username, limit))


def get_unread_notification_count(username: str) -> int:
    """Returns number of unread notifications for a user."""
    sql = "SELECT COUNT(*) as count FROM inbox_notifications WHERE recipient_username = ? AND (is_read = 0 OR is_read = FALSE)"
    res = execute_read_one(sql, (username,))
    return res["count"] if res else 0


def mark_notification_as_read(notif_id: int) -> bool:
    """Marks a single notification as read."""
    sql = "UPDATE inbox_notifications SET is_read = 1 WHERE id = ?"
    execute_write(sql, (notif_id,))
    return True


def mark_all_notifications_read(username: str) -> bool:
    """Marks all notifications for a user as read."""
    sql = "UPDATE inbox_notifications SET is_read = 1 WHERE recipient_username = ?"
    execute_write(sql, (username,))
    return True


def delete_notification(notif_id: int) -> bool:
    """Deletes a notification from inbox."""
    sql = "DELETE FROM inbox_notifications WHERE id = ?"
    execute_write(sql, (notif_id,))
    return True


