"""
Database Models (SQLite Persistence)
------------------------------------
Stores traffic logs, threat detections, and alert dispatch history.
Implemented using standard SQLite3 to avoid heavyweight ORM overhead
and ensure 100% lightweight student reproducibility.
"""

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "threat_detection.db"))

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite schema if not already present."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Traffic Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        query TEXT,
        status_code INTEGER NOT NULL,
        prediction TEXT NOT NULL,
        confidence REAL NOT NULL,
        severity TEXT NOT NULL,
        response_time_ms REAL
    );
    """)

    # 2. Threat Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        client_ip TEXT NOT NULL,
        threat_type TEXT NOT NULL,
        detection_source TEXT NOT NULL, -- 'ML_CLASSIFIER' or 'BEHAVIORAL_ENGINE'
        endpoint TEXT NOT NULL,
        payload TEXT,
        confidence REAL NOT NULL,
        severity TEXT NOT NULL,        -- 'HIGH', 'CRITICAL', 'WARNING'
        reason TEXT NOT NULL
    );
    """)

    # 3. Alert History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alert_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        threat_id INTEGER,
        channel TEXT NOT NULL,          -- 'EMAIL', 'SMS', 'DASHBOARD'
        recipient TEXT NOT NULL,
        status TEXT NOT NULL,           -- 'SENT', 'FAILED', 'NOT_CONFIGURED', 'THROTTLED'
        message_body TEXT NOT NULL,
        FOREIGN KEY (threat_id) REFERENCES threat_events (id)
    );
    """)

    conn.commit()
    conn.close()
    print(f"[+] Database initialized at: {DB_PATH}")

def insert_traffic_log(entry: dict) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO traffic_logs 
    (timestamp, client_ip, method, path, query, status_code, prediction, confidence, severity, response_time_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        entry.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        entry.get("client_ip", "127.0.0.1"),
        entry.get("method", "GET"),
        entry.get("path", "/"),
        entry.get("query", ""),
        entry.get("status_code", 200),
        entry.get("prediction", "NORMAL"),
        entry.get("confidence", 1.0),
        entry.get("severity", "LOW"),
        entry.get("response_time_ms", 0.0)
    ))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def insert_threat_event(event: dict) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO threat_events
    (timestamp, client_ip, threat_type, detection_source, endpoint, payload, confidence, severity, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        event.get("client_ip", "127.0.0.1"),
        event.get("threat_type", "UNKNOWN"),
        event.get("detection_source", "HYBRID"),
        event.get("endpoint", "/"),
        event.get("payload", ""),
        event.get("confidence", 0.95),
        event.get("severity", "HIGH"),
        event.get("reason", "")
    ))
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return threat_id

def insert_alert_record(alert: dict) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO alert_history
    (timestamp, threat_id, channel, recipient, status, message_body)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (
        alert.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        alert.get("threat_id"),
        alert.get("channel", "DASHBOARD"),
        alert.get("recipient", "admin"),
        alert.get("status", "SENT"),
        alert.get("message_body", "")
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_stats():
    conn = get_db_connection()
    cursor = conn.cursor()

    total_scanned = cursor.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    total_threats = cursor.execute("SELECT COUNT(*) FROM threat_events").fetchone()[0]
    normal_requests = cursor.execute("SELECT COUNT(*) FROM traffic_logs WHERE prediction = 'NORMAL'").fetchone()[0]
    sqli_count = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE threat_type = 'SQL_INJECTION'").fetchone()[0]
    xss_count = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE threat_type = 'XSS'").fetchone()[0]
    brute_force_count = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE threat_type = 'BRUTE_FORCE'").fetchone()[0]
    rate_limit_count = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE threat_type = 'HIGH_RATE_BURST'").fetchone()[0]

    conn.close()
    return {
        "total_scanned": total_scanned,
        "total_threats": total_threats,
        "normal_requests": normal_requests,
        "sqli_count": sqli_count,
        "xss_count": xss_count,
        "brute_force_count": brute_force_count,
        "rate_limit_count": rate_limit_count
    }
