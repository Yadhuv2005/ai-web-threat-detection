"""
Database Models (SQLite Persistence) - Cyber Risk Extended
----------------------------------------------------------
Stores traffic logs, threat detections enriched with multi-factor risk scores,
asset bindings, and risk-prioritized alert dispatch records.
"""

import sqlite3
import os
import json
from datetime import datetime
from backend.risk.asset_registry import DEFAULT_ASSETS

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "threat_detection.db"))

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes and migrates SQLite schema with cyber risk tables and columns."""
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
        reason TEXT NOT NULL,
        risk_score INTEGER DEFAULT 50,
        risk_level TEXT DEFAULT 'MEDIUM',
        affected_asset TEXT DEFAULT 'Web Application',
        likelihood REAL DEFAULT 0.8,
        potential_impact TEXT DEFAULT '',
        business_impact TEXT DEFAULT '',
        remediation_action TEXT DEFAULT ''
    );
    """)

    # Auto-migration: check if new risk columns exist in threat_events
    existing_cols = [row[1] for row in cursor.execute("PRAGMA table_info(threat_events)").fetchall()]
    new_cols = [
        ("risk_score", "INTEGER DEFAULT 50"),
        ("risk_level", "TEXT DEFAULT 'MEDIUM'"),
        ("affected_asset", "TEXT DEFAULT 'Web Application'"),
        ("likelihood", "REAL DEFAULT 0.8"),
        ("potential_impact", "TEXT DEFAULT ''"),
        ("business_impact", "TEXT DEFAULT ''"),
        ("remediation_action", "TEXT DEFAULT ''")
    ]
    for col_name, col_type in new_cols:
        if col_name not in existing_cols:
            cursor.execute(f"ALTER TABLE threat_events ADD COLUMN {col_name} {col_type}")

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
        risk_level TEXT DEFAULT 'MEDIUM',
        FOREIGN KEY (threat_id) REFERENCES threat_events (id)
    );
    """)

    alert_cols = [row[1] for row in cursor.execute("PRAGMA table_info(alert_history)").fetchall()]
    if "risk_level" not in alert_cols:
        cursor.execute("ALTER TABLE alert_history ADD COLUMN risk_level TEXT DEFAULT 'MEDIUM'")

    # 4. Monitored Assets Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        criticality TEXT NOT NULL,
        weight REAL NOT NULL,
        endpoint_pattern TEXT NOT NULL,
        description TEXT NOT NULL,
        data_classification TEXT NOT NULL,
        business_unit TEXT NOT NULL
    );
    """)

    # Seed default assets if empty
    asset_count = cursor.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
    if asset_count == 0:
        for a in DEFAULT_ASSETS:
            cursor.execute("""
            INSERT OR REPLACE INTO assets 
            (id, name, type, criticality, weight, endpoint_pattern, description, data_classification, business_unit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a["id"], a["name"], a["type"], a["criticality"], a["weight"],
                a["endpoint_pattern"], a["description"], a["data_classification"], a["business_unit"]
            ))

    conn.commit()
    conn.close()
    print(f"[+] Database initialized and risk schema verified at: {DB_PATH}")

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
    (timestamp, client_ip, threat_type, detection_source, endpoint, payload, confidence, severity, reason,
     risk_score, risk_level, affected_asset, likelihood, potential_impact, business_impact, remediation_action)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        event.get("client_ip", "127.0.0.1"),
        event.get("threat_type", "UNKNOWN"),
        event.get("detection_source", "HYBRID"),
        event.get("endpoint", "/"),
        event.get("payload", ""),
        event.get("confidence", 0.95),
        event.get("severity", "HIGH"),
        event.get("reason", ""),
        event.get("risk_score", 50),
        event.get("risk_level", "MEDIUM"),
        event.get("affected_asset", "Web Application"),
        event.get("likelihood", 0.8),
        event.get("potential_impact", ""),
        event.get("business_impact", ""),
        event.get("remediation_action", "")
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
    (timestamp, threat_id, channel, recipient, status, message_body, risk_level)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("timestamp", datetime.utcnow().isoformat() + "Z"),
        alert.get("threat_id"),
        alert.get("channel", "DASHBOARD"),
        alert.get("recipient", "admin"),
        alert.get("status", "SENT"),
        alert.get("message_body", ""),
        alert.get("risk_level", "MEDIUM")
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

    # Risk level counts
    critical_risks = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE risk_level = 'CRITICAL'").fetchone()[0]
    high_risks = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE risk_level = 'HIGH'").fetchone()[0]
    medium_risks = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE risk_level = 'MEDIUM'").fetchone()[0]
    low_risks = cursor.execute("SELECT COUNT(*) FROM threat_events WHERE risk_level = 'LOW'").fetchone()[0]

    # Overall Risk Score calculation (weighted average or max recent impact)
    avg_score_row = cursor.execute("SELECT AVG(risk_score) FROM (SELECT risk_score FROM threat_events ORDER BY id DESC LIMIT 20)").fetchone()
    if total_threats > 0 and avg_score_row and avg_score_row[0] is not None:
        # Scale based on critical risks
        base_avg = float(avg_score_row[0])
        overall_risk_score = min(100, int(round(base_avg + (critical_risks * 3))))
    else:
        overall_risk_score = 12  # baseline healthy low risk

    conn.close()
    return {
        "total_scanned": total_scanned,
        "total_threats": total_threats,
        "normal_requests": normal_requests,
        "sqli_count": sqli_count,
        "xss_count": xss_count,
        "brute_force_count": brute_force_count,
        "rate_limit_count": rate_limit_count,
        "overall_risk_score": overall_risk_score,
        "critical_risks": critical_risks,
        "high_risks": high_risks,
        "medium_risks": medium_risks,
        "low_risks": low_risks
    }

def get_prioritized_threats(limit: int = 50):
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = cursor.execute("""
    SELECT * FROM threat_events 
    ORDER BY risk_score DESC, id DESC 
    LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_registered_assets():
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM assets ORDER BY weight DESC").fetchall()
    
    result = []
    for r in rows:
        item = dict(r)
        # count threats targeted at this asset
        threat_cnt = cursor.execute(
            "SELECT COUNT(*) FROM threat_events WHERE affected_asset = ?", (item["name"],)
        ).fetchone()[0]
        item["active_threats"] = threat_cnt
        result.append(item)
        
    conn.close()
    return result
