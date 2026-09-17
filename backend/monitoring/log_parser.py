"""
Log Parser & Sanitizer
----------------------
Parses structured JSON lines or standard W3C log lines into normalized
event objects for the detection engine.
"""

import json
from datetime import datetime

def parse_log_line(line: str) -> dict:
    """
    Parses a single log line. Supports structured JSON format produced by test_website.
    Returns normalized dictionary or None if invalid.
    """
    line = line.strip()
    if not line:
        return None

    try:
        data = json.loads(line)
        return {
            "timestamp": data.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            "client_ip": data.get("client_ip", "127.0.0.1"),
            "method": data.get("method", "GET"),
            "path": data.get("path", "/"),
            "query": data.get("query", ""),
            "payload": data.get("payload", ""),
            "status_code": int(data.get("status_code", 200)),
            "user_agent": data.get("user_agent", ""),
            "response_time_ms": float(data.get("response_time_ms", 0.0))
        }
    except json.JSONDecodeError:
        # Fallback for plain space-delimited text if non-JSON log line
        parts = line.split()
        if len(parts) >= 5:
            return {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "client_ip": parts[0],
                "method": parts[1] if len(parts) > 1 else "GET",
                "path": parts[2] if len(parts) > 2 else "/",
                "query": "",
                "payload": "",
                "status_code": 200,
                "user_agent": "Unknown",
                "response_time_ms": 1.0
            }
        return None
