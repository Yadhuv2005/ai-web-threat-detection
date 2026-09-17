"""
Automated Unit & Integration Tests
-----------------------------------
Tests:
1. Text cleaning and recursive URL decoding.
2. Threat token extraction.
3. Behavioral sliding-window tracking (failed logins & rate burst).
4. Alert throttling deduplication.
5. Log parser JSON parsing.
"""

import time
from ml.preprocessing.text_cleaner import clean_web_text, extract_threat_tokens
from backend.detection.behavioral_detector import BehavioralDetector
from backend.alerts.alert_service import AlertService
from backend.monitoring.log_parser import parse_log_line

def test_text_cleaner_url_decoding():
    raw_encoded = "%27%20OR%201%3D1%20--"
    cleaned = clean_web_text(raw_encoded)
    assert "' or 1=1 --" in cleaned

def test_text_cleaner_xss_entities():
    raw_xss = "&lt;script&gt;alert(1)&lt;/script&gt;"
    cleaned = clean_web_text(raw_xss)
    assert "<script>alert(1)</script>" in cleaned

def test_extract_threat_tokens():
    text = "select * from users where id=1 union select password from credentials"
    tokens = extract_threat_tokens(text)
    assert any("union select" in t for t in tokens)

def test_behavioral_brute_force_detection():
    detector = BehavioralDetector()
    test_ip = "192.168.1.105"

    for _ in range(4):
        res = detector.analyze_behavior(test_ip, "/login", 401)
        assert res["is_threat"] is False

    res_5 = detector.analyze_behavior(test_ip, "/login", 401)
    assert res_5["is_threat"] is True
    assert res_5["threat_type"] == "BRUTE_FORCE"

def test_behavioral_rate_spike():
    detector = BehavioralDetector()
    test_ip = "10.0.0.99"

    for _ in range(25):
        detector.analyze_behavior(test_ip, "/api/data", 200)

    burst_res = detector.analyze_behavior(test_ip, "/api/data", 200)
    assert burst_res["is_threat"] is True
    assert burst_res["threat_type"] == "HIGH_RATE_BURST"

def test_alert_throttling():
    service = AlertService()
    ip = "172.16.0.4"
    threat = "SQL_INJECTION"

    assert service.should_throttle(ip, threat) is False
    assert service.should_throttle(ip, threat) is True

def test_log_parser_valid_json():
    json_log = '{"timestamp": "2026-09-17T04:00:00Z", "client_ip": "127.0.0.1", "method": "GET", "path": "/search", "query": "q=laptop", "status_code": 200}'
    parsed = parse_log_line(json_log)
    assert parsed is not None
    assert parsed["client_ip"] == "127.0.0.1"
    assert parsed["query"] == "q=laptop"
    assert parsed["status_code"] == 200
