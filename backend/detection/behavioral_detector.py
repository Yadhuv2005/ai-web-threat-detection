"""
Behavioral Anomaly & Temporal Threat Detector
---------------------------------------------
Tracks temporal state using sliding time-windows per IP address.
Detects traffic attacks that NLP cannot catch (rate spikes, brute force, endpoint scanning).

Why Behavioral Detection is Essential (Defense-in-Depth):
A single failed login request looks syntactically 100% normal to an NLP model:
   POST /login username=admin&password=wrongpassword
NLP sees benign words. Only behavioral context (observing 10 failed logins
within 30 seconds from IP 192.168.1.50) reveals an active Brute-Force Attack!
"""

import time
from collections import defaultdict, deque
import backend.config as config

class BehavioralDetector:
    def __init__(self):
        # In-memory sliding windows: ip -> deque of timestamps
        self.ip_request_history = defaultdict(deque)
        self.ip_failed_logins = defaultdict(deque)
        self.ip_sensitive_probes = defaultdict(deque)

        # Sensitive endpoints that normal users never visit
        self.sensitive_paths = [
            "/admin", "/.env", "/wp-login.php", "/config.php",
            "/server-status", "/phpmyadmin", "/.git/config", "/etc/passwd"
        ]

    def _purge_old_events(self, history: deque, window_sec: int, current_time: float):
        """Discards timestamps older than sliding window threshold."""
        while history and (current_time - history[0] > window_sec):
            history.popleft()

    def analyze_behavior(self, client_ip: str, path: str, status_code: int) -> dict:
        """
        Evaluates behavioral rules on the current request.
        Returns:
            {
                "is_threat": bool,
                "threat_type": str or None,
                "confidence": float,
                "severity": str,
                "reason": str
            }
        """
        current_time = time.time()

        # 1. Update & Check Request Rate Frequency (DDoS / High Burst)
        req_queue = self.ip_request_history[client_ip]
        req_queue.append(current_time)
        self._purge_old_events(req_queue, config.REQUEST_RATE_WINDOW_SEC, current_time)

        if len(req_queue) > config.REQUEST_RATE_THRESHOLD:
            return {
                "is_threat": True,
                "threat_type": "HIGH_RATE_BURST",
                "confidence": 0.96,
                "severity": "CRITICAL",
                "reason": f"High request surge: {len(req_queue)} requests in {config.REQUEST_RATE_WINDOW_SEC}s from IP {client_ip} (Threshold: {config.REQUEST_RATE_THRESHOLD})"
            }

        # 2. Update & Check Failed Authentication (Brute Force Detection)
        # Login endpoint with HTTP 401 Unauthorized
        if "/login" in path and status_code == 401:
            failed_queue = self.ip_failed_logins[client_ip]
            failed_queue.append(current_time)
            self._purge_old_events(failed_queue, config.FAILED_LOGIN_WINDOW_SEC, current_time)

            if len(failed_queue) >= config.FAILED_LOGIN_THRESHOLD:
                return {
                    "is_threat": True,
                    "threat_type": "BRUTE_FORCE",
                    "confidence": 0.99,
                    "severity": "CRITICAL",
                    "reason": f"Brute force credential attack: {len(failed_queue)} failed logins in {config.FAILED_LOGIN_WINDOW_SEC}s from IP {client_ip} (Threshold: {config.FAILED_LOGIN_THRESHOLD})"
                }

        # 3. Check Sensitive Endpoint Probe / Directory Scanning
        for sensitive in self.sensitive_paths:
            if sensitive in path:
                probe_queue = self.ip_sensitive_probes[client_ip]
                probe_queue.append(current_time)
                self._purge_old_events(probe_queue, 120, current_time)

                return {
                    "is_threat": True,
                    "threat_type": "RECONNAISSANCE_PROBE",
                    "confidence": 0.92,
                    "severity": "WARNING",
                    "reason": f"Unauthorized reconnaissance probe targeting restricted path: '{path}'"
                }

        return {
            "is_threat": False,
            "threat_type": None,
            "confidence": 0.0,
            "severity": "LOW",
            "reason": ""
        }
