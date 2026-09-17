"""
Continuous Background Log Monitoring Service - Cyber Risk Enhanced
------------------------------------------------------------------
Watches the target website's access log file continuously.
Reads new entries as they arrive, evaluates ML threat classification and
behavioral detection, computes multi-dimensional AI Risk Scores, persists to SQLite,
dispatches risk-based alerts, and broadcasts live updates over WebSockets.
"""

import os
import asyncio
import traceback
import backend.config as config
from backend.monitoring.log_parser import parse_log_line
from backend.detection.ml_detector import MLThreatDetector
from backend.detection.behavioral_detector import BehavioralDetector
from backend.detection.explainability import generate_explanation
from backend.risk.risk_engine import RiskEngine
from backend.alerts.alert_service import AlertService
from backend.database.models import insert_traffic_log, insert_threat_event, get_stats, get_prioritized_threats

class ContinuousLogMonitor:
    def __init__(self, broadcast_callback=None):
        self.broadcast_callback = broadcast_callback
        self.is_running = False
        self._task = None

        # Instantiate detection, risk, and alert engines
        self.ml_detector = MLThreatDetector()
        self.behavioral_detector = BehavioralDetector()
        self.alert_service = AlertService()

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._task = asyncio.create_task(self._monitor_loop())
            print("[+] Continuous Log Monitoring Service started.")

    def stop(self):
        if self.is_running:
            self.is_running = False
            if self._task:
                self._task.cancel()
            print("[-] Continuous Log Monitoring Service stopped.")

    async def _process_log_entry(self, raw_line: str):
        entry = parse_log_line(raw_line)
        if not entry:
            return

        client_ip = entry["client_ip"]
        path = entry["path"]
        query = entry["query"]
        payload = entry["payload"]
        status_code = entry["status_code"]

        # Formulate full textual payload for NLP analysis
        combined_text = f"{path}?{query} {payload}".strip()

        # 1. Run NLP / ML Text Classification
        ml_result = self.ml_detector.predict(combined_text)

        # 2. Run Behavioral Anomaly Detection
        behavioral_result = self.behavioral_detector.analyze_behavior(client_ip, path, status_code)

        # 3. Determine Final Classification
        is_threat = ml_result["is_threat"] or behavioral_result["is_threat"]

        if behavioral_result["is_threat"]:
            threat_type = behavioral_result["threat_type"]
            severity = behavioral_result["severity"]
            confidence = behavioral_result["confidence"]
            detection_source = "BEHAVIORAL_ENGINE"
        elif ml_result["is_threat"]:
            threat_type = ml_result["threat_type"]
            severity = ml_result["severity"]
            confidence = ml_result["confidence"]
            detection_source = "ML_CLASSIFIER"
        else:
            threat_type = "NORMAL"
            severity = "LOW"
            confidence = ml_result["confidence"]
            detection_source = "NONE"

        # 4. Generate Explainability Reason
        reason = generate_explanation(ml_result, behavioral_result, path, combined_text)

        # 5. Evaluate Multi-Dimensional Cyber Risk Metrics
        risk_metrics = RiskEngine.calculate_risk(
            threat_type=threat_type,
            confidence=confidence,
            detection_source=detection_source,
            endpoint=path,
            payload=combined_text,
            client_ip=client_ip
        )

        # 6. Persist Traffic Log
        entry["prediction"] = threat_type
        entry["confidence"] = confidence
        entry["severity"] = severity
        log_id = insert_traffic_log(entry)

        threat_id = None
        alert_info = None

        # 7. If Threat Detected: Save Extended Threat Record & Dispatch Risk Alert
        if is_threat:
            threat_event = {
                "timestamp": entry["timestamp"],
                "client_ip": client_ip,
                "threat_type": threat_type,
                "detection_source": detection_source,
                "endpoint": path,
                "payload": combined_text[:300],
                "confidence": confidence,
                "severity": severity,
                "reason": reason,
                "risk_score": risk_metrics["risk_score"],
                "risk_level": risk_metrics["risk_level"],
                "affected_asset": risk_metrics["affected_asset"],
                "likelihood": risk_metrics["likelihood"],
                "potential_impact": risk_metrics["potential_impact"],
                "business_impact": risk_metrics["business_impact"],
                "remediation_action": risk_metrics["remediation_action"]
            }
            threat_id = insert_threat_event(threat_event)
            alert_info = self.alert_service.dispatch_alert(threat_event, threat_id)

        # 8. Broadcast Event to Connected Frontend WebSockets
        if self.broadcast_callback:
            stats = get_stats()
            event_payload = {
                "event_type": "THREAT_DETECTED" if is_threat else "TRAFFIC_LOG",
                "is_threat": is_threat,
                "log": entry,
                "threat": {
                    "id": threat_id,
                    "threat_type": threat_type,
                    "severity": severity,
                    "confidence": confidence,
                    "reason": reason,
                    "detection_source": detection_source,
                    "risk_score": risk_metrics["risk_score"],
                    "risk_level": risk_metrics["risk_level"],
                    "affected_asset": risk_metrics["affected_asset"],
                    "business_impact": risk_metrics["business_impact"],
                    "remediation_action": risk_metrics["remediation_action"]
                } if is_threat else None,
                "risk": risk_metrics,
                "alert": alert_info,
                "stats": stats
            }
            await self.broadcast_callback(event_payload)

    async def _monitor_loop(self):
        """Asynchronous non-blocking file tailing loop."""
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        log_file = os.path.join(root_dir, config.LOG_FILE_PATH)

        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        if not os.path.exists(log_file):
            with open(log_file, "w", encoding="utf-8") as f:
                pass

        print(f"[*] Watching log stream at: {log_file}")

        try:
            with open(log_file, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while self.is_running:
                    line = f.readline()
                    if line:
                        await self._process_log_entry(line)
                    else:
                        await asyncio.sleep(0.15)
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"[-] Error in monitor loop: {e}")
            traceback.print_exc()
