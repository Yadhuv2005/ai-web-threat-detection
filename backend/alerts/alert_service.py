"""
Real-Time Alert Dispatch Service
--------------------------------
Handles alert dispatch across channels (Dashboard WebSocket, Email SMTP, Twilio SMS).
Includes an intelligent cooldown/throttling cache to eliminate duplicate alert flooding.
"""

import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import backend.config as config
from backend.database.models import insert_alert_record

class AlertService:
    def __init__(self):
        # In-memory deduplication cache: (client_ip, threat_type) -> last_alert_time
        self.last_sent_timestamps = {}

    def should_throttle(self, client_ip: str, threat_type: str) -> bool:
        """
        Prevents alert flooding (e.g., 200 SQL injections in 5 seconds should
        not trigger 200 SMS messages and exhaust API quotas).
        """
        key = (client_ip, threat_type)
        now = time.time()
        if key in self.last_sent_timestamps:
            elapsed = now - self.last_sent_timestamps[key]
            if elapsed < config.ALERT_COOLDOWN_SECONDS:
                return True
        self.last_sent_timestamps[key] = now
        return False

    def dispatch_alert(self, threat_event: dict, threat_id: int) -> dict:
        """
        Dispatches alerts across configured channels and records outcome in DB.
        """
        client_ip = threat_event.get("client_ip", "Unknown")
        threat_type = threat_event.get("threat_type", "Unknown")
        severity = threat_event.get("severity", "HIGH")
        reason = threat_event.get("reason", "")
        endpoint = threat_event.get("endpoint", "")

        alert_results = {"dashboard": "SENT", "email": "NOT_CONFIGURED", "sms": "NOT_CONFIGURED"}

        # Format message
        message = (
            f"🚨 [CYBER THREAT DETECTED] 🚨\n"
            f"Type: {threat_type}\n"
            f"Severity: {severity}\n"
            f"Attacker IP: {client_ip}\n"
            f"Target Endpoint: {endpoint}\n"
            f"Analysis Reason: {reason}\n"
            f"Timestamp: {threat_event.get('timestamp')}"
        )

        # 1. Record Dashboard Alert
        insert_alert_record({
            "timestamp": threat_event.get("timestamp"),
            "threat_id": threat_id,
            "channel": "DASHBOARD",
            "recipient": "SOC Console",
            "status": "SENT",
            "message_body": message
        })

        # Check throttling before sending external network notifications
        if self.should_throttle(client_ip, threat_type):
            print(f"[*] Throttling external alerts for {threat_type} from {client_ip} (Cooldown active)")
            insert_alert_record({
                "timestamp": threat_event.get("timestamp"),
                "threat_id": threat_id,
                "channel": "EMAIL_SMS_THROTTLED",
                "recipient": "Admin",
                "status": "THROTTLED",
                "message_body": "Suppressed due to cooldown window."
            })
            return {"status": "THROTTLED", "details": alert_results}

        # 2. Optional Email Alert (SMTP)
        if config.ENABLE_EMAIL_ALERTS and config.SMTP_USER and config.SMTP_PASSWORD:
            try:
                msg = MIMEMultipart()
                msg["From"] = config.SMTP_USER
                msg["To"] = config.ALERT_RECIPIENT_EMAIL
                msg["Subject"] = f"SECURITY ALERT: {threat_type} detected on Web Application"
                msg.attach(MIMEText(message, "plain"))

                with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT) as server:
                    server.starttls()
                    server.login(config.SMTP_USER, config.SMTP_PASSWORD)
                    server.send_message(msg)

                alert_results["email"] = "SENT"
                insert_alert_record({
                    "timestamp": threat_event.get("timestamp"),
                    "threat_id": threat_id,
                    "channel": "EMAIL",
                    "recipient": config.ALERT_RECIPIENT_EMAIL,
                    "status": "SENT",
                    "message_body": message
                })
            except Exception as e:
                print(f"[-] Failed to send email alert: {e}")
                alert_results["email"] = f"FAILED: {e}"
                insert_alert_record({
                    "timestamp": threat_event.get("timestamp"),
                    "threat_id": threat_id,
                    "channel": "EMAIL",
                    "recipient": config.ALERT_RECIPIENT_EMAIL,
                    "status": "FAILED",
                    "message_body": str(e)
                })
        else:
            alert_results["email"] = "NOT_CONFIGURED"

        # 3. Optional SMS Alert (Twilio API)
        if config.ENABLE_SMS_ALERTS and config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN:
            try:
                import requests
                twilio_url = f"https://api.twilio.com/2010-04-01/Accounts/{config.TWILIO_ACCOUNT_SID}/Messages.json"
                resp = requests.post(
                    twilio_url,
                    data={
                        "From": config.TWILIO_FROM_PHONE,
                        "To": config.ALERT_RECIPIENT_PHONE,
                        "Body": message[:160] # SMS 160-character segment limit
                    },
                    auth=(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN),
                    timeout=5
                )
                if resp.status_code in (200, 201):
                    alert_results["sms"] = "SENT"
                    status_text = "SENT"
                else:
                    alert_results["sms"] = f"FAILED: {resp.text}"
                    status_text = "FAILED"

                insert_alert_record({
                    "timestamp": threat_event.get("timestamp"),
                    "threat_id": threat_id,
                    "channel": "SMS",
                    "recipient": config.ALERT_RECIPIENT_PHONE,
                    "status": status_text,
                    "message_body": message[:160]
                })
            except Exception as e:
                print(f"[-] Failed to send SMS alert: {e}")
                alert_results["sms"] = f"FAILED: {e}"
                insert_alert_record({
                    "timestamp": threat_event.get("timestamp"),
                    "threat_id": threat_id,
                    "channel": "SMS",
                    "recipient": config.ALERT_RECIPIENT_PHONE,
                    "status": "FAILED",
                    "message_body": str(e)
                })
        else:
            alert_results["sms"] = "NOT_CONFIGURED"

        return alert_results
