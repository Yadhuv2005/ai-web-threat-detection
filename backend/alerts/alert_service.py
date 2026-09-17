"""
Smart Risk-Based Alert Dispatch Service
---------------------------------------
Routes notifications based on evaluated Risk Level:
- LOW      -> Dashboard notification only
- MEDIUM   -> Dashboard notification + audit log
- HIGH     -> Dashboard notification + Email (SMTP)
- CRITICAL -> Dashboard notification + Email (SMTP) + SMS (Twilio)

Includes an in-memory deduplication/cooldown cache to eliminate alert flooding.
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
        """Prevents alert flooding within cooldown window."""
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
        Dispatches risk-prioritized alerts across channels and records outcome in DB.
        """
        client_ip = threat_event.get("client_ip", "Unknown")
        threat_type = threat_event.get("threat_type", "Unknown")
        risk_level = threat_event.get("risk_level", "MEDIUM")
        risk_score = threat_event.get("risk_score", 50)
        affected_asset = threat_event.get("affected_asset", "Web Application")
        reason = threat_event.get("reason", "")
        remediation = threat_event.get("remediation_action", "")
        endpoint = threat_event.get("endpoint", "")

        alert_results = {
            "dashboard": "SENT",
            "email": "NOT_CONFIGURED",
            "sms": "NOT_CONFIGURED",
            "policy": f"Risk Level: {risk_level} (Score: {risk_score}/100)"
        }

        # Formulate rich executive & technical alert message
        message = (
            f"🚨 [CYBER RISK ALERT - {risk_level}] 🚨\n"
            f"Risk Score: {risk_score}/100 | Threat: {threat_type}\n"
            f"Affected Asset: {affected_asset} ({endpoint})\n"
            f"Attacker IP: {client_ip}\n"
            f"Analysis: {reason}\n"
            f"Mitigation: {remediation}\n"
            f"Timestamp: {threat_event.get('timestamp')}"
        )

        # 1. Always record Dashboard Alert
        insert_alert_record({
            "timestamp": threat_event.get("timestamp"),
            "threat_id": threat_id,
            "channel": "DASHBOARD",
            "recipient": "SOC Console",
            "status": "SENT",
            "message_body": message,
            "risk_level": risk_level
        })

        # 2. Risk-Based Routing Logic:
        # LOW: Dashboard only
        # MEDIUM: Dashboard only
        # HIGH: Dashboard + Email
        # CRITICAL: Dashboard + Email + SMS
        should_send_email = (risk_level in ["HIGH", "CRITICAL"])
        should_send_sms = (risk_level == "CRITICAL")

        # Check throttling before sending external network notifications
        if self.should_throttle(client_ip, threat_type):
            print(f"[*] Throttling external alerts for {threat_type} from {client_ip} (Cooldown active)")
            insert_alert_record({
                "timestamp": threat_event.get("timestamp"),
                "threat_id": threat_id,
                "channel": "EMAIL_SMS_THROTTLED",
                "recipient": "Security Admin",
                "status": "THROTTLED",
                "message_body": "Suppressed due to cooldown window.",
                "risk_level": risk_level
            })
            alert_results["status"] = "THROTTLED"
            return alert_results

        # 3. Email Notification (for HIGH and CRITICAL)
        if should_send_email:
            if config.ENABLE_EMAIL_ALERTS and config.SMTP_USER and config.SMTP_PASSWORD:
                try:
                    msg = MIMEMultipart()
                    msg["From"] = config.SMTP_USER
                    msg["To"] = config.ALERT_RECIPIENT_EMAIL
                    msg["Subject"] = f"[{risk_level} RISK ALERT] {threat_type} targeting {affected_asset}"
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
                        "message_body": message,
                        "risk_level": risk_level
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
                        "message_body": str(e),
                        "risk_level": risk_level
                    })
            else:
                alert_results["email"] = "NOT_CONFIGURED"

        # 4. SMS Notification (strictly for CRITICAL risks)
        if should_send_sms:
            if config.ENABLE_SMS_ALERTS and config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN:
                try:
                    import requests
                    twilio_url = f"https://api.twilio.com/2010-04-01/Accounts/{config.TWILIO_ACCOUNT_SID}/Messages.json"
                    sms_snippet = f"CRITICAL RISK ({risk_score}/100): {threat_type} on {affected_asset} from {client_ip}. Action: {remediation[:50]}"
                    resp = requests.post(
                        twilio_url,
                        data={
                            "From": config.TWILIO_FROM_PHONE,
                            "To": config.ALERT_RECIPIENT_PHONE,
                            "Body": sms_snippet[:160]
                        },
                        auth=(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN),
                        timeout=5
                    )
                    status_text = "SENT" if resp.status_code in (200, 201) else f"FAILED: {resp.text}"
                    alert_results["sms"] = status_text
                    insert_alert_record({
                        "timestamp": threat_event.get("timestamp"),
                        "threat_id": threat_id,
                        "channel": "SMS",
                        "recipient": config.ALERT_RECIPIENT_PHONE,
                        "status": "SENT" if resp.status_code in (200, 201) else "FAILED",
                        "message_body": sms_snippet[:160],
                        "risk_level": risk_level
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
                        "message_body": str(e),
                        "risk_level": risk_level
                    })
            else:
                alert_results["sms"] = "NOT_CONFIGURED"

        return alert_results
