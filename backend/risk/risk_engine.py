"""
AI Cyber Risk Engine
--------------------
Evaluates security risk on detected threats using standard NIST SP 800-30
and CVSS vulnerability assessment concepts.

Multi-Factor Risk Model:
Risk Score (0–100) = min(100, round((Likelihood * 0.35 + Severity * 0.35 + Asset Criticality * 0.30) * 100))

Where:
1. Likelihood (0.0 - 1.0): Derived from model confidence and attack complexity.
2. Technical Severity (0.0 - 1.0): Based on threat impact capability:
   - SQL_INJECTION: 0.95 (Data exfiltration, database takeover)
   - BRUTE_FORCE: 0.90 (Account takeover, privilege escalation)
   - HIGH_RATE_BURST: 0.75 (Denial of service, latency degradation)
   - XSS: 0.70 (Session hijacking, DOM manipulation)
   - RECONNAISSANCE_PROBE: 0.50 (Information gathering)
   - UNKNOWN/OTHER: 0.40
3. Asset Criticality (0.0 - 1.0): Weight from Asset Registry (Payment=1.0, Auth=1.0, API=0.8, Search=0.6, Web=0.4).

Risk Tiers:
- CRITICAL : 80 - 100
- HIGH     : 60 - 79
- MEDIUM   : 40 - 59
- LOW      : 0 - 39
"""

from typing import Dict, Any, Tuple
from backend.risk.asset_registry import asset_registry_instance

# Technical impact weights by threat type
THREAT_SEVERITY_WEIGHTS = {
    "SQL_INJECTION": 0.95,
    "BRUTE_FORCE": 0.90,
    "HIGH_RATE_BURST": 0.75,
    "XSS": 0.70,
    "RECONNAISSANCE_PROBE": 0.50,
    "UNKNOWN": 0.40
}

class RiskEngine:
    @staticmethod
    def calculate_risk(
        threat_type: str,
        confidence: float,
        detection_source: str,
        endpoint: str,
        payload: str = "",
        client_ip: str = "127.0.0.1"
    ) -> Dict[str, Any]:
        """
        Calculates multi-dimensional risk metrics for a detected security event.
        """
        # 1. Match Affected Asset
        asset = asset_registry_instance.match_asset_by_endpoint(endpoint)
        asset_weight = float(asset.get("weight", 0.5))
        asset_name = asset.get("name", "Web Endpoint")
        asset_criticality = asset.get("criticality", "MEDIUM")

        # 2. Determine Likelihood
        # Higher confidence + known signature patterns = higher likelihood of authentic exploit
        likelihood = min(1.0, max(0.2, float(confidence)))

        # 3. Determine Technical Severity Weight
        tech_severity = THREAT_SEVERITY_WEIGHTS.get(threat_type, 0.50)

        # 4. Composite Risk Score (0–100)
        # Risk = Likelihood (35%) + Technical Severity (35%) + Asset Criticality (30%)
        raw_score = (likelihood * 0.35 + tech_severity * 0.35 + asset_weight * 0.30) * 100
        risk_score = min(100, max(10, int(round(raw_score))))

        # 5. Risk Level Categorization
        if risk_score >= 80:
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # 6. Generate Potential Technical Impact & Business Impact
        potential_impact, business_impact = RiskEngine._generate_impact_descriptions(
            threat_type, asset_name, asset_criticality
        )

        # 7. Generate Actionable Mitigation Recommendations
        remediation_action = RiskEngine._generate_remediation(threat_type, asset_name, endpoint)

        # 8. Risk Justification Explanation
        risk_explanation = (
            f"Evaluated as {risk_level} Risk (Score: {risk_score}/100) due to "
            f"{threat_type} targeting {asset_criticality}-criticality asset '{asset_name}'. "
            f"Exploit likelihood is rated at {int(likelihood*100)}% with {int(tech_severity*100)}% potential severity impact."
        )

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "likelihood": round(likelihood, 2),
            "technical_severity": round(tech_severity, 2),
            "asset_criticality": asset_criticality,
            "affected_asset": asset_name,
            "asset_id": asset.get("id"),
            "potential_impact": potential_impact,
            "business_impact": business_impact,
            "remediation_action": remediation_action,
            "risk_explanation": risk_explanation
        }

    @staticmethod
    def _generate_impact_descriptions(threat_type: str, asset_name: str, asset_criticality: str) -> Tuple[str, str]:
        """Synthesizes technical impact and direct business impact."""
        if threat_type == "SQL_INJECTION":
            tech = "Arbitrary database read/write execution, potential table extraction, or authentication bypass."
            biz = (
                f"Severe customer privacy violation and data loss risk on '{asset_name}'. "
                "Possible regulatory non-compliance fines (GDPR/PCI-DSS) and brand reputation damage."
            )
        elif threat_type == "BRUTE_FORCE":
            tech = "Credential exhaustion, unauthorized account takeover, and privilege escalation."
            biz = (
                f"Unauthorized access into customer/admin accounts on '{asset_name}'. "
                "Potential account compromise, unauthorized transactions, and identity theft."
            )
        elif threat_type == "HIGH_RATE_BURST":
            tech = "Resource exhaustion, connection pool starvation, and application denial-of-service (DoS)."
            biz = (
                f"Service disruption on '{asset_name}' degrading customer experience and causing transaction abandonment."
            )
        elif threat_type == "XSS":
            tech = "Session cookie theft, client-side DOM hijacking, and credential phishing redirection."
            biz = (
                f"Compromise of visitor web sessions and trust erosion on '{asset_name}'."
            )
        else:
            tech = "Suspicious reconnaissance scan probing restricted directories."
            biz = f"Targeted discovery of internal structure on '{asset_name}' prior to an active attack."

        return tech, biz

    @staticmethod
    def _generate_remediation(threat_type: str, asset_name: str, endpoint: str) -> str:
        """Specific security engineering remediation."""
        if threat_type == "SQL_INJECTION":
            return f"Enforce parameterized queries (Prepared Statements) on '{endpoint}', validate input types, and restrict database account privileges."
        elif threat_type == "BRUTE_FORCE":
            return f"Activate IP rate limiting on '{endpoint}', enforce multi-factor authentication (MFA), and implement temporary lockout after 5 failed attempts."
        elif threat_type == "HIGH_RATE_BURST":
            return f"Configure burst rate limiting at the reverse proxy (e.g., Nginx limit_req) and deploy automated CAPTCHA challenges for aggressive IPs."
        elif threat_type == "XSS":
            return f"Implement strict Context-Aware Output Encoding, sanitize user inputs via DOMPurify, and enforce a strong Content Security Policy (CSP)."
        else:
            return f"Block unauthorized path enumeration on '{endpoint}' using firewall ACLs and ensure sensitive files are not exposed in web roots."
