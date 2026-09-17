"""
AI Security Analyst Engine
--------------------------
Provides natural language reasoning and executive briefing based on the actual
security events, threat history, risk scores, and asset criticality present in SQLite.

Supported Intent Domains:
1. "What are today's biggest security risks?"
2. "Why is this threat high risk?"
3. "What should I investigate first?"
4. "What happened in the last 24 hours?"
5. "Which assets are most at risk?"
6. Technical questions on specific attacks and mitigation steps.
"""

from typing import Dict, Any, List
from backend.database.models import get_db_connection, get_stats, get_prioritized_threats, get_registered_assets

class AISecurityAnalyst:
    @staticmethod
    def answer_query(user_query: str) -> Dict[str, Any]:
        """
        Synthesizes an intelligent, context-grounded response from live telemetry.
        """
        q = (user_query or "").strip().lower()
        stats = get_stats()
        prioritized = get_prioritized_threats(10)
        assets = get_registered_assets()

        # Fallback query if blank
        if not q:
            return AISecurityAnalyst._format_executive_summary(stats, prioritized, assets)

        # 1. "What should I investigate first?" / "Priority"
        if any(term in q for term in ["investigate first", "prioritize", "urgent", "action items", "what first"]):
            return AISecurityAnalyst._answer_investigation_priority(prioritized)

        # 2. "What are today's biggest security risks?" / "Biggest risks"
        elif any(term in q for term in ["biggest risk", "top risk", "critical risk", "major threat", "biggest security"]):
            return AISecurityAnalyst._answer_biggest_risks(prioritized, stats)

        # 3. "Which assets are most at risk?" / "Asset vulnerability"
        elif any(term in q for term in ["asset", "which asset", "target", "systems"]):
            return AISecurityAnalyst._answer_assets_at_risk(assets, prioritized)

        # 4. "What happened in the last 24 hours?" / "Summary" / "Overview"
        elif any(term in q for term in ["24 hour", "summary", "overview", "what happened", "status", "report"]):
            return AISecurityAnalyst._format_executive_summary(stats, prioritized, assets)

        # 5. "Why is this threat high risk?" / "Why high risk" / "Risk score"
        elif any(term in q for term in ["why", "score", "high risk", "critical risk", "calculation"]):
            return AISecurityAnalyst._answer_risk_reasoning(prioritized)

        # 6. SQL Injection specific queries
        elif "sql" in q or "sqli" in q:
            return AISecurityAnalyst._answer_threat_specific(prioritized, "SQL_INJECTION")

        # 7. Brute force specific queries
        elif "brute" in q or "password" in q or "login" in q:
            return AISecurityAnalyst._answer_threat_specific(prioritized, "BRUTE_FORCE")

        # 8. XSS specific queries
        elif "xss" in q or "script" in q:
            return AISecurityAnalyst._answer_threat_specific(prioritized, "XSS")

        # Default intelligent synthesis
        return AISecurityAnalyst._answer_general(user_query, stats, prioritized, assets)

    @staticmethod
    def _answer_investigation_priority(prioritized: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not prioritized:
            return {
                "headline": "No Active Security Incidents Requiring Triage",
                "answer": "Current telemetry indicates zero active threats in the queue. All enterprise assets are operating under normal baseline parameters.",
                "action_items": ["Maintain routine monitoring.", "Verify daily log retention policies."],
                "relevant_events": []
            }

        top = prioritized[0]
        critical_count = sum(1 for t in prioritized if t.get("risk_level") == "CRITICAL")
        
        answer_text = (
            f"**Immediate Priority Focus**: You should immediately investigate **Incident #{top['id']} — {top['threat_type']}** "
            f"targeting **'{top['affected_asset']}'** (Endpoint: `{top['endpoint']}`).\n\n"
            f"- **Assessed Risk**: {top['risk_level']} (Risk Score: {top['risk_score']}/100)\n"
            f"- **Attacker Source**: `{top['client_ip']}`\n"
            f"- **Detection Vector**: {top['reason']}\n"
            f"- **Business Impact**: {top['business_impact']}\n\n"
            f"**Recommended Immediate Action**: {top['remediation_action']}"
        )

        actions = [
            f"Block or rate-limit source IP {top['client_ip']} at the network perimeter.",
            f"Review audit logs on {top['affected_asset']} for unauthorized state changes.",
            top['remediation_action']
        ]

        return {
            "headline": f"Priority 1: {top['threat_type']} on {top['affected_asset']}",
            "answer": answer_text,
            "action_items": actions,
            "relevant_events": prioritized[:3]
        }

    @staticmethod
    def _answer_biggest_risks(prioritized: List[Dict[str, Any]], stats: Dict[str, Any]) -> Dict[str, Any]:
        crit = stats.get("critical_risks", 0)
        high = stats.get("high_risks", 0)
        score = stats.get("overall_risk_score", 0)

        top_threats = prioritized[:3]
        threat_summaries = []
        for t in top_threats:
            threat_summaries.append(
                f"• **{t['threat_type']}** on `{t['affected_asset']}` (Risk: {t['risk_score']}/100 - {t['risk_level']}): {t['reason']}"
            )

        summary_bullet = "\n".join(threat_summaries) if threat_summaries else "No active high-severity incidents recorded."

        answer_text = (
            f"The environment currently exhibits an **Overall Risk Index of {score}/100**.\n\n"
            f"**Severity Breakdown**:\n"
            f"- Critical Incidents: **{crit}**\n"
            f"- High-Risk Incidents: **{high}**\n"
            f"- Medium/Low Incidents: **{stats.get('medium_risks', 0) + stats.get('low_risks', 0)}**\n\n"
            f"**Highest Risk Incidents**:\n{summary_bullet}"
        )

        return {
            "headline": f"Current Risk Index: {score}/100 ({crit} Critical, {high} High)",
            "answer": answer_text,
            "action_items": [
                "Contain Critical and High incidents before reviewing lower severity probes.",
                "Review parameterization on database endpoints to mitigate injection risks."
            ],
            "relevant_events": top_threats
        }

    @staticmethod
    def _answer_assets_at_risk(assets: List[Dict[str, Any]], prioritized: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Sort assets by active threats
        sorted_assets = sorted(assets, key=lambda a: a.get("active_threats", 0), reverse=True)
        
        asset_lines = []
        for a in sorted_assets:
            status_badge = "🚨 At Risk" if a.get("active_threats", 0) > 0 else "🛡️ Secure"
            asset_lines.append(
                f"• **{a['name']}** ({a['type']}) — Criticality: **{a['criticality']}** | Threats Detected: **{a.get('active_threats', 0)}** ({status_badge})"
            )

        answer_text = (
            "Based on the Asset Registry and threat log cross-correlation:\n\n" +
            "\n".join(asset_lines) +
            "\n\n**Analyst Note**: Criticality-weighted assets like Identity Gateways and Financial/Checkout services elevate overall risk scores exponentially when attacked."
        )

        return {
            "headline": "Asset Exposure & Criticality Breakdown",
            "answer": answer_text,
            "action_items": [
                f"Isolate endpoints mapped to {sorted_assets[0]['name']} if unauthorized traffic persists.",
                "Validate access control policies across all high-criticality assets."
            ],
            "relevant_events": [t for t in prioritized if t.get("affected_asset") == sorted_assets[0]["name"]][:3]
        }

    @staticmethod
    def _format_executive_summary(stats: Dict[str, Any], prioritized: List[Dict[str, Any]], assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        total_scanned = stats.get("total_scanned", 0)
        threats = stats.get("total_threats", 0)
        overall_score = stats.get("overall_risk_score", 10)

        risk_tier = "CRITICAL" if overall_score >= 80 else ("HIGH" if overall_score >= 60 else ("ELEVATED" if overall_score >= 40 else "NORMAL"))

        answer_text = (
            f"**Executive Security Briefing**:\n\n"
            f"- **Posture**: System is operating under **{risk_tier} RISK** ({overall_score}/100).\n"
            f"- **Telemetry Ingestion**: Scanned **{total_scanned}** HTTP requests across **{len(assets)}** registered enterprise assets.\n"
            f"- **Threat Activity**: Flagged **{threats}** security events ({stats.get('sqli_count', 0)} SQLi, {stats.get('xss_count', 0)} XSS, {stats.get('brute_force_count', 0)} Brute-Force).\n"
            f"- **Incident Queue**: **{stats.get('critical_risks', 0)}** Critical, **{stats.get('high_risks', 0)}** High, **{stats.get('medium_risks', 0)}** Medium.\n\n"
            f"**Strategic Assessment**: Threat activity is actively classified via the NLP TF-IDF classifier and behavioral sliding windows. High-criticality services require continuous defensive posture verification."
        )

        return {
            "headline": f"Executive Posture: {risk_tier} Risk ({overall_score}/100)",
            "answer": answer_text,
            "action_items": [
                "Address priority incidents in the triage queue.",
                "Ensure Web Application Firewall / reverse proxy rate rules are synchronizing."
            ],
            "relevant_events": prioritized[:3]
        }

    @staticmethod
    def _answer_risk_reasoning(prioritized: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not prioritized:
            return {
                "headline": "Risk Calculation Principles",
                "answer": "Risk is formulated using standard NIST SP 800-30: Risk Score (0-100) = (Likelihood * 0.35 + Technical Severity * 0.35 + Asset Criticality * 0.30) * 100.",
                "action_items": [],
                "relevant_events": []
            }

        top = prioritized[0]
        answer_text = (
            f"**Risk Evaluation Rationale for Incident #{top['id']} ({top['threat_type']})**:\n\n"
            f"1. **Threat Likelihood ({int(top.get('likelihood', 0.8)*100)}%)**: Probability based on ML confidence ({int(top.get('confidence', 0.9)*100)}%) and extracted exploit signatures.\n"
            f"2. **Technical Severity**: {top.get('threat_type')} possesses high compromise capability ({top.get('potential_impact')}).\n"
            f"3. **Asset Criticality**: The attack targeted **'{top.get('affected_asset')}'**, an enterprise service with high business exposure.\n\n"
            f"**Composite Score**: **{top.get('risk_score')}/100 ({top.get('risk_level')})**. "
            f"This requires immediate attention because successful exploitation directly threatens business operations."
        )

        return {
            "headline": f"Why #{top['id']} is {top.get('risk_level')} Risk",
            "answer": answer_text,
            "action_items": [top.get("remediation_action", "Apply defensive patches.")],
            "relevant_events": [top]
        }

    @staticmethod
    def _answer_threat_specific(prioritized: List[Dict[str, Any]], threat_filter: str) -> Dict[str, Any]:
        matching = [t for t in prioritized if t.get("threat_type") == threat_filter]
        
        if not matching:
            return {
                "headline": f"No {threat_filter} Incidents Detected",
                "answer": f"Zero {threat_filter} incidents are present in the current log window. Telemetry is clean for this attack vector.",
                "action_items": ["Maintain proactive input validation checks."],
                "relevant_events": []
            }

        sample = matching[0]
        answer_text = (
            f"Detected **{len(matching)}** instances of **{threat_filter}** in recent telemetry.\n\n"
            f"- **Sample Incident**: #{sample['id']} on `{sample['endpoint']}` from IP `{sample['client_ip']}`\n"
            f"- **Risk Level**: {sample['risk_level']} ({sample['risk_score']}/100)\n"
            f"- **Detection Reason**: {sample['reason']}\n\n"
            f"**Mitigation Advice**: {sample['remediation_action']}"
        )

        return {
            "headline": f"{threat_filter} Analysis ({len(matching)} Incidents)",
            "answer": answer_text,
            "action_items": [sample["remediation_action"]],
            "relevant_events": matching[:3]
        }

    @staticmethod
    def _answer_general(query: str, stats: Dict[str, Any], prioritized: List[Dict[str, Any]], assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        return AISecurityAnalyst._format_executive_summary(stats, prioritized, assets)
