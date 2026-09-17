"""
Unit & Integration Tests for AI-Powered Cyber Risk Manager
-----------------------------------------------------------
Tests:
1. Asset Registry endpoint pattern matching.
2. Risk Engine formula calculation and level assignment.
3. AI Security Analyst natural language queries.
4. Smart Alerting policy routing.
"""

from backend.risk.asset_registry import asset_registry_instance
from backend.risk.risk_engine import RiskEngine
from backend.risk.analyst import AISecurityAnalyst
from backend.alerts.alert_service import AlertService

def test_asset_registry_mapping():
    # Login endpoint must map to Identity Gateway (CRITICAL)
    asset_auth = asset_registry_instance.match_asset_by_endpoint("/login")
    assert asset_auth["criticality"] == "CRITICAL"
    assert asset_auth["id"] == "asset-auth-01"

    # Search endpoint must map to Search Service (MEDIUM)
    asset_search = asset_registry_instance.match_asset_by_endpoint("/search?q=laptop")
    assert asset_search["criticality"] == "MEDIUM"

    # Root endpoint maps to Public Storefront (LOW)
    asset_web = asset_registry_instance.match_asset_by_endpoint("/")
    assert asset_web["criticality"] == "LOW"

def test_risk_score_calculation():
    # High confidence SQLi targeting search
    risk_sqli = RiskEngine.calculate_risk(
        threat_type="SQL_INJECTION",
        confidence=0.98,
        detection_source="ML_CLASSIFIER",
        endpoint="/search",
        payload="' OR 1=1 --"
    )
    assert risk_sqli["risk_score"] >= 60
    assert risk_sqli["risk_level"] in ["HIGH", "CRITICAL"]
    assert "remediation_action" in risk_sqli
    assert "business_impact" in risk_sqli

    # Brute force targeting login (Critical asset)
    risk_brute = RiskEngine.calculate_risk(
        threat_type="BRUTE_FORCE",
        confidence=0.99,
        detection_source="BEHAVIORAL_ENGINE",
        endpoint="/login",
        payload="failed attempts"
    )
    # 0.99*0.35 + 0.90*0.35 + 1.0*0.30 = 0.3465 + 0.315 + 0.30 = 0.9615 -> 96 (CRITICAL)
    assert risk_brute["risk_score"] >= 80
    assert risk_brute["risk_level"] == "CRITICAL"

def test_ai_security_analyst_query():
    res = AISecurityAnalyst.answer_query("What should I investigate first?")
    assert "headline" in res
    assert "answer" in res
    assert "action_items" in res

    res_risks = AISecurityAnalyst.answer_query("What are today's biggest security risks?")
    assert len(res_risks["answer"]) > 20

def test_smart_alerting_policy():
    alert_service = AlertService()
    test_event = {
        "timestamp": "2026-09-17T12:00:00Z",
        "client_ip": "192.168.1.99",
        "threat_type": "SQL_INJECTION",
        "risk_level": "CRITICAL",
        "risk_score": 95,
        "affected_asset": "Payment API",
        "reason": "Test payload detected",
        "remediation_action": "Sanitize query",
        "endpoint": "/cart/checkout"
    }
    # Dispatching should process without error
    dispatch_res = alert_service.dispatch_alert(test_event, 9999)
    assert dispatch_res["dashboard"] == "SENT"
