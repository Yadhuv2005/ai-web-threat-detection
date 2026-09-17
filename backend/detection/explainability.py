"""
Threat Explainability & Reasoning Engine
----------------------------------------
Translates raw probabilistic machine learning outputs and behavioral metrics
into human-understandable explanations for cybersecurity analysts.
"""

def generate_explanation(ml_result: dict, behavioral_result: dict, endpoint: str, payload: str) -> str:
    """
    Synthesizes ML tokens and behavioral telemetry into a clear defense explanation.
    """
    reasons = []

    # Behavioral Explanations
    if behavioral_result.get("is_threat"):
        reasons.append(behavioral_result["reason"])

    # ML Classification Explanations
    if ml_result.get("is_threat"):
        threat_type = ml_result["threat_type"]
        confidence = ml_result["confidence"]
        tokens = ml_result.get("tokens", [])

        if threat_type == "SQL_INJECTION":
            token_desc = f" (matched markers: {', '.join(tokens)})" if tokens else ""
            reasons.append(
                f"NLP classifier detected SQL Injection syntax patterns with {confidence * 100:.1f}% confidence{token_desc}."
            )
        elif threat_type == "XSS":
            token_desc = f" (matched markers: {', '.join(tokens)})" if tokens else ""
            reasons.append(
                f"NLP classifier detected Cross-Site Scripting (XSS) script/event tags with {confidence * 100:.1f}% confidence{token_desc}."
            )

    if not reasons:
        return "Normal web request within benign statistical thresholds."

    return " | ".join(reasons)
