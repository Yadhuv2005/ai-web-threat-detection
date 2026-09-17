"""
NLP / Machine Learning Threat Detector
--------------------------------------
Loads serialized TF-IDF vectorizer and classification model.
Performs real-time probabilistic inference on incoming web request texts.
"""

import os
import joblib
from ml.preprocessing.text_cleaner import clean_web_text, extract_threat_tokens
import backend.config as config

CLASS_MAP = {0: "NORMAL", 1: "SQL_INJECTION", 2: "XSS"}

class MLThreatDetector:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_loaded = False
        self.load_model()

    def load_model(self):
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        model_p = os.path.join(root_dir, config.MODEL_PATH)
        vec_p = os.path.join(root_dir, config.VECTORIZER_PATH)

        if os.path.exists(model_p) and os.path.exists(vec_p):
            try:
                self.model = joblib.load(model_p)
                self.vectorizer = joblib.load(vec_p)
                self.is_loaded = True
                print("[+] ML Threat Detector loaded successfully.")
            except Exception as e:
                print(f"[-] Error loading ML model: {e}")
        else:
            print("[-] Model files not found on disk. Falling back to heuristic mode until model is trained.")

    def predict(self, raw_input_text: str) -> dict:
        """
        Inference routine.
        Returns:
            {
                "threat_type": "NORMAL" | "SQL_INJECTION" | "XSS",
                "confidence": float (0.0 to 1.0),
                "is_threat": bool,
                "severity": "LOW" | "HIGH" | "CRITICAL",
                "tokens": list of identified suspicious tokens
            }
        """
        cleaned = clean_web_text(raw_input_text)
        tokens = extract_threat_tokens(cleaned)

        if not self.is_loaded:
            # Fallback heuristic if ML model is not yet compiled
            if any("SQLi" in t for t in tokens):
                return {
                    "threat_type": "SQL_INJECTION",
                    "confidence": 0.88,
                    "is_threat": True,
                    "severity": "HIGH",
                    "tokens": tokens
                }
            elif any("XSS" in t for t in tokens):
                return {
                    "threat_type": "XSS",
                    "confidence": 0.88,
                    "is_threat": True,
                    "severity": "HIGH",
                    "tokens": tokens
                }
            return {
                "threat_type": "NORMAL",
                "confidence": 0.99,
                "is_threat": False,
                "severity": "LOW",
                "tokens": []
            }

        # Vectorize and Predict using trained ML Model
        vec = self.vectorizer.transform([cleaned])
        probs = self.model.predict_proba(vec)[0]
        pred_idx = self.model.predict(vec)[0]
        confidence = float(probs[pred_idx])
        label = CLASS_MAP.get(pred_idx, "NORMAL")

        # Threshold gating: If confidence is lower than threshold, do not falsely flag
        if label != "NORMAL" and confidence < config.CONFIDENCE_THRESHOLD:
            label = "NORMAL"

        is_threat = (label != "NORMAL")
        severity = "HIGH" if is_threat else "LOW"
        if label == "SQL_INJECTION" and confidence > 0.90:
            severity = "CRITICAL"

        return {
            "threat_type": label,
            "confidence": round(confidence, 4),
            "is_threat": is_threat,
            "severity": severity,
            "tokens": tokens
        }
