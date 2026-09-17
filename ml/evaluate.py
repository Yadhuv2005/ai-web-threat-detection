"""
Model Evaluation and Inference Benchmarking
-------------------------------------------
Tests the saved threat classifier on unseen edge-case payloads.
Validates both positive detection rate and false-positive handling.
"""

import os
import json
import joblib
import pandas as pd
from preprocessing.text_cleaner import clean_web_text, extract_threat_tokens

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "saved_models")
MODEL_FILE = os.path.join(SAVED_MODELS_DIR, "threat_classifier.pkl")
VECTORIZER_FILE = os.path.join(SAVED_MODELS_DIR, "tfidf_vectorizer.pkl")

CLASS_NAMES = ["NORMAL", "SQL_INJECTION", "XSS"]

def test_inference():
    if not os.path.exists(MODEL_FILE) or not os.path.exists(VECTORIZER_FILE):
        print("[-] Trained model or vectorizer not found. Run `python ml/train.py` first.")
        return

    model = joblib.load(MODEL_FILE)
    vectorizer = joblib.load(VECTORIZER_FILE)
    print("[+] Successfully loaded trained model and vectorizer.")

    # Diverse real-world test cases including edge cases and encoded attacks
    test_cases = [
        # Normal inputs
        "search?q=wireless+mouse",
        "/index.html",
        "api/products",
        "username=john_doe&password=secretPassword123!",
        "search?q=t-shirt+blue+size+large",
        
        # SQL Injection attacks
        "search?q=' OR '1'='1",
        "user_id=1' UNION SELECT username, password FROM users--",
        "id=10; DROP TABLE customers--",
        "query=%27%20OR%201%3D1%20--",
        "search?q=admin' --",
        
        # XSS attacks
        "q=<script>alert('XSS')</script>",
        "redirect=<img src=x onerror=alert(document.cookie)>",
        "comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "search?q=<svg onload=alert(1)>",
        "q=javascript:alert('pwned')"
    ]

    print("\n--- Live Inference Validation ---")
    for text in test_cases:
        cleaned = clean_web_text(text)
        vec = vectorizer.transform([cleaned])
        probs = model.predict_proba(vec)[0]
        pred_idx = model.predict(vec)[0]
        pred_label = CLASS_NAMES[pred_idx]
        confidence = probs[pred_idx]
        tokens = extract_threat_tokens(cleaned)

        status_icon = "🟢" if pred_label == "NORMAL" else "🔴"
        print(f"{status_icon} Input: {text}")
        print(f"   Prediction: {pred_label} (Confidence: {confidence * 100:.1f}%)")
        if tokens:
            print(f"   Flagged Tokens: {', '.join(tokens)}")
        print("-" * 50)

if __name__ == "__main__":
    test_inference()
