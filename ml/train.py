"""
NLP Threat Classification Model Training Pipeline
--------------------------------------------------
Trains a machine learning model to classify web request inputs into:
- 0: NORMAL
- 1: SQL_INJECTION
- 2: XSS

NLP Pipeline Architecture:
Raw Text -> Text Cleaner (URL Unquoting & Normalization) 
         -> Character n-gram TF-IDF Vectorizer
         -> Logistic Regression / Multinomial Naive Bayes Classifier
         -> Evaluation & Model Serialization (joblib)
"""

import os
import json
import joblib
import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

from preprocessing.text_cleaner import clean_web_text
from data.dataset_generator import generate_dataset, save_dataset_csv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "dataset.csv")
SAVED_MODELS_DIR = os.path.join(BASE_DIR, "saved_models")
os.makedirs(SAVED_MODELS_DIR, exist_ok=True)

MODEL_FILE = os.path.join(SAVED_MODELS_DIR, "threat_classifier.pkl")
VECTORIZER_FILE = os.path.join(SAVED_MODELS_DIR, "tfidf_vectorizer.pkl")
METRICS_FILE = os.path.join(SAVED_MODELS_DIR, "model_metrics.json")

def load_or_create_data():
    """Ensure dataset exists; if not, generate synthetic dataset."""
    if not os.path.exists(DATA_PATH):
        print("[*] Generating training dataset...")
        data = generate_dataset(2400)
        save_dataset_csv(data, DATA_PATH)
    
    df = pd.read_csv(DATA_PATH)
    print(f"[*] Loaded dataset with {len(df)} samples.")
    print("Class distribution:\n", df["threat_type"].value_counts())
    return df

def train_threat_detector():
    df = load_or_create_data()

    # Step 1: Text Preprocessing
    print("[*] Applying text cleaning and recursive URL decoding...")
    df["cleaned_text"] = df["text"].astype(str).apply(clean_web_text)

    X = df["cleaned_text"]
    y = df["label"]

    # Step 2: Train/Test Split (80% Train, 20% Test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Train set size: {len(X_train)}, Test set size: {len(X_test)}")

    # Step 3: Feature Extraction via Character N-gram TF-IDF
    # WHY character n-grams?
    # Web attack payloads (e.g. ' OR 1=1--, <script>) do not follow natural language English words.
    # Punctuation, symbols, quotes, and tag brackets are critical signals.
    # Character n-grams (ranges 2 to 5) retain these structural symbols even with typos or evasions.
    print("[*] Fitting Character N-Gram TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(2, 5),
        max_features=5000,
        sublinear_tf=True
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Step 4: Model Training with Logistic Regression
    # Calibrated probability output, fast inference (<1ms per request), highly interpretable.
    print("[*] Training Logistic Regression Classifier...")
    model = LogisticRegression(
        C=10.0,
        max_iter=1000,
        class_weight="balanced",
        random_state=42
    )
    model.fit(X_train_vec, y_train)

    # Step 5: Evaluation
    y_pred = model.predict(X_test_vec)
    acc = accuracy_score(y_test, y_pred)
    report = classification_report(
        y_test, y_pred,
        target_names=["NORMAL", "SQL_INJECTION", "XSS"],
        output_dict=True
    )
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n================ MODEL EVALUATION ================")
    print(f"Overall Accuracy: {acc * 100:.2f}%\n")
    print(classification_report(y_test, y_pred, target_names=["NORMAL", "SQL_INJECTION", "XSS"]))
    print(f"Confusion Matrix:\n{np.array(cm)}")
    print("===================================================\n")

    # Step 6: Save Model and Vectorizer Artifacts
    joblib.dump(model, MODEL_FILE)
    joblib.dump(vectorizer, VECTORIZER_FILE)
    print(f"[+] Model saved to: {MODEL_FILE}")
    print(f"[+] Vectorizer saved to: {VECTORIZER_FILE}")

    # Step 7: Export Metrics to JSON
    metrics_summary = {
        "accuracy": round(acc, 4),
        "classes": ["NORMAL", "SQL_INJECTION", "XSS"],
        "classification_report": report,
        "confusion_matrix": cm,
        "samples_count": len(df)
    }
    with open(METRICS_FILE, "w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)
    print(f"[+] Metrics metadata saved to: {METRICS_FILE}")

if __name__ == "__main__":
    train_threat_detector()
