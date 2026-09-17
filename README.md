# AI-Based Web Threat Detection and Real-Time Alerting System

An end-to-end, hybrid AI and behavioral cybersecurity platform designed to continuously monitor web server access logs, detect security threats (SQL Injection, XSS, Brute-Force, Rate Bursts), explain threat reasons, and stream live telemetry to a Security Operations Center (SOC) dashboard.

---

## Architecture Overview

```
[ Target Website (Port 8001) ]
           │
           ▼ (Structured JSON Access Log)
    [ logs/access.log ]
           │
           ▼ (Continuous Async Log Watcher)
┌──────────────────────────────────────────────┐
│       Hybrid Threat Detection Engine         │
│  ├─ NLP Classifier (TF-IDF + LogReg)        │  --> Detects SQLi, XSS
│  ├─ Behavioral Engine (Sliding Windows)      │  --> Detects Brute-Force, Spikes
│  └─ Explainability & Rationale Generator     │
└──────────────────────┬───────────────────────┘
                       │
         ┌─────────────┴─────────────┐
         ▼                           ▼
[ SQLite Database ]          [ Alert Service ]
(Logs, Threats, Alerts)      (SMS / Email Throttled)
         │
         ▼
[ FastAPI Backend (Port 8000) ]
         │
         ▼ (Real-time WebSockets / REST)
[ SOC Cyber Dashboard UI ]
 (Animated Radar Circle, Live Table, Charts, Threat Feed)
```

---

## Quick Start Guide

### Step 1: Set Up Python Virtual Environment
```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### Step 2: Train the NLP Threat Classifier
```bash
# Generates balanced dataset and trains character n-gram TF-IDF + Logistic Regression model
python3 ml/train.py

# (Optional) Run inference benchmark on sample payloads
python3 ml/evaluate.py
```

### Step 3: Run the Target Website
```bash
# In Terminal 1: Starts the educational web application on port 8001
python3 test_website/app.py
```

### Step 4: Run the Central Monitoring Backend & SOC Dashboard
```bash
# In Terminal 2: Starts the FastAPI server and WebSocket broadcaster on port 8000
python3 backend/main.py
```
Open your browser and navigate to: **`http://127.0.0.1:8000`**

### Step 5: Test the System with Simulated Traffic
```bash
# In Terminal 3: Simulate realistic normal browsing and attack vectors
python3 tests/generate_traffic.py
```

---

## Live Demonstration Flow
1. Open the SOC Dashboard at `http://127.0.0.1:8000`.
2. Verify the **center monitoring circle is pulsing green** indicating continuous monitoring is active.
3. Open `http://127.0.0.1:8001` in another tab and browse normally. Notice the dashboard increments benign traffic and logs requests.
4. Click one of the educational attack payloads on the target website (e.g. `/search?q=' OR 1=1 --`).
5. Observe the dashboard **instantly pulse red**, record the SQL Injection threat, and output the detailed explainability rationale:
   *"NLP classifier detected SQL Injection syntax patterns with 98.2% confidence (matched markers: SQLi token: 'or 1=1')*".
6. Run the brute-force simulation (`python3 tests/generate_traffic.py 5`) and watch the behavioral engine flag the IP after repeated 401 unauthorized failures.

---

## Educational Documentation
- **[LEARNING_GUIDE.md](docs/LEARNING_GUIDE.md)**: Deep dive on NLP mechanics, TF-IDF vs LLMs, access log structure, and WAF comparisons.
- **[INTERVIEW_PREP.md](docs/INTERVIEW_PREP.md)**: 3-tier Q&A bank (Beginner, Project-Specific, Advanced) for viva and technical interviews.
- **[PRESENTATION.md](docs/PRESENTATION.md)**: 2-minute elevator pitch, 5-minute technical presentation script, and slides outline.
