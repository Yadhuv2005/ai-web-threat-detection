# AI-Powered Cyber Risk Manager — Real-Time Threat Detection, Risk Assessment & Intelligent Response Platform

An enterprise-grade, hybrid AI cybersecurity operations platform that combines **NLP payload classification** (character n-gram TF-IDF with Logistic Regression) and **behavioral sliding-window anomaly detection** with an **intelligent multi-factor Cyber Risk Engine**, **Asset Registry**, and an interactive **3D Particle Security Risk Sphere SOC Dashboard**.

---

## 🏛️ System Architecture

```
[ Target Web Application (Port 8001) ]
                  │
                  ▼ (Structured JSON Access Log)
        [ test_website/logs/access.log ]
                  │
                  ▼ (Continuous Async Log Watcher)
┌─────────────────────────────────────────────────────────────┐
│             Threat Detection Subsystem                      │
│  ├─ NLP Classifier (TF-IDF + Logistic Regression)           │  --> SQLi & XSS Detection (<1ms)
│  ├─ Behavioral Engine (Sliding Window Per-IP)               │  --> Brute-Force & Rate Spikes
│  └─ Explainability Generator                                │  --> Rationale & Matched Markers
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             NEW: AI Cyber Risk Engine                       │
│  ├─ Asset Registry Mapping (Endpoint -> Enterprise Asset)   │
│  ├─ Multi-Factor Risk Scoring (0–100)                       │
│  │   Score = Likelihood(35%) + Severity(35%) + Asset(30%)   │
│  ├─ Dynamic Triage (Critical, High, Medium, Low)            │
│  ├─ Business Impact & Actionable Remediation Synthesis      │
│  └─ Overall Organizational Risk Index Aggregator            │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
│      Smart Alert Engine      │ │   SQLite Extended Schema   │
│  Low: Dashboard only         │ │  - assets (Criticality)    │
│  Medium: Dashboard Notif     │ │  - threat_events (risk_*)  │
│  High: Dashboard + Email     │ │  - alert_history           │
│  Critical: Dash + Email + SMS│ │  - traffic_logs            │
└──────────────┬───────────────┘ └────────────┬───────────────┘
               │                              │
               └──────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│          FastAPI Monitoring Backend (Port 8000)             │
│  - REST APIs: /api/risk/overview, /api/risk/prioritized     │
│  - Asset Endpoints: /api/assets                             │
│  - AI Security Analyst: /api/analyst/query                  │
│  - WebSocket Broadcaster: /api/ws                           │
└─────────────────────────────┬───────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│        Cyber SOC Dashboard (Risk-Centered Redesign)         │
│  1. Hero 3D Particle "Security Risk Sphere" (Rotating dots) │
│  2. Risk Overview KPI Cards (Org Score, Severity counts)    │
│  3. Priority Threats (Critical & High triage queue)         │
│  4. Live Threat Feed (Real-time WebSocket event stream)     │
│  5. Risk Analytics (Risk Trend & Level Distribution Charts) │
│  6. AI Security Analyst Interactive Console                 │
│  7. Prioritized Remediation Recommendations                 │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Core Capabilities

### 1. AI Cyber Risk Engine
Moves beyond binary "threat/no threat" detection to assess **business-contextual risk**:
$$\text{Risk Score} = \min(100, \text{Round}((\text{Likelihood} \times 0.35 + \text{Technical Severity} \times 0.35 + \text{Asset Criticality} \times 0.30) \times 100))$$
- **Likelihood**: Derived from ML model probability and exploit complexity.
- **Technical Severity**: Categorized by potential system compromise (SQLi = 0.95, Brute-Force = 0.90, High-Rate = 0.75, XSS = 0.70).
- **Asset Criticality**: Weighted by enterprise asset value (Payment = 1.0, Auth = 1.0, Admin = 0.95, Catalog API = 0.8, Search = 0.6, Web = 0.4).

### 2. Enterprise Asset Registry
Defines and tracks business systems:
- **Identity & Access Gateway** (`/login`) — *CRITICAL*
- **Payment & Checkout API** (`/cart/checkout`) — *CRITICAL*
- **Administrative Management Console** (`/admin`) — *CRITICAL*
- **Product Catalog API** (`/api`) — *HIGH*
- **Customer Search Engine** (`/search`) — *MEDIUM*
- **Public Storefront** (`/`) — *LOW*

### 3. Risk Prioritization (Triage Queue)
Threats are automatically sorted by risk score so security operations teams know exactly which incidents require immediate containment.

### 4. AI Security Analyst
An intelligent Q&A engine grounded in real database telemetry. Supports questions such as:
- *"What are today's biggest security risks?"*
- *"What should I investigate first?"*
- *"Which assets are most at risk?"*
- *"Why is this threat high risk?"*
- *"What happened in the last 24 hours?"*

### 5. Smart Risk-Based Alerting
- **LOW Risk**: Logged to dashboard only.
- **MEDIUM Risk**: Dashboard notification and audit logging.
- **HIGH Risk**: Dashboard + Email alert (SMTP).
- **CRITICAL Risk**: Dashboard + Email alert + SMS alert (Twilio).
- Features **cooldown deduplication** to eliminate alert flooding.

### 6. Interactive 3D Particle "Security Risk Sphere"
A pure mathematical 3D perspective particle sphere rendered with 550 glowing dots on HTML5 Canvas:
- **Green State**: Score < 40 (System Secure / Normal).
- **Yellow/Amber State**: Score 40–79 (Elevated / High Risk).
- **Red State**: Score 80–100 (Critical Threat Active).
- Reacts with a 3D ripple wave whenever a new attack hits the server.

---

## 🚀 Quick Start Guide

### Step 1: Set Up Virtual Environment & Dependencies
```bash
cd ~/Desktop/"WEB THREAT"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Launch Both Servers (One-Command Launch)
```bash
./start.sh
```
This launches:
- **Cyber Risk SOC Dashboard**: `http://127.0.0.1:8000`
- **Target Test Website**: `http://127.0.0.1:8001`

### Step 3: Simulate Traffic & Verify
In a second terminal window:
```bash
cd ~/Desktop/"WEB THREAT"
./venv/bin/python3 tests/generate_traffic.py 1
```

Watch the **Security Risk Sphere** rotate and shift, observe the **Priority Threats triage queue**, and query the **AI Security Analyst console** in real time!
