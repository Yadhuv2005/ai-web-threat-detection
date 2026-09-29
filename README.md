# AEGIS — Autonomous Cyber Risk Operations & AI Threat Intelligence Platform

An executive-grade, hybrid AI cybersecurity platform featuring **NLP sub-word threat classification**, **behavioral sliding-window anomaly heuristics**, a **multi-factor Cyber Risk Engine**, and a **Luxury Gold 3D Particle Risk Sphere** SOC Dashboard.

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
│             AI Cyber Risk Engine (Dynamic Decay)            │
│  ├─ Asset Registry Mapping (Endpoint -> Enterprise Asset)   │
│  ├─ Multi-Factor Risk Scoring (0–100)                       │
│  │   Score = Likelihood(35%) + Severity(35%) + Asset(30%)   │
│  ├─ 90-Second Time Decay & Clean Traffic Dampening          │
│  ├─ Dynamic Triage (Critical, High, Medium, Low)            │
│  └─ Overall Organizational Risk Index Aggregator            │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
┌──────────────────────────────┐ ┌────────────────────────────┐
               │                              │
┌──────────────┴───────────────┐ ┌────────────┴───────────────┐
│     Multi-Channel Alerts     │ │    SQLite Telemetry DB     │
│  - Real-time Spoken Voice    │ │  - assets (Criticality)    │
│  - Dashboard WebSockets      │ │  - threat_events           │
│  - Automated Cooldown Rules  │ │  - traffic_logs            │
└──────────────┬───────────────┘ └────────────┬───────────────┘
               │                              │
               └──────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│          FastAPI Monitoring Backend (Port 8000)             │
│  - REST APIs: /api/stats, /api/risk/prioritized, /api/assets│
│  - AI Security Analyst Q&A Engine: /api/analyst/query       │
│  - Telemetry Reset Pipeline: /api/reset                     │
│  - WebSocket Real-Time Streamer: /api/ws                    │
└─────────────────────────────┬───────────────────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│         Executive Gold & Noir Cyber SOC Interface           │
│  1. iOS-Style Welcome Intro with Typewriter & Female Audio  │
│  2. Live Moving Stock Ticker with Real-Time Attack Intel    │
│  3. Centered 3D Particle Risk Sphere (Gold Baseline)        │
│  4. Hover Popdown Navigation (Zero-Scroll HUD)              │
│  5. Real-Time Spoken Audio Warning on Detected Attacks      │
│  6. AI Security Analyst with Remediation Playbooks          │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚡ Key Highlights & Features

### 1. iOS-Style Cinematic Welcome Intro
- Pure deep black opening canvas with glowing gold typography (*Cinzel* serif).
- Live typewriter "writing" animation for the title and subtitle.
- **Female Voice Audio Synthesis**: Automatically welcomes the operator upon initializing the security protocol:
  > *"Welcome to Aegis. Autonomous cyber defense initialized. Systems secure."*

### 2. Luxury Continuous Stock Ticker
- High-frequency marquee bar constantly streaming real-time security intelligence, machine learning model accuracy ratings (97.4%), and threat statistics across the top of the screen.

### 3. Pure Focused Zero-Scroll 3D Risk Sphere Centerpiece
- The dashboard is completely uncluttered with zero vertical scrolling required.
- The central 3D particle sphere rotates gracefully with metallic gold shaders under baseline conditions, dynamically reacting with red shockwaves when threats occur.

### 4. Real-Time Spoken Threat Warnings (Audio Alerts)
- Whenever a live attack hits the system, the platform speaks the detected attack type and exact elevated risk score in a natural female voice:
  - 🔊 *"Warning. SQL Injection detected. Risk score elevated to 85."*
  - 🔊 *"Warning. Cross-Site Scripting detected. Risk score elevated to 77."*
  - 🔊 *"Warning. Brute Force Attack detected. Risk score elevated to 96."*

### 5. Centered Executive Hover Popdowns
Access every subsystem instantly from the top navigation bar without leaving the center view:
- **📊 Risk Telemetry**: Real-time KPI cards (Overall Risk, Critical, High, Medium, Low).
- **🚨 Priority Threats**: Triage queue ranked by business impact.
- **📡 Live Feed & Assets**: Live WebSocket log stream and registered assets.
- **📈 Analytics**: Temporal risk trend chart and severity distributions.
- **🤖 AI Analyst**: Interactive SOC Q&A assistant explaining attacks and code solutions.
- **🛠️ Remediation**: Direct mitigation directives.

### 6. Dynamic Risk Scoring with 90-Second Time-Decay
- Threat density and attack severity dynamically spike the score.
- As legitimate traffic flows or after 90 seconds of inactivity, the score automatically decays back to a green baseline (**12 / 100 — SYSTEM SECURE**).

---

## 🚀 Quick Start Guide

### One-Click Launch (macOS)
Simply double-click:
👉 **`Aegis Cyber Defense.app`** or run `./launch_aegis.command`

### Terminal Launch
```bash
# 1. Clone repository
git clone https://github.com/Yadhuv2005/ai-web-threat-detection.git
cd ai-web-threat-detection

# 2. Run automated start script (auto-spawns target website & SOC backend)
./start.sh
```

- **Aegis SOC Dashboard**: `http://127.0.0.1:8000`
- **Monitored CyberShop Target**: `http://127.0.0.1:8001`

---

## 🧪 Testing Live Attacks Against the Target

Open **`http://127.0.0.1:8001`** in your browser and test these vectors:

1. **SQL Injection (SQLi)**:
   Search for: `' OR 1=1 --`
2. **Cross-Site Scripting (XSS)**:
   Search for: `<script>alert('XSS')</script>`
3. **Brute Force**:
   Go to `/login` and submit invalid credentials 5+ times in a row.

Watch the central 3D sphere glow red, hear the audio alert, and ask the **AI Analyst** how to fix it!
