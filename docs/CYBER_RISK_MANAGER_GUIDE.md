# AI-Powered Cyber Risk Manager — Architecture, Risk Formulas & Defense Guide

---

## 1. System Transformation Overview
The platform has been extended from a basic threat detector into an **Enterprise Cyber Risk Manager**. Rather than only alerting *"SQL Injection detected"*, the system now answers the executive questions:
- *"Which company asset is under attack?"*
- *"What is the numerical Risk Score (0–100) and Severity Tier?"*
- *"What is the business impact on customer trust, finances, or compliance?"*
- *"What are the exact prioritized remediation actions for security engineers?"*

---

## 2. Multi-Factor Risk Calculation Formula

Based on **NIST SP 800-30** and **CVSS** vulnerability assessment methodologies:

$$\text{Risk Score} = \min(100, \text{Round}((\text{Threat Likelihood} \times 0.35 + \text{Technical Severity} \times 0.35 + \text{Asset Criticality} \times 0.30) \times 100))$$

### Component Breakdown:
1. **Threat Likelihood ($0.20 - 1.00$, Weight: $35\%$)**:
   - Probabilistic output from the character n-gram TF-IDF + Logistic Regression model.
   - High classification confidence signifies high likelihood of authentic exploit attempt.
2. **Technical Severity ($0.40 - 0.95$, Weight: $35\%$)**:
   - `SQL_INJECTION`: $0.95$ (Database takeover, data exfiltration)
   - `BRUTE_FORCE`: $0.90$ (Account takeover, credential stuffing)
   - `HIGH_RATE_BURST`: $0.75$ (Denial-of-service, API starvation)
   - `XSS`: $0.70$ (Session hijacking, DOM injection)
   - `RECONNAISSANCE_PROBE`: $0.50$ (Directory brute-forcing, info gathering)
3. **Asset Criticality ($0.40 - 1.00$, Weight: $30\%$)**:
   - Payment / Checkout Gateway: $1.00$ (*CRITICAL*)
   - Identity & Authentication Service: $1.00$ (*CRITICAL*)
   - Admin Management Console: $0.95$ (*CRITICAL*)
   - Product Catalog API: $0.80$ (*HIGH*)
   - Customer Search Service: $0.60$ (*MEDIUM*)
   - Public Storefront: $0.40$ (*LOW*)

### Risk Tiers:
- **CRITICAL** (Score 80–100): Immediate containment required.
- **HIGH** (Score 60–79): Urgent triage within operational shift.
- **MEDIUM** (Score 40–59): Moderate priority anomaly.
- **LOW** (Score 0–39): Benign or informational event.

---

## 3. Smart Risk-Based Alerting Matrix

| Risk Tier | Risk Score | Dispatch Channels | Action Required |
| :--- | :--- | :--- | :--- |
| **LOW** | 0 – 39 | Dashboard Feed Only | Informational |
| **MEDIUM** | 40 – 59 | Dashboard + Audit Record | Monitor |
| **HIGH** | 60 – 79 | Dashboard + Email (SMTP) | Triage within 1 hr |
| **CRITICAL** | 80 – 100 | Dashboard + Email + SMS (Twilio) | Immediate Incident Response |

*Note*: An in-memory deduplication cache prevents alert flooding if identical payloads are sent in bursts.

---

## 4. Interactive 3D Particle "Security Risk Sphere"

The central visual anchor is a **3D perspective rotating particle sphere** rendered with 550 glowing points on an HTML5 canvas:
- **Fibonacci Sphere Distribution**: Distributes glowing nodes uniformly in 3-dimensional space using the golden ratio.
- **Mathematical 3D Projection**:
  $$x' = cx + (x \cos\theta + z \sin\theta) \cdot \frac{fov}{fov + z'}$$
  $$y' = cy + (y \cos\phi - z' \sin\phi) \cdot \frac{fov}{fov + z'}$$
- **State Interpolation**:
  - `Green (rgba(16, 185, 129))`: Score $< 40$ (System Secure).
  - `Yellow/Orange (rgba(249, 115, 22))`: Score $40 - 79$ (Elevated Risk).
  - `Red (rgba(239, 68, 68))`: Score $\ge 80$ (Critical Incident Active).
  - Dynamic ripple wave radiates through the sphere upon receiving fresh attacks.

---

## 5. AI Security Analyst Console

Provides natural language intelligence grounded strictly in SQLite threat data:
- Question: *"What should I investigate first?"*  
  $\rightarrow$ Queries `get_prioritized_threats()`, extracts Incident #1, explains why it poses the highest risk, and outputs concrete remediation steps.
- Question: *"Which assets are most at risk?"*  
  $\rightarrow$ Evaluates asset exposures, counting incident frequency against critical services.
- Question: *"Why is this threat high risk?"*  
  $\rightarrow$ Explains the Likelihood $\times$ Severity $\times$ Asset calculation.
