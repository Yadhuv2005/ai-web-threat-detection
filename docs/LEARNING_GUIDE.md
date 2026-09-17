# Complete Educational & Technical Learning Guide
## AI-Based Web Threat Detection and Real-Time Alerting System

---

## 1. System Overview & Core Motivations
Traditional Web Application Firewalls (WAFs) historically relied purely on static regular expression (regex) signatures. While fast, regex signatures suffer from:
1. **Brittleness**: Attackers can easily bypass signatures via encoding tricks, character mutations, or SQL dialect comments (e.g. `/*!50000SELECT*/`).
2. **Maintenance Overhead**: Security teams must constantly write and maintain thousands of brittle rules.
3. **Context Blindness**: A single HTTP request with `"admin"` is completely normal, but 20 failed login attempts in 10 seconds is a credential-stuffing attack.

### Why a Hybrid Architecture?
Our system uses a **Defense-in-Depth Hybrid Architecture**:
- **NLP / Machine Learning Classifier**: Specializes in *semantic and structural inspection of payloads* (SQL Injection syntax, XSS script tags, DOM event handlers).
- **Behavioral Detection Engine**: Specializes in *temporal and statistical traffic patterns* (Brute-Force credential attacks, DDoS/Rate spikes, Directory traversal enumeration).

Neither approach alone is sufficient. Together, they create a robust defensive barrier.

---

## 2. Deep Dive: Key Concepts

### A. Web Server Logs vs Application Logs vs Monitoring Backend
- **Website URL**: The network address (e.g., `http://localhost:8001/search`) that a client requests.
- **Web Server**: The software daemon (e.g., Uvicorn, Nginx, Apache) that handles socket connections, TLS termination, and routes HTTP packets.
- **Access Logs**: Standardized records produced by the web server for *every single incoming HTTP request*. Contains client IP, timestamp, HTTP verb, path, query string, response code, and latency.
- **Application Logs**: Internal debug logs written by developer code (e.g., database connection errors, stack traces).
- **Monitoring Backend**: An independent defensive service that reads access logs in real-time, runs threat inference, and alerts the Security Operations Center (SOC).

> **Important Defense Principle**: You cannot monitor arbitrary third-party websites without ownership, log-forwarding agent authorization, or API integration. You must have access to the log source.

---

### B. The Machine Learning & NLP Pipeline

```
Raw Web Payload ('%27%20OR%201%3D1--')
     │
     ▼
Recursive URL Unquoting & Entity Normalization
     │
     ▼
Character N-Gram Extraction (ranges 2 to 5 characters)
     │
     ▼
TF-IDF Vectorization (Term Frequency - Inverse Document Frequency)
     │
     ▼
Logistic Regression Classifier (Calibrated Probability Output)
     │
     ▼
Prediction: SQL_INJECTION (96.4% Confidence)
```

#### What is Tokenization?
Breaking raw text into discrete units (tokens). In standard NLP, tokens are natural words (`"hello"`, `"world"`). In cybersecurity payload analysis, word-based tokenization fails because malicious inputs (`' OR '1'='1`) are not English words! We therefore use **character n-grams** (sub-strings of 2 to 5 characters, such as `' o`, ` or`, `or `, ` 1=`, `1='`).

#### What is TF-IDF?
- **Term Frequency (TF)**: How frequently an n-gram appears in a given request.
- **Inverse Document Frequency (IDF)**: Penalizes tokens that appear everywhere across normal requests (like `http` or `.html`), while elevating rare, high-signal tokens (like `union select` or `<script>`).

#### Why Logistic Regression over Complex Deep Learning / LLMs?
1. **Sub-Millisecond Latency**: Security inspection occurs in the critical path of web requests. Logistic Regression with TF-IDF computes inference in **under 1 millisecond**, whereas an LLM takes 200–1000ms.
2. **Determinism & Explainability**: Logistic regression weights map directly to input feature tokens, making it easy to generate explainable rationale for security analysts.
3. **Resource Efficiency**: Can run on commodity servers or edge proxies without expensive GPUs.

---

## 3. Behavioral Detection Mechanics
Behavioral anomaly detection maintains an **in-memory sliding time-window** per IP address:
- **Brute-Force Rule**: If an IP accumulates $\ge 5$ HTTP 401 (Unauthorized) status codes within 60 seconds $\rightarrow$ Trigger `BRUTE_FORCE` alert.
- **Rate-Burst Rule**: If an IP sends $> 25$ requests within 10 seconds $\rightarrow$ Trigger `HIGH_RATE_BURST` alert.

---

## 4. Real-Time Communication: WebSockets vs Polling
Traditional web apps use **Polling** (frontend repeatedly asks the server every 2 seconds: *"Any new threats?"*). This wastes CPU, bandwidth, and adds delay.
Our platform uses a **bidirectional WebSocket (`/api/ws`)**:
- The browser opens a persistent, lightweight TCP connection.
- As soon as the background log watcher processes a new threat, the server **immediately pushes** the event to the frontend in real time (<10ms).
