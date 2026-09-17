# Comprehensive Interview Preparation & Defense Bank

A structured 3-tier interview preparation guide covering fundamental to advanced technical questions for your project presentation and technical interviews.

---

## Tier 1: Beginner / Core Fundamentals

### 1. What is NLP and why is it used here?
- **Simple Answer**: NLP (Natural Language Processing) is a branch of AI that enables computers to understand human language and textual strings.
- **Technical Answer**: In this project, NLP treats web requests, URI query parameters, and HTTP POST bodies as structured text sequences, extracting linguistic and character n-gram patterns to distinguish malicious code syntax from benign user input.
- **Example from Project**: The model converts `' OR '1'='1` into character n-grams and calculates TF-IDF weights to classify it as a SQL injection attempt.
- **Interview Soundbite**: *"We treat web attack payloads as malicious text patterns. NLP allows us to learn syntax structures rather than relying on brittle, easily bypassed static regex rules."*

---

### 2. What is SQL Injection (SQLi)?
- **Simple Answer**: An attack where a hacker tricks a database into executing unintended commands by injecting malicious code into input fields.
- **Technical Answer**: An injection vulnerability occurring when untrusted user input is concatenated directly into a database query string without parameterized queries or prepared statements, allowing the attacker to bypass authentication, dump database tables, or corrupt data.
- **Example from Project**: Entering `' OR 1=1 --` into the search form makes the query condition always evaluate to True.

---

### 3. What is Cross-Site Scripting (XSS)?
- **Simple Answer**: An attack where malicious JavaScript code is injected into a website and executed in the victim's browser.
- **Technical Answer**: A client-side code injection flaw where an application includes unvalidated/unescaped user data in a web page delivered to other users, allowing attackers to steal session cookies, hijack accounts, or redirect to malicious domains.
- **Example from Project**: Injecting `<script>alert('XSS')</script>` or `<img src=x onerror=alert(document.cookie)>`.

---

### 4. What is a Confusion Matrix, Precision, Recall, and F1-Score?
- **Precision**: Of all requests the model flagged as threats, how many were *actually* threats? ($TP / (TP + FP)$). High precision prevents alert fatigue for SOC analysts.
- **Recall**: Of all the actual attacks launched against the server, what percentage did the model catch? ($TP / (TP + FN)$). **In cybersecurity, recall is the most critical metric**, because a False Negative means an attack slipped past into the internal network!
- **F1-Score**: Harmonic mean of Precision and Recall.

---

## Tier 2: Project-Specific Architecture Questions

### 5. Why did you not use a Large Language Model (LLM) like GPT-4?
- **Interview Answer**: *"While LLMs have exceptional natural language reasoning, they are ill-suited for real-time edge security inspection. An LLM invocation requires hundreds of milliseconds to multiple seconds of latency and substantial GPU memory costs. Web traffic inspection requires sub-millisecond evaluation. Our TF-IDF + Logistic Regression model delivers high-confidence threat detection in under 1 millisecond on CPU, making it practical for real-time inline security."*

---

### 6. How does Continuous Monitoring work without blocking the server?
- **Technical Answer**: We utilize Python's `asyncio` event loop with a dedicated background task (`ContinuousLogMonitor`). It tracks the log file pointer using file seek offset tailing. It reads new lines as they are flushed by the web server, executes inference asynchronously, and broadcasts alerts via WebSockets—ensuring the main HTTP server thread never blocks.

---

### 7. How do you prevent duplicate alert storms (SMS / Email flooding)?
- **Technical Answer**: Our `AlertService` implements an in-memory **throttling and deduplication cache**. It tracks tuples of `(client_ip, threat_type)` mapped to a timestamp. If the same attacker sends 100 SQLi payloads in 10 seconds, only the first triggers an external SMS/email, while subsequent occurrences are flagged as `THROTTLED` in the audit database.

---

### 8. How does the Frontend know monitoring is active?
- **Technical Answer**: The frontend connects via a persistent WebSocket connection to `/api/ws`. Upon connection, the backend immediately sends an `INITIAL_STATE` payload indicating the monitoring daemon's state. When start/stop buttons are clicked, the server broadcasts a `STATUS_UPDATE` event, dynamically shifting the animated central circle from Gray to pulsing Green or Red.

---

## Tier 3: Advanced Cybersecurity & Scalability Questions

### 9. What is Concept Drift in Cybersecurity Machine Learning?
- **Answer**: Attack vectors constantly evolve. Attackers discover new zero-day vulnerabilities, novel encoding bypasses, or new framework vulnerabilities. If the model was only trained on 2024 attack patterns, its accuracy will degrade over time (Concept Drift). In production, this is addressed via continuous active learning, periodic model retraining pipelines, and canary testing.

---

### 10. How is this system different from a production Web Application Firewall (WAF) or SIEM?
- **Answer**: *"A production WAF (such as Cloudflare or AWS WAF) operates as an inline reverse proxy that actively drops malicious TCP/HTTP connections before they reach the application. A SIEM (Security Information and Event Management) aggregates logs across an entire enterprise infrastructure. Our project is an AI-assisted detection and alerting system designed to analyze access logs, provide explainable threat insights, and assist security analysts."*
