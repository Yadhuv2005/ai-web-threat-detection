# Project Presentation Preparation & Speech Scripts

---

## 1. Project Abstract
Modern web applications face an unprecedented volume of automated and sophisticated cyber attacks, including SQL Injection, Cross-Site Scripting (XSS), and automated credential stuffing. Traditional signature-based firewalls struggle with obfuscated payloads and fail to capture behavioral anomaly patterns without extensive manual rule maintenance. 

This project presents an **AI-Based Web Threat Detection and Real-Time Alerting System**. Featuring a hybrid architecture, the system combines Natural Language Processing (character n-gram TF-IDF vectorization with Logistic Regression classification) for payload inspection, alongside a sliding-window behavioral engine for temporal anomaly detection (brute-force attacks and rate surges). The architecture continuously ingests structured web server access logs, performs sub-millisecond threat classification, generates human-interpretable reasoning, and streams live security telemetry to an interactive Dark SOC Dashboard via WebSockets, supported by throttled multi-channel SMS and email notifications.

---

## 2. 2-Minute Elevator Pitch (Viva / Quick Demo)
> *"Respected evaluators, today I am presenting the AI-Based Web Threat Detection and Real-Time Alerting System.*
>
> *Traditional web security tools often struggle with a critical trade-off: static regex rules are easily bypassed by obfuscated code, while heavy deep-learning models introduce too much latency to inspect live HTTP traffic.*
>
> *To solve this, our project implements a **Defense-in-Depth Hybrid Architecture**:*
> *First, an **NLP machine learning pipeline** using character n-gram TF-IDF vectorization and Logistic Regression that analyzes URLs, query strings, and payloads in under one millisecond to detect SQL Injection and XSS attacks.*
> *Second, a **Behavioral Anomaly Engine** that uses sliding time-windows to identify attacks that NLP cannot see—such as credential brute-forcing and request rate spikes.*
>
> *The system monitors web server access logs in the background, persists detections to an audit database, throttles external SMS/email alerts to avoid flooding, and streams real-time telemetry over WebSockets to our Cyber SOC Dashboard. As demonstrated, when a threat is launched, the animated central radar instantly pulses red, the threat explainability feed highlights the exact attack tokens, and security teams are alerted immediately.*
>
> *Thank you, and I look forward to your questions."*

---

## 3. 5-Minute Technical Project Walkthrough
1. **Introduction & Motivation (1 min)**: Explain the limitations of static regex firewalls and the necessity of hybrid AI + behavioral detection.
2. **Architecture & Log Ingestion (1 min)**: Walk through the flow from the target website (`app.py`), down to structured JSON access logs, and into the async file-stream watcher.
3. **NLP Machine Learning Pipeline (1 min)**: Detail recursive URL decoding, character n-grams, TF-IDF weights, and high-recall model evaluation.
4. **Behavioral Engine & Throttled Alerts (1 min)**: Explain sliding-window state tracking for brute-force attacks and how cooldown deduplication prevents SMS spamming.
5. **Live Interactive Demonstration (1 min)**: Trigger normal browsing (Green radar), trigger SQLi/XSS attack (Red alert + explainability note), and demonstrate the live counters and charts.
