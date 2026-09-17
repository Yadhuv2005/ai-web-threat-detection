"""
Native Pure-Python PDF Generator
Generates a complete, beautiful multi-page Interview Preparation PDF guide
without requiring any third-party external libraries.
"""

import os
import sys

def escape_pdf(text):
    return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

def build_pdf(filename="Aegis_Cyber_Risk_Manager_Interview_Prep.pdf"):
    # Read interview prep content
    content_lines = [
        ("TITLE", "AEGIS CYBER RISK MANAGER"),
        ("SUBTITLE", "Complete BTech Project Interview & Defense Preparation Guide"),
        ("META", "Candidate: Yadhu Krishna | Track: AI, NLP & Cybersecurity"),
        ("HR", ""),
        
        ("SECTION", "1. 30-Second Elevator Pitch"),
        ("TEXT", "Aegis is an enterprise-grade Cyber Risk Management platform that bridges the gap between raw machine learning detection and actionable security operations. It utilizes character n-gram TF-IDF vectorization with Logistic Regression to classify web injection attacks in under 1ms, combined with a behavioral sliding-window engine for brute-force attacks. Built on NIST SP 800-30 principles, it computes a composite Risk Score (0-100) based on Likelihood, Severity, and Asset Criticality, streaming live telemetry to an interactive 3D particle SOC dashboard."),
        
        ("SECTION", "2. Core Architectural Questions"),
        ("Q", "Q1: Why use NLP for Cybersecurity instead of static regex signatures?"),
        ("A", "Static regex signatures are brittle and easily bypassed using URL encoding (%27%20OR%201=1), character case mutation, or SQL comments. NLP treats HTTP inputs as structured text patterns, learning structural syntax markers rather than rigid strings."),
        
        ("Q", "Q2: Why character n-grams instead of standard word tokenization?"),
        ("A", "Web exploit payloads (e.g. ' OR '1'='1, <script>alert(1)) do not consist of natural English dictionary words. Punctuation, quotes, equality signs, and brackets contain critical malicious signals. Character n-grams (sub-strings of 2 to 5 characters) preserve these exact syntax anomalies even across obfuscated inputs."),
        
        ("Q", "Q3: Why Logistic Regression over a Deep Learning LLM?"),
        ("A", "Security inspection occurs inline or in real-time streaming. A Large Language Model (LLM) takes 200-1000ms and requires costly GPUs. Our TF-IDF + Logistic Regression model executes inference in under 1 millisecond on commodity CPUs with calibrated probability scores and clear explainability."),
        
        ("Q", "Q4: Why is a Behavioral Engine necessary alongside NLP?"),
        ("A", "NLP only analyzes textual content. A single failed login request (username=admin&password=xyz) looks syntactically 100% normal. Only a temporal sliding window tracking state over time can detect that 6 failed 401 logins in 30 seconds from a single IP constitutes a Brute-Force credential attack."),
        
        ("SECTION", "3. Risk Engine & Prioritization Questions"),
        ("Q", "Q5: How is the Risk Score calculated?"),
        ("A", "Based on NIST SP 800-30 guidelines: Risk Score (0-100) = Round((Likelihood * 0.35 + Technical Severity * 0.35 + Asset Criticality * 0.30) * 100)."),
        ("A", "- Likelihood: Derived from ML prediction confidence and exploit complexity."),
        ("A", "- Technical Severity: SQLi (0.95), Brute Force (0.90), Rate Burst (0.75), XSS (0.70)."),
        ("A", "- Asset Criticality: Payment/Auth (1.0), Admin (0.95), Catalog API (0.8), Search (0.6)."),
        
        ("Q", "Q6: What are the Risk Tiers?"),
        ("A", "Critical (80-100, Immediate triage), High (60-79, Urgent within shift), Medium (40-59, Elevated anomaly), Low (0-39, Baseline/Informational)."),
        
        ("Q", "Q7: How does Smart Alerting work?"),
        ("A", "Alerts route dynamically: Low = Dashboard only; Medium = Dashboard + Audit log; High = Dashboard + SMTP Email; Critical = Dashboard + Email + Twilio SMS. An in-memory cooldown cache deduplicates alerts to prevent notification flooding."),
        
        ("SECTION", "4. Machine Learning & Metric Questions"),
        ("Q", "Q8: Why is Recall more important than Precision in threat detection?"),
        ("A", "Recall measures what percentage of actual attacks were caught (TP / (TP + FN)). A False Negative in cybersecurity means an active attacker bypassed the defense and compromised internal databases. While high Precision reduces analyst fatigue, high Recall is vital to prevent breaches."),
        
        ("Q", "Q9: What is Concept Drift and how is it mitigated?"),
        ("A", "Attack patterns evolve as new vulnerabilities emerge. A model trained on past data may degrade over time (Concept Drift). In production, this is solved by active continuous learning, periodic retraining pipelines, and canary validation."),
        
        ("SECTION", "5. Frontend & Real-Time Telemetry"),
        ("Q", "Q10: How does the 3D Particle Risk Sphere work?"),
        ("A", "Rendered using HTML5 Canvas with 550 glowing nodes distributed via a Fibonacci sphere algorithm. Uses 3D perspective projection (fov=400) and smoothly interpolates colors: Green (<40), Yellow/Orange (40-79), Red (>=80), with dynamic ripple waves upon threat arrival."),
        
        ("Q", "Q11: Why WebSockets over Polling?"),
        ("A", "Polling wastes network bandwidth and CPU by repeatedly querying the server every few seconds. WebSockets maintain a persistent lightweight TCP channel, pushing threat telemetry to the dashboard in under 10 milliseconds with zero polling latency.")
    ]

    # Generate multi-page PDF stream
    pages = []
    current_page_ops = []
    
    # Page dimensions (Letter: 612 x 792)
    width = 612
    height = 792
    margin_left = 50
    y = height - 50

    def start_new_page():
        nonlocal y, current_page_ops
        if current_page_ops:
            pages.append("\n".join(current_page_ops))
            current_page_ops = []
        y = height - 50

    def draw_text(text, x, y_pos, font="F1", size=10, r=0.1, g=0.15, b=0.25):
        escaped = escape_pdf(text)
        current_page_ops.append(f"{r:.2f} {g:.2f} {b:.2f} rg")
        current_page_ops.append(f"BT /{font} {size} Tf {x:.2f} {y_pos:.2f} Td ({escaped}) Tj ET")

    def wrap_and_draw(text, x, start_y, font="F1", size=9.5, max_chars=88, r=0.2, g=0.25, b=0.3):
        nonlocal y
        words = text.split(" ")
        lines = []
        cur_line = []
        cur_len = 0
        for w in words:
            if cur_len + len(w) + 1 > max_chars:
                lines.append(" ".join(cur_line))
                cur_line = [w]
                cur_len = len(w)
            else:
                cur_line.append(w)
                cur_len += len(w) + 1
        if cur_line:
            lines.append(" ".join(cur_line))
        
        for line in lines:
            if y < 50:
                start_new_page()
            draw_text(line, x, y, font=font, size=size, r=r, g=g, b=b)
            y -= 13

    for item_type, text in content_lines:
        if y < 65:
            start_new_page()
            
        if item_type == "TITLE":
            draw_text(text, margin_left, y, font="F2", size=20, r=0.04, g=0.35, b=0.6)
            y -= 24
        elif item_type == "SUBTITLE":
            draw_text(text, margin_left, y, font="F2", size=12, r=0.15, g=0.2, b=0.3)
            y -= 16
        elif item_type == "META":
            draw_text(text, margin_left, y, font="F1", size=9, r=0.4, g=0.45, b=0.5)
            y -= 12
        elif item_type == "HR":
            current_page_ops.append(f"0.8 0.85 0.9 RG 1 w {margin_left} {y} m {width - margin_left} {y} l S")
            y -= 18
        elif item_type == "SECTION":
            y -= 8
            if y < 60: start_new_page()
            # Draw section header banner
            current_page_ops.append(f"0.92 0.95 0.98 rg {margin_left} {y-4} {width - 2*margin_left} 18 re f")
            draw_text(text, margin_left + 6, y, font="F2", size=11, r=0.04, g=0.3, b=0.55)
            y -= 20
        elif item_type == "Q":
            y -= 4
            if y < 55: start_new_page()
            wrap_and_draw(text, margin_left, y, font="F2", size=10, max_chars=82, r=0.1, g=0.15, b=0.25)
            y -= 2
        elif item_type == "A" or item_type == "TEXT":
            wrap_and_draw(text, margin_left + 10, y, font="F1", size=9, max_chars=86, r=0.25, g=0.3, b=0.35)
            y -= 4

    if current_page_ops:
        pages.append("\n".join(current_page_ops))

    # Assemble Standard PDF 1.4 objects
    pdf_objects = []
    
    # 1. Catalog
    pdf_objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    
    # 2. Pages object (filled later)
    # 3. Fonts
    font1 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    font2 = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>"
    pdf_objects.append("") # Placeholder for 2 0 R
    pdf_objects.append(font1) # 3 0 R
    pdf_objects.append(font2) # 4 0 R

    page_obj_ids = []
    for idx, page_content in enumerate(pages):
        content_id = 5 + idx * 2
        page_id = 6 + idx * 2
        page_obj_ids.append(page_id)
        
        # Content stream
        content_stream = f"<< /Length {len(page_content.encode('utf-8'))} >>\nstream\n{page_content}\nendstream"
        pdf_objects.append(content_stream)
        
        # Page object
        page_dict = f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents {content_id} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>"
        pdf_objects.append(page_dict)

    # Fill Pages object (index 1 -> obj 2)
    kids = " ".join([f"{pid} 0 R" for pid in page_obj_ids])
    pdf_objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>"

    # Write PDF file
    with open(filename, "wb") as f:
        f.write(b"%PDF-1.4\n")
        offsets = []
        for i, obj in enumerate(pdf_objects, start=1):
            offsets.append(f.tell())
            f.write(f"{i} 0 obj\n{obj}\nendobj\n".encode('utf-8'))
        
        xref_offset = f.tell()
        f.write(f"xref\n0 {len(pdf_objects) + 1}\n0000000000 65535 f \n".encode('utf-8'))
        for off in offsets:
            f.write(f"{off:010d} 00000 n \n".encode('utf-8'))
        
        f.write(f"trailer\n<< /Size {len(pdf_objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF".encode('utf-8'))

    print(f"[+] Successfully generated Interview Prep PDF at: {filename} ({len(pages)} pages)")

if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "Aegis_Cyber_Risk_Manager_Interview_Prep.pdf"
    build_pdf(out_path)
