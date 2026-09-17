"""
Text Preprocessing Module for Web Threat Analysis
-------------------------------------------------
Converts raw, obfuscated, or URL-encoded web payloads and URI paths into
standardized textual tokens for feature extraction and ML classification.

Key Preprocessing Steps:
1. Recursive URL unquoting (decoding %20, %27, %3C, double-encoded strings).
2. HTML entity unescaping (&lt;, &gt;, &quot;).
3. Whitespace normalization.
4. Token normalization (case lowering, punctuation preservation).
"""

import re
import html
from urllib.parse import unquote

def clean_web_text(text: str) -> str:
    """
    Standardize raw HTTP payload or parameter string.
    
    Why this matters in cybersecurity:
    Attackers frequently encode payloads (e.g. %27%20OR%201%3D1 instead of ' OR 1=1)
    to bypass simplistic string-matching firewalls. We must recursively decode
    up to 3 levels to inspect the underlying intent.
    """
    if not text:
        return ""
    
    # 1. Convert to string
    cleaned = str(text)
    
    # 2. Recursive URL Decoding (handles %2527 -> %27 -> ')
    for _ in range(3):
        decoded = unquote(cleaned)
        if decoded == cleaned:
            break
        cleaned = decoded
        
    # 3. Decode HTML entities (e.g., &lt;script&gt; -> <script>)
    cleaned = html.unescape(cleaned)
    
    # 4. Normalize newlines, carriage returns, and tabs to spaces
    cleaned = re.sub(r'[\r\n\t]+', ' ', cleaned)
    
    # 5. Compress multiple consecutive spaces into a single space
    cleaned = re.sub(r'\s+', ' ', cleaned)
    
    # 6. Lowercase for standardized token matching
    cleaned = cleaned.strip().lower()
    
    return cleaned

def extract_threat_tokens(cleaned_text: str) -> list:
    """
    Extracts high-signal security tokens that explain why a request
    is suspicious (used for explainability engine).
    """
    sqli_keywords = [
        "union select", "select *", "select from", "or 1=1", "or '1'='1",
        "drop table", "insert into", "exec(", "sleep(", "benchmark(",
        "--", "/*", "*/", "waitfor delay", "information_schema"
    ]
    xss_keywords = [
        "<script", "</script>", "javascript:", "onerror=", "onload=",
        "onclick=", "<iframe", "alert(", "document.cookie", "<img src=",
        "prompt(", "confirm(", "<svg"
    ]
    
    matched = []
    for kw in sqli_keywords:
        if kw in cleaned_text:
            matched.append(f"SQLi token: '{kw}'")
    for kw in xss_keywords:
        if kw in cleaned_text:
            matched.append(f"XSS token: '{kw}'")
            
    return matched
