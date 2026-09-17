"""
Test Website Application (Target Server)
----------------------------------------
An educational, lightweight web application simulating an e-commerce catalog
and authentication portal. 

Key Responsibilities:
1. Provide realistic web endpoints (Home, Login, Search, JSON API).
2. Intercept every incoming request via logging middleware.
3. Write structured JSON-lines access log records to 'test_website/logs/access.log'.
4. Provide safe endpoints for testing normal browsing, SQLi probes, and XSS tags.
"""

import os
import json
import time
from datetime import datetime
from urllib.parse import unquote
from fastapi import FastAPI, Request, Form, Response, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
ACCESS_LOG_PATH = os.path.join(LOG_DIR, "access.log")

app = FastAPI(title="CyberShop Target Website", docs_url=None, redoc_url=None)

# Mount static files and templates
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Simulated product catalog database
SAMPLE_PRODUCTS = [
    {"id": 1, "name": "UltraBook Pro 15", "desc": "High performance developer laptop with 32GB RAM", "price": 1299},
    {"id": 2, "name": "Mechanical Cyber Keyboard", "desc": "RGB backlighting with mechanical blue switches", "price": 89},
    {"id": 3, "name": "Wireless Ergonomic Mouse", "desc": "Precision optical sensor with dual bluetooth", "price": 49},
    {"id": 4, "name": "4K Ultra-Wide Monitor", "desc": "34-inch IPS display with USB-C power delivery", "price": 450},
    {"id": 5, "name": "Noise Cancelling Headphones", "desc": "Active noise cancellation with 40-hour battery", "price": 199}
]

# Structured Access Logging Middleware
@app.middleware("http")
async def access_log_middleware(request: Request, call_next):
    start_time = time.time()
    
    # Extract client IP (handling X-Forwarded-For if behind proxy)
    client_ip = request.client.host if request.client else "127.0.0.1"
    if "x-forwarded-for" in request.headers:
        client_ip = request.headers["x-forwarded-for"].split(",")[0].strip()
        
    method = request.method
    url_path = request.url.path
    query_string = request.url.query
    user_agent = request.headers.get("user-agent", "Unknown")

    # Read body if POST/PUT without consuming it permanently
    body_text = ""
    if method in ["POST", "PUT", "PATCH"]:
        try:
            body_bytes = await request.body()
            body_text = body_bytes.decode("utf-8", errors="ignore")
        except Exception:
            body_text = ""

    # Process actual request
    response = await call_next(request)
    duration_ms = round((time.time() - start_time) * 1000, 2)
    
    # Assemble structured access log record
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "client_ip": client_ip,
        "method": method,
        "path": url_path,
        "query": query_string,
        "payload": body_text,
        "status_code": response.status_code,
        "user_agent": user_agent,
        "response_time_ms": duration_ms
    }

    # Atomically append JSON line to access log
    try:
        with open(ACCESS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
    except Exception as e:
        print(f"[Logging Error] Failed to write access log: {e}")

    return response

# Routes
@app.get("/", response_class=HTMLResponse)
async def home_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login", response_class=HTMLResponse)
async def login_post(request: Request, username: str = Form(""), password: str = Form("")):
    # Educational authentication check
    if username == "admin" and password == "secret123":
        return templates.TemplateResponse("login.html", {
            "request": request, 
            "success": f"Authenticated successfully as {username}!"
        })
    else:
        # Return 401 Unauthorized for failed logins so behavioral detector catches it
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Invalid username or password."}, 
            status_code=status.HTTP_401_UNAUTHORIZED
        )

@app.get("/search", response_class=HTMLResponse)
async def search_page(request: Request, q: str = ""):
    filtered = []
    clean_q = q.lower()
    if clean_q:
        filtered = [p for p in SAMPLE_PRODUCTS if clean_q in p["name"].lower() or clean_q in p["desc"].lower()]
    return templates.TemplateResponse("search.html", {"request": request, "query": q, "results": filtered})

@app.get("/api/products", response_class=JSONResponse)
async def get_products_api():
    return {"status": "success", "count": len(SAMPLE_PRODUCTS), "data": SAMPLE_PRODUCTS}

if __name__ == "__main__":
    import uvicorn
    print(f"[*] Starting CyberShop Target Website on http://127.0.0.1:8001")
    print(f"[*] Logging structured traffic to: {ACCESS_LOG_PATH}")
    uvicorn.run(app, host="127.0.0.1", port=8001)
