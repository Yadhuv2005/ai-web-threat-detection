"""
REST & WebSocket API Endpoints - Cyber Risk Platform
----------------------------------------------------
Provides endpoints for monitoring lifecycle management, statistics,
risk overview, prioritized threats, asset registry, AI Security Analyst,
and real-time streaming updates.
"""

import json
from pydantic import BaseModel
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from backend.database.models import (
    get_db_connection, 
    get_stats, 
    get_prioritized_threats, 
    get_registered_assets
)
from backend.risk.analyst import AISecurityAnalyst

router = APIRouter()

# Global reference to monitor instance, assigned on app startup
log_monitor_instance = None

# Active WebSocket client connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead_connections.append(connection)
        for dc in dead_connections:
            self.disconnect(dc)

ws_manager = ConnectionManager()

# Request schemas
class AnalystQueryRequest(BaseModel):
    query: str

@router.get("/status")
async def get_system_status():
    is_active = log_monitor_instance.is_running if log_monitor_instance else False
    ml_loaded = log_monitor_instance.ml_detector.is_loaded if log_monitor_instance else False
    return {
        "status": "online",
        "monitoring_active": is_active,
        "ml_model_loaded": ml_loaded,
        "active_ws_clients": len(ws_manager.active_connections),
        "stats": get_stats()
    }

@router.post("/monitoring/start")
async def start_monitoring():
    if log_monitor_instance:
        log_monitor_instance.start()
        await ws_manager.broadcast({
            "event_type": "STATUS_UPDATE",
            "monitoring_active": True,
            "message": "Continuous Cyber Risk Monitoring is now ACTIVE"
        })
        return {"status": "success", "monitoring_active": True}
    return {"status": "error", "message": "Monitor not initialized"}

@router.post("/monitoring/stop")
async def stop_monitoring():
    if log_monitor_instance:
        log_monitor_instance.stop()
        await ws_manager.broadcast({
            "event_type": "STATUS_UPDATE",
            "monitoring_active": False,
            "message": "Continuous Cyber Risk Monitoring is STOPPED"
        })
        return {"status": "success", "monitoring_active": False}
    return {"status": "error", "message": "Monitor not initialized"}

@router.get("/stats")
async def get_statistics():
    return get_stats()

@router.get("/risk/overview")
async def get_risk_overview():
    stats = get_stats()
    assets = get_registered_assets()
    prioritized = get_prioritized_threats(5)
    return {
        "stats": stats,
        "assets_count": len(assets),
        "top_priorities": prioritized
    }

@router.get("/risk/prioritized")
async def get_prioritized_risks(limit: int = 50):
    return get_prioritized_threats(limit)

@router.get("/assets")
async def get_assets_list():
    return get_registered_assets()

@router.post("/analyst/query")
async def query_ai_analyst(payload: AnalystQueryRequest):
    return AISecurityAnalyst.answer_query(payload.query)

@router.get("/traffic")
async def get_recent_traffic(limit: int = 50):
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM traffic_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

@router.get("/threats")
async def get_recent_threats(limit: int = 50):
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM threat_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

@router.get("/alerts")
async def get_alert_history(limit: int = 50):
    conn = get_db_connection()
    cursor = conn.cursor()
    rows = cursor.execute("SELECT * FROM alert_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    initial_status = {
        "event_type": "INITIAL_STATE",
        "monitoring_active": log_monitor_instance.is_running if log_monitor_instance else False,
        "stats": get_stats(),
        "prioritized": get_prioritized_threats(15),
        "assets": get_registered_assets()
    }
    await websocket.send_text(json.dumps(initial_status))
    try:
        while True:
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
