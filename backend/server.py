"""
ARGUS Backend API Server
========================
FastAPI server exposing REST + WebSocket endpoints for the frontend dashboard.

Run with:
    python server.py
or:
    uvicorn server:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
import os
import asyncio
import threading
import time
import json
import warnings
warnings.filterwarnings("ignore")

BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from pathlib import Path
from datetime import datetime, timezone
from collections import deque
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import uvicorn


# ─────────────────────────────────────────────────────────────────────────────
# ARGUS Detection Engine imports
# ─────────────────────────────────────────────────────────────────────────────
from app.detection.network_detection_engine import NetworkDetectionEngine
from app.detection.windows_detection_engine import WindowsDetectionEngine
from app.detection.alert_manager import AlertManager
from app.detection.powershell_detector import PowerShellDetector
from app.detection.sysmon_event_collector import SysmonEventCollector
from app.detection.sysmon_event_parser import SysmonEventParser
from app.detection.suspicious_process_detector import SuspiciousProcessDetector
import re

# ─────────────────────────────────────────────────────────────────────────────
# Global State
# ─────────────────────────────────────────────────────────────────────────────

MODEL_PATH = str(
    Path(BACKEND_DIR) / "app" / "models" / "argus_network_best_model.joblib"
)

# Shared alert storage (thread-safe deque, max 500 alerts)
ALERTS: deque = deque(maxlen=500)
ALERT_LOCK = threading.Lock()

# Stats counters
STATS = {
    "total_alerts": 0,
    "network_alerts": 0,
    "windows_alerts": 0,
    "packets_captured": 0,
    "flows_analyzed": 0,
    "ml_predictions": 0,
    "benign_count": 0,
    "attack_count": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "detector_status": {
        "network_ml": "running",
        "port_scan": "running",
        "outbound": "running",
        "windows": "running",
    },
    "started_at": datetime.now(timezone.utc).isoformat(),
}
STATS_LOCK = threading.Lock()

# Recent flow activity (for live chart)
FLOW_HISTORY: deque = deque(maxlen=60)

# Active WebSocket connections
WEBSOCKET_CLIENTS: List[WebSocket] = []
WS_LOCK = asyncio.Lock()
MAIN_EVENT_LOOP: Optional[asyncio.AbstractEventLoop] = None
_broadcaster_task: Optional[asyncio.Task] = None


# ─────────────────────────────────────────────────────────────────────────────
# Patched detection engines that push data to global state
# ─────────────────────────────────────────────────────────────────────────────

def push_alert(alert_dict: dict):
    """Add alert to global store, update stats, and push instant WebSocket notification."""
    with ALERT_LOCK:
        ALERTS.appendleft(alert_dict)

    with STATS_LOCK:
        STATS["total_alerts"] += 1
        sev = alert_dict.get("severity", "info").lower()
        if sev in STATS:
            STATS[sev] += 1
        stats_snap = dict(STATS)

    if MAIN_EVENT_LOOP and MAIN_EVENT_LOOP.is_running():
        try:
            asyncio.run_coroutine_threadsafe(
                broadcast_update({
                    "type": "alert",
                    "alert": alert_dict,
                    "stats": stats_snap
                }),
                MAIN_EVENT_LOOP
            )
        except Exception:
            pass


class InstrumentedNetworkEngine(NetworkDetectionEngine):
    """Network engine that also pushes data to the global state."""

    def handle_event(self, event):
        with STATS_LOCK:
            STATS["packets_captured"] += 1

        src_ip = event.get("source_ip")
        dst_ip = event.get("destination_ip")
        dst_port = event.get("destination_port")
        proto = event.get("protocol", "?")

        # ── 1. Port Scan Detection ──────────────────────────────
        if dst_port is not None:
            port_result = self.port_scan_detector.process_connection(
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=dst_port,
            )
            if port_result["alert"]:
                with STATS_LOCK:
                    STATS["network_alerts"] += 1
                aid = f"PS-{int(time.time()*1000)}"
                alert_rec = {
                    "id": aid,
                    "alert_id": aid,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "PORT_SCAN",
                    "alert_type": "Port Scanning Detected",
                    "title": f"Port Scan from {src_ip}",
                    "detector": "port_scan",
                    "severity": "HIGH",
                    "risk_score": 80,
                    "source_ip": port_result.get("source_ip"),
                    "target_ip": dst_ip,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "unique_ports": port_result.get("unique_ports"),
                    "unique_hosts": port_result.get("unique_hosts"),
                    "description": f"Host {src_ip} scanned {port_result.get('unique_ports', '?')} unique ports on {port_result.get('unique_hosts', '?')} hosts within 60s window.",
                    "status": "UNACKNOWLEDGED",
                }
                push_alert(alert_rec)

        # ── 2. Suspicious Outbound IOC Check ────────────────────
        if dst_ip is not None:
            outbound_result = self.outbound_detector.check_connection(
                source_ip=src_ip,
                destination_ip=dst_ip,
                destination_port=dst_port,
            )
            if outbound_result["alert"]:
                with STATS_LOCK:
                    STATS["network_alerts"] += 1
                aid = f"OB-{int(time.time()*1000)}"
                alert_rec = {
                    "id": aid,
                    "alert_id": aid,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "type": "SUSPICIOUS_OUTBOUND",
                    "alert_type": "Suspicious Outbound Connection",
                    "title": f"Outbound to Blocked IOC {dst_ip}",
                    "detector": "outbound_detector",
                    "severity": "HIGH",
                    "risk_score": 90,
                    "source_ip": outbound_result.get("source_ip"),
                    "target_ip": outbound_result.get("destination_ip"),
                    "destination_ip": outbound_result.get("destination_ip"),
                    "destination_port": outbound_result.get("destination_port"),
                    "reason": outbound_result.get("reason"),
                    "description": f"Outbound connection from {src_ip} to IOC-blocklisted destination {dst_ip}:{dst_port} ({proto}). Reason: {outbound_result.get('reason', 'Destination matched IOC')}.",
                    "status": "UNACKNOWLEDGED",
                }
                push_alert(alert_rec)

        # ── 3. Flow Feature Extraction + ML ─────────────────────
        features = self.flow_extractor.add_packet(event)
        if features is None:
            return

        with STATS_LOCK:
            STATS["flows_analyzed"] += 1

        import pandas as pd
        flow_df = pd.DataFrame([features])

        try:
            result = self.network_detector.predict(flow_df)[0]
        except Exception:
            return

        is_attack = result["prediction"] == "ATTACK"

        with STATS_LOCK:
            STATS["ml_predictions"] += 1
            if is_attack:
                STATS["attack_count"] += 1
            else:
                STATS["benign_count"] += 1

        # Record flow history for real-time charts
        FLOW_HISTORY.append({
            "timestamp": time.time(),
            "time": datetime.now(timezone.utc).isoformat(),
            "packets": 1,
            "flows": 1,
            "attacks": 1 if is_attack else 0,
            "prediction": result["prediction"],
            "attack_probability": result["attack_probability"],
            "source_ip": src_ip,
            "destination_ip": dst_ip,
        })

        # ── 4. ML Attack Alert ──────────────────────────────────
        if is_attack:
            with STATS_LOCK:
                STATS["network_alerts"] += 1
            attack_prob = result["attack_probability"]
            if attack_prob >= 0.95:
                sev = "CRITICAL"
                risk = 95
            elif attack_prob >= 0.80:
                sev = "HIGH"
                risk = 80
            else:
                sev = "MEDIUM"
                risk = 60

            aid = f"NML-{int(time.time()*1000)}"
            alert_rec = {
                "id": aid,
                "alert_id": aid,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "NETWORK_ML_ATTACK",
                "alert_type": "Network Attack Detected",
                "title": f"ML Attack Detection ({sev}) — {src_ip} → {dst_ip}",
                "detector": "network_ml",
                "severity": sev,
                "risk_score": risk,
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "attack_probability": round(attack_prob, 4),
                "confidence": round(result["confidence"], 4),
                "description": f"Random Forest ML classifier detected malicious network flow from {src_ip} to {dst_ip}:{dst_port}. Attack probability: {round(attack_prob*100, 1)}%, confidence: {round(result['confidence']*100, 1)}%.",
                "status": "UNACKNOWLEDGED",
            }
            push_alert(alert_rec)


class InstrumentedWindowsEngine(WindowsDetectionEngine):
    """Windows engine that also pushes data to the global state."""

    def __init__(self, failure_threshold=5, time_window_seconds=60):
        super().__init__(failure_threshold, time_window_seconds)
        self.powershell_detector = PowerShellDetector()
        self.sysmon_collector = SysmonEventCollector()
        self.sysmon_parser = SysmonEventParser()
        self.sysmon_process_detector = SuspiciousProcessDetector()
        self.processed_ps_ids = set()

    def process_event(self, event):
        result = super().process_event(event)
        if result and result.get("alert"):
            with STATS_LOCK:
                STATS["windows_alerts"] += 1
            aid = f"WIN-{int(time.time()*1000)}"
            alert_rec = {
                "id": aid,
                "alert_id": aid,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "WINDOWS_BRUTE_FORCE",
                "alert_type": result.get("alert_type", "Windows Security Alert"),
                "title": f"Windows Brute Force — {result.get('username', 'Unknown User')}",
                "detector": "windows_detector",
                "severity": result.get("severity", "HIGH"),
                "risk_score": 75,
                "source_ip": result.get("source_ip"),
                "target_ip": "localhost",
                "user": result.get("username"),
                "failure_count": result.get("failure_count"),
                "time_window_seconds": result.get("time_window_seconds"),
                "description": f"Detected {result.get('failure_count', '?')} failed login attempts for user '{result.get('username', '?')}' within {result.get('time_window_seconds', 60)}s window (Event ID 4625).",
                "status": "UNACKNOWLEDGED",
            }
            push_alert(alert_rec)
        return result

    def scan_once(self):
        # 1. Scan failed logins (Event 4625)
        fl_count = super().scan_once()

        # 2. Scan PowerShell scriptblock logs (Event 4104)
        try:
            ps_events = self.collector.get_powershell_events(max_events=20)
            for ev in ps_events:
                rec_id = ev.get("RecordId")
                if rec_id and rec_id in self.processed_ps_ids:
                    continue
                if rec_id:
                    self.processed_ps_ids.add(rec_id)

                msg = ev.get("Message", "")
                m = re.search(r"Creating Scriptblock text \(\d+ of \d+\):\s*(.*?)(?:\r?\n\r?\nScriptBlock ID:|$)", msg, re.DOTALL)
                cmdline = m.group(1).strip() if m else msg

                ps_result = self.powershell_detector.process_event({
                    "image": "powershell.exe",
                    "command_line": cmdline,
                    "timestamp": ev.get("TimeCreated"),
                })

                if ps_result.get("alert"):
                    with STATS_LOCK:
                        STATS["windows_alerts"] += 1
                    aid = f"PS-{int(time.time()*1000)}"
                    alert_rec = {
                        "id": aid,
                        "alert_id": aid,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "SUSPICIOUS_POWERSHELL",
                        "alert_type": "Suspicious PowerShell Command",
                        "title": f"Suspicious PowerShell Execution ({ps_result.get('severity')})",
                        "detector": "powershell_detector",
                        "severity": ps_result.get("severity", "HIGH"),
                        "risk_score": ps_result.get("risk_score", 70),
                        "source_ip": "127.0.0.1",
                        "target_ip": "localhost",
                        "user": ps_result.get("user", "System"),
                        "process_name": "powershell.exe",
                        "command_line": cmdline[:500],
                        "reasons": ps_result.get("reasons", []),
                        "description": f"Suspicious PowerShell command executed: {cmdline[:200]}. Reasons: {', '.join(ps_result.get('reasons', []))}",
                        "status": "UNACKNOWLEDGED",
                    }
                    push_alert(alert_rec)
        except Exception as e:
            pass

        # 3. Scan Sysmon process creation if available (Event 1)
        try:
            sys_events = self.sysmon_collector.get_process_events(max_events=20)
            for ev in sys_events:
                parsed = self.sysmon_parser.parse(ev)
                if not parsed:
                    continue
                proc_res = self.sysmon_process_detector.process_event(parsed)
                if proc_res.get("alert"):
                    with STATS_LOCK:
                        STATS["windows_alerts"] += 1
                    aid = f"SYS-{int(time.time()*1000)}"
                    alert_rec = {
                        "id": aid,
                        "alert_id": aid,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "type": "SUSPICIOUS_PROCESS",
                        "alert_type": "Suspicious Process Execution",
                        "title": f"Suspicious Process {proc_res.get('process_name')}",
                        "detector": "process_detector",
                        "severity": proc_res.get("severity", "HIGH"),
                        "risk_score": proc_res.get("risk_score", 75),
                        "source_ip": "127.0.0.1",
                        "target_ip": "localhost",
                        "user": proc_res.get("user"),
                        "process_name": proc_res.get("process_name"),
                        "image": proc_res.get("image"),
                        "command_line": proc_res.get("command_line"),
                        "description": f"Suspicious process execution detected: {proc_res.get('image')}. Reasons: {', '.join(proc_res.get('reasons', []))}",
                        "status": "UNACKNOWLEDGED",
                    }
                    push_alert(alert_rec)
        except Exception:
            pass

        return fl_count


# ─────────────────────────────────────────────────────────────────────────────
# Background detection threads
# ─────────────────────────────────────────────────────────────────────────────

network_engine: Optional[InstrumentedNetworkEngine] = None
windows_engine: Optional[InstrumentedWindowsEngine] = None
_network_thread: Optional[threading.Thread] = None
_windows_thread: Optional[threading.Thread] = None


def start_network_detection(interface=None):
    global network_engine
    try:
        network_engine = InstrumentedNetworkEngine(MODEL_PATH)
        network_engine.start(interface=interface)
    except Exception as e:
        with STATS_LOCK:
            STATS["detector_status"]["network_ml"] = f"error: {e}"
            STATS["detector_status"]["port_scan"] = "error"
            STATS["detector_status"]["outbound"] = "error"
        print(f"[ARGUS] Network detection error: {e}")


def start_windows_detection():
    global windows_engine
    try:
        windows_engine = InstrumentedWindowsEngine(
            failure_threshold=5,
            time_window_seconds=60,
        )
        windows_engine.start(interval_seconds=5)
    except Exception as e:
        with STATS_LOCK:
            STATS["detector_status"]["windows"] = f"error: {e}"
        print(f"[ARGUS] Windows detection error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(title="ARGUS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend static files
FRONTEND_DIR = Path(BACKEND_DIR).parent / "frontend"

# ─────────────────────────────────────────────────────────────────────────────
# REST Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/status")
@app.get("/api/stats")
async def get_stats():
    with STATS_LOCK:
        return dict(STATS)


@app.get("/api/alerts")
async def get_alerts(limit: int = 100, severity: str = None):
    with ALERT_LOCK:
        alerts = list(ALERTS)
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity.upper()]
    return alerts[:limit]


@app.post("/api/alerts/clear")
async def clear_alerts():
    with ALERT_LOCK:
        ALERTS.clear()
    with STATS_LOCK:
        STATS["total_alerts"] = 0
        STATS["critical"] = 0
        STATS["high"] = 0
        STATS["medium"] = 0
        STATS["low"] = 0
        STATS["info"] = 0
        STATS["network_alerts"] = 0
        STATS["windows_alerts"] = 0
    return {"status": "ok", "message": "All alerts cleared"}


@app.post("/api/alerts/test")
async def emit_test_alert():
    test_alert = {
        "id": f"test-{int(time.time())}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": "critical",
        "type": "SIMULATED_TEST_ATTACK",
        "title": "Simulated ML Threat Detection",
        "source_ip": "192.168.1.55",
        "target_ip": "192.168.0.102",
        "detector": "Network_ML",
        "description": "Test alert triggered manually from SOC Dashboard to verify real-time pipeline",
        "status": "UNACKNOWLEDGED",
    }
    push_alert(test_alert)
    return {"status": "ok", "alert": test_alert}


@app.get("/api/alerts/summary")
async def get_alert_summary():
    with ALERT_LOCK:
        alerts = list(ALERTS)
    with STATS_LOCK:
        stats = dict(STATS)

    by_type = {}
    by_detector = {}
    for alert in alerts:
        t = alert.get("alert_type", "Unknown")
        d = alert.get("detector", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
        by_detector[d] = by_detector.get(d, 0) + 1

    return {
        "total": len(alerts),
        "by_severity": {
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
            "info": stats.get("info", 0),
        },
        "by_type": by_type,
        "by_detector": by_detector,
        "network_stats": {
            "packets_captured": stats.get("packets_captured", 0),
            "flows_analyzed": stats.get("flows_analyzed", 0),
            "ml_predictions": stats.get("ml_predictions", 0),
            "attack_count": stats.get("attack_count", 0),
            "benign_count": stats.get("benign_count", 0),
        }
    }


@app.get("/api/flows")
async def get_flow_history(limit: int = 60):
    return list(FLOW_HISTORY)[-limit:]


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str):
    with ALERT_LOCK:
        for alert in ALERTS:
            if alert.get("id") == alert_id or alert.get("alert_id") == alert_id:
                alert["status"] = "ACKNOWLEDGED"
                return {"success": True, "alert": alert}
    return {"success": False, "message": "Alert not found"}


@app.get("/api/ioc")
async def get_ioc_list():
    blocklist = []
    if network_engine and hasattr(network_engine, "outbound_detector"):
        blocklist = list(getattr(network_engine.outbound_detector, "blocked_destinations", set()))
    return {"ioc_blocklist": blocklist}


@app.post("/api/ioc")
@app.post("/api/ioc/add")
async def add_ioc(ip: str = None, data: dict = None):
    target_ip = ip or (data.get("ip") if data else None)
    if not target_ip:
        return {"status": "error", "message": "IP address required"}

    if network_engine and hasattr(network_engine, "outbound_detector"):
        network_engine.outbound_detector.add_ioc(target_ip)
        blocklist = list(getattr(network_engine.outbound_detector, "blocked_destinations", set()))
        return {"status": "ok", "message": f"IOC added: {target_ip}", "ioc_blocklist": blocklist}
    return {"status": "error", "message": "Network engine not initialized"}


@app.delete("/api/ioc/{ip}")
async def remove_ioc(ip: str):
    if network_engine and hasattr(network_engine, "outbound_detector"):
        network_engine.outbound_detector.blocked_destinations.discard(ip)
        blocklist = list(getattr(network_engine.outbound_detector, "blocked_destinations", set()))
        return {"status": "ok", "message": f"IOC removed: {ip}", "ioc_blocklist": blocklist}
    return {"status": "error", "message": "Network engine not initialized"}



# Simulation engine state
SIMULATION_RUNNING = False
_sim_thread = None


def simulation_worker():
    """Generates synthetic background flows & periodic attacks for demonstration."""
    import random
    global SIMULATION_RUNNING

    sample_ips = ["192.168.1.105", "192.168.1.112", "10.0.0.45", "172.16.0.8", "198.51.100.14"]
    target_ips = ["192.168.0.102", "192.168.0.1", "10.0.0.1"]

    while SIMULATION_RUNNING:
        time.sleep(2)
        pkts = random.randint(15, 60)
        flows = random.randint(1, 4)
        is_attack = random.random() < 0.25  # 25% chance of attack flow

        with STATS_LOCK:
            STATS["packets_captured"] += pkts
            STATS["flows_analyzed"] += flows
            STATS["ml_predictions"] += flows

            if is_attack:
                STATS["attack_count"] += 1
                STATS["network_alerts"] += 1
            else:
                STATS["benign_count"] += 1

        src_ip = random.choice(sample_ips)
        dst_ip = random.choice(target_ips)

        # Append to flow history
        FLOW_HISTORY.append({
            "timestamp": time.time(),
            "time": datetime.now(timezone.utc).isoformat(),
            "packets": pkts,
            "flows": flows,
            "attacks": 1 if is_attack else 0,
            "prediction": "ATTACK" if is_attack else "BENIGN",
            "source_ip": src_ip,
            "destination_ip": dst_ip,
        })

        if is_attack:
            attack_type = random.choice([
                "DDoS-SYN Flood",
                "Port Scanning Activity",
                "SQL Injection Attempt",
                "Brute Force SSH",
                "Malicious Outbound Beacon"
            ])
            sev = random.choice(["CRITICAL", "HIGH", "MEDIUM"])
            alert_rec = {
                "id": f"SIM-{int(time.time()*1000)}",
                "alert_id": f"SIM-{int(time.time()*1000)}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": attack_type,
                "title": f"Simulated {attack_type}",
                "detector": "Simulated_Engine",
                "severity": sev,
                "risk_score": 90 if sev == "CRITICAL" else 75,
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "destination_ip": dst_ip,
                "description": f"Synthetic threat vector ({attack_type}) generated by ARGUS Simulation Mode.",
                "status": "UNACKNOWLEDGED",
            }
            push_alert(alert_rec)


@app.post("/api/simulation/toggle")
async def toggle_simulation():
    global SIMULATION_RUNNING, _sim_thread
    SIMULATION_RUNNING = not SIMULATION_RUNNING

    if SIMULATION_RUNNING:
        if _sim_thread is None or not _sim_thread.is_alive():
            _sim_thread = threading.Thread(target=simulation_worker, daemon=True, name="argus-sim")
            _sim_thread.start()
        return {"status": "ok", "running": True, "message": "Simulation started"}
    else:
        return {"status": "ok", "running": False, "message": "Simulation stopped"}


@app.get("/api/simulation/status")
async def get_simulation_status():
    return {"running": SIMULATION_RUNNING}


# ─────────────────────────────────────────────────────────────────────────────
# WebSocket — real-time push
# ─────────────────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    async with WS_LOCK:
        WEBSOCKET_CLIENTS.append(websocket)
    try:
        # Send initial snapshot
        with STATS_LOCK:
            snap = dict(STATS)
        with ALERT_LOCK:
            recent = list(ALERTS)[:50]
        flow_hist = list(FLOW_HISTORY)

        await websocket.send_text(json.dumps({
            "type": "snapshot",
            "stats": snap,
            "alerts": recent,
            "flow_history": flow_hist,
        }))
        # Keep alive — listen for client pings
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_text(), timeout=25)
                if msg == "ping":
                    await websocket.send_text(json.dumps({"type": "pong"}))
            except asyncio.TimeoutError:
                try:
                    await websocket.send_text(json.dumps({"type": "heartbeat"}))
                except Exception:
                    break
            except (WebSocketDisconnect, asyncio.CancelledError):
                break
            except Exception:
                break
    except Exception:
        pass
    except BaseException:
        pass
    finally:
        async with WS_LOCK:
            if websocket in WEBSOCKET_CLIENTS:
                WEBSOCKET_CLIENTS.remove(websocket)


async def broadcast_update(payload: dict):
    """Broadcast update to all connected WebSocket clients."""
    async with WS_LOCK:
        if not WEBSOCKET_CLIENTS:
            return
        dead = []
        for ws in list(WEBSOCKET_CLIENTS):
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)
            except BaseException:
                dead.append(ws)
        for ws in dead:
            if ws in WEBSOCKET_CLIENTS:
                WEBSOCKET_CLIENTS.remove(ws)


# ─────────────────────────────────────────────────────────────────────────────
# Background broadcaster task (pushes updates every second)
# ─────────────────────────────────────────────────────────────────────────────

_last_alert_count = 0


async def broadcaster():
    global _last_alert_count
    while True:
        await asyncio.sleep(1)
        if not WEBSOCKET_CLIENTS:
            continue

        with STATS_LOCK:
            stats_snapshot = dict(STATS)
        with ALERT_LOCK:
            alert_count = len(ALERTS)
            if alert_count > _last_alert_count:
                new_alerts = list(ALERTS)[:alert_count - _last_alert_count]
            else:
                new_alerts = []
            _last_alert_count = alert_count
            all_alerts_snap = list(ALERTS)[:100]

        flow_hist_snap = list(FLOW_HISTORY)[-30:]

        payload = {
            "type": "update",
            "stats": stats_snapshot,
            "alerts": all_alerts_snap,
            "new_alerts": new_alerts,
            "flow_history": flow_hist_snap,
        }
        await broadcast_update(payload)



# ─────────────────────────────────────────────────────────────────────────────
# Startup / shutdown
# ─────────────────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    global _network_thread, _windows_thread, MAIN_EVENT_LOOP, _broadcaster_task

    MAIN_EVENT_LOOP = asyncio.get_running_loop()
    print("[ARGUS API] Starting detection engines in background threads...")

    # Get interface from environment or use None (auto-detect)
    interface = os.environ.get("ARGUS_INTERFACE", None)

    _network_thread = threading.Thread(
        target=start_network_detection,
        args=(interface,),
        daemon=True,
        name="argus-network",
    )
    _network_thread.start()

    _windows_thread = threading.Thread(
        target=start_windows_detection,
        daemon=True,
        name="argus-windows",
    )
    _windows_thread.start()

    # Start and anchor the persistent WebSocket broadcaster
    _broadcaster_task = asyncio.create_task(broadcaster())

    print("[ARGUS API] Server ready at http://localhost:8000")


@app.on_event("shutdown")
async def shutdown_event():
    print("[ARGUS API] Shutting down...")


# ─────────────────────────────────────────────────────────────────────────────
# Mount Frontend Static Files at Root
# ─────────────────────────────────────────────────────────────────────────────
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ARGUS API Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--interface", default=None, help="Network interface (e.g. Wi-Fi)")
    args = parser.parse_args()

    if args.interface:
        os.environ["ARGUS_INTERFACE"] = args.interface

    print()
    print("=" * 70)
    print("  ARGUS API SERVER")
    print(f"  http://{args.host}:{args.port}")
    print("=" * 70)
    print()

    uvicorn.run(
        "server:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="warning",
    )
