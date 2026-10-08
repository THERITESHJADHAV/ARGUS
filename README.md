# 🛡️ ARGUS — Adaptive Real-time Guard for Unified Security

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Machine Learning](https://img.shields.io/badge/ML%20Accuracy-98.25%25-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **ARGUS** is an enterprise-grade, real-time intrusion detection system (IDS) and Security Operations Center (SOC) dashboard. It combines Machine Learning network flow classification, heuristic port-scan detection, egress IOC blocklists, and native Windows Security log auditing into a unified real-time threat monitoring platform.

---

## 🌟 Key Features

- **🤖 High-Precision ML Classifier (98.25% Accuracy, 99.85% ROC-AUC)**  
  Processes live network packets into statistical flow features and classifies traffic using a Random Forest model trained on CIC-IDS dataset metrics.
- **📡 Heuristic Port Scan & Egress IOC Monitoring**  
  Tracks high-frequency port discovery across sliding 60-second time windows and blocks outbound connections to known malicious IP indicators (IOCs).
- **🪟 Native Windows Security Auditing**  
  Monitors Windows Event Log (Security Event ID `4625` — Failed Logins) in real-time to detect RDP, SMB, and local credential brute-force attacks.
- **⚡ Live WebSockets & SOC Glassmorphism Web Dashboard**  
  A modern, high-performance SOC dashboard built with glassmorphism UI aesthetics, real-time Chart.js telemetry, Web Audio alert synthesizers, and instant alert filtering.
- **🧪 Built-in Traffic & Attack Simulator**  
  Features an integrated simulation engine to emulate live flow activity and threat vectors for demonstration and pipeline testing.

---

## 🏗️ Architecture Overview

```
                        ┌──────────────────────────────────────────────┐
                        │              ARGUS SYSTEM FLOW               │
                        └──────────────────────┬───────────────────────┘
                                               │
               ┌───────────────────────────────┴───────────────────────────────┐
               ▼                                                               ▼
 🌐 Live Network Interface (Scapy / Npcap)                     🪟 Windows Security Event Logs
               │                                                               │
               ▼                                                               ▼
 📊 Flow Feature Extraction                                   🔍 Event ID 4625 Parser
 (Dur, Pkts, Bytes, Rate, TCP Flags)                           (Failed Logins / User Tracker)
               │                                                               │
     ┌─────────┴───────────┬──────────────────┐                                │
     ▼                     ▼                  ▼                                │
🤖 Random Forest      📡 Port Scan    🚫 Outbound IOC                          │
  Classifier            Detector         Blocklist                             │
     │                     │                  │                                │
     └─────────────────────┼──────────────────┴────────────────────────────────┘
                           │
                           ▼
              ⚡ Unified Alert Manager & Stats Core
                           │
             ┌─────────────┴─────────────┐
             ▼                           ▼
      📡 REST API Endpoints      ⚡ WebSocket Server
     (/api/stats, /api/alerts)   (ws://localhost:8000/ws)
             │                           │
             └─────────────┬─────────────┘
                           ▼
             💻 Modern SOC Web Dashboard
```

---

## 🖥️ SOC Dashboard Preview

The dashboard includes 5 specialized views:

1. **📊 Security Overview**: High-level threat metrics, severity donut charts, flow timeline graphs, and real-time activity feed.
2. **🚨 Alert Center**: Interactive alert table with search, severity filters, detector filters, CSV/JSON export, and modal threat breakdown.
3. **🌐 Network Traffic & ML**: Live packet capture statistics, attack vs. benign ratio, and flow telemetry.
4. **🪟 Windows Security**: Active monitoring of failed login events, brute-force counters, and targeted accounts.
5. **🚫 IOC Blocklist**: Real-time IP blocklist manager with instant egress enforcement.

---

## 🚀 Quick Start Guide

### Prerequisites

- **Operating System**: Windows 10 / 11 (or Windows Server)
- **Python**: 3.10 or higher
- **Packet Capture Driver**: [Npcap Driver](https://npcap.com/) *(Required for live network packet capture)*
- **Privileges**: Administrator command prompt *(Recommended for raw network sniffing & Event Log access)*

### 1. Installation

Clone the repository and install required Python packages:

```bash
git clone https://github.com/THERITESHJADHAV/ARGUS.git
cd ARGUS
pip install -r backend/requirements.txt
```

### 2. Launch the System

Run the unified backend server and SOC dashboard:

```bash
python backend/server.py
```

### 3. Access the Dashboard

Open your web browser and navigate to:
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 💻 Running via Command Line Interface (CLI)

You can also run ARGUS directly in CLI mode without the web dashboard:

```bash
cd backend

# Run Network ML & Port Scan Detection
python run_argus.py --mode network

# Run Windows Brute-Force Monitoring
python run_argus.py --mode windows

# Run Both Network & Windows Detection
python run_argus.py --mode all

# List available network interfaces
python run_argus.py --list-interfaces
```

---

## 📡 API Reference

ARGUS exposes a complete REST API and WebSocket interface:

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Serves the interactive SOC Web Dashboard |
| `GET` | `/api/stats` | Returns system-wide alert counters & traffic statistics |
| `GET` | `/api/alerts` | Fetches active threat alerts (supports `limit` & `severity` parameters) |
| `POST` | `/api/alerts/test` | Triggers a simulated test threat alert |
| `POST` | `/api/alerts/clear` | Clears all active alerts from memory |
| `GET` | `/api/ioc` | Fetches the active egress IP blocklist |
| `POST` | `/api/ioc` | Adds an IP address to the IOC blocklist |
| `DELETE` | `/api/ioc/{ip}` | Removes an IP address from the IOC blocklist |
| `POST` | `/api/simulation/toggle` | Toggles background synthetic traffic & attack generator |
| `WS` | `/ws` | Real-time WebSocket connection for live threat updates |

---

## 📂 Project Structure

```
ARGUS/
├── backend/
│   ├── app/
│   │   ├── detection/             # Core detection engines & feature extractors
│   │   │   ├── network_collector.py
│   │   │   ├── flow_feature_extractor.py
│   │   │   ├── network_detector.py
│   │   │   ├── port_scan_detector.py
│   │   │   ├── outbound_detector.py
│   │   │   ├── windows_detection_engine.py
│   │   │   └── alert_manager.py
│   │   └── models/                 # Pre-trained Random Forest model
│   │       └── argus_network_best_model.joblib
│   ├── server.py                   # FastAPI + WebSocket API server
│   ├── run_argus.py                # Command-line runner script
│   └── requirements.txt            # Python dependencies
├── frontend/
│   ├── index.html                  # Dashboard HTML structure
│   ├── style.css                   # Glassmorphism dark-mode CSS design
│   └── app.js                      # Real-time WebSocket & UI logic
├── data/                           # Training data & sample flow PCAPs
└── README.md                       # Project documentation
```

---

## 🛡️ License & Author

Developed by **Ritesh Jadhav** as an open-source cybersecurity intrusion detection & threat monitoring solution.

Released under the [MIT License](LICENSE).
