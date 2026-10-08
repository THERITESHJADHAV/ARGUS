/* ============================================================
   ARGUS — Adaptive Real-time Guard for Unified Security
   Frontend Logic — app.js (v2.0 Real-time Edition)
   ============================================================ */

(() => {
  'use strict';

  // ─────────────────────────────────────────────────────────
  // Configuration & State
  // ─────────────────────────────────────────────────────────
  const API_BASE = window.location.origin.includes('http')
    ? window.location.origin
    : 'http://127.0.0.1:8000';

  const WS_URL = window.location.origin.includes('http')
    ? window.location.origin.replace(/^http/, 'ws') + '/ws'
    : 'ws://127.0.0.1:8000/ws';

  let ws = null;
  let wsReconnectTimer = null;
  let pollInterval = null;
  let soundEnabled = true;
  let simRunning = false;
  let activeTab = 'overview';

  // Local state cache
  let allAlerts = [];
  let currentStats = {};
  let iocList = [];
  let flowHistory = [];

  // Chart instances
  let flowChart = null;
  let severityChart = null;
  let netTimelineChart = null;
  let netMlRatioChart = null;

  // ─────────────────────────────────────────────────────────
  // DOM Element References
  // ─────────────────────────────────────────────────────────
  const dom = {
    // Navigation & Views
    navItems: document.querySelectorAll('.nav-item'),
    views: {
      overview: document.getElementById('view-overview'),
      alerts: document.getElementById('view-alerts'),
      network: document.getElementById('view-network'),
      windows: document.getElementById('view-windows'),
      ioc: document.getElementById('view-ioc'),
    },
    pageTitle: document.getElementById('page-title'),
    sbAlertCount: document.getElementById('sb-alert-count'),
    connDot: document.getElementById('conn-dot'),
    connLabel: document.getElementById('conn-label'),
    clock: document.getElementById('clock'),

    // Top Controls
    soundToggle: document.getElementById('sound-toggle'),
    soundIcon: document.getElementById('sound-icon'),
    btnTestAlert: document.getElementById('btn-test-alert'),
    btnSimTraffic: document.getElementById('btn-sim-traffic'),
    btnClear: document.getElementById('btn-clear'),

    // Stat Cards
    sTotal: document.getElementById('s-total'),
    sCritical: document.getElementById('s-critical'),
    sHigh: document.getElementById('s-high'),
    sMedium: document.getElementById('s-medium'),
    sNetwork: document.getElementById('s-network'),
    sPackets: document.getElementById('s-packets'),
    sFlows: document.getElementById('s-flows'),

    // Progress Bars
    pCritical: document.getElementById('p-critical'),
    pfCritical: document.getElementById('pf-critical'),
    pHigh: document.getElementById('p-high'),
    pfHigh: document.getElementById('pf-high'),
    pMedium: document.getElementById('p-medium'),
    pfMedium: document.getElementById('pf-medium'),
    pLow: document.getElementById('p-low'),
    pfLow: document.getElementById('pf-low'),

    // Detector Dots & Counts
    detDotMl: document.getElementById('det-dot-ml'),
    detCountMl: document.getElementById('det-count-ml'),
    detDotPs: document.getElementById('det-dot-ps'),
    detCountPs: document.getElementById('det-count-ps'),
    detDotOb: document.getElementById('det-dot-ob'),
    detCountOb: document.getElementById('det-count-ob'),
    detDotWin: document.getElementById('det-dot-win'),
    detCountWin: document.getElementById('det-count-win'),

    // ML Stats
    mlBenign: document.getElementById('ml-benign'),
    mlAttack: document.getElementById('ml-attack'),
    mlTotal: document.getElementById('ml-total'),

    // Overview Feed & Mini Alerts
    feedCount: document.getElementById('feed-count'),
    activityFeed: document.getElementById('activity-feed'),
    miniAlertsList: document.getElementById('mini-alerts-list'),

    // Full Alerts View
    alertTotalLabel: document.getElementById('alert-total-label'),
    alertSearch: document.getElementById('alert-search'),
    filterSev: document.getElementById('filter-sev'),
    filterDet: document.getElementById('filter-det'),
    btnExportCsv: document.getElementById('btn-export-csv'),
    btnExportJson: document.getElementById('btn-export-json'),
    fullAlertsList: document.getElementById('full-alerts-list'),

    // Network View Stats & List
    nPackets: document.getElementById('n-packets'),
    nFlows: document.getElementById('n-flows'),
    nMl: document.getElementById('n-ml'),
    netAttack: document.getElementById('net-attack'),
    netBenign: document.getElementById('net-benign'),
    flowFeed: document.getElementById('flow-feed'),

    // Windows View Stats & List
    winAlerts: document.getElementById('win-alerts'),
    winBruteforce: document.getElementById('win-bruteforce'),
    winUsers: document.getElementById('win-users'),
    winAlertsList: document.getElementById('win-alerts-list'),

    // IOC View
    iocCount: document.getElementById('ioc-count'),
    iocInput: document.getElementById('ioc-input'),
    btnAddIoc: document.getElementById('btn-add-ioc'),
    iocList: document.getElementById('ioc-list'),

    // Modal
    modalOverlay: document.getElementById('modal-overlay'),
    modalTitle: document.getElementById('modal-title'),
    modalBody: document.getElementById('modal-body'),
    modalClose: document.getElementById('modal-close'),

    // Toast Container
    toastContainer: document.getElementById('toast-container'),
  };

  // ─────────────────────────────────────────────────────────
  // Application Initialization
  // ─────────────────────────────────────────────────────────
  function init() {
    setupClock();
    setupNavigation();
    setupEventListeners();
    setupModal();
    initCharts();
    connectWebSocket();
    startPolling();
    fetchInitialData();
  }

  // Live Clock
  function setupClock() {
    const update = () => {
      const now = new Date();
      if (dom.clock) {
        dom.clock.textContent = now.toLocaleTimeString('en-US', { hour12: false });
      }
    };
    update();
    setInterval(update, 1000);
  }

  // Navigation Tabs Switcher (Fixed for data-view)
  function setupNavigation() {
    const titleMap = {
      overview: 'Security Overview',
      alerts: 'Alert Center',
      network: 'Network Traffic & ML Analysis',
      windows: 'Windows Security Monitoring',
      ioc: 'IOC & Blocklist Management',
    };

    dom.navItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const tab = item.getAttribute('data-view') || item.getAttribute('data-tab');
        if (!tab || tab === activeTab) return;

        activeTab = tab;

        // Update active class on nav items
        dom.navItems.forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');

        // Hide all views, show active
        Object.keys(dom.views).forEach(key => {
          if (dom.views[key]) {
            dom.views[key].style.display = key === tab ? 'block' : 'none';
          }
        });

        // Update Header Title
        if (dom.pageTitle) {
          dom.pageTitle.textContent = titleMap[tab] || 'ARGUS Security';
        }
      });
    });
  }

  // Modal Dialog Setup
  function setupModal() {
    if (dom.modalClose) {
      dom.modalClose.addEventListener('click', closeModal);
    }
    if (dom.modalOverlay) {
      dom.modalOverlay.addEventListener('click', (e) => {
        if (e.target === dom.modalOverlay) closeModal();
      });
    }
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeModal();
    });
  }

  function openModal(title, contentHtml) {
    if (!dom.modalOverlay) return;
    if (dom.modalTitle) dom.modalTitle.textContent = title;
    if (dom.modalBody) dom.modalBody.innerHTML = contentHtml;
    dom.modalOverlay.style.display = 'flex';
  }

  function closeModal() {
    if (dom.modalOverlay) dom.modalOverlay.style.display = 'none';
  }

  // Audio Alerts (Web Audio API Synthesizer)
  function playAlertSound(severity) {
    if (!soundEnabled) return;
    try {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (!AudioCtx) return;
      const ctx = new AudioCtx();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();

      osc.connect(gain);
      gain.connect(ctx.destination);

      const sev = (severity || '').toLowerCase();
      if (sev === 'critical') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(880, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(440, ctx.currentTime + 0.3);
        gain.gain.setValueAtTime(0.3, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3);
        osc.start();
        osc.stop(ctx.currentTime + 0.3);
      } else if (sev === 'high') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(660, ctx.currentTime);
        osc.frequency.exponentialRampToValueAtTime(330, ctx.currentTime + 0.2);
        gain.gain.setValueAtTime(0.2, ctx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);
        osc.start();
        osc.stop(ctx.currentTime + 0.2);
      }
    } catch (e) {
      console.warn('Audio playback error:', e);
    }
  }

  // ─────────────────────────────────────────────────────────
  // Event Listeners setup
  // ─────────────────────────────────────────────────────────
  function setupEventListeners() {
    // Sound Toggle
    if (dom.soundToggle) {
      dom.soundToggle.addEventListener('click', () => {
        soundEnabled = !soundEnabled;
        if (dom.soundIcon) {
          dom.soundIcon.textContent = soundEnabled ? '🔔' : '🔕';
        }
        showToast(soundEnabled ? 'Alert sounds enabled' : 'Alert sounds muted', 'info');
      });
    }

    // Trigger Test Alert
    if (dom.btnTestAlert) {
      dom.btnTestAlert.addEventListener('click', async () => {
        try {
          const res = await fetch(`${API_BASE}/api/alerts/test`, { method: 'POST' });
          const data = await res.json();
          if (data.status === 'ok') {
            showToast('Test alert emitted!', 'info');
            fetchAlerts();
            fetchStats();
          }
        } catch (err) {
          showToast('Failed to emit test alert', 'critical');
        }
      });
    }

    // Toggle Sim Traffic
    if (dom.btnSimTraffic) {
      dom.btnSimTraffic.addEventListener('click', async () => {
        try {
          const res = await fetch(`${API_BASE}/api/simulation/toggle`, { method: 'POST' });
          const data = await res.json();
          simRunning = data.running;
          if (dom.btnSimTraffic) {
            dom.btnSimTraffic.style.background = simRunning ? 'rgba(239, 68, 68, 0.2)' : '';
            dom.btnSimTraffic.style.borderColor = simRunning ? '#ef4444' : '';
            dom.btnSimTraffic.textContent = simRunning ? '⏹ Stop Sim' : '🧪 Sim Traffic';
          }
          showToast(data.message, simRunning ? 'high' : 'info');
        } catch (err) {
          showToast('Failed to toggle simulation', 'critical');
        }
      });
    }

    // Clear Alerts
    if (dom.btnClear) {
      dom.btnClear.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to clear all alerts?')) return;
        try {
          const res = await fetch(`${API_BASE}/api/alerts/clear`, { method: 'POST' });
          const data = await res.json();
          if (data.status === 'ok') {
            allAlerts = [];
            renderAlerts();
            fetchStats();
            showToast('All alerts cleared', 'info');
          }
        } catch (err) {
          showToast('Failed to clear alerts', 'critical');
        }
      });
    }

    // Filter controls for full alerts table
    if (dom.alertSearch) dom.alertSearch.addEventListener('input', renderAlerts);
    if (dom.filterSev) dom.filterSev.addEventListener('change', renderAlerts);
    if (dom.filterDet) dom.filterDet.addEventListener('change', renderAlerts);

    // Export CSV
    if (dom.btnExportCsv) {
      dom.btnExportCsv.addEventListener('click', () => exportAlerts('csv'));
    }

    // Export JSON
    if (dom.btnExportJson) {
      dom.btnExportJson.addEventListener('click', () => exportAlerts('json'));
    }

    // Add IOC
    if (dom.btnAddIoc) {
      dom.btnAddIoc.addEventListener('click', handleAddIoc);
    }
    if (dom.iocInput) {
      dom.iocInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') handleAddIoc();
      });
    }
  }

  // ─────────────────────────────────────────────────────────
  // Chart.js Visualizations
  // ─────────────────────────────────────────────────────────
  function initCharts() {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // 1. Flow Traffic Line Chart (Overview)
    const ctxFlow = document.getElementById('chart-flows');
    if (ctxFlow) {
      flowChart = new Chart(ctxFlow, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Packets / sec',
              data: [],
              borderColor: '#6366f1',
              backgroundColor: 'rgba(99, 102, 241, 0.12)',
              fill: true,
              tension: 0.4,
              borderWidth: 2,
              pointRadius: 0,
            },
            {
              label: 'Attacks Flagged',
              data: [],
              borderColor: '#f43f5e',
              backgroundColor: 'rgba(244, 63, 94, 0.12)',
              fill: true,
              tension: 0.4,
              borderWidth: 2,
              pointRadius: 0,
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: true, position: 'top' } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
          }
        }
      });
    }

    // 2. Severity Donut Chart (Overview)
    const ctxSev = document.getElementById('chart-severity');
    if (ctxSev) {
      severityChart = new Chart(ctxSev, {
        type: 'doughnut',
        data: {
          labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
          datasets: [{
            data: [0, 0, 0, 0, 0],
            backgroundColor: ['#f43f5e', '#fb923c', '#eab308', '#22c55e', '#3b82f6'],
            borderWidth: 0,
            hoverOffset: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          cutout: '72%'
        }
      });
    }

    // 3. Network View Timeline
    const ctxNetTime = document.getElementById('chart-timeline');
    if (ctxNetTime) {
      netTimelineChart = new Chart(ctxNetTime, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Total Packets',
              data: [],
              borderColor: '#00f2fe',
              backgroundColor: 'rgba(0, 242, 254, 0.1)',
              fill: true,
              tension: 0.3,
              borderWidth: 2
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: true } },
          scales: {
            x: { grid: { color: 'rgba(255,255,255,0.05)' } },
            y: { grid: { color: 'rgba(255,255,255,0.05)' }, beginAtZero: true }
          }
        }
      });
    }

    // 4. Network ML Ratio Donut
    const ctxMlRatio = document.getElementById('chart-ml-ratio');
    if (ctxMlRatio) {
      netMlRatioChart = new Chart(ctxMlRatio, {
        type: 'doughnut',
        data: {
          labels: ['Attack', 'Benign'],
          datasets: [{
            data: [0, 0],
            backgroundColor: ['#f43f5e', '#22c55e'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          cutout: '75%'
        }
      });
    }
  }

  // Update Charts with new data
  function updateCharts(stats, flowHist) {
    if (severityChart && stats) {
      severityChart.data.datasets[0].data = [
        stats.critical || 0,
        stats.high || 0,
        stats.medium || 0,
        stats.low || 0,
        stats.info || 0
      ];
      severityChart.update();
    }

    if (netMlRatioChart && stats) {
      netMlRatioChart.data.datasets[0].data = [
        stats.attack_count || 0,
        stats.benign_count || 0
      ];
      netMlRatioChart.update();
    }

    if (flowChart && Array.isArray(flowHist) && flowHist.length > 0) {
      const labels = flowHist.map(h => {
        if (h.time) {
          const d = new Date(h.time);
          return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        return '--:--';
      });
      const pkts = flowHist.map(h => h.packets || h.flows || 0);
      const attacks = flowHist.map(h => h.attacks || (h.prediction === 'ATTACK' ? 1 : 0));

      flowChart.data.labels = labels;
      flowChart.data.datasets[0].data = pkts;
      flowChart.data.datasets[1].data = attacks;
      flowChart.update();
    }

    if (netTimelineChart && Array.isArray(flowHist) && flowHist.length > 0) {
      const labels = flowHist.map(h => {
        if (h.time) {
          const d = new Date(h.time);
          return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        return '--:--';
      });
      const pkts = flowHist.map(h => h.packets || 0);

      netTimelineChart.data.labels = labels;
      netTimelineChart.data.datasets[0].data = pkts;
      netTimelineChart.update();
    }
  }

  // ─────────────────────────────────────────────────────────
  // Real-Time Communication (WebSocket & Polling)
  // ─────────────────────────────────────────────────────────
  function connectWebSocket() {
    if (ws) {
      try { ws.close(); } catch (e) {}
    }

    ws = new WebSocket(WS_URL);

    ws.onopen = () => {
      updateConnectionStatus(true);
      if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        handleWsMessage(msg);
      } catch (err) {
        console.error('Failed to parse WS message:', err);
      }
    };

    ws.onerror = (err) => {
      console.warn('WebSocket error:', err);
      updateConnectionStatus(false);
    };

    ws.onclose = () => {
      updateConnectionStatus(false);
      wsReconnectTimer = setTimeout(connectWebSocket, 5000);
    };
  }

  function updateConnectionStatus(connected) {
    if (dom.connDot) {
      dom.connDot.className = connected ? 'conn-dot active' : 'conn-dot offline';
    }
    if (dom.connLabel) {
      dom.connLabel.textContent = connected ? 'Live WebSocket' : 'Polling Sync';
    }
  }

  function handleWsMessage(msg) {
    if (msg.type === 'snapshot' || msg.type === 'init') {
      currentStats = msg.stats || {};
      allAlerts = msg.alerts || [];
      flowHistory = msg.flow_history || [];
      renderAll();
    } else if (msg.type === 'update') {
      currentStats = msg.stats || {};
      if (Array.isArray(msg.flow_history)) {
        flowHistory = msg.flow_history;
      }
      if (Array.isArray(msg.alerts)) {
        allAlerts = msg.alerts;
      }

      if (Array.isArray(msg.new_alerts) && msg.new_alerts.length > 0) {
        msg.new_alerts.forEach(newAlert => {
          // Prepend if not already present
          const exists = allAlerts.some(a => (a.id || a.alert_id) === (newAlert.id || newAlert.alert_id));
          if (!exists) {
            allAlerts.unshift(newAlert);
          }
          playAlertSound(newAlert.severity);
          showToast(`[${(newAlert.severity || 'HIGH').toUpperCase()}] ${newAlert.title || newAlert.alert_type || newAlert.type}`, newAlert.severity || 'high');
        });
      }

      renderStats();
      renderAlerts();
      renderActivityFeed();
      updateCharts(currentStats, flowHistory);
    } else if (msg.type === 'alert') {
      const newAlert = msg.alert;
      if (newAlert) {
        allAlerts.unshift(newAlert);
        if (allAlerts.length > 500) allAlerts.pop();

        playAlertSound(newAlert.severity);
        showToast(`[${(newAlert.severity || 'HIGH').toUpperCase()}] ${newAlert.title || newAlert.type}`, newAlert.severity || 'high');
        renderAlerts();
        renderActivityFeed();
      }
    }
  }

  function startPolling() {
    // Poll backup every 4 seconds if WS drops
    pollInterval = setInterval(async () => {
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        fetchStats();
        fetchAlerts();
      }
    }, 4000);
  }

  async function fetchInitialData() {
    await Promise.all([fetchStats(), fetchAlerts(), fetchIocs()]);
  }

  async function fetchStats() {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      currentStats = await res.json();
      renderStats();
      updateCharts(currentStats, flowHistory);
    } catch (e) {
      console.warn('Failed to fetch stats:', e);
    }
  }

  async function fetchAlerts() {
    try {
      const res = await fetch(`${API_BASE}/api/alerts?limit=100`);
      allAlerts = await res.json();
      renderAlerts();
      renderActivityFeed();
    } catch (e) {
      console.warn('Failed to fetch alerts:', e);
    }
  }

  async function fetchIocs() {
    try {
      const res = await fetch(`${API_BASE}/api/ioc`);
      const data = await res.json();
      iocList = data.ioc_blocklist || [];
      renderIocs();
    } catch (e) {
      console.warn('Failed to fetch IOCs:', e);
    }
  }

  // ─────────────────────────────────────────────────────────
  // Render Engine
  // ─────────────────────────────────────────────────────────
  function renderAll() {
    renderStats();
    renderAlerts();
    renderActivityFeed();
    renderIocs();
    updateCharts(currentStats, flowHistory);
  }

  function renderStats() {
    const s = currentStats;
    if (!s) return;

    // Sidebar counter
    if (dom.sbAlertCount) dom.sbAlertCount.textContent = s.total_alerts || 0;

    // Stat Cards
    if (dom.sTotal) dom.sTotal.textContent = s.total_alerts || 0;
    if (dom.sCritical) dom.sCritical.textContent = s.critical || 0;
    if (dom.sHigh) dom.sHigh.textContent = s.high || 0;
    if (dom.sMedium) dom.sMedium.textContent = s.medium || 0;
    if (dom.sNetwork) dom.sNetwork.textContent = s.network_alerts || 0;
    if (dom.sPackets) dom.sPackets.textContent = (s.packets_captured || 0).toLocaleString();
    if (dom.sFlows) dom.sFlows.textContent = `${(s.flows_analyzed || 0).toLocaleString()} flows analyzed`;

    // Severity Progress Bars
    const total = s.total_alerts || 1;
    updateBar(dom.pCritical, dom.pfCritical, s.critical || 0, total);
    updateBar(dom.pHigh, dom.pfHigh, s.high || 0, total);
    updateBar(dom.pMedium, dom.pfMedium, s.medium || 0, total);
    updateBar(dom.pLow, dom.pfLow, s.low || 0, total);

    // Detector Dots
    const det = s.detector_status || {};
    setDetectorDot(dom.detDotMl, det.network_ml);
    setDetectorDot(dom.detDotPs, det.port_scan);
    setDetectorDot(dom.detDotOb, det.outbound);
    setDetectorDot(dom.detDotWin, det.windows);

    // Network View Stats
    if (dom.nPackets) dom.nPackets.textContent = (s.packets_captured || 0).toLocaleString();
    if (dom.nFlows) dom.nFlows.textContent = (s.flows_analyzed || 0).toLocaleString();
    if (dom.nMl) dom.nMl.textContent = (s.ml_predictions || 0).toLocaleString();
    if (dom.mlBenign) dom.mlBenign.textContent = (s.benign_count || 0).toLocaleString();
    if (dom.mlAttack) dom.mlAttack.textContent = (s.attack_count || 0).toLocaleString();
    if (dom.mlTotal) dom.mlTotal.textContent = (s.ml_predictions || 0).toLocaleString();
    if (dom.netAttack) dom.netAttack.textContent = (s.attack_count || 0).toLocaleString();
    if (dom.netBenign) dom.netBenign.textContent = (s.benign_count || 0).toLocaleString();

    // Windows View Stats
    if (dom.winAlerts) dom.winAlerts.textContent = s.windows_alerts || 0;
    if (dom.winBruteforce) dom.winBruteforce.textContent = s.windows_alerts || 0;
  }

  function updateBar(valElem, fillElem, count, total) {
    if (valElem) valElem.textContent = count;
    if (fillElem) {
      const pct = Math.min(100, Math.round((count / total) * 100));
      fillElem.style.width = `${pct}%`;
    }
  }

  function setDetectorDot(dotElem, status) {
    if (!dotElem) return;
    if (status === 'running' || status === 'active' || status === 'ok') {
      dotElem.className = 'det-dot running';
    } else if (status === 'stopped' || status === 'disabled') {
      dotElem.className = 'det-dot stopped';
    } else {
      dotElem.className = 'det-dot warning';
    }
  }

  // Render Activity Feed
  function renderActivityFeed() {
    if (!dom.activityFeed) return;
    if (allAlerts.length === 0) {
      dom.activityFeed.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">🛡️</div>
          <p>System operational. No active threats detected.</p>
        </div>`;
      if (dom.feedCount) dom.feedCount.textContent = '0 events';
      return;
    }

    if (dom.feedCount) dom.feedCount.textContent = `${allAlerts.length} events`;

    const items = allAlerts.slice(0, 15).map(a => {
      const sev = (a.severity || 'info').toLowerCase();
      const timeStr = formatTimestamp(a.timestamp);
      return `
        <div class="feed-item" data-sev="${sev}">
          <div class="feed-sev-tag" data-sev="${sev}">${sev.toUpperCase()}</div>
          <div class="feed-content">
            <div class="feed-title">${escapeHtml(a.title || a.alert_type || a.type || 'Security Alert')}</div>
            <div class="feed-details">${escapeHtml(a.description || a.reason || a.details || '')}</div>
          </div>
          <div class="feed-time">${timeStr}</div>
        </div>`;
    }).join('');

    dom.activityFeed.innerHTML = items;
  }

  // Render Alerts Tables (Overview Mini + Full View + Windows View)
  function renderAlerts() {
    const filtered = filterAlerts(allAlerts);

    // 1. Overview Mini Alerts List
    if (dom.miniAlertsList) {
      if (filtered.length === 0) {
        dom.miniAlertsList.innerHTML = `
          <div class="empty-state">
            <div class="empty-icon">✅</div>
            <p>No alerts match your filter criteria.</p>
          </div>`;
      } else {
        dom.miniAlertsList.innerHTML = filtered.slice(0, 8).map(a => renderAlertRow(a)).join('');
      }
    }

    // 2. Full Alerts View List
    if (dom.fullAlertsList) {
      if (dom.alertTotalLabel) dom.alertTotalLabel.textContent = `${filtered.length} alerts showing`;
      if (filtered.length === 0) {
        dom.fullAlertsList.innerHTML = `
          <div class="empty-state">
            <div class="empty-icon">🔍</div>
            <p>No alerts match search or filter settings.</p>
          </div>`;
      } else {
        dom.fullAlertsList.innerHTML = filtered.map(a => renderAlertRow(a)).join('');
      }
    }

    // 3. Windows Alerts List
    if (dom.winAlertsList) {
      const winAlerts = allAlerts.filter(a => (a.detector || '').toLowerCase().includes('win'));
      if (winAlerts.length === 0) {
        dom.winAlertsList.innerHTML = `
          <div class="empty-state">
            <div class="empty-icon">✅</div>
            <p>No Windows security alerts — system is clean</p>
          </div>`;
      } else {
        dom.winAlertsList.innerHTML = winAlerts.map(a => renderAlertRow(a)).join('');
      }
    }
  }

  function filterAlerts(alerts) {
    const search = (dom.alertSearch ? dom.alertSearch.value : '').toLowerCase().trim();
    const sev = (dom.filterSev ? dom.filterSev.value : 'all').toLowerCase();
    const det = (dom.filterDet ? dom.filterDet.value : 'all').toLowerCase();

    return alerts.filter(a => {
      const aSev = (a.severity || '').toLowerCase();
      const aDet = (a.detector || '').toLowerCase();
      const fullText = `${a.title || ''} ${a.alert_type || ''} ${a.type || ''} ${a.description || ''} ${a.source_ip || ''} ${a.target_ip || ''} ${a.destination_ip || ''}`.toLowerCase();

      if (sev !== 'all' && aSev !== sev) return false;
      if (det !== 'all' && !aDet.includes(det)) return false;
      if (search && !fullText.includes(search)) return false;

      return true;
    });
  }

  function renderAlertRow(a) {
    const sev = (a.severity || 'info').toLowerCase();
    const type = a.title || a.alert_type || a.type || 'Alert';
    const src = a.source_ip || 'N/A';
    const timeStr = formatTimestamp(a.timestamp);
    const alertId = a.id || a.alert_id || '';

    return `
      <div class="alert-row">
        <div><span class="badge" data-severity="${sev}">${sev.toUpperCase()}</span></div>
        <div class="alert-type">${escapeHtml(type)}</div>
        <div class="alert-ip">${escapeHtml(src)}</div>
        <div class="alert-time">${timeStr}</div>
        <div><span class="alert-status">Active</span></div>
        <div style="text-align: right;">
          <button class="btn btn-ghost" style="padding: 4px 8px; font-size: 11px;" onclick="window.ARGUS.showAlertDetails('${escapeHtml(alertId)}')">Details</button>
        </div>
      </div>`;
  }

  // ─────────────────────────────────────────────────────────
  // IOC Management
  // ─────────────────────────────────────────────────────────
  function renderIocs() {
    if (dom.iocCount) dom.iocCount.textContent = `${iocList.length} IOCs Blocked`;
    if (!dom.iocList) return;

    if (iocList.length === 0) {
      dom.iocList.innerHTML = `<div class="ioc-empty">No IPs blocked yet. Add malicious IPs to block outbound connections.</div>`;
      return;
    }

    dom.iocList.innerHTML = iocList.map(ip => `
      <div class="ioc-item">
        <div class="ioc-ip">${escapeHtml(ip)}</div>
        <button class="btn btn-ghost" style="padding: 4px 8px; font-size: 11px; color: var(--critical);" onclick="window.ARGUS.removeIoc('${escapeHtml(ip)}')">Unblock</button>
      </div>
    `).join('');
  }

  async function handleAddIoc() {
    if (!dom.iocInput) return;
    const ip = dom.iocInput.value.trim();
    if (!ip) return;

    try {
      const res = await fetch(`${API_BASE}/api/ioc?ip=${encodeURIComponent(ip)}`, { method: 'POST' });
      const data = await res.json();
      if (data.status === 'ok') {
        iocList = data.ioc_blocklist || [];
        renderIocs();
        dom.iocInput.value = '';
        showToast(`IP ${ip} blocked!`, 'high');
      } else {
        showToast(data.message || 'Failed to add IOC', 'critical');
      }
    } catch (e) {
      showToast('API connection error', 'critical');
    }
  }

  async function removeIoc(ip) {
    try {
      const res = await fetch(`${API_BASE}/api/ioc/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      const data = await res.json();
      if (data.status === 'ok') {
        iocList = data.ioc_blocklist || [];
        renderIocs();
        showToast(`IP ${ip} unblocked`, 'info');
      }
    } catch (e) {
      showToast('Failed to remove IOC', 'critical');
    }
  }

  // ─────────────────────────────────────────────────────────
  // Export Capabilities
  // ─────────────────────────────────────────────────────────
  function exportAlerts(format) {
    if (allAlerts.length === 0) {
      showToast('No alerts to export', 'info');
      return;
    }

    if (format === 'json') {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(allAlerts, null, 2));
      downloadFile(dataStr, `argus_alerts_${Date.now()}.json`);
    } else if (format === 'csv') {
      const headers = ['id', 'timestamp', 'severity', 'alert_type', 'title', 'source_ip', 'destination_ip', 'detector', 'description'];
      const rows = allAlerts.map(a => headers.map(h => `"${(a[h] || '').toString().replace(/"/g, '""')}"`).join(','));
      const csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent([headers.join(','), ...rows].join('\n'));
      downloadFile(csvContent, `argus_alerts_${Date.now()}.csv`);
    }
  }

  function downloadFile(uri, filename) {
    const link = document.createElement('a');
    link.href = uri;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  // ─────────────────────────────────────────────────────────
  // UI Helpers: Toast & Formatting & Modal
  // ─────────────────────────────────────────────────────────
  function showToast(message, type = 'info') {
    if (!dom.toastContainer) return;
    const toast = document.createElement('div');
    const tSev = (type || 'info').toLowerCase();
    toast.className = `toast ${tSev}`;
    toast.innerHTML = `
      <div class="toast-icon">${getToastIcon(tSev)}</div>
      <div class="toast-body">
        <div class="toast-title">ARGUS Threat Guard</div>
        <div class="toast-msg">${escapeHtml(message)}</div>
      </div>`;

    dom.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.classList.add('removing');
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function getToastIcon(type) {
    switch (type.toLowerCase()) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return '⚡';
      case 'low': return '🟢';
      default: return 'ℹ️';
    }
  }

  function formatTimestamp(ts) {
    if (!ts) return 'N/A';
    try {
      const date = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) {
      return String(ts);
    }
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function showAlertDetails(alertId) {
    const alert = allAlerts.find(a => (a.id || a.alert_id) === alertId);
    if (!alert) {
      showToast('Alert details not found', 'info');
      return;
    }

    const sev = (alert.severity || 'info').toLowerCase();
    const html = `
      <div class="detail-grid">
        <div class="detail-item">
          <div class="detail-label">Alert ID</div>
          <div class="detail-val">${escapeHtml(alert.id || alert.alert_id || 'N/A')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Severity</div>
          <div class="detail-val"><span class="badge" data-severity="${sev}">${sev.toUpperCase()}</span></div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Source IP</div>
          <div class="detail-val">${escapeHtml(alert.source_ip || 'N/A')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Target / Dest IP</div>
          <div class="detail-val">${escapeHtml(alert.target_ip || alert.destination_ip || 'N/A')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Detector Engine</div>
          <div class="detail-val">${escapeHtml(alert.detector || 'N/A')}</div>
        </div>
        <div class="detail-item">
          <div class="detail-label">Timestamp</div>
          <div class="detail-val">${formatTimestamp(alert.timestamp)}</div>
        </div>
      </div>

      <div style="background: var(--bg-glass); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 14px;">
        <div class="detail-label" style="margin-bottom: 6px;">Description & Context</div>
        <div style="color: var(--text-secondary); line-height: 1.6;">${escapeHtml(alert.description || alert.reason || alert.details || 'Threat detected by real-time heuristic & ML rules.')}</div>
      </div>

      <div style="background: var(--bg-glass); border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 14px;">
        <div class="detail-label" style="margin-bottom: 6px;">Raw Data Parameters</div>
        <pre style="font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--accent-light); margin: 0; overflow-x: auto;">${escapeHtml(JSON.stringify(alert, null, 2))}</pre>
      </div>`;

    openModal(`🚨 ${alert.title || alert.alert_type || alert.type || 'Threat Detail'}`, html);
  }

  // Expose global methods for inline HTML onclick handlers
  window.ARGUS = {
    removeIoc,
    showAlertDetails,
  };

  // Start app on DOMContentLoaded
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
