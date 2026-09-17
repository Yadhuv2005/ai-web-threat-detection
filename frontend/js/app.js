/**
 * Cyber SOC Frontend Application Logic
 * Handles WebSocket streaming, UI state transitions, dynamic tables,
 * audio/visual alerts, and start/stop monitoring interactions.
 */

// Application State
const state = {
    monitoringActive: true,
    wsConnected: false,
    threatDetectedInSession: false,
    stats: {
        total_scanned: 0,
        total_threats: 0,
        normal_requests: 0,
        sqli_count: 0,
        xss_count: 0,
        brute_force_count: 0,
        rate_limit_count: 0
    },
    trafficHistory: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    trafficLogs: [],
    threats: [],
    alerts: []
};

let socket = null;
let reconnectTimer = null;
let currentCircleTimer = null;
let pollingInterval = null;

// DOM Elements
const circleWrapper = document.getElementById('circle-wrapper');
const circleIcon = document.getElementById('circle-icon');
const circleText = document.getElementById('circle-text');
const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const connectionBadge = document.getElementById('ws-badge');

// Stats Counters
const statTotalScanned = document.getElementById('stat-total-scanned');
const statTotalThreats = document.getElementById('stat-total-threats');
const statNormal = document.getElementById('stat-normal');
const statSqli = document.getElementById('stat-sqli');
const statXss = document.getElementById('stat-xss');
const statBrute = document.getElementById('stat-brute');

// Table & Lists
const trafficTableBody = document.getElementById('traffic-tbody');
const threatList = document.getElementById('threat-list');
const alertList = document.getElementById('alert-list');

// 1. Update Center Animated Circle State
function updateMonitoringCircle(mode) {
    if (currentCircleTimer) clearTimeout(currentCircleTimer);
    if (!circleWrapper) return;

    circleWrapper.className = 'monitoring-circle-wrapper';

    if (mode === 'red') {
        circleWrapper.classList.add('status-red');
        if (circleIcon) circleIcon.textContent = '🚨';
        if (circleText) {
            circleText.textContent = 'THREAT FLAGGED';
            circleText.style.color = '#ef4444';
        }

        // Revert back to active green after 4.5 seconds if monitoring remains active
        currentCircleTimer = setTimeout(() => {
            if (state.monitoringActive) updateMonitoringCircle('green');
        }, 4500);

    } else if (mode === 'green') {
        circleWrapper.classList.add('status-green');
        if (circleIcon) circleIcon.textContent = '🛡️';
        if (circleText) {
            circleText.textContent = 'MONITORING ACTIVE';
            circleText.style.color = '#10b981';
        }
    } else if (mode === 'yellow') {
        circleWrapper.classList.add('status-yellow');
        if (circleIcon) circleIcon.textContent = '⚠️';
        if (circleText) {
            circleText.textContent = 'ANALYZING TRAFFIC';
            circleText.style.color = '#f59e0b';
        }
    } else {
        // Gray / Stopped / Disconnected
        circleWrapper.classList.add('status-gray');
        if (circleIcon) circleIcon.textContent = '⏹️';
        if (circleText) {
            circleText.textContent = 'MONITORING STOPPED';
            circleText.style.color = '#6b7280';
        }
    }
}

// 2. Refresh Stat Counters
function updateStatsUI(stats) {
    if (!stats) return;
    state.stats = stats;
    if (statTotalScanned) statTotalScanned.textContent = stats.total_scanned || 0;
    if (statTotalThreats) statTotalThreats.textContent = stats.total_threats || 0;
    if (statNormal) statNormal.textContent = stats.normal_requests || 0;
    if (statSqli) statSqli.textContent = stats.sqli_count || 0;
    if (statXss) statXss.textContent = stats.xss_count || 0;
    if (statBrute) statBrute.textContent = stats.brute_force_count || 0;

    if (window.SimpleCharts) {
        window.SimpleCharts.drawThreatBreakdown(
            'threat-chart',
            stats.sqli_count || 0,
            stats.xss_count || 0,
            stats.brute_force_count || 0,
            stats.rate_limit_count || 0
        );
    }
}

// 3. Render Live Traffic Row
function appendTrafficRow(log) {
    if (!trafficTableBody) return;
    const row = document.createElement('tr');
    const isThreat = log.prediction !== 'NORMAL';
    const badgeClass = isThreat 
        ? (log.prediction === 'SQL_INJECTION' ? 'sqli' : log.prediction === 'XSS' ? 'xss' : 'bruteforce')
        : 'normal';

    const timeShort = log.timestamp ? log.timestamp.split('T')[1]?.replace('Z', '').split('.')[0] : '';

    row.innerHTML = `
        <td>${timeShort}</td>
        <td><code>${log.client_ip}</code></td>
        <td><strong>${log.method}</strong></td>
        <td><span title="${log.path}">${log.path}</span></td>
        <td>${log.status_code}</td>
        <td><span class="badge-threat ${badgeClass}">${log.prediction}</span></td>
        <td>${(log.confidence * 100).toFixed(1)}%</td>
    `;

    trafficTableBody.insertBefore(row, trafficTableBody.firstChild);

    while (trafficTableBody.children.length > 40) {
        trafficTableBody.removeChild(trafficTableBody.lastChild);
    }
}

// 4. Render Threat Item Card
function appendThreatCard(threat, log) {
    if (!threatList) return;
    const item = document.createElement('div');
    const isCritical = threat.severity === 'CRITICAL';
    item.className = `threat-item ${isCritical ? '' : 'warning'}`;

    const timeShort = log?.timestamp ? log.timestamp.split('T')[1]?.replace('Z', '').split('.')[0] : new Date().toLocaleTimeString();

    item.innerHTML = `
        <div class="threat-top">
            <span class="threat-title">🚨 ${threat.threat_type} (${threat.severity})</span>
            <span class="threat-time">${timeShort}</span>
        </div>
        <div class="threat-reason">${threat.reason}</div>
        <div class="threat-meta">
            <span><strong>Target:</strong> ${threat.endpoint || log?.path || '/'}</span>
            <span><strong>Attacker IP:</strong> ${log?.client_ip || threat.client_ip || '127.0.0.1'}</span>
            <span><strong>Confidence:</strong> ${(threat.confidence * 100).toFixed(1)}%</span>
            <span><strong>Source:</strong> ${threat.detection_source || 'AI_ENGINE'}</span>
        </div>
    `;

    threatList.insertBefore(item, threatList.firstChild);

    while (threatList.children.length > 25) {
        threatList.removeChild(threatList.lastChild);
    }
}

// 5. Render Alert History Item
function appendAlertItem(channel, status, recipient, message) {
    if (!alertList) return;
    const item = document.createElement('div');
    item.className = 'threat-item';
    item.style.borderLeftColor = status === 'SENT' ? '#10b981' : '#f59e0b';

    item.innerHTML = `
        <div class="threat-top">
            <span style="color: ${status === 'SENT' ? '#6ee7b7' : '#fde047'}">
                🔔 ${channel} Notification (${status})
            </span>
            <span class="threat-time">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="threat-reason" style="font-size: 0.74rem;">${message}</div>
        <div class="threat-meta"><span><strong>Recipient:</strong> ${recipient}</span></div>
    `;

    alertList.insertBefore(item, alertList.firstChild);
    while (alertList.children.length > 20) {
        alertList.removeChild(alertList.lastChild);
    }
}

// 6. WebSocket Connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    const wsUrl = `${protocol}//${host}/api/ws`;

    console.log(`[*] Connecting to WebSocket: ${wsUrl}`);
    try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            console.log('[+] WebSocket connected.');
            state.wsConnected = true;
            if (connectionBadge) {
                connectionBadge.textContent = 'CONNECTED';
                connectionBadge.style.color = '#10b981';
                connectionBadge.style.borderColor = '#10b981';
            }
            updateMonitoringCircle('green');
        };

        socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleIncomingEvent(data);
            } catch (e) {
                console.error('[-] Failed to parse WS message:', e);
            }
        };

        socket.onclose = () => {
            console.log('[-] WebSocket disconnected. Retrying in 2s...');
            state.wsConnected = false;
            if (connectionBadge) {
                connectionBadge.textContent = 'RECONNECTING';
                connectionBadge.style.color = '#f59e0b';
                connectionBadge.style.borderColor = '#f59e0b';
            }
            clearTimeout(reconnectTimer);
            reconnectTimer = setTimeout(initWebSocket, 2000);
        };
    } catch (e) {
        console.warn('[!] WebSocket init failed:', e);
    }
}

// 7. Event Dispatcher
function handleIncomingEvent(data) {
    if (data.event_type === 'INITIAL_STATE') {
        state.monitoringActive = data.monitoring_active;
        updateMonitoringCircle(state.monitoringActive ? 'green' : 'gray');
        updateStatsUI(data.stats);
        loadHistoricalRecords();
        return;
    }

    if (data.event_type === 'STATUS_UPDATE') {
        state.monitoringActive = data.monitoring_active;
        updateMonitoringCircle(state.monitoringActive ? 'green' : 'gray');
        return;
    }

    if (data.event_type === 'TRAFFIC_LOG' || data.event_type === 'THREAT_DETECTED') {
        const isThreat = data.is_threat;

        if (data.log) {
            appendTrafficRow(data.log);
        }

        state.trafficHistory.push(state.trafficHistory[state.trafficHistory.length - 1] + 1);
        if (state.trafficHistory.length > 20) state.trafficHistory.shift();
        if (window.SimpleCharts) {
            window.SimpleCharts.drawTrafficTimeline('traffic-chart', state.trafficHistory);
        }

        if (isThreat && data.threat) {
            updateMonitoringCircle('red');
            appendThreatCard(data.threat, data.log);

            if (data.alert) {
                appendAlertItem(
                    'SECURITY_DISPATCH',
                    data.alert.status || 'SENT',
                    'SOC Notification Engine',
                    data.threat.reason
                );
            }
        }

        if (data.stats) {
            updateStatsUI(data.stats);
        }
    }
}

// 8. REST Polling & Initial Load (Ensures data displays even if WebSocket is delayed)
async function loadHistoricalRecords() {
    try {
        const [trafficRes, threatsRes, alertsRes, statsRes] = await Promise.all([
            fetch('/api/traffic?limit=25'),
            fetch('/api/threats?limit=15'),
            fetch('/api/alerts?limit=10'),
            fetch('/api/stats')
        ]);

        const traffic = await trafficRes.json();
        const threats = await threatsRes.json();
        const alerts = await alertsRes.json();
        const stats = await statsRes.json();

        if (stats) updateStatsUI(stats);

        if (trafficTableBody) trafficTableBody.innerHTML = '';
        if (threatList) threatList.innerHTML = '';
        if (alertList) alertList.innerHTML = '';

        traffic.reverse().forEach(log => appendTrafficRow(log));
        threats.forEach(th => appendThreatCard(th, { client_ip: th.client_ip, timestamp: th.timestamp, path: th.endpoint }));
        alerts.forEach(al => appendAlertItem(al.channel, al.status, al.recipient, al.message_body));
    } catch (e) {
        console.warn('[!] Error loading historical data:', e);
    }
}

// 9. Button Handlers
if (btnStart) {
    btnStart.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/monitoring/start', { method: 'POST' });
            const data = await res.json();
            if (data.monitoring_active) {
                state.monitoringActive = true;
                updateMonitoringCircle('green');
            }
        } catch (e) {
            alert('Failed to start monitoring: ' + e);
        }
    });
}

if (btnStop) {
    btnStop.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/monitoring/stop', { method: 'POST' });
            const data = await res.json();
            if (!data.monitoring_active) {
                state.monitoringActive = false;
                updateMonitoringCircle('gray');
            }
        } catch (e) {
            alert('Failed to stop monitoring: ' + e);
        }
    });
}

// Initialize on page load
window.addEventListener('DOMContentLoaded', () => {
    updateMonitoringCircle('green');
    loadHistoricalRecords();
    initWebSocket();

    // Regular background poll every 3s to keep data synchronized
    setInterval(loadHistoricalRecords, 3000);
});
