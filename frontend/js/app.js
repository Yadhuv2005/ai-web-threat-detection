/**
 * AI-POWERED CYBER RISK MANAGER — SOC DASHBOARD LOGIC
 * Features:
 * 1. 3D Glowing Particle "Security Risk Sphere" (HTML5 Canvas)
 * 2. Active / Paused Monitor State Controller
 * 3. Dynamic Priority Threat Queue & Remediation Engine
 * 4. Real-Time WebSocket streaming & Synchronized Polling
 * 5. Interactive AI Security Analyst Console
 */

// Application State
const appState = {
    monitoringActive: true,
    wsConnected: false,
    overallRiskScore: 12,
    stats: {
        total_scanned: 0,
        total_threats: 0,
        normal_requests: 0,
        sqli_count: 0,
        xss_count: 0,
        brute_force_count: 0,
        rate_limit_count: 0,
        overall_risk_score: 12,
        critical_risks: 0,
        high_risks: 0,
        medium_risks: 0,
        low_risks: 0
    },
    riskHistory: [15, 18, 12, 14, 20],
    prioritizedThreats: [],
    trafficLogs: [],
    assets: []
};

// ==========================================================================
// 1. 3D GLOWING PARTICLE "SECURITY RISK SPHERE"
// ==========================================================================
class RiskSphere3D {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.numParticles = 550;
        this.sphereRadius = 140;
        this.rotX = 0;
        this.rotY = 0;
        this.rotSpeedY = 0.004;
        this.rotSpeedX = 0.002;
        this.pulse = 0;
        this.rippleActive = 0;
        this.targetColor = { r: 16, g: 185, b: 129 }; // Default low risk green

        this.initParticles();
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.animate();
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = this.canvas.width = rect.width || 580;
        this.height = this.canvas.height = rect.height || 400;
        this.sphereRadius = Math.min(this.width, this.height) * 0.38;
    }

    initParticles() {
        // Fibonacci sphere distribution for uniform 3D density
        const phi = Math.PI * (3 - Math.sqrt(5));
        for (let i = 0; i < this.numParticles; i++) {
            const y = 1 - (i / (this.numParticles - 1)) * 2;
            const radiusAtY = Math.sqrt(1 - y * y);
            const theta = phi * i;

            const x = Math.cos(theta) * radiusAtY;
            const z = Math.sin(theta) * radiusAtY;

            this.particles.push({
                baseX: x,
                baseY: y,
                baseZ: z,
                phase: Math.random() * Math.PI * 2,
                size: Math.random() * 1.5 + 1.2
            });
        }
    }

    setRiskLevel(level, score, isPaused) {
        if (isPaused) {
            this.targetColor = { r: 100, g: 116, b: 139 }; // Slate Gray when paused
            return;
        }

        if (level === 'CRITICAL' || score >= 80) {
            this.targetColor = { r: 239, g: 68, b: 68 }; // Red
        } else if (level === 'HIGH' || score >= 60) {
            this.targetColor = { r: 249, g: 115, b: 22 }; // Orange
        } else if (level === 'MEDIUM' || score >= 40) {
            this.targetColor = { r: 234, g: 179, b: 8 }; // Yellow
        } else {
            this.targetColor = { r: 16, g: 185, b: 129 }; // Green
        }
    }

    triggerThreatRipple() {
        this.rippleActive = 1.0;
    }

    animate() {
        requestAnimationFrame(() => this.animate());
        if (!this.ctx) return;

        this.ctx.clearRect(0, 0, this.width, this.height);

        // Rotate only when active, or slowly drift when paused
        this.rotY += appState.monitoringActive ? this.rotSpeedY : 0.001;
        this.rotX += appState.monitoringActive ? this.rotSpeedX : 0.0005;
        this.pulse += 0.02;

        if (this.rippleActive > 0) {
            this.rippleActive -= 0.025;
        }

        const cx = this.width / 2;
        const cy = this.height / 2;
        const breathing = Math.sin(this.pulse) * 4;
        const currentRadius = this.sphereRadius + breathing + (this.rippleActive * 24);

        const cosY = Math.cos(this.rotY);
        const sinY = Math.sin(this.rotY);
        const cosX = Math.cos(this.rotX);
        const sinX = Math.sin(this.rotX);

        const projected = [];

        for (let i = 0; i < this.particles.length; i++) {
            const p = this.particles[i];

            let x = p.baseX;
            let y = p.baseY;
            let z = p.baseZ;

            // Rotate Y
            let x1 = x * cosY + z * sinY;
            let z1 = -x * sinY + z * cosY;

            // Rotate X
            let y2 = y * cosX - z1 * sinX;
            let z2 = y * sinX + z1 * cosX;

            const wx = x1 * currentRadius;
            const wy = y2 * currentRadius;
            const wz = z2 * currentRadius;

            const fov = 400;
            const scale = fov / (fov + wz);
            const px = cx + wx * scale;
            const py = cy + wy * scale;

            const alpha = Math.max(0.12, (wz + currentRadius) / (currentRadius * 2));

            projected.push({
                x: px,
                y: py,
                scale: scale * p.size,
                alpha: alpha,
                z: wz
            });
        }

        projected.sort((a, b) => a.z - b.z);

        const { r, g, b } = this.targetColor;

        for (let i = 0; i < projected.length; i++) {
            const p = projected[i];
            this.ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${p.alpha})`;
            this.ctx.beginPath();
            this.ctx.arc(p.x, p.y, p.scale, 0, Math.PI * 2);
            this.ctx.fill();

            if (p.z > currentRadius * 0.3) {
                this.ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${p.alpha * 0.30})`;
                this.ctx.beginPath();
                this.ctx.arc(p.x, p.y, p.scale * 2.8, 0, Math.PI * 2);
                this.ctx.fill();
            }
        }
    }
}

let riskSphereInstance = null;

// ==========================================================================
// 2. UI UPDATE & RENDERING FUNCTIONS
// ==========================================================================

function updateSphereHUD(score, stats) {
    const hud = document.getElementById('sphere-hud');
    const hudScore = document.getElementById('hud-risk-score');
    const hudStatus = document.getElementById('hud-system-status');
    const hudCritical = document.getElementById('hud-crit-count');
    const hudHigh = document.getElementById('hud-high-count');
    const hudMed = document.getElementById('hud-med-count');
    const hudLow = document.getElementById('hud-low-count');

    if (!hud) return;

    if (!appState.monitoringActive) {
        hud.className = 'sphere-hud state-paused';
        if (hudScore) hudScore.innerHTML = `PAUSED`;
        if (hudStatus) {
            hudStatus.textContent = 'MONITORING PAUSED';
            hudStatus.style.color = '#94a3b8';
        }
        if (riskSphereInstance) riskSphereInstance.setRiskLevel('PAUSED', 0, true);
        return;
    }

    if (hudScore) hudScore.innerHTML = `${score}<span>/100</span>`;

    let level = 'LOW';
    hud.className = 'sphere-hud';

    if (score >= 80) {
        level = 'CRITICAL';
        hud.classList.add('state-critical');
        if (hudStatus) {
            hudStatus.textContent = 'CRITICAL RISK';
            hudStatus.style.color = '#ef4444';
        }
    } else if (score >= 60) {
        level = 'HIGH';
        hud.classList.add('state-high');
        if (hudStatus) {
            hudStatus.textContent = 'HIGH RISK';
            hudStatus.style.color = '#f97316';
        }
    } else if (score >= 40) {
        level = 'MEDIUM';
        hud.classList.add('state-medium');
        if (hudStatus) {
            hudStatus.textContent = 'ELEVATED RISK';
            hudStatus.style.color = '#eab308';
        }
    } else {
        level = 'LOW';
        hud.classList.add('state-low');
        if (hudStatus) {
            hudStatus.textContent = 'SYSTEM SECURE';
            hudStatus.style.color = '#10b981';
        }
    }

    if (hudCritical) hudCritical.textContent = stats?.critical_risks || 0;
    if (hudHigh) hudHigh.textContent = stats?.high_risks || 0;
    if (hudMed) hudMed.textContent = stats?.medium_risks || 0;
    if (hudLow) hudLow.textContent = stats?.low_risks || 0;

    if (riskSphereInstance) {
        riskSphereInstance.setRiskLevel(level, score, false);
    }
}

function updateOverviewCards(stats, assetsCount) {
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setVal('card-overall-score', stats?.overall_risk_score ?? 12);
    setVal('card-critical-risks', stats?.critical_risks ?? 0);
    setVal('card-high-risks', stats?.high_risks ?? 0);
    setVal('card-medium-risks', stats?.medium_risks ?? 0);
    setVal('card-low-risks', stats?.low_risks ?? 0);
    setVal('card-monitored-assets', assetsCount || 6);
    setVal('card-active-threats', stats?.total_threats ?? 0);

    if (window.RiskCharts) {
        window.RiskCharts.drawRiskTrend('chart-risk-trend', appState.riskHistory);
        window.RiskCharts.drawRiskDistribution('chart-risk-dist', stats);
    }
}

function renderPriorityThreats(threats) {
    const container = document.getElementById('priority-threats-container');
    if (!container) return;

    if (!threats || threats.length === 0) {
        container.innerHTML = `
            <div style="grid-column: 1/-1; text-align: center; padding: 2.5rem; color: #64748b; background: #0b111e; border: 1px dashed #1c2a45; border-radius: 12px;">
                🛡️ Zero active high-priority risks detected. All monitored endpoints operating safely within baseline.
            </div>
        `;
        return;
    }

    container.innerHTML = threats.slice(0, 6).map(t => {
        const levelClass = (t.risk_level || 'medium').toLowerCase();
        const timeShort = t.timestamp ? t.timestamp.split('T')[1]?.replace('Z', '').split('.')[0] : 'Just now';

        return `
            <div class="threat-card level-${levelClass}">
                <div class="threat-card-top">
                    <div class="threat-card-title">
                        <span>🚨</span> ${t.threat_type}
                    </div>
                    <div class="threat-card-score">
                        <span class="score-badge ${levelClass}">RISK ${t.risk_score}/100</span>
                    </div>
                </div>
                <div class="threat-meta-row">
                    <span><strong>Target Asset:</strong> ${t.affected_asset || 'Web Application'}</span>
                    <span><strong>Endpoint:</strong> <code>${t.endpoint || '/'}</code></span>
                    <span><strong>Source IP:</strong> <code>${t.client_ip || '127.0.0.1'}</code></span>
                    <span><strong>Time:</strong> ${timeShort}</span>
                </div>
                <div class="threat-detail-block">
                    <div class="threat-detail-label">Detection Rationale</div>
                    <div>${t.reason || 'Anomalous request detected by hybrid security engine.'}</div>
                </div>
                <div class="threat-detail-block" style="background: rgba(239, 68, 68, 0.05); border-color: rgba(239, 68, 68, 0.15);">
                    <div class="threat-detail-label" style="color: #fca5a5;">Potential Business Impact</div>
                    <div>${t.business_impact || 'Potential unauthorized data access or session takeover.'}</div>
                </div>
                <div class="threat-remediation-block">
                    <strong>Recommended Action:</strong> ${t.remediation_action || 'Inspect logs and verify access control.'}
                </div>
            </div>
        `;
    }).join('');
}

function appendTrafficRow(log, risk) {
    const tbody = document.getElementById('traffic-tbody');
    if (!tbody) return;

    const row = document.createElement('tr');
    const isThreat = log.prediction !== 'NORMAL';
    const riskLevel = risk?.risk_level || (isThreat ? 'HIGH' : 'LOW');
    const badgeClass = riskLevel.toLowerCase();

    const timeShort = log.timestamp ? log.timestamp.split('T')[1]?.replace('Z', '').split('.')[0] : '';

    row.innerHTML = `
        <td>${timeShort}</td>
        <td><strong>${log.prediction}</strong></td>
        <td>${risk?.affected_asset || 'Storefront'}</td>
        <td><span class="tag-pill ${badgeClass}">${riskLevel} (${risk?.risk_score || 10})</span></td>
        <td><code>${log.client_ip}</code></td>
        <td><span style="font-weight: 700; color: ${isThreat ? '#ef4444' : '#10b981'}">${isThreat ? 'FLAGGED' : 'CLEAN'}</span></td>
    `;

    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 35) {
        tbody.removeChild(tbody.lastChild);
    }
}

function renderAssetRegistry(assets) {
    const list = document.getElementById('asset-list');
    if (!list || !assets) return;

    list.innerHTML = assets.map(a => {
        const critClass = a.criticality.toLowerCase();
        return `
            <div class="asset-item">
                <div>
                    <div class="asset-name">${a.name}</div>
                    <div class="asset-sub">${a.type} • <code>${a.endpoint_pattern}</code></div>
                </div>
                <div style="text-align: right;">
                    <span class="tag-pill ${critClass}">${a.criticality}</span>
                    <div class="asset-sub">${a.active_threats || 0} incidents</div>
                </div>
            </div>
        `;
    }).join('');
}

function renderRecommendedActions(threats) {
    const container = document.getElementById('remediation-cards-container');
    if (!container) return;

    if (!threats || threats.length === 0) {
        container.innerHTML = `
            <div class="action-card">
                <div class="action-icon">✅</div>
                <div class="action-content">
                    <h4>Baseline Security Posture</h4>
                    <p>No critical mitigations required right now. Routine access log audits and perimeter checks active.</p>
                </div>
            </div>
        `;
        return;
    }

    const actionsSeen = new Set();
    const uniqueActions = [];
    for (const t of threats) {
        if (t.remediation_action && !actionsSeen.has(t.remediation_action)) {
            actionsSeen.add(t.remediation_action);
            uniqueActions.push(t);
        }
    }

    container.innerHTML = uniqueActions.slice(0, 4).map(t => {
        return `
            <div class="action-card">
                <div class="action-icon">🛡️</div>
                <div class="action-content">
                    <h4>Direct Remediation for ${t.threat_type}</h4>
                    <p>${t.remediation_action}</p>
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================================================
// 3. AI SECURITY ANALYST CONSOLE
// ==========================================================================

async function sendAnalystQuery(queryText) {
    const input = document.getElementById('analyst-input');
    const outputArea = document.getElementById('analyst-output');
    const query = queryText || input.value.trim();

    if (!query) return;
    if (input) input.value = '';

    outputArea.innerHTML = `
        <div style="color: #06b6d4; font-family: monospace;">
            🤖 AI Analyst is analyzing real-time threat telemetry and asset exposures...
        </div>
    `;

    try {
        const resp = await fetch('/api/analyst/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await resp.json();

        const formattedAnswer = (data.answer || '')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/\n\n/g, '<br><br>')
            .replace(/\n/g, '<br>');

        let actionsHtml = '';
        if (data.action_items && data.action_items.length > 0) {
            actionsHtml = `
                <div style="margin-top: 1rem; padding: 0.85rem; background: rgba(6, 182, 212, 0.08); border-left: 3px solid #06b6d4; border-radius: 4px;">
                    <div style="font-size: 0.75rem; font-weight: 800; text-transform: uppercase; color: #38bdf8; margin-bottom: 0.4rem;">Actionable Directives:</div>
                    ${data.action_items.map(a => `<div>• ${a}</div>`).join('')}
                </div>
            `;
        }

        outputArea.innerHTML = `
            <div class="analyst-output-headline">${data.headline || 'Analyst Assessment'}</div>
            <div>${formattedAnswer}</div>
            ${actionsHtml}
        `;
    } catch (e) {
        outputArea.innerHTML = `
            <div style="color: #ef4444;">
                [-] Error querying AI Analyst: ${e}
            </div>
        `;
    }
}

// ==========================================================================
// 4. WEBSOCKET & STATUS MANAGEMENT
// ==========================================================================

function updateMonitorButtonsUI(isActive) {
    appState.monitoringActive = isActive;
    const statusPill = document.getElementById('status-pill');
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');

    if (statusPill) {
        if (isActive) {
            statusPill.className = 'status-pill online';
            statusPill.innerHTML = '<span class="dot"></span> MONITORING ACTIVE';
        } else {
            statusPill.className = 'status-pill paused';
            statusPill.innerHTML = '<span class="dot"></span> MONITORING PAUSED';
        }
    }

    if (btnStart) btnStart.style.opacity = isActive ? '0.6' : '1.0';
    if (btnStop) btnStop.style.opacity = isActive ? '1.0' : '0.6';

    updateSphereHUD(appState.overallRiskScore, appState.stats);
}

function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    const wsUrl = `${protocol}//${host}/api/ws`;

    try {
        const socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            appState.wsConnected = true;
            updateMonitorButtonsUI(appState.monitoringActive);
        };

        socket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                handleIncomingEvent(data);
            } catch (e) {
                console.error('[-] WS Parse error:', e);
            }
        };

        socket.onclose = () => {
            appState.wsConnected = false;
            setTimeout(initWebSocket, 2500);
        };
    } catch (e) {
        console.warn('[!] WS init error:', e);
    }
}

function handleIncomingEvent(data) {
    if (data.event_type === 'INITIAL_STATE') {
        appState.monitoringActive = data.monitoring_active;
        appState.stats = data.stats;
        appState.overallRiskScore = data.stats.overall_risk_score || 12;
        updateMonitorButtonsUI(data.monitoring_active);
        updateOverviewCards(data.stats, data.assets?.length);
        if (data.prioritized) {
            renderPriorityThreats(data.prioritized);
            renderRecommendedActions(data.prioritized);
        }
        if (data.assets) renderAssetRegistry(data.assets);
        return;
    }

    if (data.event_type === 'STATUS_UPDATE') {
        updateMonitorButtonsUI(data.monitoring_active);
        return;
    }

    if (data.event_type === 'TRAFFIC_LOG' || data.event_type === 'THREAT_DETECTED') {
        if (data.stats) {
            appState.stats = data.stats;
            appState.overallRiskScore = data.stats.overall_risk_score || 12;
            updateSphereHUD(appState.overallRiskScore, data.stats);
            updateOverviewCards(data.stats, appState.assets.length);
        }

        const currentScore = data.risk?.risk_score || appState.overallRiskScore;
        appState.riskHistory.push(currentScore);
        if (appState.riskHistory.length > 25) appState.riskHistory.shift();

        if (data.log) {
            appendTrafficRow(data.log, data.risk);
        }

        if (data.is_threat) {
            if (riskSphereInstance) {
                riskSphereInstance.triggerThreatRipple();
            }
            refreshPriorityData();
        }
    }
}

async function refreshPriorityData() {
    try {
        const [prioritizedRes, statsRes, assetsRes, statusRes] = await Promise.all([
            fetch('/api/risk/prioritized?limit=15'),
            fetch('/api/stats'),
            fetch('/api/assets'),
            fetch('/api/status')
        ]);

        const prioritized = await prioritizedRes.json();
        const stats = await statsRes.json();
        const assets = await assetsRes.json();
        const status = await statusRes.json();

        appState.monitoringActive = status.monitoring_active;
        appState.stats = stats;
        appState.assets = assets;
        appState.overallRiskScore = stats.overall_risk_score || 12;

        updateMonitorButtonsUI(status.monitoring_active);
        updateOverviewCards(stats, assets.length);
        renderPriorityThreats(prioritized);
        renderAssetRegistry(assets);
        renderRecommendedActions(prioritized);
    } catch (e) {
        console.warn('[!] Refresh error:', e);
    }
}

// Initial Setup
window.addEventListener('DOMContentLoaded', () => {
    riskSphereInstance = new RiskSphere3D('risk-sphere-canvas');
    refreshPriorityData();
    initWebSocket();

    // AI Analyst Input & Chips
    const analystBtn = document.getElementById('analyst-send-btn');
    const analystInput = document.getElementById('analyst-input');
    if (analystBtn && analystInput) {
        analystBtn.addEventListener('click', () => sendAnalystQuery());
        analystInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendAnalystQuery();
        });
    }

    document.querySelectorAll('.prompt-chip').forEach(chip => {
        chip.addEventListener('click', (e) => {
            const query = e.target.getAttribute('data-query');
            sendAnalystQuery(query);
        });
    });

    // Start / Stop Pause Buttons
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');

    if (btnStart) {
        btnStart.addEventListener('click', async () => {
            const res = await fetch('/api/monitoring/start', { method: 'POST' });
            const data = await res.json();
            updateMonitorButtonsUI(true);
        });
    }
    if (btnStop) {
        btnStop.addEventListener('click', async () => {
            const res = await fetch('/api/monitoring/stop', { method: 'POST' });
            const data = await res.json();
            updateMonitorButtonsUI(false);
        });
    }

    // Polling sync every 3s
    setInterval(refreshPriorityData, 3000);
});
