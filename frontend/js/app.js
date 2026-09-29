/**
 * AEGIS CYBER RISK OPERATIONS — SOC DASHBOARD LOGIC
 * Features:
 * 1. Cinematic iOS-style Gold Welcome Intro with Web Speech Synthesis (Female Voice)
 * 2. Continuous Financial-grade Stock Ticker for Live Cyber Attacks & Fact Feeds
 * 3. Executive Gold & Black 3D Particle Risk Sphere
 * 4. Dropdown Hover Menu Integration & Live Sync
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
// 1. CINEMATIC WELCOME INTRO & FEMALE VOICE AUDIO SYNTHESIS
// ==========================================================================
function initWelcomeIntro() {
    const introOverlay = document.getElementById('intro-overlay');
    const enterBtn = document.getElementById('btn-enter-soc');
    const titleEl = document.getElementById('typewriter-title');
    const subEl = document.getElementById('typewriter-sub');

    // Typewriter effect on opening screen
    const titleText = "Welcome to Aegis";
    const subText = "AI-Powered Cyber Risk & Autonomous Threat Intelligence";
    let titleIdx = 0;
    let subIdx = 0;

    function typeTitle() {
        if (!titleEl) return;
        if (titleIdx < titleText.length) {
            titleEl.textContent += titleText.charAt(titleIdx);
            titleIdx++;
            setTimeout(typeTitle, 65);
        } else {
            setTimeout(typeSub, 150);
        }
    }

    function typeSub() {
        if (!subEl) return;
        if (subIdx < subText.length) {
            subEl.textContent += subText.charAt(subIdx);
            subIdx++;
            setTimeout(typeSub, 25);
        }
    }

    // Start typing after initial load
    setTimeout(typeTitle, 250);

    if (!enterBtn || !introOverlay) return;

    function speakWelcomeAudio() {
        if (!('speechSynthesis' in window)) return;

        window.speechSynthesis.cancel();

        const speech = new SpeechSynthesisUtterance("Welcome to Aegis. Autonomous cyber defense initialized. Systems secure.");
        speech.rate = 0.92;
        speech.pitch = 1.15; // Natural high tone for clear female voice
        speech.volume = 1.0;

        // Exhaustive female voice matcher across macOS, iOS, Windows, and Chrome
        const voices = window.speechSynthesis.getVoices();
        const femaleVoice = voices.find(v => {
            const name = (v.name || '').toLowerCase();
            const lang = (v.lang || '').toLowerCase();
            return lang.startsWith('en') && (
                name.includes('samantha') || 
                name.includes('karen') || 
                name.includes('victoria') || 
                name.includes('serena') ||
                name.includes('fiona') ||
                name.includes('tessa') ||
                name.includes('zira') || 
                name.includes('moira') ||
                name.includes('female') ||
                name.includes('natural')
            );
        }) || voices.find(v => v.lang.startsWith('en'));

        if (femaleVoice) {
            speech.voice = femaleVoice;
        }

        window.speechSynthesis.speak(speech);
    }

    enterBtn.addEventListener('click', () => {
        speakWelcomeAudio();

        // Smooth iOS cinematic fadeout
        introOverlay.classList.add('dismissed');

        setTimeout(() => {
            if (window.RiskCharts) {
                window.RiskCharts.drawRiskTrend('chart-risk-trend', appState.riskHistory);
                window.RiskCharts.drawRiskDistribution('chart-risk-dist', appState.stats);
            }
        }, 400);
    });

    if ('speechSynthesis' in window) {
        window.speechSynthesis.onvoiceschanged = () => {
            window.speechSynthesis.getVoices();
        };
    }
}

// Spoken Alert Audio Voice Generator
let lastSpokenThreatTime = 0;
function speakThreatAlert(threatType, riskScore) {
    if (!('speechSynthesis' in window)) return;
    const now = Date.now();
    // Prevent overlapping voice spam (at least 2.5s between announcements)
    if (now - lastSpokenThreatTime < 2500) return;
    lastSpokenThreatTime = now;

    window.speechSynthesis.cancel();

    let cleanName = "Threat";
    if (threatType === 'SQL_INJECTION') cleanName = "SQL Injection";
    else if (threatType === 'XSS') cleanName = "Cross-Site Scripting";
    else if (threatType === 'BRUTE_FORCE' || threatType === 'HIGH_RATE_BURST') cleanName = "Brute Force Attack";
    else cleanName = threatType.replace(/_/g, ' ');

    const phrase = `Warning. ${cleanName} detected. Risk score elevated to ${riskScore}.`;
    const speech = new SpeechSynthesisUtterance(phrase);
    speech.rate = 0.95;
    speech.pitch = 1.15; // Elegant, crisp female voice
    speech.volume = 1.0;

    const voices = window.speechSynthesis.getVoices();
    const femaleVoice = voices.find(v => {
        const name = (v.name || '').toLowerCase();
        const lang = (v.lang || '').toLowerCase();
        return lang.startsWith('en') && (
            name.includes('samantha') || 
            name.includes('karen') || 
            name.includes('victoria') || 
            name.includes('serena') ||
            name.includes('fiona') ||
            name.includes('tessa') ||
            name.includes('zira') || 
            name.includes('moira') ||
            name.includes('female')
        );
    }) || voices.find(v => v.lang.startsWith('en'));

    if (femaleVoice) {
        speech.voice = femaleVoice;
    }

    window.speechSynthesis.speak(speech);
}

// ==========================================================================
// 2. LUXURY CONTINUOUS STOCK TICKER CONTROLLER
// ==========================================================================
function initStockTicker() {
    const tickerContent = document.getElementById('ticker-content');
    const tickerClone = document.getElementById('ticker-content-clone');
    if (!tickerContent || !tickerClone) return;

    // Clone content for seamless non-stop continuous loop
    tickerClone.innerHTML = tickerContent.innerHTML;
}

function updateStockTicker(stats, latestThreat) {
    const tickerContent = document.getElementById('ticker-content');
    const tickerClone = document.getElementById('ticker-content-clone');
    if (!tickerContent || !tickerClone) return;

    let threatSnippet = '';
    if (latestThreat) {
        const type = latestThreat.threat_type || 'ANOMALY';
        const score = latestThreat.risk_score || 85;
        const pillClass = score >= 80 ? 'crit' : (score >= 60 ? 'high' : 'med');
        threatSnippet = `<span class="ticker-item"><span class="ticker-pill ${pillClass}">ALERT DETECTED</span> ${type} on ${latestThreat.endpoint || '/'} • Risk ${score}/100</span>`;
    }

    const html = `
        ${threatSnippet}
        <span class="ticker-item"><span class="ticker-pill ${stats.overall_risk_score >= 60 ? 'crit' : 'safe'}">AEGIS INDEX</span> Current Composite Posture: ${stats.overall_risk_score || 12}/100</span>
        <span class="ticker-item"><span class="ticker-pill gold">ATTACK FACT</span> SQL Injection represents 44% of global web layer breach vectors</span>
        <span class="ticker-item"><span class="ticker-pill crit">CRITICAL THREATS</span> ${stats.critical_risks || 0} active immediate-triage vectors</span>
        <span class="ticker-item"><span class="ticker-pill high">HIGH THREATS</span> ${stats.high_risks || 0} elevated anomaly exposures</span>
        <span class="ticker-item"><span class="ticker-pill med">MEDIUM THREATS</span> ${stats.medium_risks || 0} credential brute attempts</span>
        <span class="ticker-item"><span class="ticker-pill safe">TRAFFIC MONITORED</span> ${stats.total_scanned || 0} HTTP transactions analyzed</span>
        <span class="ticker-item"><span class="ticker-pill gold">ML ENGINE</span> Sub-word n-gram TF-IDF Logistic Classifier 97.4% accuracy</span>
        <span class="ticker-item"><span class="ticker-pill safe">TARGET SITE</span> CyberShop Node 127.0.0.1:8001 Nominal</span>
    `;

    tickerContent.innerHTML = html;
    tickerClone.innerHTML = html;
}

// ==========================================================================
// 3. 3D GLOWING PARTICLE "SECURITY RISK SPHERE" (GOLD & METALLIC SHADERS)
// ==========================================================================
class RiskSphere3D {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.numParticles = 580;
        this.sphereRadius = 155;
        this.rotX = 0;
        this.rotY = 0;
        this.rotSpeedY = 0.009;
        this.rotSpeedX = 0.0035;
        this.pulse = 0;
        this.rippleActive = 0;
        
        // Luxury Gold default baseline color
        this.targetColor = { r: 212, g: 175, b: 55 }; // Pure Luxury Gold

        this.initParticles();
        this.resize();
        window.addEventListener('resize', () => this.resize());
        
        this.animate = this.animate.bind(this);
        requestAnimationFrame(this.animate);
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = this.canvas.width = rect.width || 750;
        this.height = this.canvas.height = rect.height || 580;
        this.sphereRadius = Math.min(this.width, this.height) * 0.36;
    }

    initParticles() {
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
                size: Math.random() * 1.6 + 1.2
            });
        }
    }

    setRiskLevel(level, score, isPaused) {
        if (isPaused) {
            this.targetColor = { r: 100, g: 116, b: 139 }; // Slate Gray when paused
            return;
        }

        if (level === 'CRITICAL' || score >= 80) {
            this.targetColor = { r: 244, g: 63, b: 94 }; // Vivid Rose Red
        } else if (level === 'HIGH' || score >= 60) {
            this.targetColor = { r: 251, g: 146, b: 60 }; // Vivid Amber Orange
        } else if (level === 'MEDIUM' || score >= 40) {
            this.targetColor = { r: 234, g: 179, b: 8 }; // Yellow
        } else {
            this.targetColor = { r: 212, g: 175, b: 55 }; // Luxury Gold (Baseline Secure)
        }
    }

    triggerThreatRipple() {
        this.rippleActive = 1.0;
    }

    animate() {
        requestAnimationFrame(this.animate);
        if (!this.ctx) return;

        this.ctx.clearRect(0, 0, this.width, this.height);

        this.rotY += appState.monitoringActive ? this.rotSpeedY : 0.0025;
        this.rotX += appState.monitoringActive ? this.rotSpeedX : 0.0012;
        this.pulse += 0.03;

        if (this.rippleActive > 0) {
            this.rippleActive -= 0.02;
        }

        const cx = this.width / 2;
        const cy = this.height / 2;
        const breathing = Math.sin(this.pulse) * 6;
        const currentRadius = this.sphereRadius + breathing + (this.rippleActive * 30);

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

            const fov = 450;
            const scale = fov / (fov + wz);
            const px = cx + wx * scale;
            const py = cy + wy * scale;

            const alpha = Math.max(0.14, (wz + currentRadius) / (currentRadius * 2));

            projected.push({
                x: px,
                y: py,
                scale: Math.max(0.5, scale * p.size),
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

            // Specular metallic halo for foreground particles
            if (p.z > currentRadius * 0.25) {
                this.ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${p.alpha * 0.35})`;
                this.ctx.beginPath();
                this.ctx.arc(p.x, p.y, p.scale * 2.8, 0, Math.PI * 2);
                this.ctx.fill();
            }
        }
    }
}

let riskSphereInstance = null;

// ==========================================================================
// 4. UI UPDATE & RENDERING FUNCTIONS
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
        hud.className = 'sphere-gold-hud state-paused';
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
    hud.className = 'sphere-gold-hud';

    if (score >= 80) {
        level = 'CRITICAL';
        hud.classList.add('state-critical');
        if (hudStatus) {
            hudStatus.textContent = 'CRITICAL THREAT';
            hudStatus.style.color = '#f43f5e';
        }
    } else if (score >= 60) {
        level = 'HIGH';
        hud.classList.add('state-high');
        if (hudStatus) {
            hudStatus.textContent = 'HIGH RISK POSTURE';
            hudStatus.style.color = '#fb923c';
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
            hudStatus.style.color = '#ffd700'; // Pure Gold
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

function updateOverviewCards(stats) {
    const setVal = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val;
    };

    setVal('card-overall-score', stats?.overall_risk_score ?? 12);
    setVal('card-critical-risks', stats?.critical_risks ?? 0);
    setVal('card-high-risks', stats?.high_risks ?? 0);
    setVal('card-medium-risks', stats?.medium_risks ?? 0);
    setVal('card-low-risks', stats?.low_risks ?? 0);
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
            <div class="empty-state" style="text-align: center; padding: 2rem; color: #64748b; font-size: 0.85rem;">
                🛡️ Zero active high-priority risks detected. All monitored endpoints operating safely within baseline.
            </div>
        `;
        return;
    }

    container.innerHTML = threats.slice(0, 10).map(t => {
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
                    <span><strong>Asset:</strong> ${t.affected_asset || 'Web Application'}</span>
                    <span><strong>Endpoint:</strong> <code>${t.endpoint || '/'}</code></span>
                    <span><strong>Source:</strong> <code>${t.client_ip || '127.0.0.1'}</code></span>
                    <span><strong>Time:</strong> ${timeShort}</span>
                </div>
                <div class="threat-detail-block">
                    <div class="threat-detail-label">Detection Rationale</div>
                    <div>${t.reason || 'Anomalous request detected by hybrid security engine.'}</div>
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

    const timeShort = log.timestamp ? log.timestamp.split('T')[1]?.replace('Z', '').split('.')[0] : 'Now';

    row.innerHTML = `
        <td><code>${timeShort}</code></td>
        <td><strong>${log.prediction}</strong></td>
        <td>${risk?.affected_asset || 'Storefront'}</td>
        <td><span class="tag-pill ${badgeClass}">${riskLevel} (${risk?.risk_score || 10})</span></td>
        <td><span style="font-weight: 700; color: ${isThreat ? '#f43f5e' : '#10b981'}">${isThreat ? 'FLAGGED' : 'CLEAN'}</span></td>
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
                    <p>No critical mitigations required right now. Routine perimeter access monitoring active.</p>
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
                    <h4>Direct Action for ${t.threat_type}</h4>
                    <p>${t.remediation_action}</p>
                </div>
            </div>
        `;
    }).join('');
}

// ==========================================================================
// 5. AI SECURITY ANALYST CONSOLE
// ==========================================================================
async function sendAnalystQuery(queryText) {
    const input = document.getElementById('analyst-input');
    const outputArea = document.getElementById('analyst-output');
    const query = queryText || input.value.trim();

    if (!query) return;
    if (input) input.value = '';

    outputArea.innerHTML = `
        <div style="color: #ffd700; font-family: monospace;">
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
            .replace(/### (.*?)\n/g, '<h5 style="color:#ffd700; margin: 0.8rem 0 0.3rem 0; font-size: 0.95rem;">$1</h5>')
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/`([^`]+)`/g, '<code style="background:rgba(212,175,55,0.15); color:#ffd700; padding:1px 4px; border-radius:3px;">$1</code>')
            .replace(/\n\n/g, '<br><br>')
            .replace(/\n/g, '<br>');

        outputArea.innerHTML = `
            <div class="analyst-output-headline">${data.headline || 'Analyst Assessment'}</div>
            <div style="line-height: 1.6;">${formattedAnswer}</div>
        `;
    } catch (e) {
        outputArea.innerHTML = `
            <div style="color: #f43f5e;">
                [-] Error querying AI Analyst: ${e}
            </div>
        `;
    }
}

// ==========================================================================
// 6. WEBSOCKET & STATUS MANAGEMENT
// ==========================================================================
function updateMonitorButtonsUI(isActive) {
    appState.monitoringActive = isActive;
    const statusPill = document.getElementById('status-pill');
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');

    if (statusPill) {
        if (isActive) {
            statusPill.className = 'status-pill-gold online';
            statusPill.innerHTML = '<span class="dot-gold"></span> ACTIVE';
        } else {
            statusPill.className = 'status-pill-gold paused';
            statusPill.innerHTML = '<span class="dot-gold" style="background:#94a3b8;box-shadow:none;"></span> PAUSED';
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
        updateOverviewCards(data.stats);
        if (data.prioritized) {
            renderPriorityThreats(data.prioritized);
            renderRecommendedActions(data.prioritized);
        }
        if (data.assets) renderAssetRegistry(data.assets);
        updateStockTicker(data.stats, null);
        return;
    }

    if (data.event_type === 'RESET_STATS') {
        appState.stats = data.stats;
        appState.overallRiskScore = data.stats.overall_risk_score || 12;
        updateSphereHUD(appState.overallRiskScore, data.stats);
        updateOverviewCards(data.stats);
        renderPriorityThreats([]);
        renderRecommendedActions([]);
        const tbody = document.getElementById('traffic-tbody');
        if (tbody) tbody.innerHTML = '';
        updateStockTicker(data.stats, null);
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
            updateOverviewCards(data.stats);
            updateStockTicker(data.stats, data.threat);
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
            // Announce detected threat using the exact central System Risk Score (e.g. 56)
            const threatName = data.threat?.threat_type || data.log?.prediction || "Threat";
            const actualSystemRiskScore = appState.overallRiskScore;
            speakThreatAlert(threatName, actualSystemRiskScore);

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
        updateOverviewCards(stats);
        updateSphereHUD(appState.overallRiskScore, stats);
        renderPriorityThreats(prioritized);
        renderAssetRegistry(assets);
        renderRecommendedActions(prioritized);
    } catch (e) {
        console.warn('[!] Refresh error:', e);
    }
}

// Initial Setup
window.addEventListener('DOMContentLoaded', () => {
    initWelcomeIntro();
    initStockTicker();

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
            await fetch('/api/monitoring/start', { method: 'POST' });
            updateMonitorButtonsUI(true);
        });
    }
    if (btnStop) {
        btnStop.addEventListener('click', async () => {
            await fetch('/api/monitoring/stop', { method: 'POST' });
            updateMonitorButtonsUI(false);
        });
    }

    // Reset Telemetry Button
    const btnReset = document.getElementById('btn-reset');
    if (btnReset) {
        btnReset.addEventListener('click', async () => {
            if (confirm('Are you sure you want to reset all telemetry and risk history back to baseline?')) {
                try {
                    btnReset.disabled = true;
                    btnReset.textContent = '⏳';
                    const res = await fetch('/api/reset', { method: 'POST' });
                    const data = await res.json();
                    if (data.stats) {
                        appState.stats = data.stats;
                        appState.overallRiskScore = data.stats.overall_risk_score || 12;
                        updateSphereHUD(appState.overallRiskScore, data.stats);
                        updateOverviewCards(data.stats);
                    }
                    await refreshPriorityData();
                } catch (err) {
                    console.error('Reset error:', err);
                } finally {
                    btnReset.disabled = false;
                    btnReset.textContent = '🔄 Reset';
                }
            }
        });
    }

    // Polling sync every 3s
    setInterval(refreshPriorityData, 3000);
});
