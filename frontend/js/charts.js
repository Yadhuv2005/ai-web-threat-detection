/**
 * Cyber Risk Analytics Chart Renderer
 * High-definition HTML5 Canvas charts with glowing gradients.
 */

class RiskCharts {
    /**
     * Draws Risk Trend Timeline over recent events.
     */
    static drawRiskTrend(canvasId, scoreHistory) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth;
        const height = canvas.height = canvas.parentElement.clientHeight || 230;

        ctx.clearRect(0, 0, width, height);

        if (!scoreHistory || scoreHistory.length < 2) {
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.fillText('Awaiting live risk telemetry stream...', 20, height / 2);
            return;
        }

        const maxScore = 100;
        const leftPadding = 45;
        const rightPadding = 20;
        const bottomPadding = 30;
        const topPadding = 20;
        const chartW = width - leftPadding - rightPadding;
        const chartH = height - topPadding - bottomPadding;

        const stepX = chartW / (scoreHistory.length - 1);

        // Threshold lines
        const thresholds = [
            { val: 80, color: 'rgba(239, 68, 68, 0.35)', label: 'CRITICAL (80)' },
            { val: 60, color: 'rgba(249, 115, 22, 0.30)', label: 'HIGH (60)' },
            { val: 40, color: 'rgba(234, 179, 8, 0.20)', label: 'MED (40)' }
        ];

        thresholds.forEach(th => {
            const y = topPadding + chartH - (th.val / maxScore) * chartH;
            ctx.strokeStyle = th.color;
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.moveTo(leftPadding, y);
            ctx.lineTo(width - rightPadding, y);
            ctx.stroke();

            ctx.fillStyle = '#64748b';
            ctx.font = '9px monospace';
            ctx.fillText(th.label, 5, y + 3);
        });

        ctx.setLineDash([]);

        // Risk line
        ctx.strokeStyle = '#06b6d4';
        ctx.lineWidth = 3;
        ctx.shadowColor = 'rgba(6, 182, 212, 0.5)';
        ctx.shadowBlur = 10;

        ctx.beginPath();
        scoreHistory.forEach((score, i) => {
            const x = leftPadding + i * stepX;
            const y = topPadding + chartH - (score / maxScore) * chartH;
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        ctx.shadowBlur = 0; // Reset shadow

        // Area under curve
        ctx.lineTo(leftPadding + (scoreHistory.length - 1) * stepX, topPadding + chartH);
        ctx.lineTo(leftPadding, topPadding + chartH);
        ctx.closePath();

        const grad = ctx.createLinearGradient(0, topPadding, 0, topPadding + chartH);
        grad.addColorStop(0, 'rgba(6, 182, 212, 0.30)');
        grad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
        ctx.fillStyle = grad;
        ctx.fill();

        // Data nodes
        scoreHistory.forEach((score, i) => {
            const x = leftPadding + i * stepX;
            const y = topPadding + chartH - (score / maxScore) * chartH;
            ctx.fillStyle = score >= 80 ? '#ef4444' : (score >= 60 ? '#f97316' : '#06b6d4');
            ctx.beginPath();
            ctx.arc(x, y, 4, 0, Math.PI * 2);
            ctx.fill();
        });
    }

    /**
     * Draws Risk Tier Distribution with rounded horizontal progress bars.
     */
    static drawRiskDistribution(canvasId, stats) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth;
        const height = canvas.height = canvas.parentElement.clientHeight || 230;

        ctx.clearRect(0, 0, width, height);

        const crit = stats?.critical_risks || 0;
        const high = stats?.high_risks || 0;
        const med = stats?.medium_risks || 0;
        const low = stats?.low_risks || 0;
        const total = crit + high + med + low;

        if (total === 0) {
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.fillText('Zero risk incidents logged. Environment secure.', 20, height / 2);
            return;
        }

        const bars = [
            { label: 'Critical Risk (80-100)', count: crit, color: '#ef4444' },
            { label: 'High Risk (60-79)', count: high, color: '#f97316' },
            { label: 'Medium Risk (40-59)', count: med, color: '#eab308' },
            { label: 'Low Risk (0-39)', count: low, color: '#10b981' }
        ];

        let yPos = 30;
        const maxBarWidth = width - 200;

        bars.forEach(b => {
            const pct = total > 0 ? (b.count / total) : 0;
            const barW = Math.max(pct * maxBarWidth, b.count > 0 ? 10 : 0);

            // Label
            ctx.fillStyle = '#cbd5e1';
            ctx.font = '600 11px -apple-system, sans-serif';
            ctx.fillText(b.label, 15, yPos + 12);

            // Track
            ctx.fillStyle = '#141f33';
            ctx.fillRect(160, yPos, maxBarWidth, 14);

            // Fill
            ctx.fillStyle = b.color;
            ctx.fillRect(160, yPos, barW, 14);

            // Value text
            ctx.fillStyle = '#fff';
            ctx.font = 'bold 11px monospace';
            ctx.fillText(`${b.count} (${Math.round(pct * 100)}%)`, 165 + maxBarWidth, yPos + 12);

            yPos += 42;
        });
    }
}

window.RiskCharts = RiskCharts;
