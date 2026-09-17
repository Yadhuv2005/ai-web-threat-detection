/**
 * Chart Rendering Module
 * Handles HTML5 Canvas drawing for real-time traffic volume and threat categorization.
 * Lightweight, zero-dependency pure JavaScript canvas renderer.
 */

class SimpleCharts {
    static drawTrafficTimeline(canvasId, trafficHistory) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth;
        const height = canvas.height = canvas.parentElement.clientHeight || 180;

        ctx.clearRect(0, 0, width, height);

        if (trafficHistory.length < 2) {
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.fillText('Awaiting incoming traffic telemetry...', 20, height / 2);
            return;
        }

        const maxVal = Math.max(...trafficHistory, 10);
        const stepX = (width - 40) / (trafficHistory.length - 1);

        // Draw grid lines
        ctx.strokeStyle = '#1f293d';
        ctx.lineWidth = 1;
        ctx.beginPath();
        for (let y = 30; y < height; y += 40) {
            ctx.moveTo(20, y);
            ctx.lineTo(width - 20, y);
        }
        ctx.stroke();

        // Draw line chart
        ctx.strokeStyle = '#06b6d4';
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        trafficHistory.forEach((val, i) => {
            const x = 20 + i * stepX;
            const y = height - 20 - (val / maxVal) * (height - 50);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Fill area under line
        ctx.lineTo(20 + (trafficHistory.length - 1) * stepX, height - 20);
        ctx.lineTo(20, height - 20);
        ctx.closePath();
        ctx.fillStyle = 'rgba(6, 182, 212, 0.15)';
        ctx.fill();
    }

    static drawThreatBreakdown(canvasId, sqliCount, xssCount, bruteCount, burstCount) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const width = canvas.width = canvas.parentElement.clientWidth;
        const height = canvas.height = canvas.parentElement.clientHeight || 180;

        ctx.clearRect(0, 0, width, height);

        const total = sqliCount + xssCount + bruteCount + burstCount;
        if (total === 0) {
            ctx.fillStyle = '#64748b';
            ctx.font = '12px sans-serif';
            ctx.fillText('No threats logged yet. System secure.', 20, height / 2);
            return;
        }

        const items = [
            { label: `SQLi (${sqliCount})`, val: sqliCount, color: '#ef4444' },
            { label: `XSS (${xssCount})`, val: xssCount, color: '#f59e0b' },
            { label: `Brute Force (${bruteCount})`, val: bruteCount, color: '#ec4899' },
            { label: `Rate Spike (${burstCount})`, val: burstCount, color: '#8b5cf6' }
        ];

        let startY = 30;
        const maxBarWidth = width - 160;

        items.forEach(item => {
            const barW = total > 0 ? (item.val / total) * maxBarWidth : 0;

            // Label
            ctx.fillStyle = '#94a3b8';
            ctx.font = '11px sans-serif';
            ctx.fillText(item.label, 20, startY + 12);

            // Bar background
            ctx.fillStyle = '#1e293b';
            ctx.fillRect(130, startY, maxBarWidth, 14);

            // Bar fill
            ctx.fillStyle = item.color;
            ctx.fillRect(130, startY, barW, 14);

            startY += 32;
        });
    }
}
window.SimpleCharts = SimpleCharts;
