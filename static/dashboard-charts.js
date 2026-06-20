/**
 * Unified SOC dashboard charts — shared sizing, colors, doughnut config.
 */
(function () {
    const DONUT_CUTOUT = '78%';
    const DONUT_SIZE = 112;

    const SOC_COLORS = {
        track: 'rgba(255, 255, 255, 0.08)',
        security: '#d6fb41',
        tls: '#04e4f4',
        seo: '#20e253',
        severity: {
            critical: '#ef4444',
            high: '#f97316',
            medium: '#eab308',
            low: '#3b82f6',
            info: '#64748b',
        },
    };

    const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

    const SEVERITY_LABELS = {
        critical: 'Critical',
        high: 'High',
        medium: 'Medium',
        low: 'Low',
        info: 'Info',
    };

    const chartRegistry = {};

    function getDoughnutOptions() {
        return {
            responsive: true,
            maintainAspectRatio: true,
            aspectRatio: 1,
            animation: { duration: 420 },
            layout: { padding: 8 },
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false },
            },
            cutout: DONUT_CUTOUT,
        };
    }

    function setCenterValue(elementId, value) {
        const el = document.getElementById(`${elementId}Value`);
        if (!el) return;
        const n = Math.round(Number(value) || 0);
        el.innerHTML = `${n}<small>%</small>`;
    }

    function destroyChart(id) {
        if (chartRegistry[id]) {
            chartRegistry[id].destroy();
            delete chartRegistry[id];
        }
    }

    function showEmptyMetric(canvas, message) {
        if (!canvas) return;
        const wrap = canvas.closest('.soc-donut-wrap') || canvas.parentElement;
        if (!wrap) return;
        destroyChart(canvas.id);
        canvas.style.visibility = 'hidden';
        if (!wrap.querySelector('.soc-donut-empty')) {
            const empty = document.createElement('div');
            empty.className = 'soc-donut-empty';
            empty.textContent = message || 'No data available';
            wrap.appendChild(empty);
        }
    }

    function buildSocDoughnut(canvasId, value, mainColor, trackColor) {
        const canvas = document.getElementById(canvasId);
        if (!canvas || typeof Chart === 'undefined') return;

        const val = Math.min(100, Math.max(0, Number(value) || 0));
        destroyChart(canvasId);
        setCenterValue(canvasId, val);

        const wrap = canvas.closest('.soc-donut-wrap');
        wrap?.querySelector('.soc-donut-empty')?.remove();

        chartRegistry[canvasId] = new Chart(canvas, {
            type: 'doughnut',
            data: {
                datasets: [
                    {
                        data: [val, 100 - val],
                        backgroundColor: [mainColor, trackColor || SOC_COLORS.track],
                        borderWidth: 0,
                        hoverOffset: 2,
                    },
                ],
            },
            options: getDoughnutOptions(),
        });
    }

    function renderMetricDoughnuts() {
        if (typeof window.scanMetrics !== 'object') {
            ['securityChart', 'tlsChart', 'seoChart'].forEach((id) => {
                showEmptyMetric(document.getElementById(id), 'No metric data');
            });
            return;
        }
        const m = window.scanMetrics;
        buildSocDoughnut('securityChart', m.security, SOC_COLORS.security);
        buildSocDoughnut('tlsChart', m.tls, SOC_COLORS.tls);
        buildSocDoughnut('seoChart', m.seo, SOC_COLORS.seo);
    }

    function buildSeverityBreakdownHtml(counts) {
        const total = SEVERITY_ORDER.reduce((sum, key) => sum + (Number(counts[key]) || 0), 0);

        return SEVERITY_ORDER.map((level) => {
            const count = Number(counts[level]) || 0;
            const pct = total > 0 ? Math.round((count / total) * 100) : 0;
            const color = SOC_COLORS.severity[level];
            const label = SEVERITY_LABELS[level];
            const barWidth = total > 0 ? Math.max(count > 0 ? 4 : 0, pct) : 0;

            return `
                <div class="sev-stat-row sev-stat-row--${level}${count === 0 ? ' is-zero' : ''}">
                    <div class="sev-stat-row__head">
                        <span class="sev-stat-badge sev-stat-badge--${level}">${label}</span>
                        <span class="sev-stat-values">
                            <strong class="sev-stat-count">${count}</strong>
                            <span class="sev-stat-pct">${pct}%</span>
                        </span>
                    </div>
                    <div class="sev-stat-bar" role="presentation" aria-hidden="true">
                        <span class="sev-stat-bar__fill" style="width:${barWidth}%;background-color:${color}"></span>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderSeverityBreakdown(counts) {
        const html = buildSeverityBreakdownHtml(counts);
        const footer = document.getElementById('severityBreakdown');
        const inline = document.getElementById('severityBreakdownInline');
        if (footer) footer.innerHTML = html;
        if (inline) {
            inline.innerHTML = html;
            inline.setAttribute('aria-hidden', 'false');
        }
    }

    function renderSeverityChart() {
        const canvas = document.getElementById('severityChart');
        const dataEl = document.getElementById('severityChartData');
        if (!canvas || !dataEl || typeof Chart === 'undefined') return;

        let counts;
        try {
            counts = JSON.parse(dataEl.textContent || '{}');
        } catch {
            counts = {};
        }

        renderSeverityBreakdown(counts);

        const labels = [];
        const values = [];
        const bg = [];
        SEVERITY_ORDER.forEach((k) => {
            const n = Number(counts[k]) || 0;
            if (n > 0) {
                labels.push(SEVERITY_LABELS[k]);
                values.push(n);
                bg.push(SOC_COLORS.severity[k]);
            }
        });

        destroyChart('severityChart');

        const total = SEVERITY_ORDER.reduce((sum, k) => sum + (Number(counts[k]) || 0), 0);
        const centerEl = document.getElementById('severityChartValue');
        if (centerEl) {
            centerEl.innerHTML = `${total}<small>findings</small>`;
        }

        if (!values.length) {
            const wrap = canvas.closest('.soc-donut-wrap');
            if (wrap && !wrap.querySelector('.soc-donut-empty')) {
                const empty = document.createElement('div');
                empty.className = 'soc-donut-empty';
                empty.textContent = 'No severity data';
                wrap.appendChild(empty);
            }
            canvas.style.visibility = 'hidden';
            return;
        }

        canvas.style.visibility = 'visible';
        canvas.closest('.soc-donut-wrap')?.querySelector('.soc-donut-empty')?.remove();

        chartRegistry.severityChart = new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{ data: values, backgroundColor: bg, borderWidth: 0, hoverOffset: 3 }],
            },
            options: {
                ...getDoughnutOptions(),
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        enabled: true,
                        callbacks: {
                            label: (ctx) => `${ctx.label}: ${ctx.parsed}`,
                        },
                    },
                },
            },
        });
    }

    function initScoreGauge() {
        const gauge = document.querySelector('.soc-score-gauge');
        if (!gauge) return;
        const score = parseInt(gauge.querySelector('[data-score]')?.textContent || '0', 10);
        gauge.style.setProperty('--score-pct', `${Math.min(100, Math.max(0, score))}%`);
    }

    function renderHistoryTrendChart() {
        const canvas = document.getElementById('historyTrendChart');
        const dataEl = document.getElementById('historyTrendData');
        if (!canvas || !dataEl || typeof Chart === 'undefined') return;

        let points;
        try {
            points = JSON.parse(dataEl.textContent || '[]');
        } catch {
            points = [];
        }

        destroyChart('historyTrendChart');

        const wrap = canvas.closest('.soc-line-wrap');
        if (!points.length) {
            if (wrap && !wrap.querySelector('.soc-donut-empty')) {
                const empty = document.createElement('div');
                empty.className = 'soc-donut-empty';
                empty.textContent = 'No trend data';
                wrap.appendChild(empty);
            }
            return;
        }
        wrap?.querySelector('.soc-donut-empty')?.remove();

        chartRegistry.historyTrendChart = new Chart(canvas, {
            type: 'line',
            data: {
                labels: points.map((p) => p.label),
                datasets: [
                    {
                        label: 'Score',
                        data: points.map((p) => p.score),
                        borderColor: '#04e4f4',
                        backgroundColor: 'rgba(4, 228, 244, 0.12)',
                        fill: true,
                        tension: 0.35,
                        pointRadius: points.length > 10 ? 2 : 4,
                        pointHoverRadius: 5,
                        borderWidth: 2,
                    },
                ],
            },
            options: {
                responsive: false,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: {
                        min: 0,
                        max: 100,
                        grid: { color: 'rgba(255,255,255,0.06)' },
                        ticks: { font: { size: 9 }, maxTicksLimit: 5 },
                    },
                    x: {
                        grid: { display: false },
                        ticks: { font: { size: 8 }, maxTicksLimit: 6 },
                    },
                },
            },
        });
    }

    function renderTrendLine(canvasId, dataId, emptyMsg) {
        const canvas = document.getElementById(canvasId);
        const el = document.getElementById(dataId);
        if (!canvas || !el || typeof Chart === 'undefined') return;

        let data;
        try {
            data = JSON.parse(el.textContent || '{}');
        } catch {
            data = {};
        }

        destroyChart(canvasId);
        const wrap = canvas.closest('.soc-line-wrap') || canvas.parentElement;

        if (!data.points?.length) {
            if (wrap && !wrap.querySelector('.soc-donut-empty')) {
                const empty = document.createElement('div');
                empty.className = 'soc-donut-empty';
                empty.textContent = emptyMsg || 'No data';
                wrap.appendChild(empty);
            }
            return;
        }
        wrap?.querySelector('.soc-donut-empty')?.remove();

        chartRegistry[canvasId] = new Chart(canvas, {
            type: 'line',
            data: {
                labels: data.points.map((p) => p.label),
                datasets: [
                    {
                        data: data.points.map((p) => p.score),
                        borderColor: '#04e4f4',
                        backgroundColor: 'rgba(4, 228, 244, 0.1)',
                        fill: true,
                        tension: 0.35,
                        pointRadius: 3,
                    },
                ],
            },
            options: {
                responsive: false,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { min: 0, max: 100, ticks: { maxTicksLimit: 4 } },
                    x: { ticks: { maxTicksLimit: 6, font: { size: 8 } } },
                },
            },
        });
    }

    function renderAll() {
        initScoreGauge();
        renderMetricDoughnuts();
        renderSeverityChart();
        renderHistoryTrendChart();
        if (document.getElementById('trend30Chart')) {
            renderTrendLine('trend30Chart', 'trend30Data', 'No scans in 30 days');
        }
        if (document.getElementById('trend90Chart')) {
            renderTrendLine('trend90Chart', 'trend90Data', 'No scans in 90 days');
        }
    }

    document.addEventListener('DOMContentLoaded', renderAll);

    window.SocCharts = {
        buildSocDoughnut,
        renderMetricDoughnuts,
        renderSeverityChart,
        renderHistoryTrendChart,
        renderTrendLine,
        renderAll,
        initScoreGauge,
        DONUT_CUTOUT,
        DONUT_SIZE,
    };
})();
