function buildDoughnut(elementId, value, mainColor, trackColor) {
    const ctx = document.getElementById(elementId);
    if (!ctx) {
        return;
    }

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [value, Math.max(0, 100 - value)],
                backgroundColor: [mainColor, trackColor],
                borderWidth: 0,
                hoverOffset: 4,
            }]
        },
        options: {
            cutout: '72%',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false },
            }
        }
    });
}

function renderCharts() {
    if (typeof window.scanMetrics !== 'object') {
        return;
    }

    buildDoughnut('securityChart', window.scanMetrics.security, '#7c67ff', '#1c2443');
    buildDoughnut('tlsChart', window.scanMetrics.tls, '#48b4ff', '#121a2f');
    buildDoughnut('seoChart', window.scanMetrics.seo, '#ff9f6f', '#1b1f2d');
}
