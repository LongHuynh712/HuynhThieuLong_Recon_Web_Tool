/**
 * Scan progress UI + delegates chart rendering to dashboard-charts.js
 */
document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const loading = document.getElementById('loading');
    const scanProgress = document.getElementById('scanProgress');
    const progressFill = document.getElementById('progressFill');
    const progressMessage = document.querySelector('.progress-text');

    if (scanForm) {
        scanForm.addEventListener('submit', () => {
            scanProgress?.classList.remove('hidden');
            loading?.classList.remove('hidden');
            if (progressFill) progressFill.style.width = '10%';
            if (progressMessage) progressMessage.textContent = 'Khởi tạo quét...';
            animateProgress();
        });
    }

    function animateProgress() {
        if (!progressFill || !progressMessage) return;
        let progress = 10;
        const interval = setInterval(() => {
            if (progress >= 95) {
                clearInterval(interval);
                return;
            }
            progress += Math.round(Math.random() * 8);
            progressFill.style.width = `${progress}%`;
            progressMessage.textContent = `Đang quét: ${progress}%`;
        }, 450);
    }

    /* Charts rendered by dashboard-charts.js on DOMContentLoaded */
});
