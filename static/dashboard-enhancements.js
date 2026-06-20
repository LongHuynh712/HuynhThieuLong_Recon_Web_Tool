/**
 * Dashboard UX: collapsible hubs (charts handled by dashboard-charts.js).
 */
(function () {
    function initCollapsibleHubs() {
        document.querySelectorAll('.hub-collapsible').forEach((details) => {
            const key = details.dataset.hubKey;
            if (!key) return;
            const saved = localStorage.getItem(`rs-hub-${key}`);
            if (saved === 'open') details.open = true;
            else if (saved === 'closed') details.open = false;
            details.addEventListener('toggle', () => {
                localStorage.setItem(`rs-hub-${key}`, details.open ? 'open' : 'closed');
            });
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initCollapsibleHubs();
    });
})();
