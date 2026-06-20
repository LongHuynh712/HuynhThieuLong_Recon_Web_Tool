/**
 * OWASP WSTG INFO supplement panel — Results page only.
 */
(function () {
    'use strict';

    function targetUrl() {
        var el = document.querySelector('.results-target h2');
        if (!el) return '';
        var host = el.textContent.trim();
        if (!host) return '';
        return host.startsWith('http') ? host : 'https://' + host;
    }

    function renderResult(container, data) {
        container.classList.remove('hidden');
        if (data.error) {
            container.innerHTML = '<p class="hub-meta">Error: ' + data.error + '</p>';
            return;
        }
        var html = '';
        if (data.dorks && data.dorks.length) {
            html += '<ul class="wstg-link-list">';
            data.dorks.forEach(function (d) {
                html += '<li><a href="' + d.google_url + '" target="_blank" rel="noopener">[' + d.severity + '] ' + d.label + '</a></li>';
            });
            html += '</ul>';
        }
        if (data.lookup_links && data.lookup_links.length) {
            html += '<ul class="wstg-link-list">';
            data.lookup_links.forEach(function (l) {
                html += '<li><a href="' + l.url + '" target="_blank" rel="noopener">' + l.label + '</a></li>';
            });
            html += '</ul>';
        }
        if (data.report) {
            html += '<pre class="wstg-report-pre">' + data.report.replace(/</g, '&lt;') + '</pre>';
        }
        container.innerHTML = html || '<p class="hub-meta">No data returned.</p>';
    }

    async function runEndpoint(endpoint) {
        var url = targetUrl();
        if (!url) throw new Error('Target URL not found on page');
        var resp = await fetch('/api/scan/' + endpoint + '?url=' + encodeURIComponent(url));
        var data = await resp.json();
        if (!resp.ok || data.ok === false) {
            throw new Error(data.error || resp.statusText);
        }
        return data;
    }

    document.addEventListener('DOMContentLoaded', function () {
        var panel = document.getElementById('wstg-info-panel');
        if (!panel) return;

        var statusEl = document.getElementById('wstgInfoStatus');

        panel.querySelectorAll('.wstg-info-card').forEach(function (card) {
            var btn = card.querySelector('.wstg-run-btn');
            var out = card.querySelector('.wstg-info-result');
            if (!btn || !out) return;
            btn.addEventListener('click', async function () {
                btn.disabled = true;
                if (statusEl) statusEl.textContent = 'Running ' + card.dataset.wstg + '…';
                try {
                    var data = await runEndpoint(card.dataset.endpoint);
                    renderResult(out, data);
                    if (statusEl) statusEl.textContent = card.dataset.wstg + ' complete';
                } catch (err) {
                    renderResult(out, { error: err.message });
                    if (statusEl) statusEl.textContent = 'Error';
                } finally {
                    btn.disabled = false;
                }
            });
        });

        var allBtn = document.getElementById('wstgRunAllBtn');
        if (allBtn) {
            allBtn.addEventListener('click', async function () {
                allBtn.disabled = true;
                if (statusEl) statusEl.textContent = 'Running all WSTG INFO checks…';
                try {
                    var url = targetUrl();
                    var resp = await fetch('/api/scan/wstg-info?url=' + encodeURIComponent(url));
                    var payload = await resp.json();
                    if (!resp.ok) throw new Error(payload.error || resp.statusText);
                    Object.keys(payload.results || {}).forEach(function (testId) {
                        var card = panel.querySelector('[data-wstg="' + testId + '"]');
                        if (!card) return;
                        renderResult(card.querySelector('.wstg-info-result'), payload.results[testId]);
                    });
                    if (statusEl) statusEl.textContent = 'All WSTG INFO checks complete';
                } catch (err) {
                    if (statusEl) statusEl.textContent = 'Error: ' + err.message;
                } finally {
                    allBtn.disabled = false;
                }
            });
        }
    });
})();
