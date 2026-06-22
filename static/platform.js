/**
 * ReconSight platform: history filter, favorites, charts, scan log.
 */
(function () {
    const STORAGE_RECENT = 'rs-recent-targets';
    const STORAGE_FAVS = 'rs-favorite-targets';
    const MAX_RECENT = 8;
    const MAX_FAVS = 12;

    function loadJson(key, fallback) {
        try {
            const raw = localStorage.getItem(key);
            return raw ? JSON.parse(raw) : fallback;
        } catch {
            return fallback;
        }
    }

    function saveJson(key, data) {
        localStorage.setItem(key, JSON.stringify(data));
    }

    function normalizeHost(url) {
        const t = (url || '').trim();
        if (!t) return '';
        try {
            const u = t.startsWith('http') ? t : `https://${t}`;
            return new URL(u).hostname.replace(/^www\./, '');
        } catch {
            return t.replace(/^https?:\/\//, '').split('/')[0];
        }
    }

    function pushRecent(url) {
        const host = normalizeHost(url);
        if (!host) return;
        let list = loadJson(STORAGE_RECENT, []);
        list = [host, ...list.filter((h) => h !== host)].slice(0, MAX_RECENT);
        saveJson(STORAGE_RECENT, list);
        renderQuickActions();
    }

    function toggleFavorite(url) {
        const host = normalizeHost(url);
        if (!host) return;
        let list = loadJson(STORAGE_FAVS, []);
        if (list.includes(host)) {
            list = list.filter((h) => h !== host);
            window.rsToast?.(`Đã bỏ yêu thích: ${host}`, 'info');
        } else {
            list = [host, ...list].slice(0, MAX_FAVS);
            window.rsToast?.(`Đã thêm yêu thích: ${host}`, 'success');
        }
        saveJson(STORAGE_FAVS, list);
        renderQuickActions();
        updateFavButton();
    }

    function setUrlInput(host) {
        const input = document.getElementById('url');
        if (input) input.value = host;
        input?.focus();
    }

    function renderQuickActions() {
        const recentEl = document.getElementById('recentTargets');
        const favEl = document.getElementById('favoriteTargets');
        if (!recentEl && !favEl) return;

        const recent = loadJson(STORAGE_RECENT, []);
        const favs = loadJson(STORAGE_FAVS, []);

        const chip = (host, isFav) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = `quick-chip${isFav ? ' is-fav' : ''}`;
            btn.textContent = isFav ? `★ ${host}` : host;
            btn.addEventListener('click', () => setUrlInput(host));
            return btn;
        };

        if (recentEl) {
            recentEl.innerHTML = '';
            if (!recent.length) {
                recentEl.innerHTML = '<p class="quick-actions-empty">Chưa có mục tiêu gần đây.</p>';
            } else {
                recent.forEach((h) => recentEl.appendChild(chip(h, false)));
            }
        }

        if (favEl) {
            favEl.innerHTML = '';
            if (!favs.length) {
                favEl.innerHTML = '<p class="quick-actions-empty">Nhấn ★ để lưu mục tiêu.</p>';
            } else {
                favs.forEach((h) => favEl.appendChild(chip(h, true)));
            }
        }
    }

    function updateFavButton() {
        const btn = document.getElementById('addFavoriteBtn');
        const input = document.getElementById('url');
        if (!btn || !input) return;
        const host = normalizeHost(input.value);
        const favs = loadJson(STORAGE_FAVS, []);
        btn.textContent = favs.includes(host) ? '★ Đã lưu' : '☆ Yêu thích';
    }

    function initHistoryDashboard() {
        const search = document.getElementById('historySearch');
        const scoreFilter = document.getElementById('historyScoreFilter');
        const sortBy = document.getElementById('historySort');
        const items = document.querySelectorAll('.history-item-wrap');

        function apply() {
            const q = (search?.value || '').trim().toLowerCase();
            const minScore = parseInt(scoreFilter?.value || '0', 10);
            const sort = sortBy?.value || 'newest';
            const list = Array.from(items);

            list.forEach((li) => {
                const link = li.querySelector('.history-item');
                const host = link?.getAttribute('title')?.toLowerCase() || '';
                const text = li.textContent?.toLowerCase() || '';
                const scoreEl = li.querySelector('.history-score-value');
                const score = parseInt(scoreEl?.textContent || '0', 10);
                const matchText = !q || host.includes(q) || text.includes(q);
                const matchScore = !minScore || score >= minScore;
                li.classList.toggle('is-hidden', !(matchText && matchScore));
            });

            const parent = document.querySelector('.history-list');
            if (!parent || sort === 'newest') return;
            const visible = list.filter((li) => !li.classList.contains('is-hidden'));
            visible.sort((a, b) => {
                const sa = parseInt(a.querySelector('.history-score-value')?.textContent || '0', 10);
                const sb = parseInt(b.querySelector('.history-score-value')?.textContent || '0', 10);
                return sort === 'score-desc' ? sb - sa : sa - sb;
            });
            visible.forEach((li) => parent.appendChild(li));
        }

        search?.addEventListener('input', apply);
        scoreFilter?.addEventListener('change', apply);
        sortBy?.addEventListener('change', apply);
    }

    function appendScanLog(message, type) {
        const panel = document.getElementById('scanLiveLog');
        const list = document.getElementById('scanLogList');
        if (!panel || !list) return;
        panel.classList.remove('hidden');
        const li = document.createElement('li');
        const ts = new Date().toLocaleTimeString('vi-VN', { hour12: false });
        li.className = type === 'ok' ? 'log-ok' : type === 'err' ? 'log-err' : type === 'warn' ? 'log-warn' : '';
        li.textContent = `[${ts}] ${message}`;
        list.appendChild(li);
        if (list.children.length > 80) list.removeChild(list.firstChild);
        list.scrollTop = list.scrollHeight;
    }

    function clearScanLog() {
        const list = document.getElementById('scanLogList');
        const panel = document.getElementById('scanLiveLog');
        if (list) list.innerHTML = '';
        panel?.classList.add('hidden');
    }

    function initModuleStatusGrid() {
        const grid = document.getElementById('moduleStatusGrid');
        if (!grid) return;
        const modules = document.querySelectorAll('.module-input');
        grid.innerHTML = '';
        modules.forEach((input) => {
            const label = input.closest('.module-card')?.querySelector('.module-name')?.textContent || input.value;
            const el = document.createElement('div');
            el.className = 'module-status-item';
            el.dataset.moduleValue = input.value;
            el.innerHTML = `<span aria-hidden="true">○</span><span>${label}</span>`;
            if (input.checked) el.classList.add('status-loading');
            grid.appendChild(el);
        });
    }

    function setModuleStatus(value, state) {
        const el = document.querySelector(`#moduleStatusGrid [data-module-value="${value}"]`);
        if (!el) return;
        el.classList.remove('status-loading', 'status-ok', 'status-fail');
        el.classList.add(state === 'ok' ? 'status-ok' : state === 'fail' ? 'status-fail' : 'status-loading');
        const icon = el.querySelector('[aria-hidden="true"]');
        if (icon) icon.textContent = state === 'ok' ? '✓' : state === 'fail' ? '✗' : '◌';
    }

    document.addEventListener('DOMContentLoaded', () => {
        renderQuickActions();
        initHistoryDashboard();
        initModuleStatusGrid();
        updateFavButton();

        document.getElementById('url')?.addEventListener('input', updateFavButton);
        document.getElementById('addFavoriteBtn')?.addEventListener('click', () => {
            toggleFavorite(document.getElementById('url')?.value);
        });

        const scanForm = document.getElementById('scanForm');
        scanForm?.addEventListener('submit', () => {
            clearScanLog();
            initModuleStatusGrid();
            const modGrid = document.getElementById('moduleStatusGrid');
            if (modGrid) modGrid.classList.remove('hidden');
            pushRecent(document.getElementById('url')?.value);
            appendScanLog('Khởi tạo phiên quét…', 'info');
        });
    });

    document.addEventListener('rs-scan-log', (e) => {
        const detail = e.detail || {};
        appendScanLog(detail.message || '', detail.type || 'info');
    });

    document.addEventListener('rs-module-status', (e) => {
        const detail = e.detail || {};
        if (detail.value) setModuleStatus(detail.value, detail.state);
    });

    window.rsPushRecent = pushRecent;
    window.rsAppendScanLog = appendScanLog;
})();
