/**
 * ReconSight platform: history filter, favorites, charts, scan log.
 */
(function () {
    const STORAGE_RECENT = 'rs-recent-targets';
    const STORAGE_FAVS = 'rs-favorite-targets';
    const MAX_RECENT = 8;
    const MAX_FAVS = 12;

    // State for selected recent targets (for batch delete)
    let selectedRecentTargets = new Set();

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
            btn.className = `quick-chip${isFav ? ' is-fav' : ''}${selectedRecentTargets.has(host) ? ' is-selected' : ''}`;
            btn.textContent = isFav ? `★ ${host}` : host;
            btn.dataset.host = host;
            btn.addEventListener('click', () => {
                if (isFav) {
                    toggleFavorite(host);
                } else {
                    setUrlInput(host);
                }
            });
            // Right-click context menu
            btn.addEventListener('contextmenu', (e) => {
                if (!isFav) {
                    e.preventDefault();
                    showRecentContextMenu(e, host);
                }
            });
            // Long press for mobile (700ms)
            let pressTimer;
            btn.addEventListener('touchstart', () => {
                pressTimer = setTimeout(() => {
                    showRecentContextMenu({ clientX: 0, clientY: 0, preventDefault: () => {} }, host);
                }, 700);
            });
            btn.addEventListener('touchend', () => clearTimeout(pressTimer));
            btn.addEventListener('touchmove', () => clearTimeout(pressTimer));
            return btn;
        };

        if (recentEl) {
            recentEl.innerHTML = '';
            if (!recent.length) {
                recentEl.innerHTML = '<p class="quick-actions-empty">Chưa có mục tiêu nào gần đây.</p>';
                const manageBtn = document.getElementById('manageRecentBtn');
                const clearBtn = document.getElementById('clearAllRecentBtn');
                if (manageBtn) manageBtn.disabled = true;
                if (clearBtn) clearBtn.disabled = true;
            } else {
                const manageBtn = document.getElementById('manageRecentBtn');
                const clearBtn = document.getElementById('clearAllRecentBtn');
                if (manageBtn) manageBtn.disabled = false;
                if (clearBtn) clearBtn.disabled = false;
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

    function showRecentContextMenu(e, host) {
        const menu = document.getElementById('recentContextMenu');
        if (!menu) return;
        menu.dataset.targetHost = host;
        // Position menu at cursor, keep within viewport
        const menuWidth = 180;
        const menuHeight = 80;
        let left = e.clientX;
        let top = e.clientY;
        if (left + menuWidth > window.innerWidth) left -= menuWidth;
        if (top + menuHeight > window.innerHeight) top -= menuHeight;
        menu.style.left = `${left}px`;
        menu.style.top = `${top}px`;
        menu.classList.remove('hidden');
        menu.focus();
    }

    function hideRecentContextMenu() {
        const menu = document.getElementById('recentContextMenu');
        if (menu) menu.classList.add('hidden');
    }

    function showRecentManageModal() {
        const modal = document.getElementById('recentManageModal');
        const backdrop = document.getElementById('recentManageBackdrop');
        const list = document.getElementById('recentManageList');
        if (!modal || !list) return;

        const recent = loadJson(STORAGE_RECENT, []);
        list.innerHTML = '';

        recent.forEach((host) => {
            const item = document.createElement('label');
            item.className = 'recent-manage-item';
            item.innerHTML = `
                <input type="checkbox" value="${host}" ${selectedRecentTargets.has(host) ? 'checked' : ''}>
                <span>${host}</span>
            `;
            list.appendChild(item);
        });

        // Check all by default
        const checkboxes = list.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(cb => {
            cb.checked = true;
            selectedRecentTargets.add(cb.value);
        });

        modal.classList.remove('hidden');
        backdrop.classList.remove('hidden');
        modal.focus();
    }

    function hideRecentManageModal() {
        const modal = document.getElementById('recentManageModal');
        const backdrop = document.getElementById('recentManageBackdrop');
        if (modal) modal.classList.add('hidden');
        if (backdrop) backdrop.classList.add('hidden');
        selectedRecentTargets.clear();
    }

    function showRecentClearModal() {
        const modal = document.getElementById('recentClearModal');
        const backdrop = document.getElementById('recentClearBackdrop');
        if (modal) modal.classList.remove('hidden');
        if (backdrop) backdrop.classList.remove('hidden');
        modal.focus();
    }

    function hideRecentClearModal() {
        const modal = document.getElementById('recentClearModal');
        const backdrop = document.getElementById('recentClearBackdrop');
        if (modal) modal.classList.add('hidden');
        if (backdrop) backdrop.classList.add('hidden');
    }

    function deleteSelectedRecent() {
        const recent = loadJson(STORAGE_RECENT, []);
        const newRecent = recent.filter(host => !selectedRecentTargets.has(host));
        saveJson(STORAGE_RECENT, newRecent);
        selectedRecentTargets.clear();
        hideRecentManageModal();
        renderQuickActions();
        const count = recent.length - newRecent.length;
        if (count > 0) {
            window.rsToast?.(`Đã xóa ${count} mục tiêu thành công`, 'success');
        }
    }

    function deleteAllRecent() {
        saveJson(STORAGE_RECENT, []);
        hideRecentClearModal();
        renderQuickActions();
        window.rsToast?.(`Đã xóa toàn bộ mục tiêu gần đây`, 'success');
    }

    function initHistoryDashboard() {
        const search = document.getElementById('historySearch');
        const scoreFilter = document.getElementById('historyScoreFilter');
        const sortBy = document.getElementById('historySort');
        const items = document.querySelectorAll('.history-item-wrap');

        function fuzzyMatch(query, text) {
            if (!query) return true;
            let qIdx = 0;
            for (let i = 0; i < text.length && qIdx < query.length; i++) {
                if (text[i] === query[qIdx]) qIdx++;
            }
            return qIdx === query.length;
        }

        function matchesHost(q, rawHost) {
            if (!q) return true;
            const host = normalizeHost(rawHost).toLowerCase();
            if (host.includes(q)) return true;
            if (fuzzyMatch(q, host)) return true;
            return false;
        }

        function apply() {
            const q = (search?.value || '').trim().toLowerCase();
            const minScore = parseInt(scoreFilter?.value || '0', 10);
            const sort = sortBy?.value || 'newest';
            const list = Array.from(items);
            const seenHosts = new Set();

            let sortedList = [...list];
            if (sort !== 'newest') {
                sortedList.sort((a, b) => {
                    const sa = parseInt(a.querySelector('.history-score-value')?.textContent || '0', 10);
                    const sb = parseInt(b.querySelector('.history-score-value')?.textContent || '0', 10);
                    return sort === 'score-desc' ? sb - sa : sa - sb;
                });
            }

            sortedList.forEach((li) => {
                const link = li.querySelector('.history-item');
                const rawHost = link?.getAttribute('title')?.toLowerCase() || '';
                const cleanHost = normalizeHost(rawHost).toLowerCase();
                const text = li.textContent?.toLowerCase() || '';
                const scoreEl = li.querySelector('.history-score-value');
                const score = parseInt(scoreEl?.textContent || '0', 10);

                const matchText = matchesHost(q, rawHost) || text.includes(q);
                const matchScore = !minScore || score >= minScore;
                let shouldShow = matchText && matchScore;

                if (shouldShow && cleanHost) {
                    if (!seenHosts.has(cleanHost)) {
                        seenHosts.add(cleanHost);
                    } else {
                        shouldShow = false;
                    }
                }

                li.classList.toggle('is-hidden', !shouldShow);
            });

            const parent = document.querySelector('.history-list');
            if (parent) {
                sortedList.forEach((li) => parent.appendChild(li));
            }
        }

        const searchBtn = document.getElementById('historySearchBtn');
        searchBtn?.addEventListener('click', apply);
        search?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') apply();
        });
        search?.addEventListener('input', (e) => {
            if (!e.target.value.trim()) apply();
        });
        scoreFilter?.addEventListener('change', apply);
        sortBy?.addEventListener('change', apply);

        apply();
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

    document.addEventListener('DOMContentLoaded', () => {
        renderQuickActions();
        initHistoryDashboard();
        initModuleStatusGrid();
        updateFavButton();

        document.getElementById('url')?.addEventListener('input', updateFavButton);
        document.getElementById('addFavoriteBtn')?.addEventListener('click', () => {
            toggleFavorite(document.getElementById('url')?.value);
        });

        // Recent Targets management buttons
        document.getElementById('manageRecentBtn')?.addEventListener('click', showRecentManageModal);
        document.getElementById('clearAllRecentBtn')?.addEventListener('click', showRecentClearModal);
        document.getElementById('recentManageDismissBtn')?.addEventListener('click', hideRecentManageModal);
        document.getElementById('recentManageCancelBtn')?.addEventListener('click', hideRecentManageModal);
        document.getElementById('recentManageConfirmBtn')?.addEventListener('click', deleteSelectedRecent);
        document.getElementById('recentClearDismissBtn')?.addEventListener('click', hideRecentClearModal);
        document.getElementById('recentClearCancelBtn')?.addEventListener('click', hideRecentClearModal);
        document.getElementById('recentClearConfirmBtn')?.addEventListener('click', deleteAllRecent);

        // Close modals on backdrop click
        document.getElementById('recentManageBackdrop')?.addEventListener('click', hideRecentManageModal);
        document.getElementById('recentClearBackdrop')?.addEventListener('click', hideRecentClearModal);

        // Close context menu on outside click
        document.addEventListener('click', (e) => {
            const menu = document.getElementById('recentContextMenu');
            if (menu && !menu.contains(e.target)) {
                hideRecentContextMenu();
            }
        });

        // Keyboard navigation for modals
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                hideRecentManageModal();
                hideRecentClearModal();
                hideRecentContextMenu();
            }
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