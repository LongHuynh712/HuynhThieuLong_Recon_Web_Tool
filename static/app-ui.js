/**
 * UI nâng cao: theme, toast, preset module, lọc báo cáo, copy, phím tắt.
 */
(function () {
    const PRESETS = {
        full: null,
        security: ['security_headers', 'ssl', 'cookies', 'enumeration'],
        seo: ['seo', 'links', 'robots'],
        infra: ['whois_dns', 'fingerprint', 'browser'],
    };

    function toast(message, type = 'info') {
        const host = document.getElementById('toastHost');
        if (!host) return;
        const el = document.createElement('div');
        el.className = `toast toast-${type}`;
        el.textContent = message;
        host.appendChild(el);
        requestAnimationFrame(() => el.classList.add('is-visible'));
        setTimeout(() => {
            el.classList.remove('is-visible');
            setTimeout(() => el.remove(), 300);
        }, 3200);
    }

    function initTheme() {
        const saved = localStorage.getItem('rs-theme') || 'dark';
        document.documentElement.setAttribute('data-theme', saved);
        const btn = document.getElementById('themeToggle');
        if (btn) {
            btn.textContent = saved === 'dark' ? '🌙' : '☀️';
            btn.addEventListener('click', () => {
                const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
                document.documentElement.setAttribute('data-theme', next);
                localStorage.setItem('rs-theme', next);
                btn.textContent = next === 'dark' ? '🌙' : '☀️';
            });
        }
    }

    function applyPreset(presetId) {
        const modules = PRESETS[presetId];
        if (typeof window.setModulesByValues === 'function') {
            window.setModulesByValues(modules);
        } else {
            const grid = document.getElementById('scanOptions');
            if (!grid) return;
            grid.querySelectorAll('.module-input').forEach((input) => {
                input.checked = !modules || modules.includes(input.value);
            });
            if (typeof window.syncModulesUI === 'function') window.syncModulesUI();
        }
        document.querySelectorAll('.preset-chip').forEach((chip) => {
            chip.classList.toggle('is-active', chip.dataset.preset === presetId);
        });
        toast(modules ? `Đã chọn preset: ${presetId}` : 'Đã chọn tất cả module', 'success');
    }

    function initPresets() {
        document.querySelectorAll('.preset-chip').forEach((chip) => {
            chip.addEventListener('click', () => applyPreset(chip.dataset.preset));
        });
    }

    function initReportTools() {
        const search = document.getElementById('reportSearch');
        const sections = document.querySelectorAll('.report-sections .section-card');
        if (search) {
            search.addEventListener('input', () => {
                const q = search.value.trim().toLowerCase();
                sections.forEach((sec) => {
                    const title = sec.querySelector('h3')?.textContent?.toLowerCase() || '';
                    const body = sec.querySelector('.section-body')?.textContent?.toLowerCase() || '';
                    const match = !q || title.includes(q) || body.includes(q);
                    sec.classList.toggle('is-filtered-out', !match);
                });
            });
        }
        document.getElementById('expandAllReport')?.addEventListener('click', () => {
            sections.forEach((s) => { s.open = true; });
            toast('Đã mở tất cả mục báo cáo', 'success');
        });
        document.getElementById('collapseAllReport')?.addEventListener('click', () => {
            sections.forEach((s) => { s.open = false; });
            toast('Đã thu gọn báo cáo', 'info');
        });
        document.querySelectorAll('.severity-filter-btn').forEach((btn) => {
            btn.addEventListener('click', () => {
                const sev = btn.dataset.severity;
                document.querySelectorAll('.severity-filter-btn').forEach((b) => b.classList.remove('is-active'));
                btn.classList.add('is-active');
                sections.forEach((sec) => {
                    if (sev === 'all') {
                        sec.classList.remove('is-filtered-out');
                        return;
                    }
                    const level = sec.dataset.severityLevel || '';
                    const legacy = sec.classList.contains('high')
                        ? 'high'
                        : sec.classList.contains('medium')
                          ? 'medium'
                          : sec.classList.contains('info')
                            ? 'info'
                            : '';
                    const match =
                        level === sev ||
                        legacy === sev ||
                        (sev === 'critical' && level === 'critical') ||
                        (sev === 'low' && level === 'low');
                    sec.classList.toggle('is-filtered-out', !match);
                });
            });
        });
    }

    async function copyText(text, okMsg) {
        try {
            await navigator.clipboard.writeText(text);
            toast(okMsg || 'Đã sao chép', 'success');
        } catch {
            toast('Không sao chép được', 'error');
        }
    }

    function initCopyButtons() {
        document.getElementById('copyUrlBtn')?.addEventListener('click', () => {
            const url = document.getElementById('url')?.value || '';
            copyText(url, 'Đã sao chép URL');
        });
        document.getElementById('copyReportBtn')?.addEventListener('click', () => {
            const pre = document.querySelector('.report-sections');
            if (!pre) return;
            const parts = [];
            pre.querySelectorAll('.section-card').forEach((sec) => {
                if (sec.classList.contains('is-filtered-out')) return;
                const t = sec.querySelector('h3')?.textContent || '';
                const b = sec.querySelector('.section-body')?.textContent || '';
                parts.push(`========== ${t} ==========\n${b}`);
            });
            copyText(parts.join('\n'), 'Đã sao chép báo cáo');
        });
    }

    function initScrollTop() {
        const btn = document.getElementById('scrollTopBtn');
        if (!btn) return;
        window.addEventListener('scroll', () => {
            btn.classList.toggle('is-visible', window.scrollY > 400);
        });
        btn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
    }

    function initKeyboard() {
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const form = document.getElementById('scanForm');
                if (form && document.activeElement?.closest('#scanForm')) {
                    e.preventDefault();
                    form.requestSubmit();
                }
            }
        });
    }

    function initScoreRing() {
        const gauge = document.querySelector('.soc-score-gauge');
        if (gauge && window.SocCharts?.initScoreGauge) {
            window.SocCharts.initScoreGauge();
            return;
        }
        const ring = document.querySelector('.score-ring');
        if (!ring) return;
        const score = parseInt(ring.querySelector('span')?.textContent || '0', 10);
        ring.style.setProperty('--score-pct', `${Math.min(100, Math.max(0, score))}%`);
    }

    document.addEventListener('DOMContentLoaded', () => {
        initTheme();
        initPresets();
        initReportTools();
        initCopyButtons();
        initScrollTop();
        initKeyboard();
        initScoreRing();
        // Scan queue enqueue is handled in platform-phase34.js (single binding).
        window.rsToast = toast;
    });
})();
