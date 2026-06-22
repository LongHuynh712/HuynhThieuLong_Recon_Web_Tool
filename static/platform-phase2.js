/**
 * Phase 2: scheduled scans UI + history comparison.
 */
(function () {
    function toast(msg, type) {
        if (typeof window.rsToast === 'function') window.rsToast(msg, type);
    }

    async function fetchJson(url, options) {
        const resp = await fetch(url, {
            headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            ...options,
        });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) throw new Error(data.error || resp.statusText);
        return data;
    }

    function renderCompareResult(data) {
        const panel = document.getElementById('compareResult');
        if (!panel) return;
        panel.classList.remove('hidden');
        const delta = data.score_delta;
        const deltaClass = delta > 0 ? 'compare-improved' : delta < 0 ? 'compare-degraded' : 'compare-neutral';
        panel.innerHTML = `
            <h4>So sánh lần quét</h4>
            <p class="compare-summary ${deltaClass}">${data.summary_text || ''}</p>
            <div class="compare-meta">
                <span>${data.baseline?.timestamp || '—'} → ${data.current?.timestamp || '—'}</span>
                <span>${data.baseline?.score ?? '—'} → <strong>${data.current?.score ?? '—'}</strong> (${delta >= 0 ? '+' : ''}${delta})</span>
            </div>
            ${renderList('Phát hiện mới', data.new_findings, 'compare-new')}
            ${renderList('Đã khắc phục / cải thiện', data.resolved, 'compare-resolved')}
            ${renderList('Thay đổi', data.changed, 'compare-changed', true)}
        `;
    }

    function renderList(title, items, cls, isChanged) {
        if (!items?.length) return '';
        const rows = items
            .map((item) => {
                if (isChanged) {
                    return `<li class="${cls}">${item.title}: ${item.from_severity} → ${item.to_severity}</li>`;
                }
                const cwe = (item.cwe_ids || []).join(', ');
                return `<li class="${cls}"><strong>${item.title}</strong> (${item.severity_label || item.severity_level})${cwe ? ` · ${cwe}` : ''}</li>`;
            })
            .join('');
        return `<div class="compare-block"><h5>${title} (${items.length})</h5><ul>${rows}</ul></div>`;
    }

    function initCompare() {
        const btn = document.getElementById('runCompareBtn');
        const selA = document.getElementById('compareBaseline');
        const selB = document.getElementById('compareCurrent');
        if (!btn || !selA || !selB) return;

        btn.addEventListener('click', async () => {
            const a = selA.value;
            const b = selB.value;
            if (!a || !b) {
                toast('Chọn hai lần quét để so sánh', 'error');
                return;
            }
            if (a === b) {
                toast('Chọn hai bản ghi khác nhau', 'error');
                return;
            }
            btn.disabled = true;
            try {
                const data = await fetchJson(`/api/history/compare?a=${encodeURIComponent(a)}&b=${encodeURIComponent(b)}`);
                renderCompareResult(data);
                toast('Đã tạo báo cáo so sánh', 'success');
            } catch (err) {
                toast(err.message || 'So sánh thất bại', 'error');
            } finally {
                btn.disabled = false;
            }
        });
    }

    function renderScheduleRow(s) {
        const li = document.createElement('li');
        li.className = 'schedule-row';
        li.dataset.id = s.id;
        const next = s.next_run
            ? new Date(s.next_run * 1000).toLocaleString('vi-VN')
            : '—';
        li.innerHTML = `
            <div class="schedule-row-main">
                <strong>${s.label || s.url}</strong>
                <span class="schedule-meta">mỗi ${s.interval_hours}h · ${s.scan_mode} · ${s.enabled ? 'Bật' : 'Tắt'}</span>
                <span class="schedule-meta">Lần tới: ${next}${s.last_score != null ? ` · Điểm: ${s.last_score}` : ''}</span>
            </div>
            <div class="schedule-row-actions">
                <button type="button" class="toolbar-btn schedule-toggle">${s.enabled ? 'Tắt' : 'Bật'}</button>
                <button type="button" class="toolbar-btn schedule-delete">Xóa</button>
            </div>
        `;
        li.querySelector('.schedule-toggle')?.addEventListener('click', async () => {
            try {
                await fetchJson(`/api/schedules/${s.id}/toggle`, { method: 'POST' });
                await refreshSchedules();
                toast('Đã cập nhật lịch quét', 'success');
            } catch (e) {
                toast(e.message, 'error');
            }
        });
        li.querySelector('.schedule-delete')?.addEventListener('click', async () => {
            if (!confirm('Xóa lịch quét này?')) return;
            try {
                await fetchJson(`/api/schedules/${s.id}`, { method: 'DELETE' });
                await refreshSchedules();
                toast('Đã xóa lịch', 'info');
            } catch (e) {
                toast(e.message, 'error');
            }
        });
        return li;
    }

    async function refreshSchedules() {
        const list = document.getElementById('scheduleList');
        if (!list) return;
        try {
            const data = await fetchJson('/api/schedules');
            list.innerHTML = '';
            const schedules = data.schedules || [];
            if (!schedules.length) {
                list.innerHTML = '<li class="schedule-empty">Chưa có lịch quét tự động.</li>';
                return;
            }
            schedules.forEach((s) => list.appendChild(renderScheduleRow(s)));
        } catch {
            /* ignore */
        }
    }

    function initSchedules() {
        const form = document.getElementById('scheduleForm');
        if (!form) return;

        refreshSchedules();

        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('scheduleUrl')?.value?.trim();
            const hours = parseFloat(document.getElementById('scheduleInterval')?.value || '24', 10);
            const mode = document.getElementById('scheduleMode')?.value || 'full';
            if (!url) {
                toast('Nhập URL', 'error');
                return;
            }
            try {
                await fetchJson('/api/schedules', {
                    method: 'POST',
                    body: JSON.stringify({ url, interval_hours: hours, scan_mode: mode }),
                });
                form.reset();
                document.getElementById('scheduleInterval').value = '24';
                await refreshSchedules();
                toast('Đã thêm lịch quét', 'success');
            } catch (err) {
                toast(err.message || 'Không thêm được lịch', 'error');
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        initCompare();
        initSchedules();
    });
})();
