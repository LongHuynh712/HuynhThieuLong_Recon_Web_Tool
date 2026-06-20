/**
 * Web Check–style parallel API job progress + full server report.
 */
(function () {
    const CONCURRENCY = 6;
    const jobStates = {};

    function normalizeUrl(raw) {
        const trimmed = (raw || '').trim();
        if (!trimmed) return '';
        if (/^https?:\/\//i.test(trimmed)) return trimmed;
        return `https://${trimmed}`;
    }

    function $(id) {
        return document.getElementById(id);
    }

    function show(el) {
        if (el) el.classList.remove('hidden');
    }

    function hide(el) {
        if (el) el.classList.add('hidden');
    }

    function classifyResult(data) {
        if (!data) return { state: 'error', message: 'No response' };
        if (data.skipped) return { state: 'skipped', message: data.skipped };
        if (data.error) return { state: 'error', message: data.error };
        return { state: 'success', message: 'success' };
    }

    async function fetchJob(jobId, url, signal) {
        const start = performance.now();
        try {
            const resp = await fetch(`/api/${jobId}?url=${encodeURIComponent(url)}`, { signal });
            let data;
            try {
                data = await resp.json();
            } catch {
                data = { error: resp.statusText || `HTTP ${resp.status}` };
            }
            if (!resp.ok && !data.error && !data.skipped) {
                data = { error: data.message || `HTTP ${resp.status}` };
            }
            const elapsed = Math.round(performance.now() - start);
            const outcome = classifyResult(data);
            return { ...outcome, elapsed, data };
        } catch (err) {
            const elapsed = Math.round(performance.now() - start);
            if (err.name === 'AbortError') {
                return { state: 'skipped', message: 'Cancelled', elapsed };
            }
            return { state: 'error', message: err.message || 'Request failed', elapsed };
        }
    }

    function updateSummary() {
        const jobs = Object.values(jobStates);
        const total = jobs.length;
        const success = jobs.filter((j) => j.state === 'success').length;
        const loading = jobs.filter((j) => j.state === 'loading').length;
        const failed = jobs.filter((j) => j.state === 'error').length;
        const skipped = jobs.filter((j) => j.state === 'skipped').length;
        const done = success + failed + skipped;
        const totalMs = jobs.reduce((sum, j) => sum + (j.elapsed || 0), 0);

        const loadingText = $('jobsLoadingText');
        if (loadingText) {
            if (loading > 0) {
                loadingText.textContent = `Loading ${done} / ${total} Jobs`;
            } else {
                loadingText.textContent = `Completed ${total} Jobs`;
            }
        }

        const skippedEl = $('jobsSkippedText');
        if (skippedEl) {
            skippedEl.textContent = skipped ? `${skipped} jobs skipped` : '';
        }

        const failedEl = $('jobsFailedText');
        if (failedEl) {
            failedEl.textContent = failed ? `${failed} jobs failed` : '';
        }

        const totalMsEl = $('jobsTotalMs');
        if (totalMsEl) {
            totalMsEl.textContent = `${totalMs} ms`;
        }

        const bar = $('jobsProgressBar');
        if (bar && total > 0) {
            const pct = (n) => `${Math.max(0, (n / total) * 100)}%`;
            bar.style.setProperty('--bar-success', pct(success));
            bar.style.setProperty('--bar-loading', pct(loading));
            bar.style.setProperty('--bar-fail', pct(failed + skipped));
        }
    }

    function emitLog(message, type) {
        document.dispatchEvent(new CustomEvent('rs-scan-log', { detail: { message, type } }));
    }

    function renderJobRow(job) {
        const state = jobStates[job.id];
        const li = document.querySelector(`[data-job-id="${job.id}"]`);
        if (!li) return;

        li.className = `job-row job-${state.state}`;

        const icon = li.querySelector('.job-icon');
        const status = li.querySelector('.job-status-text');
        const timing = li.querySelector('.job-timing');
        const actions = li.querySelector('.job-actions');

        if (icon) {
            icon.textContent = state.state === 'success' ? '✓' : state.state === 'loading' ? '◌' : state.state === 'skipped' ? '−' : '✗';
        }
        if (status) {
            if (state.state === 'loading') {
                status.textContent = '(loading)';
            } else if (state.state === 'success') {
                status.textContent = '(success)';
            } else if (state.state === 'skipped') {
                status.textContent = '(skipped)';
            } else {
                status.textContent = '(error)';
            }
        }
        if (timing) {
            timing.textContent = state.elapsed != null ? `Took ${state.elapsed} ms` : '';
        }
        if (actions) {
            actions.innerHTML = '';
            if (state.state === 'error' || state.state === 'skipped') {
                const retry = document.createElement('button');
                retry.type = 'button';
                retry.className = 'job-btn';
                retry.textContent = 'Retry';
                retry.addEventListener('click', () => retryJob(job.id, job.url));
                actions.appendChild(retry);

                if (state.message) {
                    const detail = document.createElement('button');
                    detail.type = 'button';
                    detail.className = 'job-btn';
                    detail.textContent = state.state === 'skipped' ? 'Show Skip Reason' : 'Show Error';
                    detail.addEventListener('click', () => alert(state.message));
                    actions.appendChild(detail);
                }
            }
        }
        updateSummary();
        const label = jobStates[job.id]?.label || job.id;
        if (state.state === 'success') {
            emitLog(`✓ ${label} (${state.elapsed} ms)`, 'ok');
        } else if (state.state === 'error') {
            emitLog(`✗ ${label}: ${state.message || 'error'}`, 'err');
        } else if (state.state === 'skipped') {
            emitLog(`− ${label} skipped`, 'warn');
        }
    }

    function buildJobList(jobs, url) {
        const list = $('jobsList');
        if (!list) return;
        list.innerHTML = '';
        jobs.forEach((job) => {
            jobStates[job.id] = { state: 'loading', url, label: job.label };
            const li = document.createElement('li');
            li.className = 'job-row job-loading';
            li.dataset.jobId = job.id;
            li.innerHTML = `
                <span class="job-icon">◌</span>
                <span class="job-name">${job.label}</span>
                <span class="job-status-text">(loading)</span>
                <span class="job-timing"></span>
                <span class="job-actions" aria-label="Actions"></span>
            `;
            list.appendChild(li);
        });
        updateSummary();
    }

    async function runWithConcurrency(jobs, url) {
        const queue = [...jobs];
        const workers = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
            while (queue.length) {
                const job = queue.shift();
                if (!job) break;
                const controller = new AbortController();
                jobStates[job.id].controller = controller;
                const result = await fetchJob(job.id, url, controller.signal);
                jobStates[job.id] = { ...jobStates[job.id], ...result, url };
                renderJobRow(job);
            }
        });
        await Promise.all(workers);
    }

    async function retryJob(jobId, url) {
        const job = (window.API_JOBS || []).find((j) => j.id === jobId);
        if (!job) return;
        jobStates[jobId] = { state: 'loading', url, label: job.label };
        renderJobRow(job);
        const result = await fetchJob(jobId, url);
        jobStates[jobId] = { ...jobStates[jobId], ...result, url };
        renderJobRow(job);
    }

    async function runApiJobs(url) {
        const jobs = window.API_JOBS || [];
        if (!jobs.length) return;

        buildJobList(jobs, url);
        emitLog(`Bắt đầu ${jobs.length} API check song song…`, 'info');
        show($('jobsProgress'));
        const scanStart = $('scan');
        if (scanStart) scanStart.scrollIntoView({ behavior: 'smooth', block: 'start' });

        await runWithConcurrency(jobs, url);
    }

    async function fetchFullReport(form) {
        const statusEl = $('jobsReportStatus');
        if (statusEl) {
            statusEl.textContent = 'Đang tạo báo cáo đầy đủ…';
            show(statusEl);
        }
        emitLog('Đang tạo báo cáo server (module đầy đủ)…', 'info');

        const resp = await fetch(form.action || '/scan', {
            method: 'POST',
            body: new FormData(form),
            redirect: 'follow',
        });
        if (!resp.ok) {
            throw new Error(`Scan failed (${resp.status})`);
        }
        const finalUrl = resp.url || '';
        if (finalUrl.includes('/results/') || finalUrl.includes('/history/')) {
            window.location.assign(finalUrl);
            return null;
        }
        return resp.text();
    }

    function showReportHtml(html) {
        document.open();
        document.write(html);
        document.close();
    }

    async function startScan(fromUrl) {
        const form = $('scanForm');
        const urlInput = $('url');
        if (!form || !urlInput) return;

        const url = normalizeUrl(fromUrl || urlInput.value);
        if (!url) {
            urlInput.focus();
            return;
        }
        urlInput.value = url.replace(/^https?:\/\//i, '').replace(/\/$/, '') || url;

        const checked = document.querySelectorAll('.module-input:checked').length;
        if (checked === 0) {
            const proceed = window.confirm('Chưa chọn module nào. Quét toàn bộ mặc định?');
            if (!proceed) return;
        }

        const btn = $('analyzeBtn');
        if (btn) {
            btn.disabled = true;
            btn.textContent = 'Đang quét…';
        }
        hide($('scanProgress'));
        hide($('loading'));

        try {
            const [_, reportHtml] = await Promise.all([
                runApiJobs(url),
                fetchFullReport(form),
            ]);
            if (reportHtml) {
                showReportHtml(reportHtml);
            }
        } catch (err) {
            alert(err.message || 'Scan failed');
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Phân tích URL';
            }
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const form = $('scanForm');
        if (form) {
            form.addEventListener('submit', (event) => {
                event.preventDefault();
                startScan();
            });
        }

        const scanAgainBtn = $('scanAgainBtn');
        if (scanAgainBtn) {
            scanAgainBtn.addEventListener('click', () => {
                const raw = scanAgainBtn.dataset.url || $('url')?.value || '';
                const host = raw.replace(/^https?:\/\//i, '').replace(/\/$/, '');
                const target = host
                    ? `/?url=${encodeURIComponent(host)}`
                    : '/';
                window.location.assign(target);
            });
        }

        window.retryApiJob = retryJob;
    });
})();
