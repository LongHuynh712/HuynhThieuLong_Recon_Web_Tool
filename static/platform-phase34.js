/**
 * Phase 3 & 4 UI: workspace, queue, webhooks, integrations, trends.
 */
(function () {
    let enqueueInFlight = false;

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

    function dedupeQueueItems(items) {
        const seen = new Set();
        return (items || []).filter((item) => {
            const id = item && item.id;
            if (!id) {
                console.warn('[queue] skipped item without id', item);
                return false;
            }
            if (seen.has(id)) {
                console.warn('[queue] render dedupe dropped duplicate id', id);
                return false;
            }
            seen.add(id);
            return true;
        });
    }

    function renderQueueItem(item) {
        const status = item.status || 'pending';
        const cancelBtn = status === 'pending'
            ? `<button type="button" class="toolbar-btn queue-cancel" data-id="${item.id}">Hủy</button>`
            : '';
        return `<li class="queue-item status-${status}" data-queue-id="${item.id}">
            <span>${item.url}</span>
            <span class="hub-tag">${status}</span>
            ${cancelBtn}
        </li>`;
    }

    function bindQueueCancelButtons() {
        document.querySelectorAll('.queue-cancel').forEach((btn) => {
            if (btn.dataset.bound === '1') return;
            btn.dataset.bound = '1';
            btn.addEventListener('click', async () => {
                const id = btn.dataset.id;
                try {
                    await fetchJson(`/api/queue/${id}`, { method: 'DELETE' });
                    toast('Đã hủy', 'info');
                    await refreshQueueList();
                } catch (err) {
                    toast(err.message, 'error');
                }
            });
        });
    }

    async function refreshQueueList() {
        const list = document.getElementById('queueList');
        if (!list) return;
        try {
            const data = await fetchJson('/api/queue');
            const items = dedupeQueueItems(data.queue || []);
            console.log('[queue] refresh list', { count: items.length, ids: items.map((i) => i.id) });
            if (!items.length) {
                list.innerHTML = '<li class="hub-empty">Hàng đợi trống.</li>';
            } else {
                list.innerHTML = items.map(renderQueueItem).join('');
            }
            bindQueueCancelButtons();
        } catch (err) {
            console.warn('[queue] refresh failed', err);
        }
    }

    function initWorkspaceUser() {
        document.getElementById('workspaceSelect')?.addEventListener('change', async (e) => {
            try {
                await fetchJson('/api/workspaces/active', {
                    method: 'POST',
                    body: JSON.stringify({ workspace_id: e.target.value }),
                });
                toast('Đã đổi workspace', 'success');
            } catch (err) {
                toast(err.message, 'error');
            }
        });

        document.getElementById('userSelect')?.addEventListener('change', async (e) => {
            try {
                await fetchJson('/api/users/active', {
                    method: 'POST',
                    body: JSON.stringify({ user_id: e.target.value }),
                });
                toast('Đã đổi user', 'success');
            } catch (err) {
                toast(err.message, 'error');
            }
        });

        document.getElementById('createWorkspaceBtn')?.addEventListener('click', async () => {
            const name = window.prompt('Tên workspace mới:');
            if (!name) return;
            try {
                await fetchJson('/api/workspaces', {
                    method: 'POST',
                    body: JSON.stringify({ name }),
                });
                toast('Đã tạo workspace', 'success');
                await refreshWorkspaceList();
            } catch (err) {
                toast(err.message, 'error');
            }
        });

        document.getElementById('deleteWorkspaceBtn')?.addEventListener('click', async () => {
            const workspaceSelect = document.getElementById('workspaceSelect');
            const workspaceId = workspaceSelect?.value;
            if (!workspaceId) return;

            const workspaces = await fetchJson('/api/workspaces').catch(() => ({ workspaces: [] }));
            if (workspaces.workspaces?.length <= 1) {
                toast('Cannot delete the last workspace', 'error');
                return;
            }

            const selectedName = workspaceSelect.options[workspaceSelect.selectedIndex]?.text;
            const confirmed = window.confirm(`Delete workspace "${selectedName}"? This action cannot be undone.`);
            if (!confirmed) return;

            try {
                await fetchJson(`/api/workspaces/${workspaceId}`, { method: 'DELETE' });
                toast('Workspace deleted', 'success');
                await refreshWorkspaceList();
            } catch (err) {
                toast(err.message, 'error');
            }
        });

        document.getElementById('addUserBtn')?.addEventListener('click', async () => {
            const name = window.prompt('User name:');
            if (!name) return;
            const email = window.prompt('User email:');
            if (email === null) return; // User cancelled
            const role = window.prompt('Role (admin/analyst/viewer)', 'analyst');
            if (role === null) return;

            const validRole = ['admin', 'analyst', 'viewer'].includes(role?.toLowerCase()) ? role : 'analyst';
            try {
                await fetchJson('/api/users', {
                    method: 'POST',
                    body: JSON.stringify({ name, email, role: validRole }),
                });
                toast('User added', 'success');
                await refreshUserList();
            } catch (err) {
                toast(err.message, 'error');
            }
        });

        document.getElementById('deleteUserBtn')?.addEventListener('click', async () => {
            const userSelect = document.getElementById('userSelect');
            const userId = userSelect?.value;
            if (!userId) return;

            // Get the current active user ID to prevent self-deletion
            const activeUserData = await fetchJson('/api/users').catch(() => ({ active: null }));
            if (activeUserData.active === userId) {
                toast('Cannot delete your own account', 'error');
                return;
            }

            // Get all users to check admin count and get selected user's name
            const users = await fetchJson('/api/users').catch(() => ({ users: [] }));
            const selectedUser = users.users?.find((u) => u.id === userId);
            if (!selectedUser) return;

            // Prevent deleting the last admin user
            if (selectedUser.role === 'admin') {
                const adminCount = users.users?.filter((u) => u.role === 'admin').length || 0;
                if (adminCount <= 1) {
                    toast('Cannot delete the last admin user', 'error');
                    return;
                }
            }

            const confirmed = window.confirm(`Delete user "${selectedUser.name}" (${selectedUser.role})? This action cannot be undone.`);
            if (!confirmed) return;

            try {
                await fetchJson(`/api/users/${userId}`, { method: 'DELETE' });
                toast('User deleted', 'success');
                await refreshUserList();
            } catch (err) {
                toast(err.message, 'error');
            }
        });
    }

    async function refreshWorkspaceList() {
        try {
            const data = await fetchJson('/api/workspaces');
            const workspaceSelect = document.getElementById('workspaceSelect');
            if (!workspaceSelect) return;

            const currentValue = workspaceSelect.value;
            workspaceSelect.innerHTML = '';
            (data.workspaces || []).forEach((ws) => {
                const option = document.createElement('option');
                option.value = ws.id;
                option.textContent = ws.name;
                if (ws.id === currentValue || ws.id === data.active) {
                    option.selected = true;
                }
                workspaceSelect.appendChild(option);
            });
        } catch (err) {
            console.warn('[workspaces] refresh failed', err);
        }
    }

    async function refreshUserList() {
        try {
            const data = await fetchJson('/api/users');
            const userSelect = document.getElementById('userSelect');
            if (!userSelect) return;

            const currentValue = userSelect.value;
            userSelect.innerHTML = '';
            (data.users || []).forEach((u) => {
                const option = document.createElement('option');
                option.value = u.id;
                option.textContent = `${u.name} (${u.role})`;
                if (u.id === currentValue || u.id === data.active) {
                    option.selected = true;
                }
                userSelect.appendChild(option);
            });
        } catch (err) {
            console.warn('[users] refresh failed', err);
        }
    }

    function initQueue() {
        const enqueueBtn = document.getElementById('enqueueScanBtn');
        if (!enqueueBtn || enqueueBtn.dataset.queueBound === '1') {
            return;
        }
        enqueueBtn.dataset.queueBound = '1';

        enqueueBtn.addEventListener('click', async () => {
            if (enqueueInFlight) {
                console.warn('[queue] enqueue ignored — request already in flight');
                return;
            }

            const url = document.getElementById('url')?.value?.trim();
            const mode = document.getElementById('scanMode')?.value || 'full';
            const modules = Array.from(document.querySelectorAll('.module-input:checked')).map((i) => i.value);

            if (!url) {
                toast('Nhập URL trước', 'error');
                return;
            }

            enqueueInFlight = true;
            enqueueBtn.disabled = true;
            console.log('[queue] enqueue request', { url, scan_mode: mode, modules });

            try {
                const data = await fetchJson('/api/queue', {
                    method: 'POST',
                    body: JSON.stringify({ url, scan_mode: mode, modules }),
                });
                console.log('[queue] enqueue response', data);

                if (data.deduplicated) {
                    toast('URL này đã có trong hàng đợi', 'info');
                } else {
                    toast('Đã thêm vào hàng đợi', 'success');
                }
                await refreshQueueList();
            } catch (err) {
                console.error('[queue] enqueue failed', err);
                toast(err.message, 'error');
            } finally {
                enqueueInFlight = false;
                enqueueBtn.disabled = false;
            }
        });

        bindQueueCancelButtons();

        // Poll queue status so pending/running/completed updates stay live without reload.
        if (document.getElementById('queueList')) {
            setInterval(refreshQueueList, 12000);
        }
    }

    function initWebhooks() {
        document.getElementById('webhookForm')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const url = document.getElementById('webhookUrl')?.value?.trim();
            if (!url) return;
            try {
                await fetchJson('/api/webhooks', {
                    method: 'POST',
                    body: JSON.stringify({ url }),
                });
                toast('Đã thêm webhook', 'success');
                location.reload();
            } catch (err) {
                toast(err.message, 'error');
            }
        });
    }

    function initIntegrations() {
        document.getElementById('integrationsForm')?.addEventListener('submit', async (e) => {
            e.preventDefault();
            const f = e.target;
            const payload = {
                slack: {
                    enabled: f.slack_enabled?.checked || false,
                    webhook_url: f.slack_url?.value || '',
                },
                teams: {
                    enabled: f.teams_enabled?.checked || false,
                    webhook_url: f.teams_url?.value || '',
                },
                jira: {
                    enabled: f.jira_enabled?.checked || false,
                    webhook_url: f.jira_url?.value || '',
                    project_key: f.jira_project?.value || '',
                },
            };
            try {
                await fetchJson('/api/integrations', {
                    method: 'POST',
                    body: JSON.stringify(payload),
                });
                toast('Đã lưu tích hợp', 'success');
            } catch (err) {
                toast(err.message, 'error');
            }
        });
    }

    function parseTrendData(id) {
        const el = document.getElementById(id);
        if (!el) return null;
        try {
            return JSON.parse(el.textContent || '{}');
        } catch {
            return null;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        initWorkspaceUser();
        initQueue();
        initWebhooks();
        initIntegrations();
    });
})();
