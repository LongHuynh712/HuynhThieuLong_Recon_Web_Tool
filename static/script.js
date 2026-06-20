document.addEventListener('DOMContentLoaded', () => {
    const urlInput = document.getElementById('url');
    const scanForm = document.getElementById('scanForm');
    const modulesGrid = document.getElementById('scanOptions');
    const modulesCount = document.getElementById('modulesCount');
    const selectAllBtn = document.getElementById('selectAllModules');
    const clearAllBtn = document.getElementById('clearAllModules');

    if (urlInput && !urlInput.value) {
        urlInput.focus();
    }

    const clearHistoryForm = document.getElementById('clearHistoryForm');
    if (clearHistoryForm) {
        clearHistoryForm.addEventListener('submit', (e) => {
            if (!window.confirm('Xóa toàn bộ lịch sử quét?')) e.preventDefault();
        });
    }

    document.querySelectorAll('.url-chip').forEach((chip) => {
        chip.addEventListener('click', () => {
            if (!urlInput) return;
            urlInput.value = chip.dataset.url || chip.textContent.trim();
            urlInput.focus();
        });
    });

    /** Đồng bộ checkbox → shell, card, toggle switch, counter */
    function syncModulesUI() {
        if (!modulesGrid) return;
        const inputs = modulesGrid.querySelectorAll('.module-input');
        let checked = 0;
        inputs.forEach((input) => {
            const isOn = input.checked;
            const shell = input.closest('.module-card-shell');
            const card = input.closest('.module-card');
            const toggle = card?.querySelector('.module-switch');

            if (shell) shell.classList.toggle('is-active', isOn);
            if (card) card.classList.toggle('is-active', isOn);
            if (toggle) toggle.setAttribute('aria-checked', isOn ? 'true' : 'false');
            if (isOn) checked += 1;
        });
        if (modulesCount) {
            modulesCount.textContent = `${checked}/${inputs.length}`;
        }
    }

    function setAllModulesChecked(checked) {
        if (!modulesGrid) return;
        modulesGrid.querySelectorAll('.module-input').forEach((input) => {
            input.checked = checked;
        });
        syncModulesUI();
    }

    function setModulesByValues(allowedValues) {
        if (!modulesGrid) return;
        const allowAll = allowedValues === null;
        const allowed = allowAll ? null : new Set(allowedValues);
        modulesGrid.querySelectorAll('.module-input').forEach((input) => {
            input.checked = allowAll || allowed.has(input.value);
        });
        syncModulesUI();
    }

    window.syncModulesUI = syncModulesUI;
    window.setAllModulesChecked = setAllModulesChecked;
    window.setModulesByValues = setModulesByValues;

    if (modulesGrid) {
        modulesGrid.addEventListener('change', (event) => {
            if (event.target.classList.contains('module-input')) {
                syncModulesUI();
            }
        });
        modulesGrid.addEventListener('input', (event) => {
            if (event.target.classList.contains('module-input')) {
                syncModulesUI();
            }
        });
    }

    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', (event) => {
            event.preventDefault();
            setAllModulesChecked(true);
            document.querySelectorAll('.preset-chip').forEach((chip) => {
                chip.classList.toggle('is-active', chip.dataset.preset === 'full');
            });
        });
    }

    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', (event) => {
            event.preventDefault();
            setAllModulesChecked(false);
            document.querySelectorAll('.preset-chip').forEach((chip) => {
                chip.classList.remove('is-active');
            });
        });
    }

    syncModulesUI();

    document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
        anchor.addEventListener('click', (event) => {
            const href = anchor.getAttribute('href');
            if (!href || href === '#') return;
            const target = document.querySelector(href);
            if (!target) return;
            event.preventDefault();
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            if (target.tagName === 'DETAILS') {
                target.open = true;
            }
        });
    });

    if (window.location.hash.startsWith('#')) {
        const target = document.querySelector(window.location.hash);
        if (target && target.tagName === 'DETAILS') {
            target.open = true;
        }
    }

    /* Collapsible long pre blocks (report sections) */
    function initCollapsibles() {
        document.querySelectorAll('.collapsible').forEach((wrap) => {
            const pre = wrap.querySelector('.section-body');
            const btn = wrap.querySelector('.collapse-toggle');
            if (!pre || !btn) return;
            // If content fits, hide the button
            requestAnimationFrame(() => {
                if (pre.scrollHeight <= pre.clientHeight + 4) {
                    btn.style.display = 'none';
                } else {
                    btn.style.display = 'inline-block';
                }
            });
            btn.addEventListener('click', () => {
                const expanded = pre.classList.toggle('expanded');
                btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
                btn.textContent = expanded ? 'Show less' : 'Show more';
            });
        });
    }

    initCollapsibles();

});
