(function () {
    const docs = window.FEATURE_DOCS || {};

    function resolveDoc(id) {
        if (!id) return docs.default || {};
        return docs[id] || docs[`api:${id}`] || docs.default || {};
    }

    function openModal(docId) {
        const doc = resolveDoc(docId);
        const modal = document.getElementById('featureDocModal');
        const backdrop = document.getElementById('featureDocBackdrop');
        if (!modal) return;

        const set = (id, text) => {
            const el = document.getElementById(id);
            if (el) el.textContent = text || '';
        };
        const setList = (id, items) => {
            const el = document.getElementById(id);
            if (!el) return;
            el.innerHTML = '';
            if (!Array.isArray(items) || !items.length) {
                const li = document.createElement('li');
                li.textContent = 'Chưa có dữ liệu.';
                el.appendChild(li);
                return;
            }
            items.forEach((t) => {
                const li = document.createElement('li');
                li.textContent = t;
                el.appendChild(li);
            });
        };

        set('featureDocTitle', doc.title);
        set('featureDocSummary', doc.summary);
        set('featureDocAbout', doc.about);
        set('featureDocUseCases', doc.use_cases);
        set('featureDocImpact', doc.security_impact);
        set('featureDocRisk', doc.risk_explanation);
        set('featureDocSeverityContext', doc.severity_risk_context);

        setList('featureDocBusinessBenefits', doc.business_benefits);
        setList('featureDocTechnicalBenefits', doc.technical_benefits);
        setList('featureDocRemediationGuidance', doc.remediation_guidance);
        setList('featureDocBestPractices', doc.best_practices);
        setList('featureDocCommonMisconfigurations', doc.common_misconfigurations);
        setList('featureDocRecommendedActions', doc.recommended_actions);

        const img = document.getElementById('featureDocImage');
        if (img) {
            img.src = doc.image_url || doc.image || '/static/doc-illustrations/default.svg';
            img.alt = doc.image_alt || doc.title || '';
        }

        const linksEl = document.getElementById('featureDocLinks');
        const linksSec = document.getElementById('featureDocLinksSection');
        if (linksEl) {
            linksEl.innerHTML = '';
            const links = doc.links || [];
            if (linksSec) linksSec.classList.toggle('hidden', links.length === 0);
            links.forEach((l) => {
                const li = document.createElement('li');
                const a = document.createElement('a');
                a.href = l.url;
                a.textContent = l.label || l.url;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                li.appendChild(a);
                linksEl.appendChild(li);
            });
        }

        backdrop?.classList.remove('hidden');
        modal.classList.remove('hidden');
        modal.classList.add('is-open');
        document.body.classList.add('modal-open');
    }

    function closeModal() {
        document.getElementById('featureDocModal')?.classList.add('hidden');
        document.getElementById('featureDocModal')?.classList.remove('is-open');
        document.getElementById('featureDocBackdrop')?.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.addEventListener('click', (e) => {
            const btn = e.target.closest('.info-help-btn');
            if (!btn) return;
            e.preventDefault();
            e.stopPropagation();
            openModal(btn.getAttribute('data-doc-id'));
        });
        ['featureDocCloseBtn', 'featureDocDismissBtn'].forEach((id) => {
            document.getElementById(id)?.addEventListener('click', closeModal);
        });
        document.getElementById('featureDocBackdrop')?.addEventListener('click', closeModal);
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });
    });
    window.openFeatureDoc = openModal;
})();
