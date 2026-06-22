/**
 * ReconSight Premium UX — Interactive Enhancement Layer
 * Additive-only: no existing functionality is modified.
 * Runs on DOMContentLoaded alongside existing scripts.
 */
(function () {
    'use strict';

    /* ────────────────────────────────────────────────────────
       UTILITIES
       ──────────────────────────────────────────────────────── */

    function toast(msg, type) {
        if (typeof window.rsToast === 'function') {
            window.rsToast(msg, type || 'info');
        }
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            return false;
        }
    }

    function createElement(tag, attrs, children) {
        const el = document.createElement(tag);
        if (attrs) {
            Object.entries(attrs).forEach(function (pair) {
                var k = pair[0], v = pair[1];
                if (k === 'className') el.className = v;
                else if (k === 'textContent') el.textContent = v;
                else if (k === 'innerHTML') el.innerHTML = v;
                else if (k.startsWith('on')) el.addEventListener(k.slice(2).toLowerCase(), v);
                else el.setAttribute(k, v);
            });
        }
        if (children) {
            (Array.isArray(children) ? children : [children]).forEach(function (c) {
                if (typeof c === 'string') el.appendChild(document.createTextNode(c));
                else if (c) el.appendChild(c);
            });
        }
        return el;
    }


    /* ────────────────────────────────────────────────────────
       1. BREADCRUMB NAVIGATION
       ──────────────────────────────────────────────────────── */
    function initBreadcrumbs() {
        var header = document.querySelector('.site-header');
        if (!header) return;

        var isResults = document.querySelector('.page-shell--results');
        var crumbs = [];

        crumbs.push({ label: '🏠 Home', href: '/' });

        if (isResults) {
            var hostname = document.querySelector('.results-target h2');
            crumbs.push({ label: '📊 Results', href: '#dashboard' });
            if (hostname) {
                crumbs.push({ label: hostname.textContent.trim(), current: true });
            }
        } else {
            crumbs.push({ label: '🔍 Scan', current: true });
        }

        var nav = createElement('nav', {
            className: 'breadcrumb-nav',
            'aria-label': 'Breadcrumb'
        });

        crumbs.forEach(function (crumb, i) {
            if (i > 0) {
                nav.appendChild(createElement('span', { className: 'bc-sep', 'aria-hidden': 'true', textContent: '›' }));
            }
            if (crumb.current) {
                nav.appendChild(createElement('span', { className: 'bc-current', textContent: crumb.label }));
            } else {
                nav.appendChild(createElement('a', { href: crumb.href, textContent: crumb.label }));
            }
        });

        header.insertAdjacentElement('afterend', nav);
    }


    /* ────────────────────────────────────────────────────────
       2. KEY FINDINGS SUMMARY CARD (Results page only)
       ──────────────────────────────────────────────────────── */
    function initKeyFindings() {
        var summaryBar = document.querySelector('.summary-bar');
        if (!summaryBar) return;

        // Extract data from existing page elements
        var scoreText = '';
        var scoreEl = document.querySelector('.score-ring span');
        if (scoreEl) scoreText = scoreEl.textContent.trim();
        var score = parseInt(scoreText, 10) || 0;

        var riskLevel = 'N/A';
        var riskClass = '';
        var execBadge = document.querySelector('.exec-risk-badge');
        if (execBadge) {
            riskLevel = execBadge.textContent.trim();
            if (execBadge.classList.contains('risk-critical')) riskClass = 'kf-risk-critical';
            else if (execBadge.classList.contains('risk-high')) riskClass = 'kf-risk-high';
            else if (execBadge.classList.contains('risk-medium')) riskClass = 'kf-risk-medium';
            else riskClass = 'kf-risk-low';
        }

        // Count critical issues from severity stats
        var criticalCount = 0;
        var highCount = 0;
        var criticalEl = document.querySelector('.sev-stat-card.sev-critical strong');
        var highEl = document.querySelector('.sev-stat-card.sev-high strong');
        if (criticalEl) criticalCount = parseInt(criticalEl.textContent, 10) || 0;
        if (highEl) highCount = parseInt(highEl.textContent, 10) || 0;

        // TLS score
        var tlsScore = 'N/A';
        if (window.scanMetrics && typeof window.scanMetrics.tls !== 'undefined') {
            var t = window.scanMetrics.tls;
            tlsScore = t >= 90 ? 'A' : t >= 75 ? 'B' : t >= 50 ? 'C' : t >= 25 ? 'D' : 'F';
        }

        // Security headers
        var headersScore = 'N/A';
        if (window.scanMetrics && typeof window.scanMetrics.security !== 'undefined') {
            headersScore = window.scanMetrics.security + '%';
        }

        // Top recommendation
        var topRec = 'No recommendations';
        var remediationDataEl = document.getElementById('remediationData');
        if (remediationDataEl) {
            try {
                var remediationData = JSON.parse(remediationDataEl.textContent || '[]');
                if (Array.isArray(remediationData) && remediationData.length > 0) {
                    var topText = String(remediationData[0].text || '').trim();
                    if (topText) {
                        topRec = topText.substring(0, 60);
                        if (topText.length > 60) topRec += '…';
                    }
                }
            } catch (e) {
                // Ignore malformed JSON and keep default text.
            }
        }

        // Score color class
        var scoreClass = score >= 75 ? 'score-good' : score >= 45 ? 'score-mid' : 'score-low';

        var card = createElement('div', { className: 'key-findings-card', id: 'keyFindings' });

        var items = [
            { icon: '🛡️', value: score + '/100', label: 'Security Score', sublabel: '', valueClass: scoreClass },
            { icon: '⚠️', value: riskLevel, label: 'Risk Level', sublabel: '', valueClass: riskClass },
            { icon: '🔴', value: String(criticalCount + highCount), label: 'Critical Issues', sublabel: criticalCount + ' critical · ' + highCount + ' high', valueClass: (criticalCount + highCount) > 0 ? 'kf-risk-critical' : 'kf-risk-low' },
            { icon: '🔒', value: headersScore, label: 'Security Headers', sublabel: 'Headers coverage', valueClass: '' },
            { icon: '📜', value: tlsScore, label: 'TLS Grade', sublabel: 'Certificate health', valueClass: '' },
            { icon: '💡', value: '→', label: 'Top Recommendation', sublabel: topRec, valueClass: '' }
        ];

        items.forEach(function (item) {
            var kfItem = createElement('div', { className: 'kf-item' }, [
                createElement('span', { className: 'kf-icon', textContent: item.icon }),
                createElement('span', { className: 'kf-value pux-counter ' + (item.valueClass || ''), textContent: item.value }),
                createElement('span', { className: 'kf-label', textContent: item.label }),
            ]);
            if (item.sublabel) {
                kfItem.appendChild(createElement('span', { className: 'kf-sublabel', textContent: item.sublabel, title: item.sublabel }));
            }
            card.appendChild(kfItem);
        });

        summaryBar.insertAdjacentElement('afterend', card);
    }


    /* ────────────────────────────────────────────────────────
       3. SCAN PROGRESS STAGES (Home page)
       ──────────────────────────────────────────────────────── */
    function initScanStages() {
        var progressPanel = document.getElementById('scanProgress');
        if (!progressPanel) return;

        var stages = [
            { icon: '🌐', label: 'DNS Analysis' },
            { icon: '🔒', label: 'Headers Analysis' },
            { icon: '📜', label: 'SSL/TLS Inspection' },
            { icon: '⚙️', label: 'Technology Detection' },
            { icon: '🕵️', label: 'Threat Intelligence' },
            { icon: '📊', label: 'Report Generation' }
        ];

        var container = createElement('div', { className: 'scan-stages', id: 'scanStagesContainer' });

        stages.forEach(function (stage) {
            container.appendChild(createElement('div', {
                className: 'scan-stage',
                'data-stage': stage.label
            }, [
                createElement('div', { className: 'scan-stage-dot', textContent: stage.icon }),
                createElement('span', { className: 'scan-stage-label', textContent: stage.label })
            ]));
        });

        // Insert after progress bar
        var progressBar = progressPanel.querySelector('.progress-bar');
        if (progressBar) {
            progressBar.insertAdjacentElement('afterend', container);
        } else {
            progressPanel.appendChild(container);
        }

        // Observe progress fill to advance stages
        var fill = document.getElementById('progressFill');
        if (fill) {
            var observer = new MutationObserver(function () {
                var width = parseFloat(fill.style.width) || 0;
                var stageEls = container.querySelectorAll('.scan-stage');
                var stageThresholds = [0, 15, 30, 50, 70, 90];

                stageEls.forEach(function (el, i) {
                    el.classList.remove('is-active', 'is-complete');
                    if (width >= stageThresholds[i] && (i === stageEls.length - 1 || width < stageThresholds[i + 1])) {
                        el.classList.add('is-active');
                    } else if (width >= (stageThresholds[i + 1] || 100)) {
                        el.classList.add('is-complete');
                    }
                });
            });

            observer.observe(fill, { attributes: true, attributeFilter: ['style'] });
        }
    }


    /* ────────────────────────────────────────────────────────
       4. QUICK-COPY BUTTONS
       ──────────────────────────────────────────────────────── */
    function initQuickCopy() {
        // Add copy buttons to dork list items
        document.querySelectorAll('.dork-list code').forEach(function (code) {
            var btn = createElement('button', {
                className: 'pux-copy-btn',
                title: 'Copy to clipboard',
                'aria-label': 'Copy',
                textContent: '📋',
                onClick: function () {
                    copyToClipboard(code.textContent).then(function (ok) {
                        if (ok) {
                            btn.textContent = '✓';
                            btn.classList.add('is-copied');
                            toast('Copied to clipboard', 'success');
                            setTimeout(function () {
                                btn.textContent = '📋';
                                btn.classList.remove('is-copied');
                            }, 2000);
                        }
                    });
                }
            });
            var li = code.closest('li');
            if (li) {
                li.style.display = 'flex';
                li.style.alignItems = 'center';
                li.style.justifyContent = 'space-between';
                li.style.gap = '0.5rem';
                var wrapper = createElement('div', { style: 'flex: 1; min-width: 0;' });
                // Move existing children to wrapper
                while (li.firstChild && li.firstChild !== btn) {
                    wrapper.appendChild(li.firstChild);
                }
                li.insertBefore(wrapper, li.firstChild);
                li.appendChild(btn);
            }
        });

        // Add copy buttons to IP, server info
        document.querySelectorAll('.results-target p, .location-meta dd').forEach(function (el) {
            var text = el.textContent.trim();
            // Match IP addresses
            if (/\d+\.\d+\.\d+\.\d+/.test(text)) {
                var ipMatch = text.match(/(\d+\.\d+\.\d+\.\d+)/);
                if (ipMatch) {
                    var btn = createElement('button', {
                        className: 'pux-copy-btn',
                        title: 'Copy IP',
                        'aria-label': 'Copy IP address',
                        textContent: '📋',
                        style: 'margin-left: 0.35rem; vertical-align: middle;',
                        onClick: function () {
                            copyToClipboard(ipMatch[1]).then(function (ok) {
                                if (ok) {
                                    btn.textContent = '✓';
                                    btn.classList.add('is-copied');
                                    setTimeout(function () {
                                        btn.textContent = '📋';
                                        btn.classList.remove('is-copied');
                                    }, 2000);
                                }
                            });
                        }
                    });
                    el.appendChild(btn);
                }
            }
        });
    }


    /* ────────────────────────────────────────────────────────
       5. RECOMMENDATIONS PANEL (Results page)
       ──────────────────────────────────────────────────────── */
    function initRecommendationsPanel() {
        // Gather recommendation items from server-provided JSON payload
        var items = [];
        var remediationDataEl = document.getElementById('remediationData');
        if (remediationDataEl) {
            try {
                var rawItems = JSON.parse(remediationDataEl.textContent || '[]');
                if (Array.isArray(rawItems)) {
                    rawItems.forEach(function (entry) {
                        var text = String((entry && entry.text) || '').trim();
                        if (!text) return;
                        var priority = String((entry && entry.priority) || 'medium').toLowerCase();

                        // Categorize
                        var category = 'security';
                        var textLower = text.toLowerCase();
                        if (/ssl|tls|certif|hsts/i.test(textLower)) category = 'tls';
                        else if (/dns|server|infra|cdn|host|port/i.test(textLower)) category = 'infrastructure';
                        else if (/seo|meta|robot|sitemap|crawl/i.test(textLower)) category = 'seo';
                        else if (/leak|expos|disclos|version|info/i.test(textLower)) category = 'disclosure';

                        items.push({ text: text, priority: priority, category: category });
                    });
                }
            } catch (e) {
                // Ignore malformed JSON and fallback to empty list.
            }
        }

        if (items.length === 0) return;

        // Count by category
        var categories = [
            { id: 'security', label: '🛡️ Security', icon: '🛡️' },
            { id: 'infrastructure', label: '🏗️ Infrastructure', icon: '🏗️' },
            { id: 'tls', label: '🔒 TLS', icon: '🔒' },
            { id: 'seo', label: '📈 SEO', icon: '📈' },
            { id: 'disclosure', label: '🔍 Info Disclosure', icon: '🔍' }
        ];

        var counts = {};
        categories.forEach(function (c) { counts[c.id] = 0; });
        items.forEach(function (item) { counts[item.category] = (counts[item.category] || 0) + 1; });

        // Filter out empty categories
        var activeCats = categories.filter(function (c) { return counts[c.id] > 0; });

        if (activeCats.length === 0) return;

        // Build panel
        var panel = createElement('section', { className: 'pux-recommendations', id: 'puxRecommendations' });

        panel.appendChild(createElement('div', { className: 'pux-rec-header' }, [
            createElement('h2', { textContent: '💡 Recommendations by Category' })
        ]));

        // Tabs
        var tabsRow = createElement('div', { className: 'pux-rec-tabs', role: 'tablist' });

        // All tab
        var allTab = createElement('button', {
            className: 'pux-rec-tab is-active',
            'data-cat': 'all',
            role: 'tab',
            innerHTML: 'All <span class="pux-tab-count">' + items.length + '</span>'
        });
        tabsRow.appendChild(allTab);

        activeCats.forEach(function (cat) {
            var tab = createElement('button', {
                className: 'pux-rec-tab',
                'data-cat': cat.id,
                role: 'tab',
                innerHTML: cat.label + ' <span class="pux-tab-count">' + counts[cat.id] + '</span>'
            });
            tabsRow.appendChild(tab);
        });

        panel.appendChild(tabsRow);

        // Body with list
        var body = createElement('div', { className: 'pux-rec-body' });
        var list = createElement('ul', { className: 'pux-rec-list' });

        items.forEach(function (item) {
            var cat = categories.find(function (c) { return c.id === item.category; }) || categories[0];
            var li = createElement('li', { className: 'pux-rec-item', 'data-rec-cat': item.category }, [
                createElement('span', { className: 'pux-rec-icon', textContent: cat.icon }),
                createElement('div', { className: 'pux-rec-content' }, [
                    createElement('p', { className: 'pux-rec-text', textContent: item.text })
                ])
            ]);
            list.appendChild(li);
        });

        body.appendChild(list);
        panel.appendChild(body);

        // Tab click handler
        tabsRow.addEventListener('click', function (e) {
            var tab = e.target.closest('.pux-rec-tab');
            if (!tab) return;
            var cat = tab.getAttribute('data-cat');

            tabsRow.querySelectorAll('.pux-rec-tab').forEach(function (t) {
                t.classList.toggle('is-active', t === tab);
            });

            list.querySelectorAll('.pux-rec-item').forEach(function (item) {
                if (cat === 'all') {
                    item.style.display = '';
                } else {
                    item.style.display = item.getAttribute('data-rec-cat') === cat ? '' : 'none';
                }
            });
        });

        // Insert after advisory if available, otherwise before dashboard.
        var advisoryPanel = document.querySelector('.advisory-panel');
        var dashboardGrid = document.querySelector('.dashboard-grid');
        if (advisoryPanel) {
            advisoryPanel.insertAdjacentElement('afterend', panel);
        } else if (dashboardGrid) {
            dashboardGrid.insertAdjacentElement('beforebegin', panel);
        } else {
            var summaryBar = document.querySelector('.summary-bar');
            if (summaryBar) summaryBar.insertAdjacentElement('afterend', panel);
        }
    }


    /* ────────────────────────────────────────────────────────
       6. ANIMATED COUNTERS
       ──────────────────────────────────────────────────────── */
    function initAnimatedCounters() {
        var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (reducedMotion) return;

        function animateValue(el, start, end, duration) {
            if (start === end) return;
            var range = end - start;
            var startTime = null;

            function step(timestamp) {
                if (!startTime) startTime = timestamp;
                var progress = Math.min((timestamp - startTime) / duration, 1);
                var eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
                el.textContent = Math.round(start + range * eased);
                if (progress < 1) requestAnimationFrame(step);
            }

            requestAnimationFrame(step);
        }

        // Animate score ring
        var scoreSpan = document.querySelector('.score-ring span');
        if (scoreSpan) {
            var target = parseInt(scoreSpan.textContent, 10);
            if (!isNaN(target) && target > 0) {
                scoreSpan.textContent = '0';
                setTimeout(function () { animateValue(scoreSpan, 0, target, 1200); }, 300);
            }
        }

        // Animate severity stat cards
        document.querySelectorAll('.sev-stat-card strong').forEach(function (el) {
            var val = parseInt(el.textContent, 10);
            if (!isNaN(val) && val > 0) {
                el.textContent = '0';
                setTimeout(function () { animateValue(el, 0, val, 800); }, 500);
            }
        });

        // Animate leakage counts
        document.querySelectorAll('.leakage-count, .enum-count').forEach(function (el) {
            var val = parseInt(el.textContent, 10);
            if (!isNaN(val) && val > 0) {
                el.textContent = '0';
                setTimeout(function () { animateValue(el, 0, val, 900); }, 400);
            }
        });
    }


    /* ────────────────────────────────────────────────────────
       7. SCROLL-BASED ENTRANCE ANIMATIONS
       ──────────────────────────────────────────────────────── */
    function initScrollAnimations() {
        var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        if (reducedMotion) return;

        var targets = document.querySelectorAll(
            '.wc-card, .check-card, .section-card, .hub-card, .key-findings-card, .pux-recommendations, ' +
            '.leakage-panel, .recon-panel, .enum-panel, .entry-panel, .flow-panel, .arch-panel, .fwk-panel, ' +
            '.risk-panel, .executive-panel, .remediation-panel, .advisory-panel, .location-panel'
        );

        if (!targets.length) return;

        // Set initial hidden state
        targets.forEach(function (el) {
            el.style.opacity = '0';
            el.style.transform = 'translateY(16px)';
        });

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    var el = entry.target;
                    var delay = Math.min(Array.prototype.indexOf.call(targets, el) * 30, 300);
                    setTimeout(function () {
                        el.style.transition = 'opacity 0.5s ease-out, transform 0.5s ease-out';
                        el.style.opacity = '1';
                        el.style.transform = 'translateY(0)';
                    }, delay);
                    observer.unobserve(el);
                }
            });
        }, { threshold: 0.05, rootMargin: '0px 0px -40px 0px' });

        targets.forEach(function (el) { observer.observe(el); });
    }


    /* ────────────────────────────────────────────────────────
       8. EMPTY STATE ENHANCEMENTS
       ──────────────────────────────────────────────────────── */
    function initEmptyStates() {
        // Enhance scan history empty state
        var historyEmpty = document.querySelector('.history-empty-msg');
        if (historyEmpty) {
            var parent = historyEmpty.parentElement;
            var emptyState = createElement('div', { className: 'pux-empty-state' }, [
                createElement('span', { className: 'pux-empty-icon', textContent: '📋' }),
                createElement('p', { className: 'pux-empty-title', textContent: 'No scan history yet' }),
                createElement('p', { className: 'pux-empty-desc', textContent: 'Run your first security scan to see results appear here. Your scan history helps track security improvements over time.' }),
                createElement('a', { className: 'pux-empty-action', href: '/', textContent: '🔍 Start scanning' })
            ]);
            historyEmpty.replaceWith(emptyState);
        }

        // Enhance queue empty state
        document.querySelectorAll('.hub-empty').forEach(function (el) {
            var text = el.textContent.trim();
            var icon = '📭';
            var desc = 'Nothing here yet.';

            if (/hàng đợi|queue/i.test(text)) {
                icon = '📋';
                desc = 'Add URLs to the scan queue for batch processing.';
            } else if (/audit/i.test(text)) {
                icon = '📝';
                desc = 'Audit events will appear here as you use the platform.';
            }

            var empty = createElement('div', { className: 'pux-empty-state', style: 'padding: 1.25rem;' }, [
                createElement('span', { className: 'pux-empty-icon', textContent: icon, style: 'font-size: 1.75rem;' }),
                createElement('p', { className: 'pux-empty-desc', textContent: desc, style: 'font-size: 0.78rem;' })
            ]);

            el.replaceWith(empty);
        });
    }


    /* ────────────────────────────────────────────────────────
       9. DATA FRESHNESS INDICATOR
       ──────────────────────────────────────────────────────── */
    function initDataFreshness() {
        var resultsHeader = document.querySelector('.results-header');
        if (!resultsHeader) return;

        var target = resultsHeader.querySelector('.results-target p');
        if (!target) return;

        var meta = createElement('div', { className: 'pux-scan-meta' }, [
            createElement('span', { className: 'pux-freshness-dot', innerHTML: '<strong>Live scan results</strong>' }),
            createElement('span', { textContent: '· Scanned just now' }),
            createElement('span', { textContent: '· Data is current' })
        ]);

        resultsHeader.insertAdjacentElement('afterend', meta);
    }


    /* ────────────────────────────────────────────────────────
       10. ACTIVE NAV TRACKING (IntersectionObserver)
       ──────────────────────────────────────────────────────── */
    function initActiveNavTracking() {
        var navLinks = document.querySelectorAll('.site-nav a[href^="#"]');
        if (!navLinks.length) return;

        var sections = [];
        navLinks.forEach(function (link) {
            var href = link.getAttribute('href');
            if (!href || href === '#') return;
            var section = document.querySelector(href);
            if (section) {
                sections.push({ link: link, section: section });
            }
        });

        if (!sections.length) return;

        var observer = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                var match = sections.find(function (s) { return s.section === entry.target; });
                if (match) {
                    match.link.classList.toggle('is-active', entry.isIntersecting);
                }
            });
        }, { threshold: 0.3, rootMargin: '-80px 0px -30% 0px' });

        sections.forEach(function (s) { observer.observe(s.section); });
    }


    /* ────────────────────────────────────────────────────────
       11. TOOLTIPS FOR SECURITY CONCEPTS
       ──────────────────────────────────────────────────────── */
    function initTooltips() {
        var tooltipData = {
            'Security Score': 'A weighted composite score (0–100) reflecting overall security posture based on headers, TLS, and configuration checks.',
            'TLS/SSL': 'Transport Layer Security ensures encrypted communication. A poor TLS grade may indicate outdated protocols or weak ciphers.',
            'WAF': 'Web Application Firewall — a security layer that monitors and filters HTTP traffic to protect against common attacks.',
            'CDN': 'Content Delivery Network — a distributed network of servers that speeds up content delivery and provides DDoS protection.',
            'HSTS': 'HTTP Strict Transport Security — a header that forces browsers to only connect via HTTPS, preventing protocol downgrade attacks.',
            'CSP': 'Content Security Policy — a header that prevents cross-site scripting (XSS) by controlling which resources the browser can load.',
            'CORS': 'Cross-Origin Resource Sharing — controls which domains can access resources, preventing unauthorized data access.',
            'X-Frame-Options': 'Prevents your site from being loaded in iframes on other domains, protecting against clickjacking attacks.'
        };

        // Find text nodes matching tooltip keys and add tooltip attributes
        document.querySelectorAll('.check-title, .section-card summary h3, .chart-card-title').forEach(function (el) {
            var text = el.textContent.trim();
            Object.keys(tooltipData).forEach(function (key) {
                if (text.indexOf(key) !== -1 || text.toLowerCase().indexOf(key.toLowerCase()) !== -1) {
                    el.classList.add('pux-tooltip');
                    el.setAttribute('data-tooltip', tooltipData[key]);
                }
            });
        });
    }


    /* ────────────────────────────────────────────────────────
       12. SKIP-TO-CONTENT LINK (Accessibility)
       ──────────────────────────────────────────────────────── */
    function initSkipLink() {
        var mainTarget = document.querySelector('#dashboard') ||
                         document.querySelector('#scan') ||
                         document.querySelector('.dashboard-main') ||
                         document.querySelector('main');
        if (!mainTarget) return;

        if (!mainTarget.id) mainTarget.id = 'main-content';

        var link = createElement('a', {
            className: 'pux-skip-link',
            href: '#' + mainTarget.id,
            textContent: 'Skip to main content'
        });

        document.body.insertBefore(link, document.body.firstChild);
    }


    /* ────────────────────────────────────────────────────────
       13. ENHANCED SCAN PROGRESS (Home page)
       Enhance the existing progress panel with better UX
       ──────────────────────────────────────────────────────── */
    function initEnhancedProgress() {
        var form = document.getElementById('scanForm');
        var progressPanel = document.getElementById('scanProgress');
        if (!form || !progressPanel) return;

        var progressLabel = progressPanel.querySelector('.progress-label');
        if (!progressLabel) return;

        // Override progress label with more descriptive text
        var stages = [
            'Initializing scan engine…',
            'Resolving DNS records…',
            'Analyzing security headers…',
            'Inspecting SSL/TLS certificates…',
            'Detecting technologies…',
            'Gathering threat intelligence…',
            'Generating security report…'
        ];

        // Listen for progress changes to update label
        var fill = document.getElementById('progressFill');
        if (!fill) return;

        var lastStage = -1;

        var observer = new MutationObserver(function () {
            var width = parseFloat(fill.style.width) || 0;
            var stageIdx = Math.min(Math.floor(width / (100 / stages.length)), stages.length - 1);

            if (stageIdx !== lastStage) {
                lastStage = stageIdx;
                progressLabel.textContent = stages[stageIdx];
                progressLabel.style.transition = 'opacity 0.3s';
                progressLabel.style.opacity = '0.5';
                setTimeout(function () { progressLabel.style.opacity = '1'; }, 100);
            }
        });

        observer.observe(fill, { attributes: true, attributeFilter: ['style'] });
    }


    /* ────────────────────────────────────────────────────────
       INITIALIZATION
       ──────────────────────────────────────────────────────── */
    document.addEventListener('DOMContentLoaded', function () {
        // Both pages
        initBreadcrumbs();
        initActiveNavTracking();
        initSkipLink();
        initEmptyStates();
        initTooltips();

        // Home page
        initScanStages();
        initEnhancedProgress();

        // Results page
        initKeyFindings();
        initRecommendationsPanel();
        initQuickCopy();
        initDataFreshness();

        // Animations (both pages)
        initAnimatedCounters();

        // Delay scroll animations slightly for initial paint
        setTimeout(initScrollAnimations, 100);
    });

})();
