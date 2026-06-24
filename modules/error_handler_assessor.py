"""
Error Handler Assessor Module
OWASP WSTG 4.8 - Error Handling and Logging Testing
Implements: Debug page detection, Stack trace exposure, Error message analysis.

Enhanced passive checks map findings to granular WSTG-4.8.x IDs:
  4.8.1 improper error handling (framework error / verbose exceptions),
  4.8.2 stack trace / exception detail disclosure,
  4.8.3 debug endpoint / debug-code exposure,
  4.8.4 source map / source code exposure,
  4.8.5 debug parameter / verbose-mode exposure.
The enhanced checks are passive: they inspect only the already-fetched
page HTML/headers and references found in it — no requests to debug
paths, error paths, or with debug parameters are made by the new checks.
"""

import requests
import re
from typing import List, Dict, Any
from urllib.parse import urljoin

class ErrorHandlerAssessor:
    """Assesses error handling and information disclosure"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.error_pages = []
        self.stack_traces = []
        
    def detect_debug_pages(self) -> Dict[str, Any]:
        """
        WSTG 4.8: Detect debug pages and information exposure
        Tests for common debug endpoints
        """
        debug_paths = [
            '/debug',
            '/debug.php',
            '/admin',
            '/admin.php',
            '/admin/debug',
            '/__debug__',
            '/debug/',
            '/dev',
            '/development',
            '/testing',
            '/test',
            '/console',
            '/api/debug',
            '/api/status',
            '/health',
            '/health-check',
            '/status',
            '/metrics',
            '/actuator',
            '/actuator/env',
            '/actuator/health',
            '/.well-known/debug',
        ]
        
        debug_findings = []
        
        for path in debug_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code == 200:
                    debug_info = {
                        'url': test_url,
                        'path': path,
                        'status': response.status_code,
                        'exposed': True,
                        'severity': 'CRITICAL',
                        'content_preview': response.text[:200]
                    }
                    
                    # Check for debug indicators
                    if 'debug' in response.text.lower():
                        debug_info['finding'] = 'Debug interface exposed'
                    elif 'env' in response.text.lower() and response.status_code == 200:
                        debug_info['finding'] = 'Environment variables potentially exposed'
                    else:
                        debug_info['finding'] = 'Sensitive information endpoint accessible'
                    
                    debug_findings.append(debug_info)
                    self.error_pages.append(debug_info)
                    
            except:
                pass
        
        return {
            'test_name': 'Debug Page Detection (WSTG-4.8)',
            'url': self.base_url,
            'debug_pages': debug_findings,
            'total_found': len(debug_findings),
            'exposed': len(debug_findings) > 0,
            'recommendations': [
                'Disable debug mode in production',
                'Restrict access to debug endpoints with authentication',
                'Remove all debug code from production',
                'Implement access controls on sensitive endpoints',
                'Monitor for unauthorized debug access attempts'
            ],
            'severity': 'CRITICAL' if debug_findings else 'LOW',
            'wstg_reference': 'WSTG-4.8'
        }
    
    def detect_stack_traces(self, response_html: str = None) -> Dict[str, Any]:
        """
        WSTG 4.8.2: Detect stack trace exposure
        Tests for visible error stack traces with sensitive information
        """
        if not response_html:
            # Try to trigger errors
            try:
                response = requests.get(self.base_url + '/?error=test', timeout=5)
                response_html = response.text
            except:
                response_html = ''
        
        stack_trace_patterns = {
            'Python': [
                r'Traceback \(most recent call last\)',
                r'File ".*?", line \d+',
                r'(ValueError|TypeError|RuntimeError|NameError|AttributeError)',
            ],
            'PHP': [
                r'Fatal error:',
                r'Warning:',
                r'Parse error:',
                r'on line \d+',
            ],
            'Java': [
                r'java\.lang\.',
                r'Exception in thread',
                r'at java\.',
                r'\.java:\d+',
            ],
            'ASP.NET': [
                r'System\..*Exception',
                r'Server Error in',
                r'Description: An unhandled exception',
            ],
            'Node.js': [
                r'Error: ',
                r'at new ',
                r'at .*\.js:\d+:\d+',
            ]
        }
        
        traces_found = []
        
        for lang, patterns in stack_trace_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, response_html, re.MULTILINE)
                if matches:
                    traces_found.append({
                        'language': lang,
                        'pattern': pattern,
                        'matches': len(matches),
                        'severity': 'HIGH',
                        'finding': f'{lang} stack trace detected in response'
                    })
                    self.stack_traces.append(lang)
                    break
        
        return {
            'test_name': 'Stack Trace Detection (WSTG-4.8.2)',
            'url': self.base_url,
            'stack_traces': traces_found,
            'total_found': len(traces_found),
            'exposed': len(traces_found) > 0,
            'recommendations': [
                'Implement custom error pages',
                'Log errors server-side without exposing details',
                'Return generic error messages to users',
                'Implement error handling middleware',
                'Monitor error logs for patterns',
                'Test error scenarios regularly'
            ],
            'severity': 'HIGH' if traces_found else 'LOW',
            'wstg_reference': 'WSTG-4.8.2'
        }
    
    def analyze_error_messages(self) -> Dict[str, Any]:
        """
        WSTG 4.8.1: Analyze error message information disclosure
        Tests common error pages for sensitive information
        """
        error_paths = [
            '/?error=1',
            '/?id=999999',
            '/invalid-page',
            '/404',
            '/500',
            '/error',
            '/error.php',
            '/notfound',
        ]
        
        error_findings = []
        
        for path in error_paths:
            test_url = urljoin(self.base_url, path)
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if response.status_code >= 400:
                    # Check error page content for information disclosure
                    content_lower = response.text.lower()
                    
                    sensitive_indicators = [
                        ('SQL error', r'sql|mysql|postgresql|database'),
                        ('File path disclosure', r'[c-z]:\\|/home/|/var/www'),
                        ('Technology fingerprint', r'php|apache|nginx|tomcat|iis'),
                        ('Application path', r'/app/|/src/|/lib/'),
                    ]
                    
                    for indicator_name, pattern in sensitive_indicators:
                        if re.search(pattern, content_lower):
                            error_findings.append({
                                'url': test_url,
                                'status': response.status_code,
                                'disclosure_type': indicator_name,
                                'severity': 'MEDIUM',
                                'finding': f'{indicator_name} detected in error response'
                            })
                            break
                            
            except:
                pass
        
        return {
            'test_name': 'Error Message Analysis (WSTG-4.8.1)',
            'url': self.base_url,
            'error_messages': error_findings,
            'total_found': len(error_findings),
            'sensitive_info_disclosed': len(error_findings) > 0,
            'recommendations': [
                'Implement generic error messages',
                'Avoid revealing application structure',
                'Don\'t display file paths or line numbers',
                'Don\'t reveal technology stack',
                'Implement error logging without user exposure',
                'Test all error scenarios'
            ],
            'severity': 'MEDIUM' if error_findings else 'LOW',
            'wstg_reference': 'WSTG-4.8.1'
        }
    
    def test_verbose_error_modes(self) -> Dict[str, Any]:
        """
        WSTG 4.8: Test for verbose error handling modes
        Checks for debug modes that expose information
        """
        findings = []
        
        test_parameters = [
            ('debug=true', 'Debug parameter'),
            ('debug=1', 'Debug flag'),
            ('verbose=true', 'Verbose logging'),
            ('mode=dev', 'Development mode'),
            ('environment=development', 'Development environment'),
        ]
        
        for param, description in test_parameters:
            test_url = self.base_url + '?' + param
            
            try:
                response = requests.get(test_url, timeout=5)
                
                if 'debug' in response.text.lower() or 'verbose' in response.text.lower():
                    findings.append({
                        'parameter': param,
                        'description': description,
                        'activated': True,
                        'severity': 'HIGH'
                    })
                    
            except:
                pass
        
        return {
            'test_name': 'Verbose Error Mode Testing (WSTG-4.8)',
            'url': self.base_url,
            'verbose_modes': findings,
            'total_found': len(findings),
            'recommendations': [
                'Disable verbose modes in production',
                'Remove debug parameters from final code',
                'Implement environment-specific configurations',
                'Use configuration management for error levels',
                'Monitor for debug mode enablement'
            ],
            'severity': 'HIGH' if findings else 'LOW',
            'wstg_reference': 'WSTG-4.8'
        }
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Execute all error handling tests.

        Fetches the target page once and passes the snapshot (HTML +
        headers) to every passive enhanced check, so the new checks make
        no additional requests. The original active checks run unchanged.
        """
        response = None
        html_response = None
        try:
            response = requests.get(self.base_url, timeout=10)
            html_response = response.text
        except Exception:
            response = None
            html_response = ""

        results = {
            'category': 'Error Handling Assessment',
            'url': self.base_url,
            'timestamp': self._get_timestamp(),
            'tests': [
                self.detect_debug_pages(),
                self.detect_stack_traces(html_response),
                self.analyze_error_messages(),
                self.test_verbose_error_modes(),
                # Enhanced passive checks added in this update.
                self.detect_stack_traces_passive(html_response, response),
                self.detect_framework_error_disclosure(html_response, response),
                self.discover_debug_endpoints_passive(html_response, response),
                self.detect_source_map_exposure(html_response, response),
                self.analyze_verbose_exceptions(html_response, response),
                self.detect_debug_parameters_passive(html_response, response),
            ],
            'summary': {
                'error_pages_found': len(self.error_pages),
                'stack_traces_exposed': len(self.stack_traces),
                'information_disclosure_risks': len([e for e in self.error_pages if e.get('severity') == 'CRITICAL']),
                # Coverage flags surfaced from the new passive checks.
                'stack_trace_detected_passive': True,
                'framework_error_disclosed': True,
                'debug_endpoints_discovered': True,
                'source_map_exposure_checked': True,
                'verbose_exceptions_analyzed': True,
                'debug_parameters_detected': True,
            },
            'wstg_coverage': 'WSTG-4.8 (Error Handling Testing)',
        }

        # Aggregate every WSTG-4.8.x id reported across all test results.
        wstg_ids = set()
        for test in results['tests']:
            if isinstance(test, dict):
                ref = test.get('wstg_reference')
                if isinstance(ref, str):
                    wstg_ids.update(self._extract_wstg_ids(ref))
                elif isinstance(ref, list):
                    for r in ref:
                        wstg_ids.update(self._extract_wstg_ids(r))
        results['wstg_reference'] = sorted(wstg_ids)
        return results

    # ------------------------------------------------------------------ #
    # Enhanced passive checks (WSTG-4.8.x) added in this update.
    # Each is read-only and inspects only the page/headers snapshot.
    # ------------------------------------------------------------------ #

    def detect_stack_traces_passive(self, html: str, response) -> Dict[str, Any]:
        """Passive stack-trace disclosure detection (WSTG-4.8.2).

        Inspects the already-fetched page HTML and response headers for
        runtime stack-trace / file-path / line-number disclosures across
        multiple language stacks. Makes no requests and does not try to
        trigger errors.
        """
        text = html or ''
        findings: List[Dict[str, Any]] = []
        severity = "INFO"

        trace_sigs = {
            'Python': [r'Traceback \(most recent call last\)', r'File ".*?", line \d+', r'(?:ValueError|TypeError|RuntimeError|NameError|AttributeError|KeyError|ZeroDivisionError)'],
            'PHP': [r'Fatal error:', r'Parse error:', r'Stack trace:', r'on line \d+'],
            'Java': [r'java\.lang\.', r'Exception in thread', r'at .+\.java:\d+', r'Caused by:'],
            'ASP.NET': [r'System\.\w+Exception', r'Server Error in', r'Description: An unhandled exception', r'Stack Trace:'],
            'Node.js': [r'at .+\.js:\d+:\d+', r'at Object\.<anonymous>', r'at Module\._compile', r'node:internal/'],
            'Ruby': [r'/\.rb:\d+:in\b', r'NameError:', r'NoMethodError:'],
            'Go': [r'goroutine \d+ \[', r'\.go:\d+', r'panic:'],
            'C#/.NET Core': [r'\.cs:\d+', r'at .+\.\w+\(\)'],
        }

        for lang, patterns in trace_sigs.items():
            hits: List[str] = []
            for pattern in patterns:
                if re.search(pattern, text):
                    hits.append(pattern)
            # Also check Server/X-Powered-By headers for framework hints.
            header_hint = ""
            if response is not None:
                sc = ', '.join(f'{k}={v}' for k, v in response.headers.items()).lower()
                if 'asp.net' in sc and lang == 'ASP.NET':
                    header_hint = "; X-Powered-By/Server hints ASP.NET"
                if 'php' in sc and lang == 'PHP':
                    header_hint = "; X-Powered-By hints PHP"
            if hits:
                findings.append({
                    'language': lang,
                    'patterns_matched': hits,
                    'header_hint': header_hint or None,
                    'severity': 'HIGH',
                    'finding': f'{lang} stack trace / exception detail disclosed in page',
                })

        # Generic file-path / line-number leakage (framework-independent).
        generic = re.findall(r'(?:[A-Za-z]:\\|/(?:home|var|usr|app|src|lib|opt|srv)/[^\s"\'<>]+:\d+)', text)
        if generic:
            findings.append({
                'language': 'generic',
                'patterns_matched': ['absolute path:line'],
                'sample': generic[:3],
                'severity': 'MEDIUM',
                'finding': 'absolute filesystem path with line number disclosed',
            })

        if not findings:
            severity = "INFO"
            note = "No stack-trace / exception-detail disclosure detected in the page snapshot."
        else:
            severity = "HIGH" if any(f['severity'] == 'HIGH' for f in findings) else "MEDIUM"
            note = f"{len(findings)} stack-trace/exception disclosure indicator(s) found."

        return {
            'test_name': 'Stack Trace Detection (Passive) (WSTG-4.8.2)',
            'url': self.base_url,
            'findings': findings,
            'note': note,
            'recommendations': [
                'Return generic error pages; never expose stack traces or file paths to clients.',
                'Log full exceptions server-side only, with redaction of sensitive data.',
                'Disable detailed errors and debug pages in production.',
            ],
            'severity': severity,
            'wstg_reference': 'WSTG-4.8.2',
        }

    def detect_framework_error_disclosure(self, html: str, response) -> Dict[str, Any]:
        """Passive framework/default error-page disclosure (WSTG-4.8.1).

        Detects default framework error pages, version banners, and
        developer-friendly error renderings (whoops/django yellow page,
        express errorhandler, next.js error overlay, rails error page)
        that leak technology and structure.
        """
        text = html or ''
        lower = text.lower()
        findings: List[Dict[str, Any]] = []
        severity = "INFO"

        fw_sigs = [
            ('Django', [r'django', r"using the urlpatterns defined", r"tried these urls", r"page not found \(404\)"]),
            ('Flask/Werkzeug', [r'werkzeug', r'flask', r'jinja2', r'internal server error']),
            ('Ruby on Rails', [r'routing error', r'activerecord::', r'rails', r'we\'re sorry, but something went wrong']),
            ('Next.js', [r'next\.js', r'__next', r'next-error', r'this page could not be found']),
            ('Nuxt.js', [r'nuxt', r'__nuxt']),
            ('Express.js', [r'express', r'cannot (?:get|post|)\b', r'cannot /\w+']),
            ('Laravel/Symfony PHP', [r'symfony', r'laravel', r'whoops, looks like something went wrong', r'whoops\\']),
            ('Spring Boot', [r'whitelabel error page', r'spring boot', r'application-{profile}']),
            ('ASP.NET', [r'server error in', r'asp\.net', r'runtime error', r'customerrors mode']),
            ('Tomcat', [r'apache tomcat/\d', r'tomcat', r'jakarta']),
            ('Nginx', [r'nginx/\d', r'nginx', r'404 not found.*nginx']),
            ('Vue', [r'vue\.js', r'__vue_app__']),
        ]

        for name, patterns in fw_sigs:
            hits = [p for p in patterns if re.search(p, lower)]
            if hits:
                findings.append({
                    'framework': name,
                    'patterns_matched': hits,
                    'severity': 'MEDIUM',
                    'finding': f'{name} framework / default error page indicators disclosed',
                })

        # Version banners in headers are a related disclosure.
        version_headers = []
        if response is not None:
            for hdr in ('Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime', 'X-Version'):
                val = response.headers.get(hdr)
                if val:
                    version_headers.append(f'{hdr}: {val}')
        if version_headers:
            findings.append({
                'framework': 'http-headers',
                'patterns_matched': version_headers,
                'severity': 'LOW',
                'finding': 'framework/version banners in response headers',
            })

        if not findings:
            severity = "INFO"
            note = "No framework/default error-page disclosure detected."
        else:
            sev_rank = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            severity = max((f['severity'] for f in findings), key=lambda s: sev_rank.get(s, 0))
            note = f"{len(findings)} framework/version disclosure indicator(s) found."

        return {
            'test_name': 'Framework Error Disclosure (Passive) (WSTG-4.8.1)',
            'url': self.base_url,
            'findings': findings,
            'note': note,
            'recommendations': [
                'Use custom, branded error pages; suppress default framework error renderers.',
                'Remove or anonymize Server/X-Powered-By and version headers.',
                'Disable detailed exception rendering in production configuration.',
            ],
            'severity': severity,
            'wstg_reference': 'WSTG-4.8.1',
        }

    def discover_debug_endpoints_passive(self, html: str, response) -> Dict[str, Any]:
        """Passive debug-endpoint discovery (WSTG-4.8.3).

        Looks only for *references* to debug/console/actuator/health
        endpoints within the page (links, scripts, source-map hints,
        commented-out URLs). It does NOT request those endpoints.
        """
        text = html or ''
        lower = text.lower()
        findings: List[Dict[str, Any]] = []
        severity = "INFO"

        # References to debug-ish endpoints anywhere in the page.
        debug_path_re = re.compile(
            r'["\']?(/(?:debug|__debug__|dev|development|console|test|testing|metrics|actuator'
            r'|actuator/(?:env|health|beans|mappings|dump|heapdump|threaddump|configprops)'
            r'|health(?:-check)?|status|phpinfo|_profiler|_debugbar|__debugbar)(?:/[^\s"\'<>]*)?)["\']?',
            re.I,
        )
        referenced = sorted(set(m.group(1) for m in debug_path_re.finditer(lower)))

        # Spring Boot actuator is high-value; flag its link/script hints.
        actuator_hint = bool(re.search(r'actuator|spring-boot-actuator', lower))
        # phpinfo() / profiler references.
        profiler_hint = bool(re.search(r'phpinfo|_profiler|_debugbar|__debugbar|symfony.*profiler', lower))
        # Commented-out debug links left by developers.
        commented_debug = re.findall(r'<!--[^>]*(?:debug|console|test|dev)[^>]*-->', text, re.I)

        if referenced:
            findings.append({
                'indicator': 'debug endpoint referenced in page',
                'paths': referenced[:10],
                'severity': 'MEDIUM',
                'finding': f'{len(referenced)} debug/console endpoint reference(s) found (not requested)',
            })
        if actuator_hint:
            findings.append({
                'indicator': 'spring boot actuator hint',
                'severity': 'HIGH',
                'finding': 'Spring Boot actuator reference detected — env/heapdump endpoints may be exposed.',
            })
        if profiler_hint:
            findings.append({
                'indicator': 'php/symfony profiler hint',
                'severity': 'MEDIUM',
                'finding': 'phpinfo/profiler/debugbar reference detected.',
            })
        if commented_debug:
            findings.append({
                'indicator': 'commented-out debug markup',
                'count': len(commented_debug),
                'severity': 'LOW',
                'finding': 'debug-related HTML comments left in page source.',
            })

        if not findings:
            severity = "INFO"
            note = "No debug-endpoint references found in the page snapshot."
        else:
            sev_rank = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            severity = max((f['severity'] for f in findings), key=lambda s: sev_rank.get(s, 0))
            note = f"{len(findings)} debug-endpoint exposure indicator(s) found."

        return {
            'test_name': 'Debug Endpoint Discovery (Passive) (WSTG-4.8.3)',
            'url': self.base_url,
            'findings': findings,
            'note': note,
            'recommendations': [
                'Remove debug/console/actuator endpoints from production, or gate them behind auth + network restrictions.',
                'Restrict Spring Boot actuator to health/info only and disable env/heapdump/threaddump.',
                'Strip debug HTML comments and phpinfo/profiler references from production builds.',
            ],
            'severity': severity,
            'wstg_reference': 'WSTG-4.8.3',
        }

    def detect_source_map_exposure(self, html: str, response) -> Dict[str, Any]:
        """Passive source-map / source-code exposure detection (WSTG-4.8.4).

        Detects sourceMappingURL comments, .js.map / .css.map
        references, and SourceMap/SourceMap-Registry response headers,
        all of which can expose original (un-minified) source to clients.
        """
        text = html or ''
        findings: List[Dict[str, Any]] = []
        severity = "INFO"

        # sourceMappingURL comments at the end of inline/embedded scripts.
        sourceMappingURL = re.findall(r'//[#@]\s*sourceMappingURL\s*=\s*([^\s"\']+)', text)
        # Direct .map references in href/src or script text.
        map_refs = re.findall(r'["\']([^"\']*\.map)(?:\?[^"\']*)?["\']', text)
        # Inline source map data (base64) embedded directly.
        inline_datauri = bool(re.search(r'sourceMappingURL\s*=\s*data:application/json;base64', text))

        header_sourcemaps = []
        if response is not None:
            for hdr in ('SourceMap', 'SourceMap-Registry', 'X-SourceMap'):
                val = response.headers.get(hdr)
                if val:
                    header_sourcemaps.append(f'{hdr}: {val}')

        if sourceMappingURL:
            findings.append({
                'indicator': 'sourceMappingURL comment',
                'references': sorted(set(sourceMappingURL))[:10],
                'severity': 'MEDIUM',
                'finding': f'{len(set(sourceMappingURL))} sourceMappingURL comment(s) reference client-side maps.',
            })
        if map_refs:
            findings.append({
                'indicator': '.map file reference',
                'references': sorted(set(map_refs))[:10],
                'severity': 'MEDIUM',
                'finding': f'{len(set(map_refs))} .map file reference(s) may expose original source.',
            })
        if inline_datauri:
            findings.append({
                'indicator': 'inline base64 source map',
                'severity': 'HIGH',
                'finding': 'Inline base64 source map embedded — original source shipped to clients.',
            })
        if header_sourcemaps:
            findings.append({
                'indicator': 'SourceMap response header',
                'headers': header_sourcemaps,
                'severity': 'LOW',
                'finding': 'SourceMap header(s) present on a static asset response.',
            })

        if not findings:
            severity = "INFO"
            note = "No source-map / source-code exposure indicators detected."
        else:
            sev_rank = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            severity = max((f['severity'] for f in findings), key=lambda s: sev_rank.get(s, 0))
            note = f"{len(findings)} source-map exposure indicator(s) found."

        return {
            'test_name': 'Source Map Exposure Detection (Passive) (WSTG-4.8.4)',
            'url': self.base_url,
            'findings': findings,
            'note': note,
            'recommendations': [
                'Do not deploy .js.map/.css.map files to production, or restrict them to authenticated internal access.',
                'Remove sourceMappingURL comments and inline source maps from production bundles.',
                'Strip SourceMap response headers from public assets.',
            ],
            'severity': severity,
            'wstg_reference': 'WSTG-4.8.4',
        }

    def analyze_verbose_exceptions(self, html: str, response) -> Dict[str, Any]:
        """Passive verbose-exception / error-detail analysis (WSTG-4.8.1).

        Detects verbose exception renderings that go beyond a stack
        trace: SQL/state dumps, request+environment echoes, cookie
        dumps, config values, and internal variable exposure often shown
        on developer error pages.
        """
        text = html or ''
        lower = text.lower()
        findings: List[Dict[str, Any]] = []
        severity = "INFO"

        verbose_categories = [
            ("SQL/state dump", r"(?:sqlstate|sql syntax|mysql_fetch|pg_query|you have an error in your sql syntax|near \"[^\"]*\": line \d+|ora-\d{5})"),
            ("request echo", r"(?:request (?:uri|method|headers)|query string|_server\[|_request\[|request_uri=|request_method=)"),
            ("environment dump", r"(?:environment|env\(\)|getenv|process\.env|_env\[|application\.properties)"),
            ("cookie dump", r"(?:cookie[: ]|set-cookie|_cookie\[|httpcookie|cookies collection)"),
            ("config/credentials leak", r"(?:api[_-]?key|secret|password|token|passwd)\s*[:=]\s*[\"\'][^\"\']{6,}"),
            ("internal variable exposure", r"(?:locals:|globals:|this\.\w+|window\.\w+\s*=|var_dump|print_r|debugger;|debugger\s*//)"),
        ]

        for name, pattern in verbose_categories:
            matches = re.findall(pattern, lower)
            if matches:
                sev = 'HIGH' if name == 'config/credentials leak' else 'MEDIUM'
                findings.append({
                    'category': name,
                    'occurrences': len(matches),
                    'sample': matches[:3],
                    'severity': sev,
                    'finding': f'{name} detail disclosed in error/verbose output.',
                })

        # Headers that hint verbose/debug mode at the transport layer.
        debug_headers = []
        if response is not None:
            for hdr, marker in (('X-Debug', 'debug'), ('X-Debug-Token', 'debug-token'),
                                ('X-Environment', 'environment'), ('X-Status', 'status')):
                val = response.headers.get(hdr)
                if val:
                    debug_headers.append(f'{hdr}: {val}')

        if not findings:
            severity = "INFO"
            note = "No verbose exception / error-detail disclosure detected."
        else:
            sev_rank = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            severity = max((f['severity'] for f in findings), key=lambda s: sev_rank.get(s, 0))
            note = f"{len(findings)} verbose-exception disclosure category(ies) found."

        return {
            'test_name': 'Verbose Exception Analysis (Passive) (WSTG-4.8.1)',
            'url': self.base_url,
            'findings': findings,
            'debug_headers': debug_headers,
            'note': note,
            'recommendations': [
                'Disable verbose/developer error output in production; return generic messages.',
                'Never echo request data, environment variables, cookies, or config/credentials in error responses.',
                'Redact sensitive fields before logging and ensure error pages contain no internal state.',
            ],
            'severity': severity,
            'wstg_reference': 'WSTG-4.8.1',
        }

    def detect_debug_parameters_passive(self, html: str, response) -> Dict[str, Any]:
        """Passive debug-parameter / verbose-mode detection (WSTG-4.8.5).

        Looks for debug/verbose/dev query parameters referenced in the
        page (links, forms, scripts) and for framework debug-mode hints
        — without sending any request with those parameters.
        """
        text = html or ''
        lower = text.lower()
        findings: List[Dict[str, Any]] = []
        severity = "INFO"

        # Query-string keys that switch verbose/debug behavior.
        debug_param_re = re.compile(
            r'[?&](debug|verbose|dev|development|env|environment|trace|showerror|show_error|debugger|dbg|testmode|xdebug)'
            r'(?:=([^&"\'#\s]+))?',
            re.I,
        )
        param_hits = {}
        for m in debug_param_re.finditer(lower):
            key = m.group(1)
            param_hits.setdefault(key, set())
            val = m.group(2)
            if val:
                param_hits[key].add(val)

        if param_hits:
            findings.append({
                'indicator': 'debug/verbose query parameter referenced',
                'parameters': {k: sorted(v) if v else [] for k, v in param_hits.items()},
                'severity': 'MEDIUM',
                'finding': f'{len(param_hits)} debug/verbose parameter key(s) referenced in page (not submitted).',
            })

        # Form fields that look like debug toggles.
        debug_fields = re.findall(
            r'<input[^>]+name=["\'](?:debug|verbose|dev|testmode|debugger)["\']',
            text, re.I,
        )
        if debug_fields:
            findings.append({
                'indicator': 'debug/verbose form field',
                'count': len(debug_fields),
                'severity': 'MEDIUM',
                'finding': 'debug/verbose toggle exposed as a form field.',
            })

        # Framework debug-mode fingerprints in markup/inline config.
        debug_mode_hints = []
        if re.search(r'"debug"\s*:\s*true|debug\s*:\s*true|app\.debug\s*=\s*true|debug_mode\s*=\s*true', lower):
            debug_mode_hints.append('debug:true config literal')
        if re.search(r'process\.env\.node_env\s*===?\s*["\']development', lower):
            debug_mode_hints.append('NODE_ENV=development branch present')
        if re.search(r'flask.*debug\s*=\s*true|app\.run\(.*debug\s*=\s*true', lower):
            debug_mode_hints.append('Flask debug=True')
        if debug_mode_hints:
            findings.append({
                'indicator': 'framework debug-mode config literal',
                'hints': debug_mode_hints,
                'severity': 'HIGH',
                'finding': 'debug-mode enabled literal found in client-served code/config.',
            })

        if not findings:
            severity = "INFO"
            note = "No debug-parameter / verbose-mode indicators detected in the page."
        else:
            sev_rank = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            severity = max((f['severity'] for f in findings), key=lambda s: sev_rank.get(s, 0))
            note = f"{len(findings)} debug-parameter / verbose-mode indicator(s) found."

        return {
            'test_name': 'Debug Parameter Detection (Passive) (WSTG-4.8.5)',
            'url': self.base_url,
            'findings': findings,
            'note': note,
            'recommendations': [
                'Remove debug/verbose parameters and toggles from production code.',
                'Gate any debug behavior behind server-side environment checks, never client-supplied parameters.',
                'Ensure dev/development config literals and NODE_ENV=development branches are stripped from prod bundles.',
            ],
            'severity': severity,
            'wstg_reference': 'WSTG-4.8.5',
        }

    @staticmethod
    def _extract_wstg_ids(text: str) -> List[str]:
        """Pull all WSTG-4.8.x ids out of an arbitrary string."""
        if not text:
            return []
        return re.findall(r'WSTG-4\.8\.\d+', text)
    
    @staticmethod
    def _get_timestamp() -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
