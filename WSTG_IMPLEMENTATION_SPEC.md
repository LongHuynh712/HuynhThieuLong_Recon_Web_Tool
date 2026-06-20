# OWASP WSTG Missing Features - Implementation Specification

## Summary

**Current Coverage: 65%**
**Target Coverage: 95%+**

### Missing Features List

1. ✅ **Content Leakage Scanner** (Priority: HIGH)
   - Email extraction
   - Phone number extraction
   - API key pattern detection
   - Secrets detection (passwords, tokens, keys)
   - Comment analysis
   - JavaScript secret exposure

2. ✅ **Search Engine Reconnaissance** (Priority: HIGH)
   - Google Dork suggestions
   - Indexed URLs analysis
   - Document discovery (PDF, DOCX, XLS)
   - Cached pages detection
   - Public repositories detection

3. ✅ **Enhanced Application Enumeration** (Priority: MEDIUM)
   - Virtual host detection
   - Alternate port scanning
   - Technology-specific admin panels

4. ✅ **Entry Point Mapper** (Priority: MEDIUM)
   - Form parameter documentation
   - GET vs POST distinction
   - Input type mapping
   - Hidden input detection
   - API endpoint documentation

5. ✅ **Execution Path Analyzer** (Priority: MEDIUM)
   - Endpoint relationship graphs
   - Request flow analysis
   - Navigation chain visualization

6. ✅ **Architecture Mapper** (Priority: MEDIUM)
   - CDN detection enhancement
   - Subdomain enumeration
   - Third-party service mapping
   - Visual architecture diagram

7. ✅ **Framework Detection Enhancement** (Priority: LOW)
   - React/Vue/Angular/Next.js/Nuxt
   - Django/Flask/FastAPI
   - Laravel/Symfony
   - ASP.NET/Spring Boot
   - Express.js/Node.js
   - WordPress/Drupal/Joomla
   - Version detection

---

## Implementation Details by Priority

### PRIORITY 1: Content Leakage Scanner

**Files to Modify:**
- `webcheck_checks.py` (add new functions)
- `scanner.py` (integrate into scan flow)
- `app.py` (add SCAN_MODULES entry)
- `templates/results.html` (add dashboard card)
- `static/style.css` (styling)
- `api_handlers.py` (new API endpoint)

**Backend Functions to Add (webcheck_checks.py):**
```python
def extract_emails(html, url):
    """Extract and classify email addresses"""
    # Patterns: admin@, support@, info@, contact@, etc.
    # Return: [{"email": "admin@example.com", "type": "admin", "context": "..."}]

def extract_phone_numbers(html):
    """Extract phone numbers with type detection"""
    # Patterns: +1-XXX-XXX-XXXX, (XXX) XXX-XXXX, XXX.XXX.XXXX
    # Return: [{"number": "...", "type": "phone/fax/mobile", "context": "..."}]

def detect_api_keys(html):
    """Detect common API key patterns"""
    # Patterns: AWS keys, Stripe keys, JWT tokens, API_KEY=, etc.
    # Return: [{"type": "aws|stripe|jwt|api_key", "value": "...", "context": "..."}]

def detect_secrets(html):
    """Detect common secrets patterns"""
    # Patterns: password, secret, token, private_key, etc.
    # Return: [{"pattern": "...", "value": "...", "confidence": 0.95}]

def analyze_comments(html):
    """Extract and analyze HTML/JavaScript comments"""
    # Return: [{"type": "html|javascript", "content": "...", "risk": "..."}]

def extract_js_secrets(js_text):
    """Analyze JavaScript for exposed secrets"""
    # Variables, API endpoints, tokens, keys
    # Return: [{"type": "variable|endpoint|secret", "name": "...", "value": "..."}]
```

**Scanner Integration (scanner.py):**
```python
if should_scan("content_leakage"):
    full_report += "\n========== CONTENT LEAKAGE ==========\n"
    full_report += extract_emails(response.text, url)
    full_report += extract_phone_numbers(response.text)
    full_report += detect_api_keys(response.text)
    full_report += detect_secrets(response.text)
    full_report += analyze_comments(response.text)
    if browser_data:
        full_report += extract_js_secrets(browser_data.get("js_content", ""))
```

**Module Definition (app.py):**
```python
{
    "value": "content_leakage",
    "label": "Content Leakage",
    "icon": "🔍",
    "desc": "Email, phone, API keys, secrets, comments",
    "tags": ["Information Leakage", "Content Analysis", "Secrets"],
}
```

**API Endpoint (api_handlers.py):**
```python
def api_content_leakage(url):
    response = _fetch(url)
    return {
        "emails": extract_emails(response.text, url),
        "phones": extract_phone_numbers(response.text),
        "api_keys": detect_api_keys(response.text),
        "secrets": detect_secrets(response.text),
        "comments": analyze_comments(response.text),
        "report": "Content Leakage Detection Report"
    }
```

---

### PRIORITY 2: Search Engine Reconnaissance

**Files to Modify:**
- `webcheck_checks.py` (add new functions)
- `scanner.py` (integrate into scan flow)
- `app.py` (add SCAN_MODULES entry)
- `templates/results.html` (add dashboard card)
- `api_handlers.py` (new API endpoint)

**Backend Functions to Add (webcheck_checks.py):**
```python
def generate_google_dorks(domain):
    """Generate Google Dork suggestions for reconnaissance"""
    # Suggestions for: site:, filetype:, inurl:, intitle:, cache:
    # Return: [
    #   {"dork": "site:example.com filetype:pdf", "purpose": "Exposed PDFs"},
    #   {"dork": "site:example.com admin", "purpose": "Admin pages"},
    #   ...
    # ]

def analyze_search_engine_exposure(domain):
    """Check indexing status and exposure"""
    # Estimate indexed pages, subdomains, document types
    # Return: {"indexed_pages": "~10K", "subdomains": 12, "documents": {...}}

def find_cached_pages(domain):
    """Identify cached versions of pages"""
    # Return: [{"url": "...", "cached_date": "...", "cache_url": "..."}]

def discover_exposed_documents(domain):
    """Find exposed documents via search patterns"""
    # Look for: PDF, DOCX, XLS, PPT, etc.
    # Return: [{"url": "...", "type": "pdf", "title": "..."}]

def find_public_repositories(domain):
    """Find GitHub/GitLab repositories"""
    # Return: [{"repo": "...", "url": "...", "stars": 10}]

def find_paste_references(domain):
    """Find references in pastebin, gist, etc."""
    # Return: [{"paste": "...", "url": "...", "date": "..."}]
```

**Module Definition (app.py):**
```python
{
    "value": "search_engine_recon",
    "label": "Search Engine Recon",
    "icon": "🔎",
    "desc": "Google Dorks, indexed URLs, documents, repositories",
    "tags": ["OSINT", "Search Engine", "Exposure"],
}
```

---

### PRIORITY 3: Enhanced Application Enumeration

**Files to Modify:**
- `scanner.py` (enhance enumeration section)
- `webcheck_checks.py` (add new functions)

**Backend Functions to Add:**
```python
def enumerate_virtual_hosts(domain, ip):
    """Detect virtual hosts on IP"""
    # Reverse DNS, common virtual host names
    # Return: [{"hostname": "...", "ip": "..."}]

def scan_alternate_ports(domain):
    """Scan common alternate ports"""
    # Ports: 8080, 8443, 3000, 5000, 8000, 9000, 8888
    # Return: [{"port": 8080, "service": "http", "status": "open"}]

def detect_technology_panels(response):
    """Detect technology-specific admin panels"""
    # CMS: /wp-admin, /admin, /phpmyadmin, etc.
    # Return: [{"panel": "WordPress Admin", "url": "/wp-admin", "status": 200}]
```

---

### PRIORITY 4: Entry Point Mapper

**Files to Modify:**
- `scanner.py` (enhance links section)
- `webcheck_checks.py` (add new functions)

**Backend Functions to Add:**
```python
def map_form_parameters(html, url):
    """Document all form parameters"""
    # Extract: input name, type, required, validation patterns
    # Return: [{
    #   "form_id": "login",
    #   "action": "/login",
    #   "method": "POST",
    #   "parameters": [
    #     {"name": "username", "type": "text", "required": True},
    #     {"name": "password", "type": "password", "required": True}
    #   ]
    # }]

def classify_endpoints(html):
    """Classify GET vs POST endpoints"""
    # Return: {"get_endpoints": [...], "post_endpoints": [...]}

def extract_api_documentation(html, js_content):
    """Extract API endpoint documentation"""
    # From comments, Swagger, OpenAPI definitions
    # Return: [{"endpoint": "/api/users", "method": "GET", "description": "..."}]
```

---

### PRIORITY 5: Execution Path Analyzer

**Files to Modify:**
- `scanner.py` (new section)
- `webcheck_checks.py` (new functions)

**Backend Functions to Add:**
```python
def analyze_execution_paths(crawl_results):
    """Build execution path graph"""
    # From crawled pages, identify request chains: A → B → C
    # Return: {
    #   "paths": [{"source": "/", "destination": "/login", "method": "GET"}],
    #   "critical_paths": [...]
    # }

def map_request_flow(url_tree):
    """Map request flow and response codes"""
    # 200→302→403 patterns
    # Return: request flow analysis
```

---

### PRIORITY 6: Architecture Mapper

**Files to Modify:**
- `scanner.py` (enhance network section)
- `webcheck_checks.py` (add new functions)
- `templates/results.html` (add architecture card)

**Backend Functions to Add:**
```python
def detect_cdn_service(ip, domain):
    """Enhanced CDN detection"""
    # Akamai, Cloudflare, CloudFront, Fastly, etc.
    # Return: {"cdn": "Cloudflare", "confidence": 0.95}

def enumerate_subdomains_dns(domain):
    """Enumerate subdomains via DNS"""
    # Common patterns: www, mail, admin, api, staging, dev, etc.
    # Return: [{"subdomain": "api.example.com", "ip": "..."}]

def map_third_party_services(html, js_content):
    """Identify third-party service integrations"""
    # Analytics: Google Analytics, Mixpanel
    # Payment: Stripe, PayPal
    # CDN: jsDelivr, unpkg
    # Return: [{"service": "Google Analytics", "type": "analytics", "id": "..."}]

def generate_architecture_diagram(target_info):
    """Generate application architecture visualization"""
    # Connections: Domain → IP → Hosting → CDN
    # Return: SVG or JSON representation
```

---

### PRIORITY 7: Framework Detection Enhancement

**Files to Modify:**
- `scanner.py` (enhance fingerprint section)
- `webcheck_checks.py` (add new signatures)

**Backend Functions to Add:**
```python
def detect_frameworks(response, html, js_content):
    """Enhanced framework detection"""
    # Signatures for: React, Vue, Angular, Next.js, Nuxt, Django, Flask, etc.
    # Return: [
    #   {"framework": "React", "version": "18.2.0", "confidence": 0.95, "evidence": "..."},
    #   {"framework": "Express.js", "version": "4.18.0", "confidence": 0.8, "evidence": "..."}
    # ]

def detect_framework_version(signatures):
    """Version-specific detection"""
    # Changelog parsing, installation markers
    # Return: version info with evidence
```

---

## New Module Definitions (app.py)

```python
SCAN_MODULES = [
    # ... existing modules ...
    {
        "value": "content_leakage",
        "label": "Content Leakage",
        "icon": "🔍",
        "desc": "Email, phone, API keys, secrets, comments",
        "tags": ["Information Leakage", "Content Analysis", "Secrets"],
    },
    {
        "value": "search_engine_recon",
        "label": "Search Engine Recon",
        "icon": "🔎",
        "desc": "Google Dorks, indexed URLs, documents, repositories",
        "tags": ["OSINT", "Search Engine", "Exposure"],
    },
    {
        "value": "entry_points",
        "label": "Entry Points",
        "icon": "📍",
        "desc": "Forms, parameters, API endpoints, input mapping",
        "tags": ["Entry Points", "API", "Forms"],
    },
    {
        "value": "execution_paths",
        "label": "Execution Paths",
        "icon": "🔀",
        "desc": "Request flow, navigation chains, critical paths",
        "tags": ["Flow Analysis", "Navigation"],
    },
    {
        "value": "architecture",
        "label": "Architecture Map",
        "icon": "🏗️",
        "desc": "Infrastructure, CDN, subdomains, third-party services",
        "tags": ["Infrastructure", "Architecture"],
    },
]
```

---

## API Endpoints to Add (api_handlers.py)

```python
API_REGISTRY.update({
    "content-leakage": api_content_leakage,
    "search-engine-recon": api_search_engine_recon,
    "entry-points": api_entry_points,
    "execution-paths": api_execution_paths,
    "architecture-map": api_architecture_map,
})
```

---

## UI Components to Add (templates/results.html)

1. **Content Leakage Card**
   - Email summary
   - Secrets count
   - Risk indicators

2. **Search Engine Recon Card**
   - Dork suggestions
   - Indexed page estimate
   - Document discovery

3. **Entry Points Card**
   - Form count
   - Parameter count
   - API endpoint count

4. **Execution Paths Card**
   - Navigation graph visualization
   - Request flow tree

5. **Architecture Card**
   - Infrastructure diagram
   - Service mapping
   - Subdomain list

---

## Styling to Add (static/style.css)

```css
.leakage-card, .recon-card, .entry-card, .path-card, .arch-card {
    /* Standard wc-card styling + specific enhancements */
}

.email-list, .secret-list, .dork-suggestions, .parameter-table {
    /* Specific list/table styling */
}

.architecture-diagram, .flow-graph {
    /* SVG/visualization styling */
}
```

---

## Implementation Roadmap

**Week 1-2: Content Leakage Scanner**
- Email + phone extraction
- API key detection
- Secrets pattern matching

**Week 3-4: Search Engine Recon**
- Dork generation
- Document discovery
- Repository detection

**Week 5: Enhanced Enumeration + Entry Points**
- Virtual host detection
- Form parameter mapping
- Alternate port scanning

**Week 6: Execution Path Analyzer**
- Flow graph generation
- Request chain analysis

**Week 7: Architecture Mapper**
- CDN + subdomain detection
- Service mapping
- Visual generation

**Week 8: Framework Detection Enhancement**
- Expanded framework signatures
- Version detection

---

## OWASP WSTG Coverage After Implementation

| Test | Current | After | Gap |
|------|---------|-------|-----|
| WSTG-INFO-01 | 40% | 95% | ✅ Closed |
| WSTG-INFO-02 | 100% | 100% | ✅ N/A |
| WSTG-INFO-03 | 100% | 100% | ✅ N/A |
| WSTG-INFO-04 | 60% | 95% | ✅ Closed |
| WSTG-INFO-05 | 30% | 95% | ✅ Closed |
| WSTG-INFO-06 | 50% | 90% | ✅ Closed |
| WSTG-INFO-07 | 40% | 85% | ✅ Closed |
| WSTG-INFO-08 | 85% | 95% | ✅ Closed |
| WSTG-INFO-09 | 50% | 80% | ✅ Closed |
| WSTG-INFO-10 | 60% | 95% | ✅ Closed |

**Overall: 65% → 93%** ✅

---

## Critical Notes

- ⚠️ **No existing functionality will be modified**
- ✅ **All additions are new modules or enhancements to existing functions**
- ✅ **Backward compatibility maintained**
- ✅ **Existing dashboards, reports, exports unchanged**
- ✅ **New features integrate seamlessly with current UI/UX**
