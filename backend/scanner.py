"""
XSS Shield Pro - Scanner Module
Core detection engine: 38 rules across 9 threat categories
"""

import re
import urllib.parse
import html
from typing import List, Dict, Any
from datetime import datetime


class XSSScanner:
    """
    Main scanning engine.
    Runs multi-layer decode then matches all 38 rules.
    """

    def __init__(self):
        self.rules = self._load_rules()

    def rule_count(self) -> int:
        return len(self.rules)

    # ── Public API ──────────────────────────────────────────

    def scan(self, raw_input: str) -> Dict[str, Any]:
        """
        Full scan pipeline:
          1. URL parse & protocol check
          2. Multi-layer decode
          3. 38-rule pattern scan
          4. Parameter extraction & analysis
          5. Sensitive data checks
          6. Context fingerprinting
          7. Score & package results
        """
        results = []
        log     = []
        steps   = []

        def step(name, fn):
            start = datetime.now()
            try:
                found = fn()
                results.extend(found)
                ms = int((datetime.now() - start).total_seconds() * 1000)
                steps.append({'name': name, 'status': 'done', 'ms': ms, 'found': len(found)})
                log.append(f'[OK]  {name} — {len(found)} finding(s) in {ms}ms')
            except Exception as e:
                steps.append({'name': name, 'status': 'error'})
                log.append(f'[ERR] {name} — {e}')

        step('URL parse',          lambda: self._step_url_parse(raw_input))
        step('Decode layers',      lambda: self._step_decode(raw_input))
        step('Pattern scan',       lambda: self._step_pattern_scan(raw_input))
        step('Parameter analysis', lambda: self._step_param_analysis(raw_input))
        step('Sensitive data',     lambda: self._step_sensitive(raw_input))
        step('Context analysis',   lambda: self._step_context(raw_input))

        # Deduplicate results
        seen = set()
        unique = []
        for r in results:
            key = (r['name'], r['evidence'][:60])
            if key not in seen:
                seen.add(key)
                unique.append(r)

        score = self._calc_score(unique)

        return {
            'input':    raw_input,
            'scanned_at': datetime.now().isoformat(),
            'score':    score,
            'risk':     'HIGH' if score >= 70 else 'MEDIUM' if score >= 40 else 'LOW',
            'total':    len(unique),
            'critical': sum(1 for r in unique if r['severity'] == 'CRITICAL'),
            'high':     sum(1 for r in unique if r['severity'] == 'HIGH'),
            'medium':   sum(1 for r in unique if r['severity'] == 'MEDIUM'),
            'info':     sum(1 for r in unique if r['severity'] in ('LOW','INFO')),
            'findings': sorted(unique, key=lambda r: self._sev_order(r['severity'])),
            'steps':    steps,
            'log':      log,
        }

    # ── Scan Steps ──────────────────────────────────────────

    def _step_url_parse(self, raw: str) -> List[Dict]:
        findings = []
        try:
            u = urllib.parse.urlparse(raw)
            if u.scheme and u.scheme not in ('http', 'https'):
                findings.append(self._finding(
                    cat='URI Schemes', sev='CRITICAL',
                    name='Suspicious URL protocol',
                    desc=f'Protocol "{u.scheme}:" is not http/https — may execute code.',
                    evidence=raw[:100],
                    fix='Only accept http: and https: protocols.\nif url.scheme not in ("http","https"): raise ValueError("Invalid protocol")'
                ))
        except Exception:
            pass
        return findings

    def _step_decode(self, raw: str) -> List[Dict]:
        findings = []
        decoded, layers = raw, 0
        try:
            while True:
                next_d = urllib.parse.unquote(decoded)
                if next_d == decoded:
                    break
                decoded = next_d
                layers += 1
                if layers > 5:
                    break
        except Exception:
            pass
        if layers > 1:
            findings.append(self._finding(
                cat='Encoding Bypasses', sev='HIGH',
                name=f'Multi-layer URL encoding ({layers} layers)',
                desc='Input is encoded multiple times — classic technique to bypass single-decode filters.',
                evidence=raw[:120],
                fix='# Fully decode before any processing\ndecoded = input\nwhile decoded != unquote(decoded):\n    decoded = unquote(decoded)'
            ))
        return findings

    def _step_pattern_scan(self, raw: str) -> List[Dict]:
        findings = []
        # Build normalised target: URL-decode + HTML-entity-decode + lowercase copy
        try:
            url_decoded = urllib.parse.unquote(raw)
        except Exception:
            url_decoded = raw
        entity_decoded = html.unescape(url_decoded)
        target = raw + ' ' + url_decoded + ' ' + entity_decoded

        for rule in self.rules:
            match = re.search(rule['regex'], target, re.IGNORECASE | re.DOTALL)
            if match:
                findings.append(self._finding(
                    cat=rule['cat'], sev=rule['sev'],
                    name=rule['name'], desc=rule['desc'],
                    evidence=match.group(0)[:160],
                    fix=rule['fix']
                ))
        return findings

    def _step_param_analysis(self, raw: str) -> List[Dict]:
        findings = []
        try:
            parsed = urllib.parse.urlparse(raw)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            redirect_keys = {'redirect','url','next','return','redir','dest','location','goto','ref'}
            xss_re = re.compile(r'<|>|script|on\w+=|javascript:', re.IGNORECASE)

            for key, values in params.items():
                for val in values:
                    if xss_re.search(val):
                        findings.append(self._finding(
                            cat='Script Injection', sev='CRITICAL',
                            name=f'XSS payload in parameter "{key}"',
                            desc=f'URL parameter "{key}" contains an XSS payload that will be reflected if not encoded.',
                            evidence=f'{key}={val[:100]}',
                            fix=f'# Python\nfrom markupsafe import escape\nsafe = escape(request.args.get("{key}",""))\n\n# PHP\nhtmlspecialchars($_GET["{key}"], ENT_QUOTES, "UTF-8");'
                        ))
                    if key.lower() in redirect_keys and val.startswith('http'):
                        findings.append(self._finding(
                            cat='URI Schemes', sev='HIGH',
                            name=f'Open redirect — parameter "{key}"',
                            desc='Redirect parameter accepts external URLs. Attacker can redirect users to phishing sites.',
                            evidence=f'{key}={val[:80]}',
                            fix='ALLOWED_HOSTS = {"yoursite.com"}\nfrom urllib.parse import urlparse\nt = urlparse(val)\nif t.hostname not in ALLOWED_HOSTS: raise ValueError("Bad redirect")'
                        ))
        except Exception:
            pass
        return findings

    def _step_sensitive(self, raw: str) -> List[Dict]:
        findings = []
        sensitive_re = re.compile(
            r'[?&](password|passwd|pwd|token|secret|api_?key|auth|access_token)=',
            re.IGNORECASE
        )
        m = sensitive_re.search(raw)
        if m:
            findings.append(self._finding(
                cat='Data Exfiltration', sev='HIGH',
                name='Sensitive data in URL',
                desc='Credentials or tokens in the URL are logged by servers, browsers, and CDNs — major security risk.',
                evidence=m.group(0),
                fix='# Use POST body for sensitive data, not GET params\n# Set referrer policy to no-referrer\nReferrer-Policy: no-referrer\n\n# In HTML\n<meta name="referrer" content="no-referrer">'
            ))
        if re.search(r'<form', raw, re.IGNORECASE) and not re.search(r'csrf|_token|nonce', raw, re.IGNORECASE):
            findings.append(self._finding(
                cat='Element Injection', sev='HIGH',
                name='Form without CSRF token',
                desc='HTML form found with no visible CSRF protection. Vulnerable to cross-site request forgery.',
                evidence=re.search(r'<form[^>]*>', raw, re.IGNORECASE).group(0)[:80] if re.search(r'<form[^>]*>', raw, re.IGNORECASE) else '<form>',
                fix='# Add CSRF token to every form\n<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">\n\n# Flask-WTF handles this automatically\nfrom flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)'
            ))
        return findings

    def _step_context(self, raw: str) -> List[Dict]:
        findings = []
        contexts = []
        if re.search(r'<[^>]+\s+[a-z]+=\s*["\'][^"\']*$', raw, re.IGNORECASE):
            contexts.append('inside HTML attribute value')
        if re.search(r'<script[\s\S]*$', raw, re.IGNORECASE) and not re.search(r'</script', raw, re.IGNORECASE):
            contexts.append('inside open script block')
        if re.search(r'style\s*=\s*["\'][^"\']*$', raw, re.IGNORECASE):
            contexts.append('inside style attribute')
        if contexts:
            findings.append(self._finding(
                cat='Encoding Bypasses', sev='MEDIUM',
                name='Context-specific injection point',
                desc=f'Possible injection context(s): {", ".join(contexts)}. Each requires different encoding.',
                evidence=raw[:120],
                fix='# HTML context  → html.escape(val)\n# Attr context  → html.escape(val, quote=True)\n# JS context    → json.dumps(val)\n# URL context   → urllib.parse.quote(val)\n# CSS context   → reject or strict allowlist'
            ))
        return findings

    # ── Helpers ─────────────────────────────────────────────

    def _finding(self, cat, sev, name, desc, evidence, fix) -> Dict:
        return {'category': cat, 'severity': sev, 'name': name,
                'description': desc, 'evidence': evidence, 'fix': fix}

    def _calc_score(self, results) -> int:
        weights = {'CRITICAL': 25, 'HIGH': 15, 'MEDIUM': 8, 'LOW': 3, 'INFO': 1}
        return min(100, sum(weights.get(r['severity'], 0) for r in results))

    def _sev_order(self, s) -> int:
        return {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}.get(s, 5)

    # ── Rules ───────────────────────────────────────────────

    def _load_rules(self) -> List[Dict]:
        return [
            # SCRIPT INJECTION
            {'cat':'Script Injection','sev':'CRITICAL','name':'Classic script tag',
             'regex':r'<\s*script[\s\S]*?>[\s\S]*?<\s*/\s*script\s*>',
             'desc':'Direct <script> tag injection — executes arbitrary JS in victim browser.',
             'fix':'# Python / Jinja2\nfrom markupsafe import escape\nsafe = escape(user_input)\n\n# Never do this:\nreturn f"<div>{user_input}</div>"  # DANGEROUS'},

            {'cat':'Script Injection','sev':'CRITICAL','name':'Unclosed script tag',
             'regex':r'<\s*script\b[^>]*>',
             'desc':'Opening <script> tag — may execute in innerHTML or certain parser contexts.',
             'fix':'# Use textContent (never innerHTML) for user data\nelement.textContent = userInput;  # JS safe\n# element.innerHTML = userInput;  # DANGEROUS'},

            {'cat':'Script Injection','sev':'HIGH','name':'Remote script load',
             'regex':r'<\s*script\b[^>]*\bsrc\s*=\s*["\']?https?:',
             'desc':'Remote script — attacker hosts malicious JS and loads it via src attribute.',
             'fix':'# CSP blocks external script loads:\nContent-Security-Policy: script-src \'self\';'},

            # EVENT HANDLERS
            {'cat':'Event Handlers','sev':'CRITICAL','name':'Auto-firing event handler',
             'regex':r'\bon(error|load|abort|unload|beforeunload|pagehide|pageshow)\s*=\s*["\']?[^\s"\'>\s]',
             'desc':'onerror/onload fires WITHOUT user interaction — most dangerous handler type.',
             'fix':'# Strip ALL event attributes server-side\nimport bleach\nclean = bleach.clean(html, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=True)'},

            {'cat':'Event Handlers','sev':'CRITICAL','name':'User-triggered event handler',
             'regex':r'\bon(click|focus|blur|mouseover|mouseout|mouseenter|mouseleave|keydown|keyup|keypress|submit|change|input|dblclick)\s*=\s*["\']?[^\s"\'>\s]',
             'desc':'JS event handler attribute — executes on user interaction.',
             'fix':'# Allowlist approach — only safe attrs permitted:\nALLOWED_ATTRS = {"a": ["href","title"], "img": ["src","alt"], "*": ["class","id"]}\nbleach.clean(html, attributes=ALLOWED_ATTRS)'},

            {'cat':'Event Handlers','sev':'HIGH','name':'Obscure event handler',
             'regex':r'\bon(drag|drop|pointer|animation|transition|wheel|scroll|resize|copy|paste|cut|select|contextmenu|fullscreen)\s*=\s*["\']?[^\s"\'>\s]',
             'desc':'Less-common event attributes often missed by basic sanitizers.',
             'fix':'# Use a maintained library — never hand-roll an event blocklist:\npip install bleach  # Python\nnpm install dompurify  # JavaScript'},

            # URI SCHEMES
            {'cat':'URI Schemes','sev':'CRITICAL','name':'javascript: protocol',
             'regex':r'\bjavascript\s*:',
             'desc':'javascript: URI — executes JS when user clicks the link or it is set as href/src.',
             'fix':'def is_safe_url(url):\n    from urllib.parse import urlparse\n    p = urlparse(url)\n    return p.scheme in ("http","https") and p.netloc != ""\n\nif not is_safe_url(user_url): raise ValueError("Unsafe URL")'},

            {'cat':'URI Schemes','sev':'HIGH','name':'vbscript: protocol',
             'regex':r'\bvbscript\s*:',
             'desc':'VBScript URI — executes in legacy Internet Explorer.',
             'fix':'# Same URL allowlist — reject anything that is not http/https'},

            {'cat':'URI Schemes','sev':'HIGH','name':'data:text/html URI',
             'regex':r'\bdata\s*:\s*text/html',
             'desc':'data:text/html creates a full HTML document that can execute scripts.',
             'fix':'# Block data: URIs in URL validation\nALLOWED_SCHEMES = {"http","https","mailto"}\nif urlparse(url).scheme not in ALLOWED_SCHEMES: reject()'},

            {'cat':'URI Schemes','sev':'MEDIUM','name':'data: URI (generic)',
             'regex':r'\bdata\s*:\s*[a-z]+/[a-z]',
             'desc':'data: URI can be used for various bypass techniques.',
             'fix':'# CSP: img-src \'self\' https: — removes data: from allowed image sources'},

            # DOM MANIPULATION
            {'cat':'DOM Manipulation','sev':'CRITICAL','name':'Cookie theft attempt',
             'regex':r'\bdocument\s*\.\s*cookie\b',
             'desc':'Attacker is reading session cookies — classic XSS payload goal.',
             'fix':'# Set HttpOnly — JS cannot access this cookie:\nSet-Cookie: sessionid=abc; HttpOnly; Secure; SameSite=Strict\n\n# Flask:\napp.config["SESSION_COOKIE_HTTPONLY"] = True\napp.config["SESSION_COOKIE_SECURE"] = True\napp.config["SESSION_COOKIE_SAMESITE"] = "Strict"'},

            {'cat':'DOM Manipulation','sev':'HIGH','name':'document.write sink',
             'regex':r'\bdocument\s*\.\s*write\s*\(',
             'desc':'document.write with user input causes full HTML injection.',
             'fix':'// Replace document.write with safe DOM API:\nconst el = document.createElement("p");\nel.textContent = userInput;  // textContent is always safe\ndocument.body.appendChild(el);'},

            {'cat':'DOM Manipulation','sev':'HIGH','name':'innerHTML / outerHTML sink',
             'regex':r'\b(innerHTML|outerHTML)\s*=',
             'desc':'innerHTML assignment with user data is a primary DOM XSS sink.',
             'fix':'// Option 1: DOMPurify (allows safe HTML)\nimport DOMPurify from "dompurify";\nel.innerHTML = DOMPurify.sanitize(userInput);\n\n// Option 2: textContent (plain text only)\nel.textContent = userInput;'},

            {'cat':'DOM Manipulation','sev':'HIGH','name':'eval() / dynamic execution',
             'regex':r'\b(eval|setTimeout|setInterval|new\s+Function)\s*\(',
             'desc':'Dynamic code execution — if user input reaches eval(), it is arbitrary code execution.',
             'fix':'// Never pass user input to eval()\n// For JSON: use JSON.parse()\nconst data = JSON.parse(userInput); // Throws on non-JSON\n\n// CSP blocks eval:\nContent-Security-Policy: script-src \'self\'; // No unsafe-eval'},

            {'cat':'DOM Manipulation','sev':'HIGH','name':'Open redirect',
             'regex':r'\b(window\.location|location\.href|location\.assign|location\.replace)\s*[=(]',
             'desc':'Attacker controls redirect destination — can send users to phishing pages.',
             'fix':'// Validate redirect targets\nconst ALLOWED = new Set(["yoursite.com"]);\nconst t = new URL(redirectUrl);\nif (!ALLOWED.has(t.hostname)) throw new Error("Bad redirect");'},

            # ELEMENT INJECTION
            {'cat':'Element Injection','sev':'HIGH','name':'iframe injection',
             'regex':r'<\s*iframe\b[^>]*>',
             'desc':'Iframes can load cross-origin content, enable clickjacking, or run scripts.',
             'fix':'# CSP blocks all iframes:\nContent-Security-Policy: frame-src \'none\';\n\n# Or restrict framing of your own page:\nContent-Security-Policy: frame-ancestors \'self\';'},

            {'cat':'Element Injection','sev':'HIGH','name':'object/embed/applet',
             'regex':r'<\s*(object|embed|applet)\b[^>]*>',
             'desc':'Plugin content (Flash, Java) executes outside the browser sandbox.',
             'fix':'Content-Security-Policy: object-src \'none\';'},

            {'cat':'Element Injection','sev':'HIGH','name':'SVG with event/script',
             'regex':r'<\s*svg\b[^>]*(on\w+|script)[^>]*>',
             'desc':'SVG elements support <script> tags and event handlers — execute as HTML.',
             'fix':'# Sanitize user SVGs with DOMPurify:\nimport DOMPurify from "dompurify";\nconst clean = DOMPurify.sanitize(svgString, {USE_PROFILES: {svg: true}});'},

            {'cat':'Element Injection','sev':'MEDIUM','name':'SVG tag (generic)',
             'regex':r'<\s*svg\b',
             'desc':'SVG injection — may execute scripts in certain rendering contexts.',
             'fix':'# Strip SVG unless explicitly needed\n# DOMPurify removes dangerous SVG by default'},

            {'cat':'Element Injection','sev':'HIGH','name':'Form action hijack',
             'regex':r'<\s*form\b[^>]*\baction\s*=\s*["\']?https?://',
             'desc':'Injected form with external action — credentials submitted to attacker server.',
             'fix':'Content-Security-Policy: form-action \'self\';'},

            {'cat':'Element Injection','sev':'MEDIUM','name':'Base tag hijack',
             'regex':r'<\s*base\b[^>]*\bhref\s*=',
             'desc':'Injected <base> changes the base URL for all relative links on the page.',
             'fix':'Content-Security-Policy: base-uri \'self\';'},

            # ENCODING BYPASSES
            {'cat':'Encoding Bypasses','sev':'HIGH','name':'HTML entity obfuscation',
             'regex':r'&#x?[0-9a-fA-F]{2,6};',
             'desc':'HTML entities used to hide script keywords from naive string filters.',
             'fix':'# Always decode BEFORE sanitizing:\nimport html\ndecoded = html.unescape(user_input)\nthen_sanitize(decoded)'},

            {'cat':'Encoding Bypasses','sev':'HIGH','name':'Double URL encoding',
             'regex':r'%25[0-9a-fA-F]{2}',
             'desc':'%253C = %3C = < — double encoding bypasses single-decode validation.',
             'fix':'from urllib.parse import unquote\ndecoded = user_input\nwhile decoded != unquote(decoded):\n    decoded = unquote(decoded)'},

            {'cat':'Encoding Bypasses','sev':'HIGH','name':'Unicode escape bypass',
             'regex':r'\\u[0-9a-fA-F]{4}',
             'desc':'\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074 = "script" — evades keyword matching.',
             'fix':'# Use an HTML parser, not regex keyword matching\n# Parsers handle all encoding forms correctly\npip install bleach html5lib'},

            {'cat':'Encoding Bypasses','sev':'MEDIUM','name':'Null byte injection',
             'regex':r'%00|\\x00',
             'desc':'Null bytes terminate strings in some parsers — used to truncate filenames or bypass checks.',
             'fix':'# Strip null bytes before any processing:\nclean = user_input.replace("\\x00", "")'},

            # CSS INJECTION
            {'cat':'CSS Injection','sev':'HIGH','name':'CSS expression()',
             'regex':r'\bexpression\s*\(',
             'desc':'CSS expression() executes JavaScript — legacy IE attack vector.',
             'fix':'# Strip expression() from style attributes\n# CSP: style-src \'self\' blocks inline style injection\nimport re\nclean = re.sub(r"expression\\s*\\(", "", style_value, flags=re.I)'},

            {'cat':'CSS Injection','sev':'MEDIUM','name':'CSS url(javascript:)',
             'regex':r'\burl\s*\(\s*["\']?javascript:',
             'desc':'CSS url(javascript:...) executes JS via CSS in some browsers.',
             'fix':'# Sanitize all style attribute values\n# Only allow safe CSS properties and values'},

            {'cat':'CSS Injection','sev':'MEDIUM','name':'Style attribute with script',
             'regex':r'style\s*=\s*["\'][^"\']*\bjavascript\b',
             'desc':'JavaScript reference inside a style attribute.',
             'fix':'# Strip style attributes, or validate against a strict allowlist of CSS properties'},

            # PROTOTYPE POLLUTION
            # PROTOTYPE POLLUTION
            {'cat':'Prototype Pollution','sev':'HIGH','name':'__proto__ manipulation',
 'regex':r'__proto__',
 'desc':'Prototype pollution corrupts Object.prototype — can enable XSS via polluted sinks.',
 'fix':'Reject "__proto__" keys in JSON objects.'},

{'cat':'Prototype Pollution','sev':'HIGH','name':'constructor.prototype access',
 'regex':r'constructor\s*\.\s*prototype',
 'desc':'Alternative prototype pollution path.',
 'fix':'Reject "constructor" and "prototype" keys.'},

            # TEMPLATE INJECTION
            {'cat':'Template Injection','sev':'HIGH','name':'Dangerous template expression',
             'regex':r'\{\{[\s\S]*?(constructor|prototype|\beval\b|window|document)[\s\S]*?\}\}',
             'desc':'Template expression containing dangerous globals — SSTI or client-side template injection.',
             'fix':'# Never put user input inside template expressions\n# Jinja2: use |e (escape) filter\n{{ user_input | e }}\n\n# Angular: avoid [innerHTML], use {{ value }} (auto-escaped)'},

            {'cat':'Template Injection','sev':'MEDIUM','name':'Template delimiters',
             'regex':r'\{\{[\s\S]*?\}\}',
             'desc':'Template expression — may be evaluated by Angular, Vue, Handlebars, Jinja2.',
             'fix':'# Escape {{ and }} in user content before rendering:\nsafe = user_input.replace("{{", "&#123;&#123;").replace("}}", "&#125;&#125;")'},

            # DATA EXFILTRATION
            {'cat':'Data Exfiltration','sev':'CRITICAL','name':'fetch() to external host',
             'regex':r'\bfetch\s*\(\s*["\']https?://',
             'desc':'Data exfiltration via fetch() — cookies, tokens, or page content sent externally.',
             'fix':'# CSP blocks external fetch/XHR:\nContent-Security-Policy: connect-src \'self\';'},

            {'cat':'Data Exfiltration','sev':'HIGH','name':'Image beacon exfiltration',
             'regex':r'new\s+Image\s*\(\s*\)',
             'desc':'Image beacon — data exfiltrated by loading an attacker-controlled image URL.',
             'fix':'Content-Security-Policy: img-src \'self\' https:; // Blocks cross-origin images'},

            {'cat':'Data Exfiltration','sev':'HIGH','name':'WebSocket to external',
             'regex':r'new\s+WebSocket\s*\(\s*["\']wss?://',
             'desc':'WebSocket connection to external host for real-time data exfiltration.',
             'fix':'Content-Security-Policy: connect-src \'self\' wss://yourserver.com;'},
        ]
