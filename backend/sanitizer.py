"""
XSS Shield Pro - Sanitizer Module
Three independent sanitization strategies
"""

import html
import re


class Sanitizer:

    def sanitize_all(self, raw: str) -> dict:
        return {
            'original':  raw,
            'encoded':   self.html_encode(raw),
            'stripped':  self.strip_tags(raw),
            'allowlist': self.allowlist_filter(raw),
        }

    def html_encode(self, s: str) -> str:
        """Strategy 1 — HTML entity encode all special characters"""
        return html.escape(s, quote=True)

    def strip_tags(self, s: str) -> str:
        """Strategy 2 — Remove ALL HTML tags, event attrs, js: references"""
        s = re.sub(r'<[^>]+>', '', s)
        s = re.sub(r'javascript:', '', s, flags=re.IGNORECASE)
        s = re.sub(r'\bon\w+\s*=\s*["\'][^"\']*["\']', '', s, flags=re.IGNORECASE)
        return s.strip()

    def allowlist_filter(self, s: str) -> str:
        """Strategy 3 — Keep only safe tags; strip all event attributes"""
        SAFE_TAGS = {'p','br','b','i','em','strong','span','a','ul','ol','li','blockquote'}
        def replace_tag(m):
            full = m.group(0)
            tag  = re.match(r'<\s*/?([a-z][a-z0-9]*)', full, re.IGNORECASE)
            if not tag or tag.group(1).lower() not in SAFE_TAGS:
                return ''
            # Remove event attributes from safe tags
            cleaned = re.sub(r'\s+on\w+\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s>]*)', '', full, flags=re.IGNORECASE)
            cleaned = re.sub(r'\s+javascript:[^\s"\']*', '', cleaned, flags=re.IGNORECASE)
            return cleaned
        return re.sub(r'<[^>]+>', replace_tag, s)
