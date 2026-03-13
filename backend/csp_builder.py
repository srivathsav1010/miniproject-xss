"""
XSS Shield Pro - CSP Builder Module
Generates Content-Security-Policy headers from user options
"""


class CSPBuilder:

    DEFAULTS = {
        'inline': True, 'eval': True, 'object': True, 'form': True,
        'base': True, 'connect': True, 'img': True, 'frame': True,
        'upgrade': False, 'report': True,
    }

    def build(self, options: dict) -> dict:
        opt = {**self.DEFAULTS, **options}
        parts = []

        script = "'self'"
        if not opt.get('eval'):
            script += " 'unsafe-eval'"
        parts.append(f"script-src {script}")
        parts.append("style-src 'self' 'unsafe-inline'")
        parts.append("default-src 'self'")

        if opt.get('object'):  parts.append("object-src 'none'")
        if opt.get('form'):    parts.append("form-action 'self'")
        if opt.get('base'):    parts.append("base-uri 'self'")
        if opt.get('connect'): parts.append("connect-src 'self'")
        if opt.get('img'):     parts.append("img-src 'self' https:")
        if opt.get('frame'):   parts.append("frame-ancestors 'self'")
        if opt.get('upgrade'): parts.append("upgrade-insecure-requests")
        if opt.get('report'):  parts.append("report-uri /csp-report")

        value = "; ".join(parts) + ";"
        return {
            'header': f"Content-Security-Policy: {value}",
            'meta':   f'<meta http-equiv="Content-Security-Policy" content="{value}">',
            'value':  value,
        }
