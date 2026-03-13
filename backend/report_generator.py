"""
XSS Shield Pro - Report Generator Module
Produces a plain-text/markdown vulnerability report
"""

from datetime import datetime


class ReportGenerator:

    def generate(self, scan: dict) -> dict:
        if not scan:
            return {'text': 'No scan data provided.'}

        lines = [
            "=" * 60,
            "  XSS SHIELD PRO — VULNERABILITY REPORT",
            "=" * 60,
            f"  Target   : {scan.get('input','')[:80]}",
            f"  Scanned  : {scan.get('scanned_at', datetime.now().isoformat())}",
            f"  Risk     : {scan.get('risk','UNKNOWN')}   Score: {scan.get('score',0)}/100",
            "-" * 60,
            f"  CRITICAL : {scan.get('critical',0)}",
            f"  HIGH     : {scan.get('high',0)}",
            f"  MEDIUM   : {scan.get('medium',0)}",
            f"  INFO/LOW : {scan.get('info',0)}",
            "=" * 60,
        ]

        for i, f in enumerate(scan.get('findings', []), 1):
            lines += [
                f"\n[{i}] {f['severity']} — {f['name']}",
                f"    Category  : {f['category']}",
                f"    Issue     : {f['description']}",
                f"    Evidence  : {f['evidence'][:100]}",
                "    Fix:",
            ]
            for fix_line in f['fix'].split('\n'):
                lines.append(f"      {fix_line}")

        lines += ["", "=" * 60, "  END OF REPORT", "=" * 60]
        return {'text': '\n'.join(lines)}
