import os
from fpdf import FPDF
from datetime import datetime


class PDFReport:

    def clean(self, text):
        return str(text).encode("latin-1", "replace").decode("latin-1")

    def generate(self, results, filename="reports/report.pdf"):

        os.makedirs("reports", exist_ok=True)

        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "XSS Shield Pro Vulnerability Report", ln=True)

        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 8, f"Generated: {datetime.now()}", ln=True)

        pdf.ln(5)

        for r in results:

            url = r.get("url", "Unknown")

            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 8, f"Target URL: {url}", ln=True)

            xss = r.get("xss", {})

            pdf.set_font("Arial", "", 10)

            pdf.cell(0, 6, f"Risk Level: {xss.get('risk','LOW')}", ln=True)
            pdf.cell(0, 6, f"Score: {xss.get('score',0)}", ln=True)

            pdf.cell(0, 6, f"Total Findings: {xss.get('total',0)}", ln=True)
            pdf.cell(0, 6, f"Critical: {xss.get('critical',0)}", ln=True)
            pdf.cell(0, 6, f"High: {xss.get('high',0)}", ln=True)
            pdf.cell(0, 6, f"Medium: {xss.get('medium',0)}", ln=True)

            pdf.ln(3)

            findings = xss.get("findings", [])

            if not findings:

                pdf.cell(0, 6, "No vulnerabilities detected.", ln=True)

            else:

                pdf.set_font("Arial", "B", 11)
                pdf.cell(0, 6, "Findings:", ln=True)

                pdf.set_font("Arial", "", 10)

                for f in findings:

                    name = self.clean(f.get("name"))
                    severity = self.clean(f.get("severity"))
                    evidence = self.clean(f.get("evidence"))

                    pdf.multi_cell(0, 6, f"{name} ({severity})")
                    pdf.multi_cell(0, 6, f"Evidence: {evidence}")

                    pdf.ln(2)

            pdf.ln(5)

        pdf.output(filename)

        print("Report saved to:", filename)