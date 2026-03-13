from crawler import WebCrawler
from injector import PayloadInjector
from scanner import XSSScanner
from dom_scanner import DOMScanner
from vuln_detectors import VulnDetectors
from pdf_report import PDFReport


class FullScanner:

    def __init__(self):

        self.crawler = WebCrawler()
        self.injector = PayloadInjector()
        self.xss = XSSScanner()
        self.dom = DOMScanner()
        self.detectors = VulnDetectors()
        self.report = PDFReport()

    # compatibility for old API
    def scan(self, raw_input):
        return self.xss.scan(raw_input)

    def rule_count(self):
        return self.xss.rule_count()

    def scan_site(self, url):

        results = []

        print("Crawling site...")

        urls = self.crawler.crawl(url)

        print("Found pages:", urls)

        for u in urls:

            print("Scanning:", u)

            xss_result = self.xss.scan(u)

            results.append({
                "url": u,
                "xss": xss_result
            })

            dom_result = self.dom.scan(u)

            if dom_result:
                results.append({
                    "url": u,
                    "dom_xss": dom_result
                })

            if self.detectors.detect_ssrf(u):

                results.append({
                    "url": u,
                    "vulnerability": "SSRF"
                })

            if self.detectors.detect_traversal(u):

                results.append({
                    "url": u,
                    "vulnerability": "Path Traversal"
                })

        self.report.generate(results)

        return results