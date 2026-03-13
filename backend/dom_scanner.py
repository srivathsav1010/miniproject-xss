from playwright.sync_api import sync_playwright

class DOMScanner:

    def scan(self, url):

        findings = []

        with sync_playwright() as p:

            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(url)

            content = page.content()

            if "alert(" in content:
                findings.append("Possible DOM XSS")

            browser.close()

        return findings