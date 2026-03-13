import re

class VulnDetectors:

    SQL_ERRORS = [
        "sql syntax",
        "mysql_fetch",
        "ORA-01756",
        "SQLSTATE",
        "syntax error near"
    ]

    def detect_sqli(self, response_text):

        for err in self.SQL_ERRORS:
            if err.lower() in response_text.lower():
                return True

        return False
    def detect_ssrf(self, url):

        if "127.0.0.1" in url:
            return True

        if "169.254.169.254" in url:
            return True

        if "localhost" in url:
            return True

        return False
    def detect_traversal(self, url):

        patterns = [
            "../",
            "..\\",
            "%2e%2e%2f",
            "%252e%252e"
        ]

        for p in patterns:
            if p in url:
                return True

        return False