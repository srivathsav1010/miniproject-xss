import requests
from urllib.parse import urlparse, parse_qs, urlencode

class PayloadInjector:

    def inject(self, url, payloads):

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        results = []

        for param in params:
            for payload in payloads:

                test_params = params.copy()
                test_params[param] = payload

                new_query = urlencode(test_params, doseq=True)

                test_url = parsed._replace(query=new_query).geturl()

                try:
                    r = requests.get(test_url, timeout=5)

                    results.append({
                        "url": test_url,
                        "status": r.status_code,
                        "length": len(r.text)
                    })

                except:
                    pass

        return results