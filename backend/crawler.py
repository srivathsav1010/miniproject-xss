import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class WebCrawler:

    def crawl(self, base_url, depth=2):
        visited = set()
        to_visit = [base_url]
        urls = []

        while to_visit and depth > 0:
            url = to_visit.pop()
            if url in visited:
                continue

            visited.add(url)
            urls.append(url)

            try:
                r = requests.get(url, timeout=5)
                soup = BeautifulSoup(r.text, "html.parser")

                for link in soup.find_all("a", href=True):
                    new_url = urljoin(base_url, link['href'])

                    if base_url in new_url and new_url not in visited:
                        to_visit.append(new_url)

            except:
                pass

            depth -= 1

        return urls