# crawler/crawler.py
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from utils.http import safe_get

class Form:
    def __init__(self, action, method, inputs):
        self.action = action
        self.method = method
        self.inputs = inputs

class Page:
    def __init__(self, url, html, forms):
        self.url = url
        self.html = html
        self.forms = forms

class Crawler:
    def __init__(self, base_url, max_pages=30, allowed_domain=None):
        self.base_url = base_url.rstrip('/')
        self.max_pages = max_pages
        self.allowed_domain = allowed_domain or urlparse(self.base_url).netloc
        self.visited = set()
        self.pages = []

    def _extract_forms(self, html, base_url):
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for f in soup.find_all("form"):
            action = f.get("action")
            action = urljoin(base_url, action) if action else base_url
            method = f.get("method", "get").lower()
            inputs = []
            for inp in f.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name: continue
                typ = inp.get("type", "text")
                value = inp.get("value", "")
                inputs.append({"name": name, "type": typ, "value": value})
            forms.append(Form(action, method, inputs))
        return forms

    def _extract_links(self, html, base_url):
        soup = BeautifulSoup(html, "lxml")
        links = set()
        for a in soup.find_all("a", href=True):
            href = a['href']
            full = urljoin(base_url, href)
            if urlparse(full).netloc == self.allowed_domain:
                links.add(full.split('#')[0])
        return links

    def crawl(self):
        to_visit = [self.base_url]
        while to_visit and len(self.visited) < self.max_pages:
            url = to_visit.pop(0)
            if url in self.visited:
                continue
            r = safe_get(url)
            if r is None:
                self.visited.add(url)
                continue
            html = r.text
            forms = self._extract_forms(html, url)
            self.pages.append(Page(url, html, forms))
            self.visited.add(url)
            links = self._extract_links(html, url)
            for link in links:
                if link not in self.visited and link not in to_visit:
                    to_visit.append(link)
        return self.pages
