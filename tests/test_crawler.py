# tests/test_crawler.py
import pytest
from crawler.crawler import Crawler, Form, Page

SAMPLE_HTML = """
<html>
  <body>
    <a href="/page2">Next</a>
    <form action="/login" method="post">
      <input type="text" name="username" value="">
      <input type="password" name="password" value="">
      <input type="hidden" name="csrf_token" value="abc123">
    </form>
    <form>
      <input name="q" value="search">
    </form>
  </body>
</html>
"""

class DummyResp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200

def test_extract_forms_and_links(monkeypatch):
    c = Crawler("http://example.com", max_pages=2)
    # call private methods directly for unit testing
    forms = c._extract_forms(SAMPLE_HTML, "http://example.com")
    links = c._extract_links(SAMPLE_HTML, "http://example.com")
    assert len(forms) == 2
    # first form action resolved to absolute URL
    assert forms[0].action == "http://example.com/login"
    assert any(inp['name'] == 'csrf_token' for inp in forms[0].inputs)
    assert "http://example.com/page2" in links

def test_crawl_basic(monkeypatch):
    # monkeypatch safe_get to return SAMPLE_HTML for base page and empty for page2
    def fake_safe_get(url, **kwargs):
        if url.endswith("page2"):
            return DummyResp("<html><body><p>page2</p></body></html>")
        return DummyResp(SAMPLE_HTML)
    monkeypatch.setattr("crawler.crawler.safe_get", fake_safe_get)
    c = Crawler("http://example.com", max_pages=3)
    pages = c.crawl()
    assert len(pages) >= 1
    # ensure pages are Page instances and contain html
    assert all(isinstance(p, Page) for p in pages)
    assert any("login" in p.html for p in pages)
