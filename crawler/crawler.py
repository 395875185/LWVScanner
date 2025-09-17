# crawler/crawler.py
import requests                                 # <<< ADDED: need requests for session login
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
    def __init__(self, base_url, max_pages=30, allowed_domain=None, login_url=None, login_data=None):
        self.base_url = base_url.rstrip('/')
        self.max_pages = max_pages
        self.allowed_domain = allowed_domain or urlparse(self.base_url).netloc
        self.visited = set()
        self.pages = []

        # <<< ADDED: create a requests.Session to keep cookies after login
        self.session = requests.Session()
        # set a conservative User-Agent (you can adjust)
        self.session.headers.update({"User-Agent": "WebScanner/1.0"})

        if login_url and login_data:
            self.login(login_url, login_data)

    def login(self, login_url, login_data):
        """
        <<< MODIFIED >>>
        基于 DVWA 登录:
        1) 获取登录页面，查找动作以‘login.php’结尾的表单
        2) 提取表单中的输入（用户名、密码、登录和隐藏的user_token）
        3) 将提取的隐藏输入合并到login_data和POST中
        4) 通过检查基本页面的“Logout”或其他指标来验证登录
        """
        try:
            # 1) GET login page to extract token and real form fields
            r_get = self.session.get(login_url, timeout=10, allow_redirects=True)
            if not r_get:
                print(f"[!] Failed to GET login page: {login_url}")
                return
            soup = BeautifulSoup(r_get.text, "lxml")

            # Find the form element that posts to login.php (relative or absolute)
            login_form = None
            for f in soup.find_all("form"):
                action = f.get("action", "")
                # normalize action to check endswith login.php
                if action and action.strip().lower().endswith("login.php"):
                    login_form = f
                    break
            # fallback: if not found, just take the first form
            if login_form is None:
                forms = soup.find_all("form")
                if forms:
                    login_form = forms[0]

            # collect default hidden/input fields from the login form
            extracted = {}
            if login_form:
                for inp in login_form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    # prioritize hidden or existing values
                    val = inp.get("value", "")
                    typ = inp.get("type", "").lower()
                    # include hidden token or other hidden defaults
                    if typ == "hidden" or val:
                        extracted[name] = val

            # 2) merge provided login_data with extracted hidden inputs (without overwriting username/password if present)
            merged = {}
            merged.update(extracted)      # hidden fields first
            merged.update(login_data or {})  # provided username/password override if present
            # Ensure "Login" submit value exists if form used a submit input with name=Login
            if "Login" not in merged:
                # try to see if login_form has a submit input with name "Login"
                if login_form:
                    sub = login_form.find("input", {"type": "submit"})
                    if sub and sub.get("name"):
                        merged[sub.get("name")] = sub.get("value", "")
                    else:
                        # default DVWA uses name "Login"
                        merged["Login"] = "Login"
                else:
                    merged["Login"] = "Login"

            # 3) POST to login_url (use absolute URL)
            post_url = urljoin(login_url, login_form.get("action")) if login_form and login_form.get("action") else login_url
            r_post = self.session.post(post_url, data=merged, timeout=10, allow_redirects=True)

            # 4) verify: request base page and check for indicators of logged-in state
            r_check = self.session.get(self.base_url, timeout=10, allow_redirects=True)
            check_text = r_check.text if r_check else ""
            if r_check and ("Logout" in check_text or "logout.php" in check_text or "Security Level" in check_text or "Username:" in check_text):
                print("[+] Login successful")
            else:
                print(f"[!] Login may have failed (post_status={getattr(r_post,'status_code', None)}).")
                # print snippet to help debugging
                snippet = (check_text or "")[:400].replace("\n", " ")
                print(f"[debug] post-login page snippet: {snippet!r}")

        except Exception as e:
            print(f"[!] Login exception: {e}")

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
                if not name: 
                    continue
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

            # <<< MODIFIED: use session.get so requests include login cookies
            try:
                r = self.session.get(url, timeout=10, allow_redirects=True)
            except Exception:
                # fallback to safe_get if session request fails
                r = safe_get(url)
            if r is None:
                self.visited.add(url)
                continue

            html = r.text
            forms = self._extract_forms(html, url)
            # debug: if page contains "<form" but forms==0, print snippet
            if "<form" in html.lower() and len(forms) == 0:
                print(f"[warn] page contains '<form' but parser returned 0 forms for {url}. Snippet:")
                print(html[:500])
            self.pages.append(Page(url, html, forms))
            self.visited.add(url)
            links = self._extract_links(html, url)
            for link in links:
                if link not in self.visited and link not in to_visit:
                    to_visit.append(link)
        return self.pages
