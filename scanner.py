# scanner.py
import argparse
from crawler.crawler import Crawler
from detector.sqli_detector import SQLiDetector
from detector.xss_detector import XSSDetector
from detector.csrf_detector import CSRFDetector
from reporter.html_report import HTMLReport
from utils import http as http_utils  
from urllib.parse import urlparse, urljoin 

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-u","--url",required=True)
    p.add_argument("-o","--output",default="demo_report.html")
    p.add_argument("-p","--pages",type=int,default=30)
    p.add_argument("--username",default=None)#
    p.add_argument("--password",default=None)#
    return p.parse_args()

def make_login_url(base_target_url):
    parsed = urlparse(base_target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return urljoin(base, "login.php")

def main():
    args = parse_args()

    login_data = None
    login_url = None
    if args.username and args.password:
        # <<< MODIFIED: compute login_url from target so host/port match
        login_url = make_login_url(args.url)
        login_data = {"username": args.username, "password": args.password, "Login": "Login"}
        print(f"[i] Using login URL: {login_url}")

    # create crawler with optional login
    crawler = Crawler(args.url, max_pages=args.pages, login_url=login_url, login_data=login_data)

    # <<< ADDED: sync cookies from crawler.session to utils.http.session
    # Reason: detectors use utils.http.session (safe_get). Ensure they share login cookies.
    try:
        # get_dict gives cookie key->value; update the global session's cookies
        http_utils.session.cookies.update(crawler.session.cookies.get_dict())
        print("[i] Synced crawler session cookies to utils.http.session")
    except Exception as e:
        print(f"[!] Failed to sync cookies: {e}")
        
    pages = crawler.crawl()
    sqli = SQLiDetector()
    xss = XSSDetector()
    csrf = CSRFDetector()
    findings = []
    for page in pages:
        for form in page.forms:
            findings.extend(sqli.test_form(form))
            findings.extend(xss.test_form(form))
            findings.extend(csrf.test_form(form))
    unique = []
    seen = set()
    for f in findings:
        # key 包含 url, param, payload, type 以判断重复
        key = (f.get("url"), f.get("param"), f.get("payload"), f.get("type"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    findings = unique
            
    report = HTMLReport(args.url, len(pages), findings)
    out = report.generate(args.output)
    print(f"Report saved to {out} with {len(findings)} findings.")

if __name__ == "__main__":
    main()