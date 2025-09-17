# debug_scan.py
"""
调试脚本：运行爬虫并打印每个抓到的页面及其表单详情
用法：
    python debug_scan.py -u http://localhost/vulnerabilities/sqli/ -p 10
"""
import argparse
from crawler.crawler import Crawler

def parse_args():
    p = argparse.ArgumentParser(description="Debug crawler: list pages and forms")
    p.add_argument("-u", "--url", required=True, help="Base URL to crawl (e.g. http://localhost:8080)")
    p.add_argument("-p", "--pages", type=int, default=30, help="Max pages to crawl")
    p.add_argument("--username", default="admin")
    p.add_argument("--password", default="password")
    return p.parse_args()

def print_form(form, indent="    "):
    print(f"{indent}- action: {form.action}")
    print(f"{indent}  method: {form.method}")
    print(f"{indent}  inputs ({len(form.inputs)}):")
    for inp in form.inputs:
        name = inp.get("name")
        typ = inp.get("type")
        val = inp.get("value")
        print(f"{indent}    * name='{name}', type='{typ}', value='{val}'")

def main():
    args = parse_args()
    login_url = None
    login_data = None
    if args.username and args.password:
        # build login url from target host (simple heuristic)
        from urllib.parse import urlparse, urljoin
        parsed = urlparse(args.url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        login_url = urljoin(base, "login.php")
        login_data = {"username": args.username, "password": args.password, "Login": "Login"}
        print(f"[i] Using login URL: {login_url}")

    print(f"Crawling {args.url} (max pages = {args.pages}) ...")
    crawler = Crawler(args.url, max_pages=args.pages, login_url=login_url, login_data=login_data)
    pages = crawler.crawl()
    print(f"-> Done. Crawled {len(pages)} pages.\n")
    for i, p in enumerate(pages, start=1):
        print(f"[{i}] {p.url}")
        print(f"    HTML length: {len(p.html)} chars")
        print(f"    Forms found: {len(p.forms)}")
        for fi, form in enumerate(p.forms, start=1):
            print(f"  Form #{fi}:")
            print_form(form, indent="      ")
        print("-" * 60)

if __name__ == "__main__":
    main()
