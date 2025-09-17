# check_response.py
from crawler.crawler import Crawler
import argparse

p = argparse.ArgumentParser()
p.add_argument("-u","--url", required=True)
p.add_argument("--username", default="admin")
p.add_argument("--password", default="password")
args = p.parse_args()

login_url = "http://localhost:8080/login.php"
login_data = {"username": args.username, "password": args.password, "Login": "Login"}

c = Crawler(args.url, max_pages=1, login_url=login_url, login_data=login_data)
# manually request the page via crawler.session (same one used by crawl)
r = c.session.get(args.url, allow_redirects=True, timeout=10)
if not r:
    print("No response (None).")
else:
    print("Status:", r.status_code)
    text = r.text
    print("==== First 1000 chars of response ====")
    print(text[:1000])
    print("==== Contains <form> ? ", "<form" in text.lower())
