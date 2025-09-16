# scanner.py
import argparse
from crawler.crawler import Crawler
from detector.sqli_detector import SQLiDetector
from detector.xss_detector import XSSDetector
from reporter.html_report import HTMLReport

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-u","--url",required=True)
    p.add_argument("-o","--output",default="demo_report.html")
    p.add_argument("-p","--pages",type=int,default=30)
    return p.parse_args()

def main():
    args = parse_args()
    crawler = Crawler(args.url, max_pages=args.pages)
    pages = crawler.crawl()
    sqli = SQLiDetector()
    xss = XSSDetector()
    findings = []
    for page in pages:
        for form in page.forms:
            findings.extend(sqli.test_form(form))
            findings.extend(xss.test_form(form))
    report = HTMLReport(args.url, len(pages), findings)
    out = report.generate(args.output)
    print(f"Report saved to {out} with {len(findings)} findings.")

if __name__ == "__main__":
    main()
