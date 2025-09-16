# config.py
DEFAULT_TIMEOUT = 10
USER_AGENT = "WebScanner/1.0 (+https://github.com/yourname/web-scanner)"
SQLI_PAYLOADS = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- "]
XSS_PAYLOADS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
SQL_ERROR_PATTERNS = [
    "You have an error in your SQL syntax",
    "Warning: mysql",
    "unclosed quotation mark after the character string",
    "ORA-"
]
