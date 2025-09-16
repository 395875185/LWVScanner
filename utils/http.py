# utils/http.py
import requests
from config import USER_AGENT, DEFAULT_TIMEOUT

session = requests.Session()
session.headers.update({"User-Agent": USER_AGENT})

def safe_get(url, params=None, data=None, method="GET", timeout=DEFAULT_TIMEOUT, allow_redirects=True):
    try:
        if method.upper() == "GET":
            r = session.get(url, params=params, timeout=timeout, allow_redirects=allow_redirects)
        else:
            r = session.post(url, data=data, timeout=timeout, allow_redirects=allow_redirects)
        return r
    except Exception as e:
        return None
