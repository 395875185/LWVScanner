# tests/test_detector.py
import pytest
from detector.sqli_detector import SQLiDetector, contains_sql_error
from detector.xss_detector import XSSDetector
from detector.csrf_detector import CSRFDetector

class DummyResp:
    def __init__(self, text):
        self.text = text
        self.status_code = 200

def test_contains_sql_error():
    assert contains_sql_error("You have an error in your SQL syntax")
    assert contains_sql_error("Warning: mysql_fetch_array() failed")
    assert not contains_sql_error("normal content")

def test_sqli_detector(monkeypatch):
    # make safe_get return a response containing SQL error when payload present
    def fake_safe_get(url, params=None, data=None, method="GET", **kwargs):
        # if payload looks like an SQL payload, return error text
        all_vals = {}
        if params: all_vals.update(params)
        if data: all_vals.update(data)
        combined = " ".join(str(v) for v in all_vals.values())
        if "'" in combined or "OR" in combined:
            return DummyResp("You have an error in your SQL syntax near '...'")
        return DummyResp("normal")
    monkeypatch.setattr("detector.sqli_detector.safe_get", fake_safe_get)

    # build a fake Form-like object
    class F:
        action = "http://example.com/search"
        method = "get"
        inputs = [{"name":"q","type":"text","value":""}]
    s = SQLiDetector()
    findings = s.test_form(F)
    assert any(f['type'] == "SQLi" for f in findings)

def test_xss_detector(monkeypatch):
    def fake_safe_get(url, params=None, data=None, method="GET", **kwargs):
        all_vals = {}
        if params: all_vals.update(params)
        if data: all_vals.update(data)
        combined = " ".join(str(v) for v in all_vals.values())
        # simulate reflection
        return DummyResp(f"<html>{combined}</html>")

    monkeypatch.setattr("detector.xss_detector.safe_get", fake_safe_get)

    class F:
        action = "http://example.com/echo"
        method = "get"
        inputs = [{"name":"msg","type":"text","value":""}]
    x = XSSDetector()
    findings = x.test_form(F)
    assert any(f['type'] == "XSS" for f in findings)

def test_csrf_detector():
    # form with hidden csrf token
    class F_ok:
        action = "http://example.com/transfer"
        method = "post"
        inputs = [{"name":"amount","type":"text","value":"1"},
                  {"name":"csrf_token","type":"hidden","value":"abc"}]
    c = CSRFDetector()
    res_ok = c.test_form(F_ok)
    assert any(r['severity'] == "Low" for r in res_ok)

    # form without token
    class F_bad:
        action = "http://example.com/transfer"
        method = "post"
        inputs = [{"name":"amount","type":"text","value":"1"}]
    res_bad = c.test_form(F_bad)
    assert any(r['severity'] == "Medium" for r in res_bad)
