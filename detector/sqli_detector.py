# detector/sqli_detector.py
from utils.http import safe_get
from config import SQLI_PAYLOADS, SQL_ERROR_PATTERNS

def contains_sql_error(text):
    if not text:
        return False
    for p in SQL_ERROR_PATTERNS:
        if p.lower() in text.lower():
            return True
    return False

class SQLiDetector:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def test_form(self, form):
        findings = []
        base_action = form.action
        baseline_params = {inp['name']: inp.get('value', 'test') for inp in form.inputs}
        base_resp = safe_get(base_action, params=baseline_params if form.method=="get" else None,
                             data=baseline_params if form.method=="post" else None,
                             method=form.method.upper())
        base_text = base_resp.text if base_resp else ""
        for inp in form.inputs:
            name = inp['name']
            orig = baseline_params.get(name, "")
            for payload in SQLI_PAYLOADS:
                test_params = baseline_params.copy()
                test_params[name] = orig + payload
                r = safe_get(base_action, params=test_params if form.method=="get" else None,
                             data=test_params if form.method=="post" else None,
                             method=form.method.upper())
                if not r: continue
                text = r.text
                if contains_sql_error(text):
                    findings.append({
                        "type": "SQLi", "param": name, "payload": payload,
                        "evidence": "SQL error string in response",
                        "url": base_action, "severity": "High"
                    })
                    break
                if abs(len(text) - len(base_text)) > 200:
                    findings.append({
                        "type": "SQLi", "param": name, "payload": payload,
                        "evidence": f"Response size changed",
                        "url": base_action, "severity": "Medium"
                    })
                    break
        return findings
