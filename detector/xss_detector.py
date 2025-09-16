# detector/xss_detector.py
from utils.http import safe_get
from config import XSS_PAYLOADS

class XSSDetector:
    def __init__(self, timeout=10):
        self.timeout = timeout

    def test_form(self, form):
        findings = []
        base_action = form.action
        baseline_params = {inp['name']: inp.get('value', 'test') for inp in form.inputs}
        for inp in form.inputs:
            name = inp['name']
            orig = baseline_params.get(name, "")
            for payload in XSS_PAYLOADS:
                test_params = baseline_params.copy()
                test_params[name] = orig + payload
                r = safe_get(base_action, params=test_params if form.method=="get" else None,
                             data=test_params if form.method=="post" else None,
                             method=form.method.upper())
                if not r: continue
                text = r.text
                if payload in text:
                    findings.append({
                        "type": "XSS", "param": name, "payload": payload,
                        "evidence": "Payload reflected in response",
                        "url": base_action, "severity": "Medium"
                    })
                    break
        return findings
