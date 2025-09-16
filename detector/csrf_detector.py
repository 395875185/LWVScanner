# detector/csrf_detector.py
"""
简单的 CSRF 检测器（保持轻量）
策略（heuristic）：
- 针对 method == "post" 的表单：
  - 如果表单中包含 name 中带 "csrf" / "token" / "_token" 的 hidden 字段，则认为有 CSRF token（低风险）
  - 否则认为存在潜在 CSRF 风险（Medium)
此检测为启发式提示，真实验证需要结合登录/会话流程。
"""

class CSRFDetector:
    def __init__(self):
        pass

    def _has_csrf_token(self, form):
        for inp in form.inputs:
            name = inp.get("name", "").lower()
            typ = inp.get("type", "").lower()
            if typ == "hidden" and ("csrf" in name or "token" in name or "_token" in name):
                return True
        return False

    def test_form(self, form):
        findings = []
        # only care about state-changing forms (POST)
        if form.method and form.method.lower() == "post":
            if self._has_csrf_token(form):
                findings.append({
                    "type": "CSRF",
                    "param": None,
                    "payload": None,
                    "evidence": "Form contains a hidden CSRF/token field",
                    "url": form.action,
                    "severity": "Low"
                })
            else:
                findings.append({
                    "type": "CSRF",
                    "param": None,
                    "payload": None,
                    "evidence": "POST form has no obvious CSRF token",
                    "url": form.action,
                    "severity": "Medium"
                })
        # For non-POST forms we return empty (no check)
        return findings
