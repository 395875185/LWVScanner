# detector/csrf_detector.py
"""
CSRF 检测器（保持轻量且模块化）
策略（heuristic）：
- 针对 method == "post" 的表单：
    - 如果表单中包含 name 中带 "csrf" / "token" / "_token" 的 hidden 字段，则认为有 CSRF token（Low）
    - 否则认为存在潜在 CSRF 风险（Medium）
- 针对 method == "get" 的敏感表单：
    - 如果 action URL 或 input 名称中包含关键字（如 password、change、update、delete 等），则检测 CSRF token
此检测为启发式提示，真实验证需要结合登录/会话流程。
"""

class CSRFDetector:
    # 关键 GET 表单关键字
    CRITICAL_KEYWORDS = ["password", "change", "update", "delete", "set", "config", "security"]

    def __init__(self):
        pass

    def _has_csrf_token(self, form):
        """检查表单是否含有 CSRF token"""
        for inp in form.inputs:
            name = inp.get("name", "").lower()
            typ = inp.get("type", "").lower()
            if typ == "hidden" and ("csrf" in name or "token" in name or "_token" in name):
                return True
        return False

    def _is_critical_get(self, form):
        """判断 GET 表单是否是关键操作"""
        if not form.method or form.method.lower() != "get":
            return False
        # 检查 action URL
        action = form.action.lower() if form.action else ""
        for kw in self.CRITICAL_KEYWORDS:
            if kw in action:
                return True
        # 检查 input 名称
        for inp in form.inputs:
            name = inp.get("name", "").lower()
            for kw in self.CRITICAL_KEYWORDS:
                if kw in name:
                    return True
        return False

    def test_form(self, form):
        """检测表单的 CSRF 风险"""
        findings = []

        method = form.method.lower() if form.method else "get"

        # 对 POST 表单总是检测
        if method == "post" or (method == "get" and self._is_critical_get(form)):
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
                    "evidence": f"{method.upper()} form has no obvious CSRF token",
                    "url": form.action,
                    "severity": "Medium"
                })

        return findings
