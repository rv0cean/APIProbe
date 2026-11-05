"""扫描报告解析：Semgrep JSON 与 OWASP ZAP JSON → 统一 Finding。"""
import json
import re

from ops.model import Finding, norm_severity

_CWE_FIX = {
    "89": "使用参数化查询/ORM 绑定变量，禁止字符串拼接 SQL，并做输入白名单校验后复扫。",
    "79": "输出编码与上下文转义，设置 CSP，富文本走白名单清洗后复扫验证。",
    "352": "接入 CSRF Token 校验并校验 Origin/Referer，修复后复扫确认。",
    "798": "移除硬编码凭据，改用环境变量/密钥管理，轮换已泄露凭据后复扫。",
    "327": "替换弱加密算法（MD5/SHA1/DES）为 SHA-256+ 或专用密码哈希（bcrypt/argon2）。",
    "78": "禁止 shell=True 与命令拼接，使用参数数组调用并做输入白名单校验。",
    "94": "禁止 eval/exec 处理外部输入，改用安全的数据结构与解析方式。",
}


def _fix_for(cwe: str, fallback: str = "") -> str:
    m = re.search(r"(\d+)", cwe or "")
    if m and m.group(1) in _CWE_FIX:
        return _CWE_FIX[m.group(1)]
    return fallback or "按扫描器给出的修复建议整改，完成后复扫并保留验证证据。"


def parse_semgrep(path: str) -> list[Finding]:
    data = json.load(open(path, encoding="utf-8"))
    out = []
    for r in data.get("results", []):
        meta = (r.get("extra", {}).get("metadata") or {})
        cwe = ""
        raw_cwe = meta.get("cwe")
        if isinstance(raw_cwe, list) and raw_cwe:
            cwe = str(raw_cwe[0])
        elif raw_cwe:
            cwe = str(raw_cwe)
        loc = f"{r.get('path')}:{r.get('start', {}).get('line', '')}"
        out.append(Finding(
            source="semgrep",
            rule_id=r.get("check_id", "unknown"),
            vuln_type=cwe or meta.get("category", "code-security"),
            severity=norm_severity(r.get("extra", {}).get("severity", "")),
            location=loc,
            message=(r.get("extra", {}).get("message") or "")[:300],
            remediation=_fix_for(cwe),
        ))
    return out


def parse_zap(path: str) -> list[Finding]:
    data = json.load(open(path, encoding="utf-8"))
    sites = data if isinstance(data, list) else data.get("site", [])
    out = []
    for site in sites:
        for a in site.get("alerts", []):
            risk = norm_severity(a.get("risk") or a.get("riskcode", ""))
            insts = a.get("instances") or [{}]
            first = insts[0]
            uri = (first.get("uri") or "").split("?")[0]
            method = first.get("method", "GET")
            param = first.get("param", "")
            loc = f"{method} {uri}" + (f" (param={param})" if param else "")
            f = Finding(
                source="zap",
                rule_id=str(a.get("pluginid", "unknown")),
                vuln_type=a.get("alert", "unknown"),
                severity=risk,
                location=loc,
                message=re.sub(r"<[^>]+>", "", a.get("desc", ""))[:300],
                remediation=re.sub(r"<[^>]+>", "", a.get("solution", ""))[:300]
                or _fix_for(str(a.get("cweid", ""))),
            )
            f.occurrences = len(insts)
            out.append(f)
    return out
