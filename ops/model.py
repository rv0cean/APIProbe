"""统一告警模型：不同扫描器的输出都收敛到 Finding。

字段对齐安全运营口径：漏洞类型、风险等级、位置（代码 file:line 或接口
method+path+param）、修复建议、运营状态与历史。
"""
import hashlib
import re
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# 运营状态机：new → confirmed / false_positive → fixing → verified_fixed
# verified_fixed 在复扫中再次出现 → reopened
STATUSES = ["new", "confirmed", "false_positive", "fixing", "verified_fixed", "reopened"]


def norm_severity(raw: str) -> str:
    s = (raw or "").strip().lower()
    return {
        "critical": "critical", "error": "high", "high": "high", "3": "high",
        "warning": "medium", "medium": "medium", "2": "medium",
        "low": "low", "1": "low", "info": "info", "informational": "info",
        "0": "info", "none": "info",
    }.get(s, "info")


def fingerprint(source: str, rule_id: str, location: str) -> str:
    # 归一化：去掉行号后的波动与查询串具体值，同类同位置只算一条告警
    loc = re.sub(r":\d+$", "", location)
    loc = re.sub(r"([?&][^=]+=)[^&]*", r"\1", loc)
    return hashlib.sha1(f"{source}|{rule_id}|{loc}".encode()).hexdigest()[:12]


@dataclass
class Finding:
    source: str            # semgrep / zap
    rule_id: str
    vuln_type: str
    severity: str
    location: str          # app/main.py:73 或 GET http://host/path (param=q)
    message: str
    remediation: str
    fingerprint: str = ""
    status: str = "new"
    occurrences: int = 1
    first_seen: str = ""
    last_seen: str = ""
    history: list = field(default_factory=list)

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.source, self.rule_id, self.location)

    def to_dict(self):
        return asdict(self)
