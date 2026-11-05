"""闭环报告：按状态与等级汇总告警台账，输出 JSON + HTML。"""
import json
import os
from collections import Counter

from ops.model import SEVERITY_ORDER
from ops.store import DEFAULT_STORE, load

OUT_DIR = os.path.join("results", "ops")


def build(store_path: str = DEFAULT_STORE) -> dict:
    store = load(store_path)
    by_status = Counter(f.status for f in store.values())
    by_severity = Counter(f.severity for f in store.values())
    open_items = [f for f in store.values()
                  if f.status in ("new", "confirmed", "fixing", "reopened")]
    summary = {
        "total": len(store),
        "by_status": dict(by_status),
        "by_severity": {s: by_severity.get(s, 0) for s in SEVERITY_ORDER},
        "open": len(open_items),
        "false_positive": by_status.get("false_positive", 0),
        "verified_fixed": by_status.get("verified_fixed", 0),
        "reopened": by_status.get("reopened", 0),
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    json.dump(summary, open(os.path.join(OUT_DIR, "summary.json"), "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    rows = "".join(
        f"<tr><td>{f.severity}</td><td>{f.status}</td><td>{f.source}</td>"
        f"<td>{f.vuln_type}</td><td>{f.location}</td><td>x{f.occurrences}</td>"
        f"<td>{f.remediation}</td></tr>"
        for f in sorted(store.values(),
                        key=lambda x: (SEVERITY_ORDER.index(x.severity), x.location))
    )
    html = f"""<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">
<title>APIProbe 安全运营闭环报告</title></head><body>
<h1>安全运营闭环报告</h1>
<p>告警总数 {summary['total']}｜待处理 {summary['open']}｜误报 {summary['false_positive']}｜
已验证修复 {summary['verified_fixed']}｜复扫重开 {summary['reopened']}</p>
<p>按等级：{summary['by_severity']}</p>
<p>按状态：{summary['by_status']}</p>
<table border="1" cellspacing="0" cellpadding="4">
<tr><th>等级</th><th>状态</th><th>来源</th><th>类型</th><th>位置</th><th>次数</th><th>修复建议</th></tr>
{rows}</table></body></html>"""
    open(os.path.join(OUT_DIR, "report.html"), "w", encoding="utf-8").write(html)
    return summary


if __name__ == "__main__":
    print(build())
