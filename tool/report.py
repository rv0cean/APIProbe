"""缺陷定位与报告：跑 pytest -> 解析结果 -> 按规则聚类定位 -> 生成 HTML 报告。

口径（重要）：
- 功能用例失败 = 真失败，计入功能通过率。
- 安全用例断言的是安全行为，失败 = 检出一个预置缺陷，
  按 docs/defects.md 的 D1-D6 统计检出数，不计入功能通过率。
"""
import json
import subprocess
import sys
import defusedxml.ElementTree as ET  # Semgrep 整改：防 XXE/实体注入
from collections import defaultdict
from pathlib import Path

import yaml
from jinja2 import Template

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

TEMPLATE = """<!DOCTYPE html>
<html lang="zh"><head><meta charset="utf-8"><title>APIProbe 测试报告</title>
<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}
td,th{border:1px solid #ccc;padding:4px 10px}.high{color:#b00}.mid{color:#a60}.low{color:#555}</style>
</head><body>
<h1>APIProbe 测试报告</h1>
<p>功能用例：{{ func_total }} 条，通过 {{ func_passed }} 条，通过率 {{ func_rate }}%</p>
<p>安全检出：预置缺陷 {{ defects_total }} 个，检出 {{ defects_found }} 个</p>
<p>全部用例总耗时：{{ total_time }}s，最慢用例：{{ slowest }}</p>
<h2>失败聚类与疑似定位（按风险排序）</h2>
<table><tr><th>风险</th><th>缺陷</th><th>疑似原因</th><th>失败用例</th><th>数量</th></tr>
{% for c in clusters %}<tr><td class="{{ c.risk_class }}">{{ c.risk }}</td><td>{{ c.defect }}</td>
<td>{{ c.cause }}</td><td>{{ c.tests | join('<br>') }}</td><td>{{ c.tests | length }}</td></tr>
{% endfor %}</table>
</body></html>"""


def run_pytest():
    RESULTS.mkdir(exist_ok=True)
    cmd = [sys.executable, "-m", "pytest", "-q",
           f"--junitxml={RESULTS / 'junit.xml'}"]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    print(proc.stdout[-500:])
    return RESULTS / "junit.xml"


def locate(test_name, rules_cfg):
    for rule in rules_cfg["rules"]:
        if rule["match"] in test_name:
            return rule
    d = rules_cfg["default"]
    return {"cause": d["cause"], "risk": d["risk"], "defect": d["defect"]}


def main():
    junit = run_pytest()
    rules_cfg = yaml.safe_load((ROOT / "data" / "locating_rules.yaml").read_text(encoding="utf-8"))
    root = ET.parse(junit).getroot()
    suite = root.find("testsuite") if root.tag == "testsuites" else root

    func_total = func_passed = 0
    security_total = 0
    detected = set()
    clusters = defaultdict(list)
    times = {}
    for case in suite.iter("testcase"):
        name = case.get("name")
        classname = case.get("classname")
        failed = case.find("failure") is not None or case.find("error") is not None
        times[name] = float(case.get("time", 0))
        is_security = "test_security" in classname
        if is_security:
            security_total += 1
            if failed:
                rule = locate(name, rules_cfg)
                if rule["defect"] != "-":
                    detected.add(rule["defect"])
                clusters[(rule["risk"], rule["defect"], rule["cause"])].append(name)
        else:
            func_total += 1
            if not failed:
                func_passed += 1
            elif failed:
                rule = locate(name, rules_cfg)
                clusters[(rule["risk"], rule["defect"], rule["cause"])].append(name)

    risk_order = {"高": 0, "中": 1, "低": 2}
    risk_class = {"高": "high", "中": "mid", "低": "low"}
    cluster_list = [
        {"risk": r, "defect": d, "cause": c, "tests": t, "risk_class": risk_class.get(r, "mid")}
        for (r, d, c), t in sorted(clusters.items(), key=lambda kv: risk_order.get(kv[0][0], 1))
    ]
    summary = {
        "func_total": func_total,
        "func_passed": func_passed,
        "func_rate": round(100 * func_passed / func_total, 1) if func_total else 0,
        "security_cases": security_total,
        "defects_total": 6,
        "defects_found": len(detected),
        "detected": sorted(detected),
        "total_time_s": round(sum(times.values()), 2),
        "slowest": max(times, key=times.get) if times else "-",
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    html = Template(TEMPLATE).render(
        func_total=summary["func_total"], func_passed=summary["func_passed"],
        func_rate=summary["func_rate"], defects_total=6,
        defects_found=summary["defects_found"], total_time=summary["total_time_s"],
        slowest=summary["slowest"], clusters=cluster_list)
    (RESULTS / "report.html").write_text(html, encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    print(f"报告已写入 {RESULTS / 'report.html'}")


if __name__ == "__main__":
    main()
