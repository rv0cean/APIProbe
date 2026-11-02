"""用例自动生成：解析靶机 OpenAPI -> 规则生成 + 安全字典生成。

生成结果写入 results/generated_cases.json，每条用例标来源
（规则 / 安全字典），统计接口覆盖率。AI 生成层预留在
build_ai_cases()：没有模型接口时返回空列表，流程不因此中断，
生成的用例入库前仍需人工确认（见清单阶段 2）。
"""
import json
from pathlib import Path

import yaml

from app.main import app

ROOT = Path(__file__).resolve().parent.parent

BOUNDARY_VALUES = {
    "string": ["", "a" * 256, "正常值"],
    "integer": [0, -1, 2147483647],
}


def iter_operations(spec):
    for path, methods in spec["paths"].items():
        for method, op in methods.items():
            yield path, method.upper(), op


def build_rule_cases(spec):
    cases = []
    for path, method, op in iter_operations(spec):
        params = op.get("parameters", [])
        for p in params:
            schema = p.get("schema", {})
            ptype = schema.get("type", "string")
            for value in BOUNDARY_VALUES.get(ptype, [""]):
                cases.append({
                    "endpoint": f"{method} {path}",
                    "param": p["name"],
                    "value": str(value)[:40],
                    "kind": "边界/异常",
                    "source": "规则",
                })
        cases.append({"endpoint": f"{method} {path}", "param": "-",
                      "value": "-", "kind": "正常", "source": "规则"})
    return cases


def build_security_cases(spec):
    payloads = yaml.safe_load((ROOT / "data" / "payloads.yaml").read_text(encoding="utf-8"))
    endpoints = {f"{m} {p}" for p, m, _ in iter_operations(spec)}
    cases = []
    mapping = [
        ("injection", "GET /search"),
        ("prompt_injection", "POST /chat"),
        ("idor", "GET /users/{user_id}"),
    ]
    for kind, endpoint in mapping:
        if endpoint not in endpoints:
            continue
        for payload in payloads.get(kind, []):
            cases.append({"endpoint": endpoint, "param": kind,
                          "value": payload[:40], "kind": "安全", "source": "安全字典"})
    return cases


def build_ai_cases(spec):
    """AI 生成层预留：接模型后按接口描述生成 JSON 用例。

    约定输出仍走同一结构，且 source 标为 AI，入库前必须过
    格式校验 + 去重 + 人工确认。当前未接模型，返回空列表。
    """
    return []


def main():
    spec = app.openapi()
    endpoints = [f"{m} {p}" for p, m, _ in iter_operations(spec)]
    cases = build_rule_cases(spec) + build_security_cases(spec) + build_ai_cases(spec)
    seen, deduped = set(), []
    for c in cases:
        key = (c["endpoint"], c["param"], c["value"], c["kind"])
        if key not in seen:
            seen.add(key)
            deduped.append(c)
    out = {
        "endpoints_total": len(endpoints),
        "endpoints": endpoints,
        "cases_total": len(deduped),
        "by_source": {},
        "cases": deduped,
    }
    for c in deduped:
        out["by_source"][c["source"]] = out["by_source"].get(c["source"], 0) + 1
    target = ROOT / "results" / "generated_cases.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"接口 {out['endpoints_total']} 个，生成用例 {out['cases_total']} 条，来源分布 {out['by_source']}")
    print(f"已写入 {target}")


if __name__ == "__main__":
    main()
