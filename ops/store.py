"""告警台账：去重合并、状态跟踪与复扫验证。

台账是单个 JSON 文件（默认 results/ops/findings.json）。合并规则：
- 同指纹重复出现 → occurrences 累加、更新 last_seen；人工状态不被覆盖；
- verified_fixed 的告警在复扫中再次出现 → 自动 reopened（修复未生效）；
- 已确认/修复中的告警在本次同源扫描中消失 → verified_fixed（修复生效），
  并在 history 里记录复扫证据目录。
"""
import json
import os

from ops.model import Finding

DEFAULT_STORE = os.path.join("results", "ops", "findings.json")


def load(path: str = DEFAULT_STORE) -> dict[str, Finding]:
    if not os.path.exists(path):
        return {}
    raw = json.load(open(path, encoding="utf-8"))
    return {fp: Finding(**item) for fp, item in raw.items()}


def save(store: dict[str, Finding], path: str = DEFAULT_STORE) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump({fp: f.to_dict() for fp, f in store.items()},
              open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def merge(store: dict[str, Finding], fresh: list[Finding], ts: str,
          sources_scanned: set[str], evidence: str) -> dict:
    stats = {"new": 0, "merged": 0, "reopened": 0, "verified_fixed": 0}
    seen_now = set()
    for f in fresh:
        seen_now.add(f.fingerprint)
        old = store.get(f.fingerprint)
        if old is None:
            f.first_seen = f.last_seen = ts
            f.history.append({"ts": ts, "event": "detected", "note": evidence})
            store[f.fingerprint] = f
            stats["new"] += 1
            continue
        old.occurrences += f.occurrences
        old.last_seen = ts
        old.history.append({"ts": ts, "event": "seen_again", "note": evidence})
        stats["merged"] += 1
        if old.status == "verified_fixed":
            old.status = "reopened"
            old.history.append({"ts": ts, "event": "reopened",
                                "note": "已验证修复的告警在复扫中再次出现"})
            stats["reopened"] += 1
    for fp, old in store.items():
        if old.source not in sources_scanned or fp in seen_now:
            continue
        if old.status in ("confirmed", "fixing", "reopened"):
            old.status = "verified_fixed"
            old.history.append({"ts": ts, "event": "verified_fixed",
                                "note": f"复扫未再检出，证据：{evidence}"})
            stats["verified_fixed"] += 1
    return stats
