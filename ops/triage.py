"""告警运营 CLI：查看台账、人工确认、误报标记与状态流转。

用法：
  python -m ops.triage list [--status confirmed]
  python -m ops.triage set <fingerprint> <status> [--note 备注]
状态：new / confirmed / false_positive / fixing / verified_fixed / reopened
"""
import argparse

from ops.model import STATUSES
from ops.store import DEFAULT_STORE, load, save


def main() -> None:
    ap = argparse.ArgumentParser(description="告警台账运营")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list")
    p_list.add_argument("--status", choices=STATUSES)
    p_set = sub.add_parser("set")
    p_set.add_argument("fingerprint")
    p_set.add_argument("status", choices=STATUSES)
    p_set.add_argument("--note", default="")
    args = ap.parse_args()

    store = load()
    if args.cmd == "list":
        rows = [f for f in store.values() if not args.status or f.status == args.status]
        rows.sort(key=lambda f: (f.severity, f.last_seen))
        for f in rows:
            print(f"{f.fingerprint} [{f.severity:>6}] {f.status:<14} "
                  f"{f.source}/{f.rule_id} {f.location} x{f.occurrences}")
        print(f"共 {len(rows)} 条")
        return
    target = store.get(args.fingerprint)
    if target is None:
        raise SystemExit(f"未找到指纹 {args.fingerprint}")
    target.status = args.status
    target.history.append({"ts": "manual", "event": "triage", "note": args.note or args.status})
    save(store)
    print(f"{args.fingerprint} -> {args.status}")


if __name__ == "__main__":
    main()
