"""扫描调度：一条命令跑完 SAST（Semgrep）+ DAST（OWASP ZAP），
解析为统一告警后合并进台账，并生成闭环报告。

用法：
  python -m ops.scan                       # 扫本仓库代码 + 本地启动靶机做 DAST
  python -m ops.scan --skip-dast           # 只做 SAST
  python -m ops.scan --target-url http://staging.example.com   # 对已部署环境做 DAST（须自有/授权）

环境变量：SEMGREP_BIN（默认 PATH 中的 semgrep）、ZAP_HOME（ZAP 安装目录）、
JAVA_HOME（ZAP 需要的 JRE）。原始报告留存在 results/ops/evidence/<时间戳>/ 作为证据。
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

from ops.parse import parse_semgrep, parse_zap
from ops.report import build as build_report
from ops.store import DEFAULT_STORE, load, merge, save

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(cmd, env=None, timeout=900):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT, env=env, timeout=timeout,
                          capture_output=True, text=True)


def run_semgrep(evidence: str, configs: list[str]) -> str:
    out = os.path.join(evidence, "semgrep.json")
    cmd = [os.getenv("SEMGREP_BIN", "semgrep"), "scan", "--json", "--output", out,
           "--metrics", "off", "--exclude", ".venv"]
    for c in configs:
        cmd += ["--config", c]
    cmd += ["app", "tool", "ops"]
    r = _run(cmd)
    if not os.path.exists(out):
        raise SystemExit(f"semgrep 未产出报告：{r.stdout[-500:]} {r.stderr[-500:]}")
    return out


def _wait_ready(url: str, seconds: int = 30) -> bool:
    for _ in range(seconds * 2):
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status < 500:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def run_zap(evidence: str, target_url: str | None) -> tuple[str, str]:
    zap_home = os.getenv("ZAP_HOME", "")
    zap_sh = os.path.join(zap_home, "zap.sh") if zap_home else "zap.sh"
    out = os.path.join(evidence, "zap.json")
    proc = None
    url = target_url
    if url is None:
        url = "http://127.0.0.1:8010"
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", "8010"],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not _wait_ready(url + "/openapi.json"):
            proc.kill()
            raise SystemExit("本地被测服务未能启动")
    env = dict(os.environ)
    if "127.0.0.1" in url or "localhost" in url:
        # ZAP 会继承环境代理：本机目标必须直连，否则代理无法回连 127.0.0.1
        for k in list(env):
            if k.lower() in ("http_proxy", "https_proxy", "all_proxy"):
                env.pop(k)
    if os.getenv("JAVA_HOME"):
        env["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + ":" + env["PATH"]
    try:
        r = _run([zap_sh, "-cmd", "-quickurl", url, "-quickout", out], env=env, timeout=1200)
    finally:
        if proc:
            proc.terminate()
    if not os.path.exists(out):
        raise SystemExit(f"ZAP 未产出报告：{r.stdout[-500:]} {r.stderr[-500:]}")
    return out, url


def main() -> None:
    ap = argparse.ArgumentParser(description="SAST+DAST 扫描调度")
    ap.add_argument("--target-url", help="DAST 目标（默认本地启动被测服务）；须为自有或已授权系统")
    ap.add_argument("--skip-sast", action="store_true")
    ap.add_argument("--skip-dast", action="store_true")
    ap.add_argument("--semgrep-config", action="append",
                    default=[], help="可重复；默认 p/security-audit + 本地规则集")
    args = ap.parse_args()

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    evidence = os.path.join(ROOT, "results", "ops", "evidence", ts)
    os.makedirs(evidence, exist_ok=True)

    fresh, scanned = [], set()
    meta = {"ts": ts, "target": args.target_url or "local-app"}
    if not args.skip_sast:
        configs = args.semgrep_config or ["p/security-audit", "ops/rules/apiprobe-rules.yaml"]
        sg = run_semgrep(evidence, configs)
        got = parse_semgrep(sg)
        fresh += got
        scanned.add("semgrep")
        meta["semgrep_findings"] = len(got)
    if not args.skip_dast:
        zp, url = run_zap(evidence, args.target_url)
        got = parse_zap(zp)
        fresh += got
        scanned.add("zap")
        meta["zap_target"] = url
        meta["zap_findings"] = len(got)
    json.dump(meta, open(os.path.join(evidence, "scan_meta.json"), "w"), indent=2)

    store = load(os.path.join(ROOT, DEFAULT_STORE))
    stats = merge(store, fresh, ts, scanned, evidence)
    save(store, os.path.join(ROOT, DEFAULT_STORE))
    summary = build_report(os.path.join(ROOT, DEFAULT_STORE))
    print(json.dumps({"merge": stats, "ledger": summary, "evidence": evidence},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
