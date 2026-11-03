# APIProbe

面向安全运营的扫描与漏洞闭环工具：接入 **Semgrep（SAST）** 与 **OWASP ZAP（DAST）**，
用 Python 做扫描调度与报告解析，把多来源告警收敛为统一台账，完成
「告警 → 确认 → 整改 → 复扫验证」的运营闭环；同时内置接口自动化测试内核
（用例生成、执行、缺陷定位）。

设计目标是解决安全运营里三个常见问题：**告警量大**（同指纹重复告警自动合并计数）、
**误报高**（人工确认与误报标记，状态不被复扫覆盖）、**修复难闭环**
（修复后同源复扫自动判定 `verified_fixed` / `reopened`，原始报告按时间戳留存证据）。

## 结构

- `ops/` 安全运营层：扫描调度（`scan.py`）、统一告警模型（`model.py`）、
  Semgrep/ZAP 报告解析（`parse.py`）、告警台账与状态机（`store.py`）、
  运营 CLI（`triage.py`）、闭环报告（`report.py`）；设计见 `docs/secops-loop.md`
- `app/` 被测示例服务（FastAPI），预置 6 个缺陷，清单见 `docs/defects.md`
- `tests/` pytest 接口测试（功能 + 安全），支持 P0/P1 分级
- `tool/` 用例生成（OpenAPI + 规则 + 安全字典）、缺陷定位规则、HTML 报告生成
- `data/` 安全 payload 字典与定位规则配置
- `results/` 运行结果、台账与扫描证据（生成物，不进版本库）

## 快速开始

接口测试内核：

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest                             # 跑全量测试（进程内直连被测服务）
python -m tool.report              # 生成 results/report.html
python -m tool.generate_cases      # 生成用例统计到 results/generated_cases.json
```

安全运营闭环：

```bash
pip install -r requirements-scanners.txt   # Semgrep（建议装进独立虚拟环境）
# OWASP ZAP 为外部程序：安装后设置 ZAP_HOME 与 JAVA_HOME
python -m ops.scan                 # SAST + DAST：调度、解析、合并入台账、出闭环报告
python -m ops.triage list          # 查看告警台账
python -m ops.triage set <指纹> confirmed --note "已派单整改"
# 整改后再次 python -m ops.scan 即复扫验证，结论与证据自动写入台账
```

安全测试用例按设计会检出被测示例服务的预置缺陷，因此其安全用例失败 = 检出成功，
报告里单独统计检出数，不与功能通过率混算。实测数字见 `docs/results.md`，
闭环机制与本地实测留痕见 `docs/secops-loop.md`。

## 使用边界

- DAST 默认只扫本地隔离启动的示例服务；`--target-url` 仅用于自有或已明确授权的系统。
- 对第三方公开平台只做只读契约校验，不发送攻击性 payload。
