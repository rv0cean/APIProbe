# 安全运营闭环设计

针对安全运营中「告警量大、误报高、修复难闭环」的问题，本项目在接口测试内核之上
增加运营层（`ops/`）：

```
扫描调度 ──► 报告解析 ──► 统一告警台账 ──► 人工确认/误报标记 ──► 整改 ──► 复扫验证
 Semgrep      parse.py      store.py          triage.py               (同源扫描
 OWASP ZAP   （统一模型）    去重合并/状态机                          自动判定）
```

## 组成

| 模块 | 职责 |
|---|---|
| `ops/scan.py` | 扫描调度：一条命令执行 Semgrep（SAST）与 OWASP ZAP（DAST，默认本地隔离启动被测服务，也可 `--target-url` 指向已部署环境，须自有/授权） |
| `ops/model.py` | 统一告警模型：漏洞类型、风险等级、位置（代码 `file:line` / 接口 `method+path+param`）、修复建议；指纹 = 来源+规则+归一化位置 |
| `ops/parse.py` | 解析 Semgrep JSON 与 ZAP JSON 到统一模型，CWE 映射修复建议 |
| `ops/store.py` | 告警台账（JSON）：同指纹合并计数、人工状态保护、复扫自动验证/重开 |
| `ops/triage.py` | 运营 CLI：列表、确认、误报标记、状态流转，操作留痕 |
| `ops/report.py` | 闭环报告（JSON+HTML）：按等级/状态统计、待处理/误报/已验证修复/重开 |

## 状态机

`new → confirmed / false_positive → fixing → verified_fixed`；
`verified_fixed` 若在复扫中再次出现，自动置为 `reopened`（修复未生效）；
`confirmed / fixing / reopened` 若在同源复扫中消失，自动置为 `verified_fixed`
并在 history 中记录证据目录。

## 证据

每次扫描的原始报告（semgrep.json / zap.json）与扫描元数据保存在
`results/ops/evidence/<时间戳>/`，台账 history 引用该目录，复扫结论可追溯。

## 运行

```bash
pip install -r requirements.txt        # 项目与报告解析（defusedxml）
pip install semgrep                    # 或独立虚拟环境安装扫描器
export ZAP_HOME=/path/to/ZAP JAVA_HOME=/path/to/jre
python -m ops.scan                     # SAST + DAST 全量
python -m ops.triage list              # 看台账
python -m ops.triage set <指纹> confirmed --note "已派单"
```

## 本地实测留痕（2026-11-03）

- 首扫 Semgrep（官方 p/security-audit + 本地规则集）：4 条新告警；
- 二扫：同指纹全部合并（occurrences 递增、无重复建账），本地规则命中的两行
  硬编码测试口令合并为 1 条；
- 运营处理：1 条确认整改（xml.etree → defusedxml），4 条标记误报并注明理由
  （指纹哈希非密码学用途、健康检查固定地址、靶机预置测试口令）；
- 整改后复扫：确认项自动转 `verified_fixed`，台账待处理归零，证据目录已留存。
- ZAP 实扫在受限沙箱中需开放直连 TCP 权限；CI 环境无此限制，工作流中已配置
  隔离启动被测服务 + ZAP baseline 扫描。
