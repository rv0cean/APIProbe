# APIProbe

接口自动化测试与安全缺陷定位工具。针对一个自建 FastAPI 靶机，自动生成接口用例与安全用例、自动执行、按规则聚类失败并定位疑似原因，最终生成一份静态 HTML 报告。

只测本仓库自带的本地靶机，不对任何真实网站或公开 API 发送安全 payload。

## 结构

- `app/` 被测靶机（FastAPI），预置 6 个缺陷，清单见 `docs/defects.md`
- `tests/` pytest 接口测试（功能 + 安全），支持 P0/P1 分级
- `tool/` 用例生成（OpenAPI + 规则 + 安全字典）、缺陷定位规则、HTML 报告生成
- `data/` 安全 payload 字典与定位规则配置
- `results/` 运行结果与报告（生成物，不进版本库）

## 快速开始

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000   # 终端 1：启动靶机
pytest                             # 终端 2：跑全量测试
python -m tool.report              # 生成 results/report.html
python -m tool.generate_cases      # 生成用例统计到 results/generated_cases.json
```

安全测试用例按设计会检出靶机的预置缺陷，因此安全用例失败 = 检出成功，报告里会单独统计检出数，不与功能通过率混算。实测数字见 `docs/results.md`。
