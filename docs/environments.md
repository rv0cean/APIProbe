# 环境区分

本项目明确区分两个阶段/环境，避免"只测自建靶机"的误读：

| | dev（开发阶段，默认） | real（真实测试阶段） |
|---|---|---|
| 被测对象 | 仓库自带靶机 `app/`（进程内运行） | 真实平台接口（公网真实服务或自有系统部署） |
| 数据来源 | 预置假数据（alice/bob 等） | 真实服务的数据与契约（OpenAPI / 公开接口文档） |
| 用例 | `test_functional.py`、`test_security.py` | `test_live_platform.py`（标记 `live`） |
| 缺陷预期 | 6 个缺陷已登记（`docs/defects.md`），检出口径确定 | 不预设缺陷；安全类用例只观察与记录，不预设结论 |
| 用途 | 开发工具本身、回归测试、CI | 验证工具在真实网络、真实契约、真实数据下成立 |
| 运行方式 | `pytest` | `APIPROBE_ENV=real pytest -m live` |

切换方式：环境变量 `APIPROBE_ENV=dev|real`，配置定义在 `tool/config.py`；
real 环境的目标地址用 `APIPROBE_BASE_URL` 指定。

注意：real 环境只能对自有或已明确授权的系统做安全类测试；
对第三方公开平台只做只读契约校验（状态码、字段结构、错误格式），不做攻击性探测。
