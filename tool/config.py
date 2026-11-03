"""环境配置：区分开发阶段与真实测试阶段。

- dev（默认）：被测对象是仓库自带靶机（进程内 TestClient），数据为预置假数据，
  缺陷已登记，检出口径确定。用在工具本身的开发与回归、CI。
- real：被测对象是真实平台接口（公网真实服务或自有系统部署），通过
  APIPROBE_BASE_URL 指定；用例来自真实服务的 OpenAPI 与公开接口契约，
  不预设缺陷，安全用例只观察不下结论。仅对自有或已授权系统使用。
"""
import os

ENVS = {
    "dev": {"mode": "inprocess", "base_url": None},
    "real": {"mode": "http", "base_url": os.getenv("APIPROBE_BASE_URL", "")},
}


def current_env() -> dict:
    name = os.getenv("APIPROBE_ENV", "dev").lower()
    if name not in ENVS:
        raise ValueError(f"unknown APIPROBE_ENV={name}, expected one of {sorted(ENVS)}")
    cfg = dict(ENVS[name])
    cfg["name"] = name
    return cfg
