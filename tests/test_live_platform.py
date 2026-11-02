"""真实平台接口用例：仅在 APIPROBE_ENV=real 时运行。

被测对象是 GitHub 官方 REST API（真实平台、真实数据），校验工具的
请求、断言与状态码处理在真实网络与真实契约下同样成立。
"""
import httpx
import pytest

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        __import__("os").getenv("APIPROBE_ENV", "dev") != "real",
        reason="真实平台用例仅在 real 环境运行",
    ),
]

GH = "https://api.github.com"


@pytest.fixture(scope="module")
def gh():
    # 显式读取代理：部分沙箱/公司网络的 NO_PROXY 写法会让 httpx 解析环境代理时报错
    _os = __import__("os")
    proxy = _os.getenv("HTTPS_PROXY") or _os.getenv("https_proxy") or None
    verify = _os.getenv("SSL_CERT_FILE") or True  # 沙箱/公司代理自签 CA 时走系统注入的 CA 包
    with httpx.Client(base_url=GH, timeout=15, proxy=proxy, verify=verify, trust_env=False,
                      headers={"Accept": "application/vnd.github+json"}) as c:
        yield c


def test_github_repo_metadata_real(gh):
    r = gh.get("/repos/rv0cean/APIProbe")
    assert r.status_code == 200
    body = r.json()
    assert body["full_name"] == "rv0cean/APIProbe"
    assert body["owner"]["login"] == "rv0cean"
    assert body["default_branch"] == "main"


def test_github_not_found_contract(gh):
    r = gh.get("/repos/rv0cean/this-repo-does-not-exist-404")
    assert r.status_code == 404
    assert r.json()["message"] == "Not Found"


def test_github_rate_limit_contract(gh):
    r = gh.get("/rate_limit")
    assert r.status_code == 200
    resources = r.json()["resources"]
    assert "core" in resources and "limit" in resources["core"]
