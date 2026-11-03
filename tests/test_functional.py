"""功能用例：正常路径与基础异常路径，这些用例应当全部通过。"""

import os

import pytest

# 靶机专用用例：依赖自建靶机的预置数据与缺陷，仅在 dev 环境运行
pytestmark = pytest.mark.skipif(
    os.getenv("APIPROBE_ENV", "dev") != "dev",
    reason="靶机专用用例仅在 dev 环境运行，real 环境请看 test_live_platform.py",
)


@pytest.mark.p0
def test_login_ok(client):
    r = client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    assert r.status_code == 200
    assert r.json()["user_id"] == 1


@pytest.mark.p0
def test_login_wrong_password(client):
    r = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401


@pytest.mark.p0
def test_me_requires_auth(client):
    assert client.get("/users/me").status_code == 401


@pytest.mark.p0
def test_me_ok(client, alice_headers):
    r = client.get("/users/me", headers=alice_headers)
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


@pytest.mark.p1
def test_get_own_user(client, alice_headers):
    r = client.get("/users/1", headers=alice_headers)
    assert r.status_code == 200
    assert r.json()["username"] == "alice"


@pytest.mark.p1
def test_get_missing_user_404(client, alice_headers):
    assert client.get("/users/999", headers=alice_headers).status_code == 404


@pytest.mark.p0
def test_order_flow(client, alice_headers):
    r = client.post("/orders", json={"item": "pen", "quantity": 2}, headers=alice_headers)
    assert r.status_code == 200
    oid = r.json()["id"]
    r2 = client.get(f"/orders/{oid}", headers=alice_headers)
    assert r2.status_code == 200
    assert r2.json()["quantity"] == 2


@pytest.mark.p1
def test_order_not_visible_to_other_user(client, alice_headers, bob_headers):
    r = client.post("/orders", json={"item": "pen", "quantity": 1}, headers=alice_headers)
    oid = r.json()["id"]
    assert client.get(f"/orders/{oid}", headers=bob_headers).status_code == 404


@pytest.mark.p1
def test_search_normal(client, alice_headers):
    r = client.get("/search", params={"q": "ali"}, headers=alice_headers)
    assert r.status_code == 200
    names = [x["username"] for x in r.json()["results"]]
    assert names == ["alice"]


@pytest.mark.p1
def test_chat_normal(client, alice_headers):
    r = client.post("/chat", json={"message": "hello"}, headers=alice_headers)
    assert r.status_code == 200
    assert "SECRET_SYSTEM_PROMPT" not in r.text
