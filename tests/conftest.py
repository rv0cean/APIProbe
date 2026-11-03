import pytest
from fastapi.testclient import TestClient

from app.main import ORDERS, TOKENS, app
from tool.config import current_env


@pytest.fixture(scope="session")
def env_cfg():
    return current_env()


@pytest.fixture()
def client():
    # 每条用例前清理可变状态：保证连跑两遍结果一致（数据隔离）
    TOKENS.clear()
    ORDERS.clear()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def alice_headers(client):
    r = client.post("/auth/login", json={"username": "alice", "password": "alice123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture()
def bob_headers(client):
    r = client.post("/auth/login", json={"username": "bob", "password": "bob123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}
