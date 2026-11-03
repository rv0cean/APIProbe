"""被测靶机：一个带 6 个预置缺陷的小型 FastAPI 后台。

缺陷清单见 docs/defects.md（D1-D6）。正常接口逻辑先写对，
缺陷只出现在清单登记的位置，便于测试工具逐个检出与定位。
只用于本地测试，不要部署到任何真实环境。
"""
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="APIProbe Target", version="0.1.0")

# 内存假数据：两个普通用户 + 一个管理员口令（仅测试用）
USERS = {
    "alice": {"id": 1, "username": "alice", "password": "alice123", "email": "alice@example.com"},
    "bob": {"id": 2, "username": "bob", "password": "bob123", "email": "bob@example.com"},
}
TOKENS = {}  # token -> username
ORDERS = {}
SYSTEM_PROMPT = "SECRET_SYSTEM_PROMPT: you are a shopping assistant."


class LoginIn(BaseModel):
    username: str
    password: str


class ChatIn(BaseModel):
    message: str


def current_user(authorization: str = Header(default="")) -> dict:
    token = authorization.removeprefix("Bearer ").strip()
    username = TOKENS.get(token)
    if not username:
        raise HTTPException(status_code=401, detail="unauthorized")
    return USERS[username]


@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    # 靶机故意不做兜底：未处理异常直接 500，D3 靠它检出
    return JSONResponse(status_code=500, content={"detail": f"internal error: {exc.__class__.__name__}"})


@app.post("/auth/login")
def login(body: LoginIn):
    user = USERS.get(body.username)
    if not user or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="bad credentials")
    token = f"tok-{body.username}"
    TOKENS[token] = body.username
    return {"token": token, "user_id": user["id"]}


@app.get("/users/me")
def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "username": user["username"], "email": user["email"]}


@app.get("/users/{user_id}")
def get_user(user_id: int, user: dict = Depends(current_user)):
    # D2 越权 IDOR：只校验登录，不校验 user_id 是否属于当前用户
    for u in USERS.values():
        if u["id"] == user_id:
            return {"id": u["id"], "username": u["username"], "email": u["email"]}
    raise HTTPException(status_code=404, detail="user not found")


@app.get("/admin/users")
def admin_users():
    # D1 未鉴权访问：管理接口没有接 current_user 依赖
    return [{"id": u["id"], "username": u["username"], "email": u["email"]} for u in USERS.values()]


@app.get("/search")
def search(q: str = "", user: dict = Depends(current_user)):
    # D4 注入模拟：检测到典型注入片段时“错误地”返回全量数据（仅内存假数据）
    if "' or " in q.lower() or "'='" in q:
        return {"results": [{"id": u["id"], "username": u["username"], "email": u["email"]} for u in USERS.values()]}
    hits = [u for u in USERS.values() if q.lower() in u["username"]]
    return {"results": [{"id": u["id"], "username": u["username"]} for u in hits]}


@app.post("/orders")
async def create_order(request: Request, user: dict = Depends(current_user)):
    body = await request.json()
    item = body.get("item", "book")
    quantity = body.get("quantity", 1)
    # D3 参数校验缺失：quantity<=0 时不拦截，用它做除法触发未处理异常 -> 500
    unit_price = 100
    per_item_fee = unit_price // quantity  # quantity=0 时 ZeroDivisionError
    if quantity < 0:
        raise RuntimeError("negative quantity not handled")
    order_id = len(ORDERS) + 1
    order = {"id": order_id, "user_id": user["id"], "item": item,
             "quantity": quantity, "total": unit_price * quantity + per_item_fee}
    ORDERS[order_id] = order
    return order


@app.get("/orders/{order_id}")
def get_order(order_id: int, user: dict = Depends(current_user)):
    order = ORDERS.get(order_id)
    if not order or order["user_id"] != user["id"]:
        raise HTTPException(status_code=404, detail="order not found")
    return order


@app.get("/slow-report")
def slow_report(user: dict = Depends(current_user)):
    # D5 慢接口：人为延迟 2 秒
    time.sleep(2)
    return {"report": "ok", "rows": 42}


@app.post("/chat")
def chat(body: ChatIn, user: dict = Depends(current_user)):
    msg = body.message.lower()
    # D6 提示注入未拦截：遇到要求泄露系统提示的话术就直接返回系统提示
    if "ignore" in msg or "system prompt" in msg or "系统提示" in body.message:
        return {"answer": SYSTEM_PROMPT}
    return {"answer": f"echo: {body.message}"}
