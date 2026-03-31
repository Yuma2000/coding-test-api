from __future__ import annotations

import base64
import re
from typing import Optional, Dict

from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse

app = FastAPI()

# In-memory user store
users: Dict[str, dict] = {}

# Pre-create test account
users["TaroYamada"] = {
    "user_id": "TaroYamada",
    "password": "PaSSwd4TY",
    "nickname": "たろー",
    "comment": "僕は元気です",
}


def authenticate(authorization: Optional[str]) -> Optional[dict]:
    if not authorization or not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8")
        uid, pwd = decoded.split(":", 1)
    except Exception:
        return None
    user = users.get(uid)
    if user and user["password"] == pwd:
        return user
    return None


@app.post("/signup")
async def signup(request: Request):
    body = await request.json()
    user_id = body.get("user_id")
    password = body.get("password")

    # Required check
    if not user_id or not password:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Required user_id and password",
            },
        )

    # Character pattern check
    if not re.fullmatch(r"[a-zA-Z0-9]+", user_id):
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Incorrect character pattern",
            },
        )
    if not re.fullmatch(r"[\x21-\x7e]+", password):
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Incorrect character pattern",
            },
        )

    # Length check
    if not (6 <= len(user_id) <= 20):
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Input length is incorrect",
            },
        )
    if not (8 <= len(password) <= 20):
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Input length is incorrect",
            },
        )

    # Duplicate check
    if user_id in users:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Already same user_id is used",
            },
        )

    users[user_id] = {
        "user_id": user_id,
        "password": password,
        "nickname": user_id,
    }

    return JSONResponse(
        status_code=200,
        content={
            "message": "Account successfully created",
            "user": {
                "user_id": user_id,
                "nickname": user_id,
            },
        },
    )


@app.get("/users/{user_id}")
async def get_user(user_id: str, authorization: Optional[str] = Header(default=None)):
    auth_user = authenticate(authorization)
    if not auth_user:
        return JSONResponse(
            status_code=401, content={"message": "Authentication failed"}
        )

    user = users.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"message": "No user found"})

    result = {"user_id": user["user_id"], "nickname": user.get("nickname", user["user_id"])}
    if "comment" in user and user["comment"] is not None:
        result["comment"] = user["comment"]

    return JSONResponse(
        status_code=200,
        content={"message": "User details by user_id", "user": result},
    )


@app.patch("/users/{user_id}")
async def update_user(
    user_id: str, request: Request, authorization: Optional[str] = Header(default=None)
):
    auth_user = authenticate(authorization)
    if not auth_user:
        return JSONResponse(
            status_code=401, content={"message": "Authentication failed"}
        )

    # Permission check
    if auth_user["user_id"] != user_id:
        return JSONResponse(
            status_code=403, content={"message": "No permission for update"}
        )

    user = users.get(user_id)
    if not user:
        return JSONResponse(status_code=404, content={"message": "No user found"})

    body = await request.json()

    # Check if trying to update user_id or password
    if "user_id" in body or "password" in body:
        return JSONResponse(
            status_code=400,
            content={
                "message": "User updation failed",
                "cause": "Not updatable user_id and password",
            },
        )

    nickname = body.get("nickname")
    comment = body.get("comment")

    # At least one must be provided
    if nickname is None and comment is None:
        return JSONResponse(
            status_code=400,
            content={
                "message": "User updation failed",
                "cause": "Required nickname or comment",
            },
        )

    # Validate lengths and characters
    if nickname is not None:
        if len(nickname) > 30 or re.search(r"[\x00-\x1f\x7f]", nickname):
            return JSONResponse(
                status_code=400,
                content={
                    "message": "User updation failed",
                    "cause": "String length limit exceeded or containing invalid characters",
                },
            )
    if comment is not None:
        if len(comment) > 100 or re.search(r"[\x00-\x1f\x7f]", comment):
            return JSONResponse(
                status_code=400,
                content={
                    "message": "User updation failed",
                    "cause": "String length limit exceeded or containing invalid characters",
                },
            )

    # Apply updates
    if nickname is not None:
        if nickname == "":
            user["nickname"] = user["user_id"]
        else:
            user["nickname"] = nickname

    if comment is not None:
        if comment == "":
            user.pop("comment", None)
        else:
            user["comment"] = comment

    result = {"user_id": user["user_id"], "nickname": user.get("nickname", user["user_id"])}
    if "comment" in user and user["comment"] is not None:
        result["comment"] = user["comment"]

    return JSONResponse(
        status_code=200,
        content={"message": "User successfully updated", "user": result},
    )


@app.post("/close")
async def close(authorization: Optional[str] = Header(default=None)):
    auth_user = authenticate(authorization)
    if not auth_user:
        return JSONResponse(
            status_code=401, content={"message": "Authentication failed"}
        )

    del users[auth_user["user_id"]]

    return JSONResponse(
        status_code=200,
        content={"message": "Account and user successfully removed"},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
