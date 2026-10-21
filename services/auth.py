from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import requests

SESSION_COOKIE_NAME = "webdev_app_session"
SESSION_TTL_SECONDS = 8 * 60 * 60

def setting(config: Any, name: str, default: Any = "") -> Any:
    if hasattr(config, "get"):
        return config.get(name, default)
    return getattr(config, name, default)


def auth_configured(config: Any) -> bool:
    return bool(setting(config, "MANUS_PROJECT_ID") and setting(config, "MANUS_OAUTH_PORTAL_URL") and setting(config, "MANUS_OAUTH_API_URL") and setting(config, "MANUS_JWT_SECRET"))


def create_session_token(user: dict[str, Any], config: Any) -> str:
    now = datetime.now(timezone.utc)
    claims = {
        "openId": user.get("openId", ""),
        "name": user.get("name", ""),
        "email": user.get("email", ""),
        "appId": setting(config, "MANUS_PROJECT_ID"),
        "iat": now,
        "exp": now + timedelta(seconds=SESSION_TTL_SECONDS),
    }
    return jwt.encode(claims, config.MANUS_JWT_SECRET, algorithm="HS256")


def decode_session_token(token: str, config: Any) -> dict[str, Any] | None:
    secret = setting(config, "MANUS_JWT_SECRET")
    project_id = setting(config, "MANUS_PROJECT_ID")
    if not token or not secret or not project_id:
        return None
    try:
        claims = jwt.decode(token, secret, algorithms=["HS256"])
        if claims.get("appId") != project_id or not claims.get("openId"):
            return None
        return claims
    except jwt.PyJWTError:
        return None


def exchange_code(code: str, redirect_uri: str, config: Any) -> dict[str, Any]:
    response = requests.post(
        setting(config, "MANUS_OAUTH_API_URL").rstrip("/") + "/webdev.v1.WebDevAuthPublicService/ExchangeToken",
        json={
            "clientId": setting(config, "MANUS_PROJECT_ID"),
            "grantType": "authorization_code",
            "code": code,
            "redirectUri": redirect_uri,
        },
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


def get_user_info(access_token: str, config: Any) -> dict[str, Any]:
    response = requests.post(
        setting(config, "MANUS_OAUTH_API_URL").rstrip("/") + "/webdev.v1.WebDevAuthPublicService/GetUserInfo",
        json={"accessToken": access_token},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()
