from __future__ import annotations

import hmac
from typing import Any

from werkzeug.security import check_password_hash


def setting(config: Any, name: str, default: Any = "") -> Any:
    if hasattr(config, "get"):
        return config.get(name, default)
    return getattr(config, name, default)


def auth_configured(config: Any) -> bool:
    return bool(setting(config, "ADMIN_USERNAME") and (setting(config, "ADMIN_PASSWORD_HASH") or setting(config, "ADMIN_PASSWORD")))


def authenticate(username: str, password: str, config: Any) -> bool:
    configured_username = str(setting(config, "ADMIN_USERNAME"))
    if not configured_username or not hmac.compare_digest(username, configured_username):
        return False
    password_hash = str(setting(config, "ADMIN_PASSWORD_HASH"))
    if password_hash:
        try:
            return check_password_hash(password_hash, password)
        except ValueError:
            return False
    configured_password = str(setting(config, "ADMIN_PASSWORD"))
    return bool(configured_password) and hmac.compare_digest(password, configured_password)
