from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


def _new_uuid() -> str:
    return str(uuid.uuid4())


class User(BaseModel):
    id: str = Field(default_factory=_new_uuid)
    name: str
    email: str
    created_at: datetime | None = None


class Connection(BaseModel):
    id: str = Field(default_factory=_new_uuid)
    user_id: str
    path_token: str
    label: str
    password: str
    enabled: bool = True
    created_at: datetime | None = None
    # Pydantic Literal validates on construction (`Connection(plugin=...)`). It
    # does NOT validate on `model_copy(update={"plugin": ...})` -- that's
    # documented Pydantic v2 behaviour. The DB-level CHECK constraint in
    # migration 2 is the catch-all defence for any code path that bypasses the
    # Pydantic boundary.
    plugin: Literal["v2ray-plugin", "galoshes"] = "v2ray-plugin"
    # Per-connection ECH mode. No per-instance validation on model_copy() (same
    # Pydantic caveat as `plugin`); the migration-3 CHECK is the catch-all.
    ech: Literal["never", "auto", "always"] = "auto"


class OtpCode(BaseModel):
    id: int | None = None
    email: str
    code_hash: str
    attempts: int = 0
    expires_at: datetime
    used: bool = False


class Session(BaseModel):
    token: str
    user_id: str
    expires_at: str | datetime
