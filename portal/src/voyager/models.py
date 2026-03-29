from __future__ import annotations

import uuid
from datetime import datetime

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
