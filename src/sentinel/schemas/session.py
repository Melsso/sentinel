from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class SessionResponse(BaseModel):
    id: UUID
    created_at: datetime
    expires_at: datetime
    ip_address: str | None = None
    user_agent: str | None = None
    is_current: bool = False

    model_config = ConfigDict(from_attributes=True)
