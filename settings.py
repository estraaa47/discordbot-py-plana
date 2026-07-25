import os
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    command_prefix: str = field(default_factory=lambda: os.getenv("PREFIX") or "/")
    token: Optional[str] = field(default_factory=lambda: os.getenv("TOKEN"))

    admin_role_id: int = 888839822184153089
    semiadmin_role_id: int = 888817303188287519
    restricted_role_id: int = 1087892271703261316

    max_message_length: int = 300
    spam_window_seconds: int = 2
    spam_message_limit: int = 3
    state_expiration_seconds: int = 3600


SETTINGS = Settings()
