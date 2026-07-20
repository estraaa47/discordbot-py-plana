import os
from dataclasses import dataclass, field
from typing import Dict, Optional

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    command_prefix: str = field(default_factory=lambda: os.getenv("PREFIX") or "/")
    token: Optional[str] = field(default_factory=lambda: os.getenv("TOKEN"))

    admin_role_id: int = 888839822184153089
    semiadmin_role_id: int = 888817303188287519
    restricted_role_id: int = 1087892271703261316
    bot_role_id: int = 888840043463053333

    role_channel_id: int = 1032650685180813312
    role_message_id: int = 1094422274607689759
    welcome_channel_id: int = 1087554522378948609
    reaction_roles: Dict[str, int] = field(
        default_factory=lambda: {
            "🇴": 1087692814462242816,
            "🇻": 1087691245868032010,
            "🇦": 1087692165242683392,
            "🇱": 1087693182441099275,
            "🇪": 1087693438423666809,
            "🅾️": 1087693693122773054,
        }
    )

    max_message_length: int = 300
    spam_window_seconds: int = 2
    spam_message_limit: int = 3
    state_expiration_seconds: int = 3600


SETTINGS = Settings()
