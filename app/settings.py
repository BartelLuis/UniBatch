import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv('DATA_DIR', 'data')))
    demo: bool = field(default_factory=lambda: os.getenv('DEMO_MODE') == 'true')
    writes: bool = field(default_factory=lambda: os.getenv('ENABLE_WRITES') == 'true')
    origin: str = field(default_factory=lambda: os.getenv('APP_ORIGIN', 'https://unifi-batch.intern.example'))
    users_file: str | None = field(default_factory=lambda: os.getenv('USERS_FILE'))
    servers_file: str | None = field(default_factory=lambda: os.getenv('SERVERS_FILE'))
    encryption_key_file: str | None = field(default_factory=lambda: os.getenv('ENCRYPTION_KEY_FILE'))
    ldap_config_file: str | None = field(default_factory=lambda: os.getenv('LDAP_CONFIG_FILE'))
    allowed_controller_hosts: list[str] = field(default_factory=lambda: [v.strip().casefold() for v in os.getenv('ALLOWED_CONTROLLER_HOSTS', '').split(',') if v.strip()])
    inventory_interval: int = field(default_factory=lambda: max(60, int(os.getenv('INVENTORY_INTERVAL', '900'))))
    preview_ttl: int = field(default_factory=lambda: max(300, int(os.getenv('PREVIEW_TTL', '86400'))))

    def __post_init__(self):
        self.data_dir = Path(self.data_dir)
        if self.origin.endswith('/'):
            raise ValueError('APP_ORIGIN must not end in /')
        if not self.demo and not self.origin.startswith('https://'):
            raise ValueError('HTTPS APP_ORIGIN required')
        if self.demo:
            self.writes = True  # simulator only; no real client can be used in this mode
