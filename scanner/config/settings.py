from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ScannerSettings:
    timeout: float = 3.0
    max_threads: int = 100
    max_retries: int = 2
    rate_limit: float = 0.0
    verbose: bool = False
    output_format: str = "console"
    output_file: Optional[str] = None


settings = ScannerSettings()


def get_settings() -> ScannerSettings:
    return settings
