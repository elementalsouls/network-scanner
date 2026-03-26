from dataclasses import dataclass
from typing import Optional, Dict


@dataclass
class ScanProfile:
    name: str
    description: str
    ping_only: bool = False
    ports: Optional[str] = None
    scan_type: str = "connect"
    service_detection: bool = False
    os_detection: bool = False
    timeout: float = 3.0
    max_threads: int = 100
    rate_limit: float = 0.0


PROFILES: Dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        description="Quick ping scan with top 100 ports",
        ping_only=False,
        ports="top100",
        scan_type="connect",
        timeout=2.0,
        max_threads=200,
    ),
    "full": ScanProfile(
        name="full",
        description="Full scan of all 65535 ports",
        ports="all",
        scan_type="connect",
        service_detection=True,
        os_detection=True,
        timeout=5.0,
        max_threads=100,
    ),
    "stealth": ScanProfile(
        name="stealth",
        description="Stealthy SYN scan with rate limiting",
        ports="top1000",
        scan_type="syn",
        rate_limit=0.1,
        max_threads=50,
        timeout=3.0,
    ),
    "service": ScanProfile(
        name="service",
        description="Service and version detection",
        ports="top1000",
        scan_type="connect",
        service_detection=True,
        os_detection=True,
        timeout=5.0,
        max_threads=100,
    ),
}


def get_profile(name: str) -> ScanProfile:
    if name not in PROFILES:
        raise ValueError(f"Unknown profile: {name}. Available: {list(PROFILES.keys())}")
    return PROFILES[name]
