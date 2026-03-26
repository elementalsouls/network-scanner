"""JSON output formatter."""
import json
from datetime import datetime
from typing import Any

from scanner.models.scan_result import ScanResult


class JSONOutput:
    """Output scan results as JSON."""

    def __init__(self, indent: int = 2):
        self.indent = indent

    def _default_serializer(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

    def format(self, result: ScanResult) -> str:
        """Format a ScanResult as a JSON string."""
        return json.dumps(result.to_dict(), indent=self.indent, default=self._default_serializer)

    def write(self, result: ScanResult, filepath: str) -> None:
        """Write JSON output to a file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.format(result))

    def parse(self, json_str: str) -> ScanResult:
        """Parse a JSON string back into a ScanResult."""
        data = json.loads(json_str)
        return ScanResult.from_dict(data)
