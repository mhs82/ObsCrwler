from typing import Dict, Optional
from scanners.base import BaseScanner


class ScannerRegistry:
    def __init__(self):
        self._scanners: Dict[str, BaseScanner] = {}
        self._enabled: set = set()

    def register(self, scanner: BaseScanner):
        self._scanners[scanner.name] = scanner

    def enable(self, *names: str):
        for name in names:
            if name in self._scanners:
                self._enabled.add(name)

    def get(self, name: str) -> Optional[BaseScanner]:
        return self._scanners.get(name)

    def enabled(self) -> list:
        return [self._scanners[name] for name in self._enabled if name in self._scanners]