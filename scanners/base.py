from abc import ABC, abstractmethod
from playwright.async_api import BrowserContext
from models import Vulnerability

class BaseScanner(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    async def scan(self, targets: list, context: BrowserContext) -> list[Vulnerability]:
        pass