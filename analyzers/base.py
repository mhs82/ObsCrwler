from abc import ABC, abstractmethod
from models import PageData
class BaseAnalyzer(ABC):
    name: str = "base"

    @abstractmethod
    async def analyze(self, page, url: str) -> PageData:
        pass