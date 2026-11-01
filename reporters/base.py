from abc import ABC, abstractmethod
from models import CrawlResult
class BaseReporter(ABC):
    @abstractmethod
    def generate(self, result: CrawlResult, output_path: str):
        pass