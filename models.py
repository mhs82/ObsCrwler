from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set, Any


@dataclass
class FormInput:
    name: str = ""
    type: str = "text"
    id: str = ""
    value: str = ""
    placeholder: str = ""
    required: bool = False

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


@dataclass
class Form:
    action: str = ""
    method: str = "GET"
    title: str = ""
    inputs: List[FormInput] = field(default_factory=list)
    source_url: str = ""
    content_type: str = "application/x-www-form-urlencoded"

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "title": self.title,
            "source_url": self.source_url,
            "content_type": self.content_type,
            "inputs": [inp.to_dict() for inp in self.inputs],
        }


@dataclass
class Parameter:
    name: str = ""
    sample_value: str = ""
    source_url: str = ""
    path: str = ""
    location: str = "query"

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class InjectionTarget:
    target_type: str
    url: str
    method: str
    param_name: str
    param_location: str
    sample_value: str
    content_type: str = "application/x-www-form-urlencoded"
    form_title: str = ""
    form_fields: list = None
    form_page_url: str = ""
    crawl_depth: int = 0

    def __post_init__(self):
        if self.form_fields is None:
            self.form_fields = []

    def to_dict(self) -> dict:
        return self.__dict__


@dataclass
class Finding:
    category: str
    severity: str
    match: str
    source: str
    line: Optional[int] = None
    context: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "match": self.match,
            "source": self.source,
            "line": self.line,
            "context": self.context,
            **self.metadata,
        }


@dataclass
class Vulnerability(Finding):
    endpoint: str = ""
    payload: str = ""
    proof: str = ""
    cwe_id: Optional[str] = None
    parameter: str = ""
    exfiltrated_data: Optional[Dict[str, str]] = None


@dataclass
class JSFileInfo:
    url: str
    local_path: str
    file_hash: str
    content: Optional[str] = None


@dataclass
class PageData:
    url: str
    forms: List[Form] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    network_requests: List[dict] = field(default_factory=list)
    pwa_manifests: List[str] = field(default_factory=list)
    angular_routes: List[dict] = field(default_factory=list)


@dataclass
class Technology:
    name: str = ""
    version: str = "N/A"
    source: str = ""
    indicator: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "indicator": self.indicator
        }


@dataclass
class CrawlResult:
    target: str
    visited_pages: Set[str] = field(default_factory=set)
    all_links: Set[str] = field(default_factory=set)
    all_forms: List[Form] = field(default_factory=list)
    all_parameters: List[Parameter] = field(default_factory=list)
    parameter_groups: Dict[str, Any] = field(default_factory=dict)
    injection_targets: List[InjectionTarget] = field(default_factory=list)

    all_js_files: Set[str] = field(default_factory=set)
    js_apis: List[dict] = field(default_factory=list)
    websockets: List[dict] = field(default_factory=list)
    sensitive_paths: List[Finding] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    network_logs: List[dict] = field(default_factory=list)
    active_scan_results: List[dict] = field(default_factory=list)

    technologies: List[Technology] = field(default_factory=list)
    api_domains: List[str] = field(default_factory=list)

    pwa_manifests: Set[str] = field(default_factory=set)
    pwa_extracted_js: Set[str] = field(default_factory=set)
    url_depth_map: Dict[str, int] = field(default_factory=dict)
    pwa_info: Dict = field(default_factory=dict)