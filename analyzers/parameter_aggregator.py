"""گروه‌بندی و aggregation پارامترها برای تست Injection"""
from models import Parameter


class ParameterGroup:
    def __init__(self, name: str):
        self.name = name
        self.occurrences = []
        self.unique_urls = set()

    @property
    def total_occurrences(self) -> int:
        return len(self.occurrences)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "total_occurrences": self.total_occurrences,
            "unique_urls_count": len(self.unique_urls),
            "sample_values": [p.sample_value for p in self.occurrences[:5]],
            "is_sensitive": any(self._is_sensitive(p.name) for p in self.occurrences),
        }

    def _is_sensitive(self, name: str) -> bool:
        sensitive = {"id", "user", "user_id", "email", "q", "query", "search", "cmd", "file", "path", "name", "token"}
        return name.lower() in sensitive


class ParameterAggregator:
    """پارامترهای مشابه را در یک گروه جمع می‌کند"""

    def aggregate(self, parameters: list) -> dict:
        groups = {}
        for param in parameters:
            name = param.name
            if not name:
                continue
            if name not in groups:
                groups[name] = ParameterGroup(name=name)
            
            groups[name].occurrences.append(param)
            groups[name].unique_urls.add(param.source_url)
        return groups

    def summary(self, groups: dict) -> dict:
        total = len(groups)
        sensitive = sum(1 for g in groups.values() if any(g._is_sensitive(p.name) for p in g.occurrences))
        return {
            "total_unique_params": total,
            "sensitive_named_params": sensitive,
            "numeric_params": sum(1 for g in groups.values() if g.occurrences and str(g.occurrences[0].sample_value).isdigit()),
            "multi_occurrence_params": sum(1 for g in groups.values() if g.total_occurrences > 1),
        }

    def get_injection_targets(self, groups: dict) -> dict:
        targets = {"high_priority": [], "medium_priority": [], "low_priority": []}
        for name, group in groups.items():
            if not group.occurrences:
                continue
            
            entry = {
                "name": name,
                "urls": list(group.unique_urls)[:5],
                "sample_values": [p.sample_value for p in group.occurrences[:5]],
                "occurrences": group.total_occurrences,
            }
            
            if group._is_sensitive(name):
                targets["high_priority"].append(entry)
            elif group.total_occurrences >= 3:
                targets["medium_priority"].append(entry)
            else:
                targets["low_priority"].append(entry)
        
        for key in targets:
            targets[key].sort(key=lambda x: -x["occurrences"])
        return targets