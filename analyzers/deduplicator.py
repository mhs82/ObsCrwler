from urllib.parse import urlparse, parse_qs
from models import CrawlResult


class ResultDeduplicator:
    def deduplicate(self, result: CrawlResult):
        result.all_links = self._deduplicate_links(result.all_links)
        result.all_parameters = self._deduplicate_parameters(result.all_parameters)
        result.all_forms = self._deduplicate_forms(result.all_forms)
        result.injection_targets = self._deduplicate_injection_targets(result.injection_targets)

    def _deduplicate_links(self, links: set) -> set:
        seen = set()
        unique_links = set()
        
        for link in links:
            try:
                parsed = urlparse(link)
                path = parsed.path.rstrip('/')
                if not path:
                    path = '/'
                
                query = parsed.query
                if query:
                    params = parse_qs(query, keep_blank_values=True)
                    sorted_params = sorted(params.items())
                    query = '&'.join([f"{k}={v[0]}" for k, v in sorted_params])
                
                normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
                if query:
                    normalized += f"?{query}"
                
                if normalized not in seen:
                    seen.add(normalized)
                    unique_links.add(link)
            except Exception:
                unique_links.add(link)
        
        return unique_links

    def _deduplicate_parameters(self, parameters: list) -> list:
        seen = set()
        unique_params = []
        
        for param in parameters:
            p_dict = param.to_dict() if hasattr(param, 'to_dict') else param
            source_url = p_dict.get('source_url', '')
            param_name = p_dict.get('name', '')
            location = p_dict.get('location', 'query')
            
            try:
                parsed = urlparse(source_url)
                path = parsed.path.rstrip('/')
                if not path:
                    path = '/'
                
                key = (path, param_name, location)
                if key not in seen:
                    seen.add(key)
                    unique_params.append(param)
            except Exception:
                unique_params.append(param)
        
        return unique_params

    def _deduplicate_forms(self, forms: list) -> list:
        seen = set()
        unique_forms = []
        
        for form in forms:
            f_dict = form.to_dict() if hasattr(form, 'to_dict') else form
            action = f_dict.get('action', '')
            method = f_dict.get('method', 'GET')
            
            try:
                parsed = urlparse(action)
                path = parsed.path.rstrip('/')
                if not path:
                    path = '/'
                
                inputs = f_dict.get('inputs', [])
                input_names = tuple(sorted([inp.get('name', '') for inp in inputs]))
                
                key = (path, method, input_names)
                if key not in seen:
                    seen.add(key)
                    unique_forms.append(form)
            except Exception:
                unique_forms.append(form)
        
        return unique_forms

    def _deduplicate_injection_targets(self, targets: list) -> list:
        seen = set()
        unique_targets = []
        
        for target in targets:
            try:
                parsed = urlparse(target.url)
                path = parsed.path.rstrip('/')
                if not path:
                    path = '/'
                
                key = (path, target.param_name, target.target_type, target.method)
                if key not in seen:
                    seen.add(key)
                    unique_targets.append(target)
            except Exception:
                unique_targets.append(target)
        
        return unique_targets