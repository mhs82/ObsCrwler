from urllib.parse import urlparse, parse_qs, urlencode


class ScopeChecker:
    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.target_host = parsed.netloc
        self.target_scheme = parsed.scheme or "https"
        self.target_path = parsed.path
        self.target_query = parsed.query
        
        host_parts = self.target_host.split('.')
        if host_parts[0].lower() == 'www' and len(host_parts) > 2:
            self.base_domain = '.'.join(host_parts[1:])
        else:
            self.base_domain = self.target_host
        
        self._api_domains = set()
        
        print(f"  [*] Scope Configuration:")
        print(f"      ├─ Host: {self.target_host}")
        print(f"      ├─ Base Domain: {self.base_domain}")
        print(f"      ├─ Scheme: {self.target_scheme}")
        print(f"      ├─ Path: {self.target_path}")
        if self.target_query:
            print(f"      ├─ Query: {self.target_query}")
        print(f"      └─ Base Path: /")

    @property
    def api_domains(self) -> set:
        return self._api_domains

    def add_api_domain(self, domain: str):
        self._api_domains.add(domain)

    def is_in_scope(self, url: str) -> bool:
        if not url:
            return False
        
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        
        if parsed.scheme and parsed.scheme not in ['http', 'https']:
            return False
        
        host = parsed.netloc.lower()
        if not host:
            return False
        
        if host == self.target_host.lower():
            return True
        
        if host.endswith('.' + self.base_domain.lower()):
            return True
        
        for api_domain in self._api_domains:
            if host == api_domain.lower() or host.endswith('.' + api_domain.lower()):
                return True
        
        return False

    def normalize_url(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip('/')
            if not path:
                path = '/'
            
            query = parsed.query
            if query:
                params = parse_qs(query, keep_blank_values=True)
                sorted_params = sorted(params.items())
                query = urlencode(sorted_params, doseq=True)
            
            normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
            if query:
                normalized += f"?{query}"
            
            return normalized
        except Exception:
            return url

    def get_url_pattern(self, url: str) -> str:
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip('/')
            
            parts = path.split('/')
            pattern_parts = []
            
            for part in parts:
                if not part:
                    continue
                
                if part.isdigit():
                    pattern_parts.append('{id}')
                elif len(part) == 32 and all(c in '0123456789abcdef' for c in part.lower()):
                    pattern_parts.append('{hash}')
                elif len(part) > 8 and '-' in part and all(c.isalnum() or c == '-' for c in part):
                    pattern_parts.append('{uuid}')
                else:
                    pattern_parts.append(part)
            
            pattern = '/' + '/'.join(pattern_parts)
            if not pattern.endswith('/'):
                pattern += '/'
            
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{pattern}"
        except Exception:
            return url