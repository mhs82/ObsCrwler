from urllib.parse import urlparse
from typing import Dict, List, Set


class APIDetector:
    """تشخیص‌دهنده هوشمند معماری API و دامنه‌های مرتبط"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_host = parsed.netloc
        self.target_scheme = parsed.scheme
        
        self.base_domain = self._extract_base_domain(self.target_host)
        
        self.api_domains: Set[str] = set()
        self.api_domains.add(self.target_host)
        
        self.auth_headers: Dict[str, str] = {}
        
        self.architecture_patterns = {
            'spa_api': {
                'indicators': ['xhr', 'fetch', 'application/json'],
                'description': 'SPA with Separate API Domain'
            },
            'microservices': {
                'indicators': ['/api/', '/v1/', '/v2/', '/rest/'],
                'description': 'Microservices Architecture'
            },
            'gateway': {
                'indicators': ['authorization', 'bearer', 'api-key'],
                'description': 'API Gateway with Authentication'
            }
        }
        
        self.important_headers = {
            'authorization', 'client-id', 'forgery-token', 'session-gateway',
            'withcredentials', 'x-api-key', 'x-auth-token', 'access-token',
            'csrf-token', 'x-csrf-token', 'x-xsrf-token'
        }
    
    def _extract_base_domain(self, host: str) -> str:
        host = host.split(':')[0]
        parts = host.split('.')
        
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return host
    
    def analyze_request(self, url: str, headers: Dict, resource_type: str) -> Dict:
        result = {
            'is_api': False,
            'api_domain': None,
            'auth_headers': {},
            'architecture': None
        }
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path.lower()
        
        # 🔑 تشخیص دامنه API - بهبود یافته
        if resource_type in ['xhr', 'fetch']:
            # بررسی اینکه دامنه متفاوت از تارگت اصلی است
            if domain != self.target_host:
                # 🔑 بررسی هوشمند: ساب‌دامین یا دامنه مرتبط
                domain_clean = domain.split(':')[0]
                target_clean = self.target_host.split(':')[0]
                
                # بررسی اینکه دامنه پایه یکسان است
                if self._is_related_domain(domain_clean):
                    result['is_api'] = True
                    result['api_domain'] = domain
                    
                    # استخراج هدرهای احراز هویت
                    for header_name, header_value in headers.items():
                        if header_name.lower() in self.important_headers:
                            result['auth_headers'][header_name] = header_value
                    
                    # تشخیص معماری
                    if '/api/' in path or '/v1/' in path or '/v2/' in path:
                        result['architecture'] = 'microservices'
                    elif any(h.lower() in headers for h in ['authorization', 'Authorization']):
                        result['architecture'] = 'gateway'
                    else:
                        result['architecture'] = 'spa_api'
        
        return result
    
    def _is_related_domain(self, domain: str) -> bool:
        """بررسی هوشمند ارتباط دامنه"""
        domain_parts = domain.split('.')
        target_parts = self.target_host.split(':')[0].split('.')
        
        # بررسی ساب‌دامین
        if domain.endswith(f".{self.base_domain}"):
            return True
        
        # بررسی دامنه‌های مشابه (مثل apibc.babc.ir و bc.babc.ir)
        if len(domain_parts) >= 2 and len(target_parts) >= 2:
            # بررسی اینکه دو بخش آخر یکسان است
            if domain_parts[-2:] == target_parts[-2:]:
                return True
        
        return False
    
    def register_api_domain(self, domain: str):
        if domain not in self.api_domains:
            self.api_domains.add(domain)
            return True
        return False
    
    def register_auth_headers(self, headers: Dict):
        for header_name, header_value in headers.items():
            if header_name.lower() in self.important_headers:
                if header_name.lower() not in self.auth_headers:
                    self.auth_headers[header_name.lower()] = header_value
    
    def get_api_domains(self) -> List[str]:
        return sorted(list(self.api_domains))
    
    def get_auth_headers(self) -> Dict[str, str]:
        return self.auth_headers.copy()
    
    def get_summary(self) -> Dict:
        return {
            'target': self.target_url,
            'base_domain': self.base_domain,
            'api_domains_count': len(self.api_domains) - 1,
            'api_domains': self.get_api_domains(),
            'auth_headers_count': len(self.auth_headers),
            'auth_headers': list(self.auth_headers.keys())
        }
    
    def is_related_domain(self, domain: str) -> bool:
        return self._is_related_domain(domain)