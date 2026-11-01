import re
import json
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set


class PWAAnalyzer:
    """تحلیلگر PWA Manifests و Service Workers"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self.pwa_files = [
            '/ngsw.json',
            '/ngsw-worker.js',
            '/manifest.webmanifest',
            '/manifest.json',
            '/sw.js',
            '/service-worker.js',
            '/precache-manifest.',
            '/workbox-',
        ]
        self.discovered_manifests = {}
        self.extracted_js_urls = set()
        self.extracted_assets = set()
        self.pwa_info = {
            'is_pwa': False,
            'framework': None,
            'version': None,
            'routes': [],
            'navigation_patterns': []
        }
    
    def check_for_pwa_files(self, page) -> List[str]:
        """بررسی وجود فایل‌های PWA در صفحه"""
        discovered = []
        
        try:
            # بررسی تگ‌های link و script در DOM
            pwa_links = page.evaluate("""
            () => {
                const links = [];
                // بررسی manifest link
                document.querySelectorAll('link[rel="manifest"]').forEach(l => {
                    if (l.href) links.push(l.href);
                });
                // بررسی service worker registration
                if ('serviceWorker' in navigator) {
                    links.push('__HAS_SERVICE_WORKER__');
                }
                return links;
            }
            """)
            discovered.extend(pwa_links)
            
            # بررسی URL های احتمالی
            for pwa_path in self.pwa_files:
                test_url = urljoin(self.base_url, pwa_path)
                discovered.append(test_url)
                
        except Exception as e:
            print(f"    [!] Error checking PWA files: {e}")
        
        return discovered
    
    def analyze_ngsw_json(self, content: str, url: str) -> Dict:
        """تحلیل فایل ngsw.json (Angular Service Worker)"""
        result = {
            'type': 'angular_pwa',
            'js_files': [],
            'assets': [],
            'routes': [],
            'version': None,
            'app_data': {}
        }
        
        try:
            data = json.loads(content)
            
            # استخراج نسخه
            if 'appData' in data:
                result['app_data'] = data['appData']
                result['version'] = data['appData'].get('version')
            
            # استخراج JS files از assetGroups
            for group in data.get('assetGroups', []):
                for js_url in group.get('urls', []):
                    if js_url.endswith('.js'):
                        absolute_url = urljoin(url, js_url)
                        result['js_files'].append(absolute_url)
                        self.extracted_js_urls.add(absolute_url)
                    else:
                        absolute_url = urljoin(url, js_url)
                        result['assets'].append(absolute_url)
                        self.extracted_assets.add(absolute_url)
            
            # استخراج navigation patterns
            for nav in data.get('navigationUrls', []):
                if nav.get('positive'):
                    result['routes'].append(nav.get('regex', ''))
            
            # استخراج API patterns از dataGroups
            for data_group in data.get('dataGroups', []):
                for pattern in data_group.get('patterns', []):
                    result['routes'].append(pattern)
            
            self.pwa_info['is_pwa'] = True
            self.pwa_info['framework'] = 'Angular'
            self.pwa_info['version'] = result['version']
            self.pwa_info['routes'] = result['routes']
            
        except json.JSONDecodeError:
            print(f"    [!] Invalid JSON in {url}")
        except Exception as e:
            print(f"    [!] Error analyzing ngsw.json: {e}")
        
        return result
    
    def analyze_webmanifest(self, content: str, url: str) -> Dict:
        """تحلیل فایل manifest.webmanifest"""
        result = {
            'type': 'webmanifest',
            'name': None,
            'short_name': None,
            'icons': [],
            'start_url': None,
            'theme_color': None,
            'background_color': None
        }
        
        try:
            data = json.loads(content)
            result['name'] = data.get('name')
            result['short_name'] = data.get('short_name')
            result['start_url'] = data.get('start_url')
            result['theme_color'] = data.get('theme_color')
            result['background_color'] = data.get('background_color')
            
            for icon in data.get('icons', []):
                icon_url = urljoin(url, icon.get('src', ''))
                result['icons'].append({
                    'url': icon_url,
                    'sizes': icon.get('sizes'),
                    'type': icon.get('type')
                })
            
            self.pwa_info['is_pwa'] = True
            
        except json.JSONDecodeError:
            pass
        except Exception as e:
            print(f"    [!] Error analyzing webmanifest: {e}")
        
        return result
    
    def analyze_service_worker(self, content: str, url: str) -> Dict:
        """تحلیل فایل service worker"""
        result = {
            'type': 'service_worker',
            'cache_names': [],
            'api_endpoints': [],
            'urls': []
        }
        
        try:
            # استخراج cache names
            cache_patterns = [
                r'cacheName\s*[=:]\s*["\']([^"\']+)["\']',
                r'caches\.open\(["\']([^"\']+)["\']',
                r'workbox.*?cacheName["\s:]+["\']([^"\']+)["\']'
            ]
            for pattern in cache_patterns:
                matches = re.findall(pattern, content)
                result['cache_names'].extend(matches)
            
            # استخراج API endpoints
            api_patterns = [
                r'["\'](/api/[^"\']+)["\']',
                r'["\'](https?://[^"\']+/api/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']'
            ]
            for pattern in api_patterns:
                matches = re.findall(pattern, content)
                result['api_endpoints'].extend(matches)
            
            # استخراج URL های precache
            precache_pattern = r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'
            matches = re.findall(precache_pattern, content)
            for match in matches:
                if len(match) > 10 and '/' in match:  # فیلتر کردن مقادیر کوتاه
                    absolute_url = urljoin(url, match)
                    if absolute_url.startswith('http'):
                        result['urls'].append(absolute_url)
                        if match.endswith('.js'):
                            self.extracted_js_urls.add(absolute_url)
            
        except Exception as e:
            print(f"    [!] Error analyzing service worker: {e}")
        
        return result
    
    def get_all_extracted_urls(self) -> Set[str]:
        """دریافت تمام URL های استخراج شده"""
        return self.extracted_js_urls | self.extracted_assets
    
    def get_pwa_summary(self) -> Dict:
        """خلاصه اطلاعات PWA"""
        return {
            'is_pwa': self.pwa_info['is_pwa'],
            'framework': self.pwa_info['framework'],
            'version': self.pwa_info['version'],
            'js_files_count': len(self.extracted_js_urls),
            'assets_count': len(self.extracted_assets),
            'routes': self.pwa_info['routes'][:10],  # فقط 10 تای اول
            'manifests_found': list(self.discovered_manifests.keys())
        }