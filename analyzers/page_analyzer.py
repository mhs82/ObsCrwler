import re
from urllib.parse import urljoin, urlparse, parse_qs
from analyzers.base import BaseAnalyzer
from analyzers.api_detector import APIDetector
from models import PageData, Form, FormInput, Parameter
from core.scope import ScopeChecker

GENERAL_JUNK_PARAMS = {
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'gclid', 'fbclid', 'msclkid', '_ga', '_gid',
    't', 'v', 'ver', 'version', 'cache', 'nocache', 'timestamp', '_',
    'sessionid', 'jsessionid', 'phpsessid', 'aspnetsessionid',
    '__VIEWSTATE', '__EVENTVALIDATION', 'authenticity_token', 'csrf_token'
}


class PageAnalyzer(BaseAnalyzer):
    name = "page"

    def __init__(self, scope_checker: ScopeChecker, api_detector: APIDetector = None):
        self.scope = scope_checker
        self.api_detector = api_detector or APIDetector(scope_checker.target_host)
        self.network_requests = []

    async def analyze(self, page, url: str) -> PageData:
        data = PageData(url=url)
        await self._start_network_capture(page)
        await page.wait_for_timeout(5000)
        data.forms = await self._extract_forms(page, url)
        data.links = await self._extract_links(page, url)
        data.parameters = self._extract_parameters(data.links)
        data.js_files = await self._extract_js_files(page, url)
        data.angular_routes = await self._extract_angular_routes(page, url)
        angular_forms = await self._extract_angular_forms(page, url)
        data.forms.extend(angular_forms)
        network_forms = await self._extract_forms_from_network(page, url)
        data.forms.extend(network_forms)
        await page.wait_for_timeout(3000)
        data.network_requests = self.network_requests
        self._detect_api_domains(data.network_requests)
        angular_params = self._extract_angular_parameters(data.angular_routes)
        data.parameters.extend(angular_params)
        return data

    async def _start_network_capture(self, page):
        self.network_requests = []

        def on_request(request):
            req_info = {
                'url': request.url,
                'method': request.method,
                'resource_type': request.resource_type,
                'headers': dict(request.headers),
                'post_data': request.post_data,
            }
            self.network_requests.append(req_info)

        def on_response(response):
            for req in self.network_requests:
                if req['url'] == response.url:
                    req['status'] = response.status
                    req['response_headers'] = dict(response.headers)
                    break

        page.on('request', on_request)
        page.on('response', on_response)

    def _detect_api_domains(self, requests_list: list):
        for req in requests_list:
            url = req.get('url', '')
            resource_type = req.get('resource_type', '')
            headers = req.get('headers', {})
            result = self.api_detector.analyze_request(url, headers, resource_type)
            if result['is_api']:
                domain = result['api_domain']
                if self.api_detector.register_api_domain(domain):
                    self.scope.add_api_domain(domain)
                    print(f"      [🔍] API domain discovered: {domain}")
                if result['auth_headers']:
                    self.api_detector.register_auth_headers(result['auth_headers'])
                    for header_name in result['auth_headers'].keys():
                        print(f"      [🔑] Auth header captured: {header_name}")
                parsed = urlparse(url)
                endpoint = parsed.path
                print(f"      [📡] API call: {domain}{endpoint}")

    async def _extract_forms_from_network(self, page, base_url: str) -> list:
        forms = []
        for req in self.network_requests:
            if req.get('method') != 'POST':
                continue
            post_data = req.get('post_data', '')
            if not post_data:
                continue
            url = req.get('url', '')
            content_type = req.get('headers', {}).get('content-type', '')
            inputs = []
            detected_ct = 'application/x-www-form-urlencoded'
            import json
            from urllib.parse import parse_qs as _parse_qs
            parsed_data = None
            if 'application/json' in content_type:
                try:
                    parsed_data = json.loads(post_data)
                    detected_ct = 'application/json'
                except Exception:
                    pass
            if parsed_data is None:
                try:
                    parsed_data = {k: v[0] for k, v in _parse_qs(post_data, keep_blank_values=True).items()}
                    detected_ct = 'application/x-www-form-urlencoded'
                except Exception:
                    pass
            if parsed_data is None:
                try:
                    parsed_data = json.loads(post_data)
                    detected_ct = 'application/json'
                except Exception:
                    pass
            if not parsed_data:
                continue
            for key, value in parsed_data.items():
                inputs.append(FormInput(
                    name=str(key),
                    type='text',
                    value=str(value) if value else '',
                    required=False
                ))
            if inputs:
                forms.append(Form(
                    action=url,
                    method='POST',
                    title=f'Network POST: {urlparse(url).path}',
                    inputs=inputs,
                    source_url=base_url,
                    content_type=detected_ct
                ))
                print(f"    [📡] Found network form: {urlparse(url).path} ({len(inputs)} fields) [{detected_ct}]")
        return forms

    async def _extract_angular_routes(self, page, base_url: str) -> list:
        routes = []
        try:
            has_angular = await page.evaluate("""
            () => {
                return {
                    hasNg: typeof window.ng !== 'undefined',
                    hasAngular: typeof window.angular !== 'undefined',
                    hasGetComponent: typeof window.ng?.getComponent === 'function',
                    appRoot: !!document.querySelector('app-root')
                };
            }
            """)
            print(f"    [🔍] Angular Debug: {has_angular}")
            if not has_angular.get('hasNg'):
                print(f"    [⚠️] Angular not available in production mode")
                return routes
            angular_routes = await page.evaluate("""
            () => {
                const routes = [];
                if (window.ng && window.ng.getComponent) {
                    try {
                        const appRoot = document.querySelector('app-root');
                        if (appRoot) {
                            const component = window.ng.getComponent(appRoot);
                            if (component && component.router) {
                                const extractRoutes = (config, prefix = '') => {
                                    config.forEach(route => {
                                        if (route.path) {
                                            const fullPath = prefix + '/' + route.path;
                                            routes.push({
                                                path: fullPath,
                                                component: route.component?.name || 'Unknown',
                                                data: route.data || {}
                                            });
                                        }
                                        if (route.children) {
                                            extractRoutes(route.children, prefix + '/' + route.path);
                                        }
                                    });
                                };
                                if (component.router.config) {
                                    extractRoutes(component.router.config);
                                }
                            }
                        }
                    } catch (e) {
                        console.error('Angular Router extraction error:', e);
                    }
                }
                return routes;
            }
            """)
            for route in angular_routes:
                path = route.get('path', '')
                if path:
                    absolute_url = urljoin(base_url, path.lstrip('/'))
                    routes.append({
                        'url': absolute_url,
                        'component': route.get('component', ''),
                        'data': route.get('data', {})
                    })
            print(f"    [🛤️] Found {len(routes)} Angular routes")
        except Exception as e:
            print(f"    [!] Error extracting Angular routes: {e}")
        return routes

    async def _extract_angular_forms(self, page, base_url: str) -> list:
        forms = []
        try:
            angular_forms = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('[formGroup], [formGroupName], [formArrayName]').forEach(el => {
                    const inputs = [];
                    el.querySelectorAll('input[formControlName], textarea[formControlName], select[formControlName]').forEach(i => {
                        inputs.push({
                            name: i.getAttribute('formControlName') || '',
                            type: (i.type || 'text').toLowerCase(),
                            id: i.id || '',
                            value: i.value || '',
                            placeholder: i.placeholder || '',
                            required: i.hasAttribute('required')
                        });
                    });
                    if (inputs.length > 0) {
                        forms.push({
                            title: 'Angular Reactive Form',
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });
                document.querySelectorAll('[ngForm], [ngSubmit]').forEach(el => {
                    const inputs = [];
                    el.querySelectorAll('input[ngModel], textarea[ngModel], select[ngModel]').forEach(i => {
                        inputs.push({
                            name: i.getAttribute('name') || i.getAttribute('ngModel') || '',
                            type: (i.type || 'text').toLowerCase(),
                            id: i.id || '',
                            value: i.value || '',
                            placeholder: i.placeholder || '',
                            required: i.hasAttribute('required')
                        });
                    });
                    if (inputs.length > 0) {
                        forms.push({
                            title: 'Angular Template Form',
                            action: window.location.href,
                            method: 'POST',
                            inputs: inputs
                        });
                    }
                });
                return forms;
            }
            """)
            for form_data in angular_forms:
                inputs = []
                for inp in form_data.get("inputs", []):
                    inputs.append(FormInput(
                        name=str(inp.get("name", "")),
                        type=str(inp.get("type", "text")),
                        id=str(inp.get("id", "")),
                        value=str(inp.get("value", "")),
                        placeholder=str(inp.get("placeholder", "")),
                        required=bool(inp.get("required", False))
                    ))
                action = form_data.get("action", "")
                if action:
                    action = urljoin(base_url, action)
                else:
                    action = base_url
                forms.append(Form(
                    action=action,
                    method=str(form_data.get("method", "POST")).upper(),
                    title=str(form_data.get("title", "")),
                    inputs=inputs,
                    source_url=base_url,
                ))
            print(f"    [📝] Found {len(forms)} Angular forms")
        except Exception as e:
            print(f"    [!] Error extracting Angular forms: {e}")
        return forms

    def _extract_angular_parameters(self, routes: list) -> list:
        params = []
        seen = set()
        for route in routes:
            url = route.get('url', '')
            data = route.get('data', {})
            for key, value in data.items():
                if key.lower() not in GENERAL_JUNK_PARAMS:
                    param_key = (url, key)
                    if param_key not in seen:
                        seen.add(param_key)
                        params.append(Parameter(
                            name=str(key),
                            sample_value=str(value),
                            source_url=url,
                            path=urlparse(url).path,
                            location="route_data",
                        ))
        return params

    async def _extract_forms(self, page, base_url: str) -> list:
        try:
            raw_forms = await page.evaluate("""
            () => {
                const forms = [];
                document.querySelectorAll('form').forEach(f => {
                    const inputs = [];
                    f.querySelectorAll('input, textarea, select').forEach(i => {
                        inputs.push({
                            name: i.name || '',
                            type: (i.type || 'text').toLowerCase(),
                            id: i.id || '',
                            value: i.value || '',
                            placeholder: i.placeholder || '',
                            required: !!i.required
                        });
                    });
                    forms.push({
                        title: f.getAttribute('title') || f.getAttribute('name') || f.id || 'Unknown Form',
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        inputs: inputs
                    });
                });
                return forms;
            }
            """)
            print(f"    [📝] Found {len(raw_forms)} HTML forms")
        except Exception as e:
            print(f"    [!] Error extracting forms: {e}")
            raw_forms = []

        forms = []
        for raw in raw_forms:
            inputs = []
            for inp in raw.get("inputs", []):
                inputs.append(FormInput(
                    name=str(inp.get("name", "")),
                    type=str(inp.get("type", "text")),
                    id=str(inp.get("id", "")),
                    value=str(inp.get("value", "")),
                    placeholder=str(inp.get("placeholder", "")),
                    required=bool(inp.get("required", False))
                ))
            action = raw.get("action", "")
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url
            forms.append(Form(
                action=action,
                method=str(raw.get("method", "GET")).upper(),
                title=str(raw.get("title", "")),
                inputs=inputs,
                source_url=base_url,
            ))
        return forms

    async def _extract_links(self, page, base_url: str) -> list:
        raw_links = set()
        js_links_count = 0
        try:
            js_links = await page.evaluate("""
            () => {
                const links = new Set();
                const origin = window.location.origin;
                const toAbs = (u) => {
                    if (!u) return null;
                    try {
                        if (u.startsWith('//')) return window.location.protocol + u;
                        if (u.startsWith('http')) return u;
                        if (u.startsWith('/')) return origin + u;
                        if (u.startsWith('?') || u.startsWith('#')) return window.location.href.split('?')[0] + u;
                        return origin + '/' + u;
                    } catch(e) { return null; }
                };
                const skip = (u) => !u || u.startsWith('mailto:') || u.startsWith('tel:') ||
                    u.startsWith('javascript:') || u === '#' || u.startsWith('data:') ||
                    u.startsWith('blob:') || u.startsWith('void');
                document.querySelectorAll('a[href]').forEach(a => {
                    const h = a.getAttribute('href');
                    if (!skip(h)) links.add(a.href || toAbs(h));
                });
                document.querySelectorAll('area[href]').forEach(a => {
                    const h = a.getAttribute('href');
                    if (!skip(h)) links.add(toAbs(h));
                });
                document.querySelectorAll('form[action]').forEach(f => {
                    const a = f.getAttribute('action');
                    if (a && !skip(a)) links.add(toAbs(a));
                });
                document.querySelectorAll('link[rel="alternate"], link[rel="canonical"], link[rel="next"], link[rel="prev"]').forEach(l => {
                    const h = l.getAttribute('href');
                    if (h && !skip(h)) links.add(toAbs(h));
                });
                document.querySelectorAll('[routerLink], [ng-href], [data-ng-href]').forEach(el => {
                    const u = el.getAttribute('routerLink') || el.getAttribute('ng-href') || el.getAttribute('data-ng-href');
                    if (u && !skip(u)) links.add(toAbs(u));
                });
                document.querySelectorAll('[ui-sref]').forEach(el => {
                    const s = el.getAttribute('ui-sref');
                    if (s) links.add(origin + '/' + s.split('(')[0]);
                });
                const dataAttrs = ['data-url','data-href','data-link','data-action','data-navigate','data-redirect'];
                dataAttrs.forEach(attr => {
                    document.querySelectorAll('[' + attr + ']').forEach(el => {
                        const u = el.getAttribute(attr);
                        if (u && !skip(u)) links.add(toAbs(u));
                    });
                });
                document.querySelectorAll('[onclick]').forEach(el => {
                    const oc = el.getAttribute('onclick') || '';
                    const patterns = [
                        /(?:location\.href|window\.location(?:\.href)?)\s*=\s*['"]([^'"]+)['"]/g,
                        /(?:navigate|open|go)\s*\(\s*['"]([^'"]+)['"]/g,
                        /href\s*[:=]\s*['"]([^'"]+)['"]/g,
                    ];
                    patterns.forEach(p => {
                        let m;
                        while ((m = p.exec(oc)) !== null) {
                            if (!skip(m[1])) links.add(toAbs(m[1]));
                        }
                    });
                });
                ['hx-get','hx-post','hx-put','hx-delete','hx-patch'].forEach(attr => {
                    document.querySelectorAll('[' + attr + ']').forEach(el => {
                        const u = el.getAttribute(attr);
                        if (u && !skip(u)) links.add(toAbs(u));
                    });
                });
                document.querySelectorAll('[\\@click], [x-on\\:click]').forEach(el => {
                    const oc = el.getAttribute('@click') || el.getAttribute('x-on:click') || '';
                    const m = oc.match(/['"](\/[^'"]+)['"]/);
                    if (m) links.add(toAbs(m[1]));
                });
                document.querySelectorAll('meta[http-equiv="refresh"]').forEach(m => {
                    const c = m.getAttribute('content') || '';
                    const match = c.match(/url=([^;'"\s]+)/i);
                    if (match) links.add(toAbs(match[1].replace(/['"]/g, '')));
                });
                document.querySelectorAll('script[src]').forEach(s => {
                    const src = s.getAttribute('src');
                    if (src && !skip(src)) links.add(toAbs(src));
                });
                document.querySelectorAll('iframe[src]').forEach(i => {
                    const src = i.getAttribute('src');
                    if (src && !skip(src) && !src.startsWith('about:')) links.add(toAbs(src));
                });
                document.querySelectorAll('object[data], embed[src]').forEach(o => {
                    const u = o.getAttribute('data') || o.getAttribute('src');
                    if (u && !skip(u)) links.add(toAbs(u));
                });
                return Array.from(links).filter(u => u && u.startsWith('http'));
            }
            """)
            raw_links.update(js_links)
            js_links_count = len(js_links)
        except Exception as e:
            print(f"    [!] JS link extraction error: {str(e)[:80]}")

        try:
            html_content = await page.content()
            import re as _re
            for pat_str in [
                r'href=["\']+([^"\'>\s#][^"\'>]*)["\']+',
                r'action=["\']+([^"\'>\s#][^"\'>]*)["\']+',
            ]:
                for m in _re.finditer(pat_str, html_content, _re.IGNORECASE):
                    u = m.group(1).strip()
                    if u and not any(u.startswith(s) for s in ['mailto:', 'tel:', 'javascript:', 'data:', '#']):
                        raw_links.add(urljoin(base_url, u))
        except Exception:
            pass

        try:
            for req in self.network_requests:
                req_url = req.get('url', '')
                if req_url and self.scope.is_in_scope(req_url):
                    raw_links.add(req_url)
        except Exception:
            pass

        full_links = []
        for link in raw_links:
            try:
                absolute = urljoin(base_url, link)
                parsed = urlparse(absolute)
                if parsed.scheme not in ('http', 'https'):
                    continue
                clean = absolute.split('#')[0]
                if self.scope.is_in_scope(clean):
                    full_links.append(clean)
            except Exception:
                pass

        unique_links = list(set(full_links))
        print(f"    [🔗] Links: {js_links_count} from JS + extras → {len(unique_links)} unique in-scope")
        return unique_links

    def _extract_parameters(self, links: list) -> list:
        params = []
        seen = set()
        for link in links:
            parsed = urlparse(link)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                if name.lower() in GENERAL_JUNK_PARAMS:
                    continue
                sample = values[0] if values else ""
                key = (link, name)
                if key not in seen:
                    seen.add(key)
                    params.append(Parameter(
                        name=str(name),
                        sample_value=str(sample),
                        source_url=link,
                        path=str(parsed.path),
                        location="query",
                    ))
        return params

    async def _extract_js_files(self, page, base_url: str) -> list:
        js_files = set()
        try:
            raw = await page.evaluate("""
            () => {
                const scripts = [];
                document.querySelectorAll('script[src]').forEach(s => {
                    if (s.src && s.src.length > 0) scripts.push(s.src);
                });
                return scripts;
            }
            """)
            for js in raw:
                absolute_js = urljoin(base_url, js)
                js_files.add(absolute_js)
        except Exception as e:
            print(f"    [!] Error extracting JS from DOM: {e}")

        try:
            perf_resources = await page.evaluate("""
            () => {
                return performance.getEntriesByType('resource')
                    .filter(r => {
                        const name = r.name.toLowerCase();
                        return r.initiatorType === 'script' || 
                               name.includes('.js') || 
                               name.includes('scriptresource.axd') ||
                               name.includes('webresource.axd');
                    })
                    .map(r => r.name);
            }
            """)
            for js in perf_resources:
                absolute_js = urljoin(base_url, js)
                js_files.add(absolute_js)
        except Exception as e:
            print(f"    [!] Error extracting JS from Performance API: {e}")

        try:
            html = await page.content()
            patterns = [
                r'<script[^>]+src\s*=\s*["\']?([^"\'\s>]+)["\']?',
            ]
            for pattern in patterns:
                for match in re.findall(pattern, html, re.IGNORECASE):
                    if match and not match.startswith('data:') and not match.startswith('javascript:'):
                        absolute_js = urljoin(base_url, match)
                        js_files.add(absolute_js)
        except Exception as e:
            print(f"    [!] Error extracting JS from HTML: {e}")

        final_js = []
        for js in js_files:
            if self.scope.is_in_scope(js):
                final_js.append(js)

        if final_js:
            print(f"    [✅] Found {len(final_js)} JS files")

        return final_js