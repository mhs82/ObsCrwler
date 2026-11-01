import os
import asyncio
import requests
from urllib.parse import urlparse


class JSDownloader:
    def __init__(self, config, browser_manager):
        self.config = config
        self.browser = browser_manager
        self.js_dir = config.js_dir
        self.url_map = {}
        os.makedirs(self.js_dir, exist_ok=True)

    def get_url_map(self):
        return self.url_map

    async def download_many(self, js_urls: set):
        if not js_urls:
            return

        print(f"\n  [⬇️] Downloading {len(js_urls)} JS files...")
        success_count = 0

        for url in js_urls:
            if url in self.url_map:
                success_count += 1
                continue
            ok = await self._download_single_via_browser(url)
            if not ok:
                ok = self._download_single_via_requests(url)
            if ok:
                success_count += 1

        print(f"  [✅] Downloaded: {success_count}/{len(js_urls)}")

    def _build_output_path(self, url: str) -> str:
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path)

        if not filename.endswith('.js'):
            filename = f"{parsed.netloc.replace('.', '_')}_{filename or 'script'}.js"

        output_path = os.path.join(self.js_dir, filename)
        counter = 1
        base, ext = os.path.splitext(output_path)
        while os.path.exists(output_path):
            output_path = f"{base}_{counter}{ext}"
            counter += 1
        return output_path

    def _save_content(self, url: str, content: str, output_path: str):
        try:
            import jsbeautifier
            content = jsbeautifier.beautify(content)
        except ImportError:
            pass

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

        self.url_map[url] = output_path

    async def _download_single_via_browser(self, url: str) -> bool:
        """
        دانلود از طریق context.request همان Playwright context که قبلاً سایت رو
        با موفقیت کرال کرده — همون cookie/TLS/session معتبر رو داره.

        نکته مهم: از page.goto() استفاده نمی‌کنیم چون Chromium فایل‌های JS/باینری
        رو گاهی به‌عنوان "دانلود فایل" تشخیص می‌ده و response body رو در DOM
        نگه نمی‌داره (خطای "No response body found"). به‌جاش از context.request
        استفاده می‌کنیم که یک HTTP client سطح پایین‌تر و مخصوص همین کاره و از
        همون cookie jar و TLS session مرورگر استفاده می‌کنه.
        """
        try:
            context = self.browser.context
        except Exception:
            return False

        try:
            response = await context.request.get(url, timeout=15000)

            if not response.ok:
                print(f"    [!] Browser download failed for {url[:70]}: status={response.status}")
                return False

            content = await response.text()
            output_path = self._build_output_path(url)
            self._save_content(url, content, output_path)
            return True

        except Exception as e:
            print(f"    [!] Browser download error for {url[:70]}: {type(e).__name__}: {str(e)[:150]}")
            return False

    def _download_single_via_requests(self, url: str) -> bool:
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
            }

            if self.config.cookies:
                cookie_str = "; ".join([f"{k}={v}" for k, v in self.config.cookies.items()])
                headers["Cookie"] = cookie_str

            if self.config.headers:
                headers.update(self.config.headers)

            # سیستم ممکنه یه پروکسی محلی (مثلاً v2ray/Xray روی 127.0.0.1) تنظیم
            # کرده باشه که الان در دسترس نیست. صراحتاً نادیده‌اش می‌گیریم تا
            # درخواست مستقیم به مقصد بره.
            response = requests.get(
                url, headers=headers, timeout=15, verify=False,
                proxies={"http": None, "https": None}
            )
            response.raise_for_status()

            output_path = self._build_output_path(url)
            self._save_content(url, response.text, output_path)
            return True

        except Exception as e:
            print(f"    [!] requests fallback failed for {url[:70]}: {type(e).__name__}: {str(e)}")
            return False