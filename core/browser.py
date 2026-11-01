import asyncio
import warnings
from typing import Optional
from urllib.parse import urlparse, urlunparse
from playwright.async_api import async_playwright, Browser, BrowserContext, Playwright

warnings.filterwarnings('ignore', message='Unverified HTTPS request')


class BrowserManager:
    def __init__(self, config):
        self.config = config
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None

    @property
    def context(self) -> BrowserContext:
        if self._context is None:
            raise RuntimeError("Browser not started. Call start() first.")
        return self._context

    @property
    def browser(self) -> Browser:
        if self._browser is None:
            raise RuntimeError("Browser not started. Call start() first.")
        return self._browser

    async def start(self):
        print(f"\n[*] Starting browser...")
        
        self._playwright = await async_playwright().start()
        
        if self.config.browser_cdp:
            print(f"    Connecting to CDP: {self.config.browser_cdp}")
            self._browser = await self._playwright.chromium.connect_over_cdp(
                self.config.browser_cdp
            )
            contexts = self._browser.contexts
            if contexts:
                self._context = contexts[0]
                print(f"    [+] Using existing context from CDP")
            else:
                self._context = await self._browser.new_context()
                print(f"    [+] Created new context in CDP")

            if self.config.cookies:
                print(f"    [+] Adding {len(self.config.cookies)} cookie(s) to CDP context...")
                parsed_target = urlparse(self.config.target)
                domain = parsed_target.netloc.split(':')[0]
                cookies_to_add = []
                for name, value in self.config.cookies.items():
                    cookies_to_add.append({
                        'name': name,
                        'value': value,
                        'domain': domain,
                        'path': '/',
                        'secure': parsed_target.scheme == 'https',
                        'httpOnly': False,
                        'sameSite': 'Lax',
                    })
                    if '.' in domain:
                        parts = domain.split('.')
                        if len(parts) >= 2:
                            base_domain = '.' + '.'.join(parts[-2:])
                            cookies_to_add.append({
                                'name': name,
                                'value': value,
                                'domain': base_domain,
                                'path': '/',
                                'secure': parsed_target.scheme == 'https',
                                'httpOnly': False,
                                'sameSite': 'Lax',
                            })
                await self._context.add_cookies(cookies_to_add)
                print(f"    [+] Added {len(cookies_to_add)} cookie entries")
                browser_cookies = await self._context.cookies()
                print(f"    [+] CDP context now has {len(browser_cookies)} cookie(s):")
                for c in browser_cookies[:10]:
                    print(f"        ├─ {c['name']} @ {c['domain']}")
        else:
            print(f"    Launching new Chromium instance...")
            self._browser = await self._playwright.chromium.launch(
                headless=getattr(self.config, 'headless', True),
                args=[
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-blink-features=AutomationControlled',
                ]
            )
            
            context_options = {
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:152.0) Gecko/20100101 Firefox/152.0',
                'viewport': {'width': 1920, 'height': 1080},
                'locale': 'fa-IR',
                'timezone_id': 'Asia/Tehran',
                'ignore_https_errors': True,
            }
            
            if self.config.headers:
                context_options['extra_http_headers'] = self.config.headers
            
            self._context = await self._browser.new_context(**context_options)
            
            if self.config.cookies:
                cookies = []
                parsed_target = urlparse(self.config.target)
                domain = parsed_target.netloc.split(':')[0]
                print(f"    [+] Received {len(self.config.cookies)} cookie(s):")
                for name, value in self.config.cookies.items():
                    print(f"        ├─ {name} = {value[:20]}...")
                for name, value in self.config.cookies.items():
                    cookies.append({
                        'name': name,
                        'value': value,
                        'domain': domain,
                        'path': '/',
                        'secure': parsed_target.scheme == 'https',
                        'httpOnly': False,
                        'sameSite': 'Lax',
                    })
                    if '.' in domain:
                        parts = domain.split('.')
                        if len(parts) >= 2:
                            base_domain = '.' + '.'.join(parts[-2:])
                            cookies.append({
                                'name': name,
                                'value': value,
                                'domain': base_domain,
                                'path': '/',
                                'secure': parsed_target.scheme == 'https',
                                'httpOnly': False,
                                'sameSite': 'Lax',
                            })
                await self._context.add_cookies(cookies)
                print(f"    [+] Added {len(cookies)} cookie entries for domain: {domain}")
            
            print(f"    [+] New browser context created")
        
        print(f"[+] Browser ready")

    async def validate_authentication(self) -> bool:
        if not self.config.cookies:
            print(f"\n[⚠️] No cookies provided, skipping authentication validation")
            return True
        
        print(f"\n[*] Validating authentication...")
        print(f"    Target URL: {self.config.target}")
        print(f"    Cookies   : {list(self.config.cookies.keys())}")
        
        try:
            browser_cookies = await self._context.cookies()
            print(f"    [Debug] Browser has {len(browser_cookies)} cookie(s)")
            
            cookie_names = [c['name'] for c in browser_cookies]
            for name in self.config.cookies.keys():
                if name in cookie_names:
                    print(f"    [✓] Cookie '{name}' found in browser")
                else:
                    print(f"    [!] Cookie '{name}' NOT found in browser!")
            
            page = await self._context.new_page()
            try:
                print(f"    [1/2] Navigating to target (timeout=90s)...")
                response = None
                try:
                    response = await page.goto(
                        self.config.target, 
                        wait_until="domcontentloaded", 
                        timeout=90000
                    )
                except Exception as nav_err:
                    print(f"    [!] Navigation error: {type(nav_err).__name__}: {str(nav_err)[:100]}")
                    print(f"    [!] Trying with 'commit' wait_until...")
                    try:
                        response = await page.goto(
                            self.config.target,
                            wait_until="commit",
                            timeout=90000
                        )
                    except Exception as nav_err2:
                        print(f"    [!] Second navigation failed: {str(nav_err2)[:100]}")
                
                try:
                    final_url = page.url
                    content = await page.content()
                    status = response.status if response else "N/A (no response object)"
                    
                    print(f"    ├─ Status: {status}")
                    print(f"    ├─ Final URL: {final_url[:80]}")
                    print(f"    ├─ Content length: {len(content)} chars")
                    
                    login_indicators = ['/login', '/signin', '/auth', '/wp-login', 
                                       '/admin/login', 'login.php', '/accounts/login']
                    is_login_page = any(indicator in final_url.lower() for indicator in login_indicators)
                    
                    if is_login_page:
                        print(f"    [✗] Redirected to login page!")
                        return False
                    
                    logout_indicators = ['logout', 'خروج', 'sign out', '/logout']
                    has_logout = any(ind in content.lower() for ind in logout_indicators)
                    if has_logout:
                        print(f"    [✓] Logout link found - authentication confirmed")
                        return True
                    
                    if len(content) > 1000:
                        print(f"    [✓] Page has content ({len(content)} chars) - authentication appears valid")
                        return True
                    
                    print(f"    [!] Page content is short ({len(content)} chars)")
                    return True
                except Exception as content_err:
                    print(f"    [!] Cannot get page content: {type(content_err).__name__}: {str(content_err)[:100]}")
                    return True
            finally:
                await page.close()
        except Exception as e:
            print(f"    [!] Validation error: {type(e).__name__}: {str(e) or 'no message'}")
            print(f"    [!] Continuing with crawl anyway...")
            return True

    async def stop(self):
        print(f"\n[*] Cleaning up browser resources...")
        
        if self._context:
            try:
                await self._context.close()
                print(f"  [-] Browser context closed.")
            except Exception as e:
                print(f"  [!] Error closing context: {e}")
        
        if self._browser:
            try:
                if not self.config.browser_cdp:
                    await self._browser.close()
                print(f"  [-] Disconnected from browser.")
            except Exception as e:
                print(f"  [!] Error closing browser: {e}")
        
        if self._playwright:
            try:
                await self._playwright.stop()
                print(f"  [-] Playwright instance stopped.")
            except Exception as e:
                print(f"  [!] Error stopping playwright: {e}")