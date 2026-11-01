import argparse
import os
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional, Dict, Tuple, List


@dataclass
class Config:
    target: str
    max_depth: int = 10
    num_workers: int = 3
    rate_limit: float = 0.5
    js_dir: str = "js_files"
    output_dir: str = "results"
    payload_file: Optional[str] = None
    xss_payload_file: Optional[str] = None
    oob_server: Optional[str] = None
    oob_port: int = 8877
    oob_public_host: Optional[str] = None
    browser_cdp: Optional[str] = None
    headless: bool = True
    dry_run: bool = True
    cookies: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    request_catcher_url: Optional[str] = None

    def __post_init__(self):
        os.makedirs(self.js_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)
        parsed = urlparse(self.target)
        self.target_host = parsed.netloc
        self.target_scheme = parsed.scheme or "https"

    def ensure_output_dirs(self):
        os.makedirs(self.js_dir, exist_ok=True)
        os.makedirs(self.output_dir, exist_ok=True)


def parse_args() -> Config:
    parser = argparse.ArgumentParser(description="Obscura Web Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--max-depth", type=int, default=10, help="Maximum crawl depth (default: 10)")
    parser.add_argument("--workers", type=int, default=3, help="Number of concurrent workers (default: 3)")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Delay between requests (default: 0.5)")
    parser.add_argument("--js-dir", default="js_files", help="Directory to save JS files")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--payload-file", help="Path to XSS payload file")
    parser.add_argument("--xss-payload-file", help="Path to XSS payload file (alias)")
    parser.add_argument("--oob", help="OOB server URL for blind XSS")
    parser.add_argument("--oob-port", type=int, default=8877, help="OOB server port (default: 8877)")
    parser.add_argument("--oob-public-host", help="OOB server public host")
    parser.add_argument("--browser-cdp", help="Browser CDP endpoint (e.g., ws://127.0.0.1:9222)")
    parser.add_argument("--no-headless", action="store_true", help="Run browser in visible mode")
    parser.add_argument("--live", action="store_true", help="Enable live active scanning")
    parser.add_argument("--cookie", action="append", help="Cookies in format 'name=value'")
    parser.add_argument("--header", action="append", help="Headers in format 'name:value'")
    parser.add_argument("--request-catcher", help="RequestCatcher URL for OOB detection")

    args = parser.parse_args()

    cookies = {}
    if args.cookie:
        for c in args.cookie:
            if '=' in c:
                name, value = c.split('=', 1)
                cookies[name] = value

    headers = {}
    if args.header:
        for h in args.header:
            if ':' in h:
                name, value = h.split(':', 1)
                headers[name] = value

    payload = args.xss_payload_file or args.payload_file

    return Config(
        target=args.url,
        max_depth=args.max_depth,
        num_workers=args.workers,
        rate_limit=args.rate_limit,
        js_dir=args.js_dir,
        output_dir=args.output,
        payload_file=payload,
        xss_payload_file=payload,
        oob_server=args.oob,
        oob_port=args.oob_port,
        oob_public_host=args.oob_public_host,
        browser_cdp=args.browser_cdp,
        headless=not args.no_headless,
        dry_run=not args.live,
        cookies=cookies if cookies else None,
        headers=headers if headers else None,
        request_catcher_url=args.request_catcher,
    )


def ask_crawl_depth() -> int:
    MAX_DEPTH = 15
    print(f"\n  Crawl depth [0-{MAX_DEPTH}] (0=only start page, default=3): ", end="")
    try:
        val = input().strip()
        if not val:
            return 3
        d = int(val)
        if d < 0:
            d = 0
        if d > MAX_DEPTH:
            print(f"  [!] Max allowed depth is {MAX_DEPTH}. Setting to {MAX_DEPTH}.")
            d = MAX_DEPTH
        return d
    except ValueError:
        print("  [!] Invalid input. Using default depth=3.")
        return 3


def create_target_output_dir(url: str, output_base: str = "results") -> Tuple[str, str]:
    parsed = urlparse(url)
    host = parsed.netloc.replace(':', '_').replace('/', '_')
    target_dir = os.path.join(output_base, host)
    js_dir = os.path.join(target_dir, "js")
    reports_dir = os.path.join(target_dir, "reports")
    os.makedirs(target_dir, exist_ok=True)
    os.makedirs(js_dir, exist_ok=True)
    os.makedirs(reports_dir, exist_ok=True)
    return target_dir, js_dir