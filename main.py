import argparse
import asyncio
import sys
from config import Config, create_target_output_dir
from core.crawler import Crawler


def parse_header(header_str: str) -> tuple[str, str]:
    if ':' not in header_str:
        raise ValueError(f"Invalid header format: {header_str}. Expected 'Name: Value'")
    name, value = header_str.split(':', 1)
    return name.strip(), value.strip()


def parse_cookies(cookie_str: str) -> dict:
    cookies = {}
    for pair in cookie_str.split(';'):
        pair = pair.strip()
        if '=' in pair:
            name, value = pair.split('=', 1)
            cookies[name.strip()] = value.strip()
    return cookies


def main():
    parser = argparse.ArgumentParser(
        description="Obscura Web Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('--oob', default='', help='Out-of-Band server URL for XSS callback')
    parser.add_argument('--request-catcher', default='', help='RequestCatcher URL for OOB detection (e.g., https://shahh.requestcatcher.com/test)')

    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("⚙️  Interactive Scan Configuration")
    print("=" * 60)

    try:
        num_workers = int(input("\n  Number of workers [3]: ").strip() or "3")
    except ValueError:
        num_workers = 3
    print(f"  ✓ Workers: {num_workers}")

    try:
        max_depth = int(input("  Maximum crawl depth [2]: ").strip() or "2")
    except ValueError:
        max_depth = 2
    print(f"  ✓ Depth: {max_depth}")

    output_base = input("  Base output directory [results]: ").strip() or "results"
    print(f"  ✓ Output base: {output_base}")

    payloads_file = input("  XSS payloads file [xss_payloads/payloads.txt]: ").strip() or "xss_payloads/payloads.txt"
    print(f"  ✓ Payloads file: {payloads_file}")

    cookie_input = input("\n  Cookies (format: 'name1=value1; name2=value2') or press Enter to skip: ").strip()
    all_cookies = parse_cookies(cookie_input) if cookie_input else {}
    if all_cookies:
        print(f"  ✓ Cookies loaded: {len(all_cookies)}")
    else:
        print(f"  ✓ No cookies")

    print("\n  Custom headers (format: 'Header-Name: value')")
    print("  Press Enter on empty line to finish:")
    all_headers = {}
    while True:
        header_input = input("    > ").strip()
        if not header_input:
            break
        try:
            name, value = parse_header(header_input)
            all_headers[name] = value
            print(f"      ✓ Added: {name}")
        except ValueError as e:
            print(f"      ✗ Error: {e}")
    
    if all_headers:
        print(f"  ✓ Headers loaded: {len(all_headers)}")
    else:
        print(f"  ✓ No custom headers")

    cdp_url = input("\n  Chrome DevTools Protocol URL [http://127.0.0.1:9222]: ").strip() or "http://127.0.0.1:9222"
    print(f"  ✓ CDP URL: {cdp_url}")

    try:
        rate_limit = float(input("  Delay between requests in seconds [0.5]: ").strip() or "0.5")
    except ValueError:
        rate_limit = 0.5
    print(f"  ✓ Rate limit: {rate_limit}s")

    print("\n" + "=" * 60)
    print("=" * 60 + "\n")

    target_output_dir, target_js_dir = create_target_output_dir(args.url, output_base)
    
    print(f"[*] Target: {args.url}")
    print(f"[*] Target-specific directory: {target_output_dir}")
    print(f"[*] JS files directory: {target_js_dir}")
    
    if args.oob:
        print(f"[*] OOB Server: {args.oob}")
    if args.request_catcher:
        print(f"[*] RequestCatcher URL: {args.request_catcher}")
    
    print()

    config = Config(
        target=args.url,
        num_workers=num_workers,
        max_depth=max_depth,
        output_dir=target_output_dir,
        xss_payload_file=payloads_file,
        browser_cdp=cdp_url,
        rate_limit=rate_limit,
        cookies=all_cookies,
        headers=all_headers,
        js_dir=target_js_dir,
        oob_server=args.oob,
        request_catcher_url=args.request_catcher,
    )

    if all_cookies or all_headers:
        print("=" * 60)
        print("🔐 Authentication Configuration")
        print("=" * 60)
        if all_cookies:
            print(f"  Cookies ({len(all_cookies)}):")
            for name in list(all_cookies.keys())[:5]:
                value = all_cookies[name]
                print(f"    • {name} = {value[:30]}{'...' if len(value) > 30 else ''}")
            if len(all_cookies) > 5:
                print(f"    ... and {len(all_cookies) - 5} more")
        if all_headers:
            print(f"  Custom Headers ({len(all_headers)}):")
            for name, value in all_headers.items():
                print(f"    • {name}: {value[:50]}{'...' if len(value) > 50 else ''}")
        print("=" * 60 + "\n")

    try:
        crawler = Crawler(config)
        asyncio.run(crawler.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[✗] Fatal error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()