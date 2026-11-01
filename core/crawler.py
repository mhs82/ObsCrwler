import os
import json
import asyncio
from models import CrawlResult
from config import Config
from core.browser import BrowserManager
from core.scope import ScopeChecker
from analyzers.page_analyzer import PageAnalyzer
from analyzers.js_downloader import JSDownloader
from analyzers.js_analyzer import JSAnalyzer
from analyzers.parameter_aggregator import ParameterAggregator
from analyzers.injection_target_extractor import InjectionTargetExtractor
from analyzers.deduplicator import ResultDeduplicator
from analyzers.tech_analyzer import TechAnalyzer
from scanners.registry import ScannerRegistry
from scanners.active_scanner import ActiveScanner
from scanners.xss_scanner import XSSScanner
from reporters.json_reporter import JSONReporter
from reporters.html_reporter import HTMLReporter
from urllib.parse import urlparse, urljoin
from analyzers.api_detector import APIDetector


class Crawler:
    def __init__(self, config: Config):
        self.config = config
        self.scope = ScopeChecker(config.target)
        self.result = CrawlResult(target=config.target)
        self.scanners = ScannerRegistry()
        self._setup_scanners()
        self.api_detector = APIDetector(config.target)

    def _setup_scanners(self):
        active = ActiveScanner(
            base_url=self.config.target,
            dry_run=True,
            rate_limit=self.config.rate_limit,
        )
        xss = XSSScanner(
            payload_file=self.config.xss_payload_file,
            oob_server=self.config.oob_server,
            request_catcher_url=getattr(self.config, 'request_catcher_url', None),
            target_domain=self.scope.target_host,
        )
        self.scanners.register(active)
        self.scanners.register(xss)
        self.scanners.enable("active", "xss")

    async def run(self):
        print("\n[*] Starting Crawler...")
        self.config.ensure_output_dirs()
        print(f"[*] Output directory: {self.config.output_dir}")

        browser = BrowserManager(self.config)
        await browser.start()

        try:
            print("[*] Browser connected successfully.")

            if self.config.cookies or self.config.headers:
                await browser.validate_authentication()

            js_downloader = JSDownloader(self.config, browser)
            await self._crawl_parallel(browser, js_downloader)

            print(f"\n[*] Phase 1 complete. Visited: {len(self.result.visited_pages)}, Links: {len(self.result.all_links)}")

            if len(self.scope.api_domains) > 1:
                print(f"\n[🔍] API Domains Discovery:")
                print(f"    Found {len(self.scope.api_domains) - 1} API domain(s):")
                for domain in sorted(self.scope.api_domains):
                    if domain != self.scope.target_host:
                        print(f"      ├─ {domain}")

            api_summary = self.api_detector.get_summary()
            if api_summary['api_domains_count'] > 0:
                print(f"\n[🔍] API Architecture Discovery:")
                print(f"    ├─ Base Domain: {api_summary['base_domain']}")
                print(f"    ├─ API Domains Found: {api_summary['api_domains_count']}")
                for domain in api_summary['api_domains']:
                    if domain != self.scope.target_host:
                        print(f"      └─ {domain}")

            self.result.api_domains = api_summary['api_domains']

            print("\n[*] Phase 2: Analyzing JS files...")
            js_analyzer = JSAnalyzer()
            url_map = js_downloader.get_url_map()
            apis, sensitive, websockets = js_analyzer.analyze_all(self.config.js_dir, url_map)
            self.result.js_apis = apis
            self.result.sensitive_paths = sensitive
            self.result.websockets = websockets

            print("\n[*] Phase 2.5: Aggregating parameters...")
            aggregator = ParameterAggregator()
            self.result.parameter_groups = aggregator.aggregate(self.result.all_parameters)
            summary = aggregator.summary(self.result.parameter_groups)
            print(f"  [📊] Parameters:")
            print(f"       Total unique  : {summary['total_unique_params']}")
            print(f"       Sensitive     : {summary['sensitive_named_params']}")

            print("\n[*] Phase 2.6: Technology Fingerprinting...")
            tech_analyzer = TechAnalyzer()
            tech_from_js = tech_analyzer.analyze_js_files(self.config.js_dir)
            self.result.technologies.extend(tech_from_js)

            if self.result.technologies:
                print(f"  [✓] Found {len(self.result.technologies)} technology indicators")
            else:
                print("  [!] No specific technologies identified.")

            print("\n[*] Phase 2.7: Extracting Injection Targets...")
            extractor = InjectionTargetExtractor()
            self.result.injection_targets = extractor.extract(self.result)

            url_targets = sum(1 for t in self.result.injection_targets if t.target_type == "url_param")
            form_targets = sum(1 for t in self.result.injection_targets if t.target_type == "form_input")
            print(f"  [✓] Total Injection Points Found: {len(self.result.injection_targets)}")
            print(f"      ├─ URL Parameters : {url_targets}")
            print(f"      └─ Form Inputs    : {form_targets}")

            print("\n[*] Phase 2.8: Deduplicating all results...")
            deduplicator = ResultDeduplicator()

            pre_links = len(self.result.all_links)
            pre_params = len(self.result.all_parameters)
            pre_forms = len(self.result.all_forms)
            pre_targets = len(self.result.injection_targets)

            deduplicator.deduplicate(self.result)

            print(f"  [✓] Deduplication complete:")
            print(f"      ├─ Links reduced    : {pre_links} -> {len(self.result.all_links)}")
            print(f"      ├─ Parameters       : {pre_params} -> {len(self.result.all_parameters)}")
            print(f"      ├─ Forms            : {pre_forms} -> {len(self.result.all_forms)}")
            print(f"      └─ Injection Targets: {pre_targets} -> {len(self.result.injection_targets)}")

            self._save_intermediate_results()

            print("\n[*] Phase 3: Running scanners...")
            await self._run_scanners(browser.context)

        finally:
            await browser.stop()

        print("\n[*] Phase 4: Generating reports...")
        self._generate_reports()
        self._print_summary()

    async def _crawl_parallel(self, browser: BrowserManager, js_downloader: JSDownloader):
        queue = asyncio.Queue()
        start_url = self.config.target.rstrip('/')
        await queue.put((start_url, 0))
        visited = set()
        lock = asyncio.Lock()
        url_depth_map = {start_url: 0}
        page_analyzer = PageAnalyzer(self.scope, self.api_detector)

        max_depth = getattr(self.config, 'max_depth', None)
        if max_depth is None or max_depth == 10:
            from config import ask_crawl_depth
            max_depth = ask_crawl_depth()
            self.config.max_depth = max_depth

        print(f"\n[*] Crawl starting from: {start_url}")
        print(f"[*] Max depth: {max_depth}")

        async def worker(worker_id: int):
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=5.0)
                except asyncio.TimeoutError:
                    if queue.empty():
                        break
                    continue
                except asyncio.CancelledError:
                    break

                if depth > max_depth:
                    queue.task_done()
                    continue

                print(f"\n[Worker-{worker_id}] [{depth}/{max_depth}] {url[:90]}")

                page = None
                try:
                    try:
                        page = await browser.context.new_page()
                    except Exception as pe:
                        err = str(pe).lower()
                        if any(k in err for k in ['connection', 'closed', 'disconnected', 'websocket', 'target closed']):
                            print(f"[Worker-{worker_id}] ⚠️ CDP disconnected — stopping worker.")
                            queue.task_done()
                            break
                        print(f"[Worker-{worker_id}] [!] Cannot open page: {str(pe)[:80]}")
                        queue.task_done()
                        await asyncio.sleep(self.config.rate_limit)
                        continue

                    response = None
                    for wait_until, timeout in [("domcontentloaded", 20000), ("commit", 10000)]:
                        try:
                            response = await page.goto(url, wait_until=wait_until, timeout=timeout)
                            break
                        except Exception as nav_err:
                            print(f"[Worker-{worker_id}]   nav ({wait_until}): {str(nav_err)[:70]}")
                            continue

                    final_url = response.url if response else page.url
                    status = response.status if response else 0

                    if not final_url or final_url in ("about:blank", ""):
                        print(f"[Worker-{worker_id}] ⚠️ Page failed to load, skipping.")
                        queue.task_done()
                        await asyncio.sleep(self.config.rate_limit)
                        continue

                    print(f"[Worker-{worker_id}]   status={status} final={final_url[:80]}")

                    await page.wait_for_timeout(3000)
                    try:
                        await page.wait_for_selector("body", timeout=3000)
                    except Exception:
                        pass

                    data = await page_analyzer.analyze(page, final_url)

                    print(f"[Worker-{worker_id}]   → links={len(data.links)} forms={len(data.forms)} js={len(data.js_files)} params={len(data.parameters)}")

                    if data.forms:
                        for fi, fm in enumerate(data.forms):
                            fd = fm.to_dict() if hasattr(fm, 'to_dict') else fm
                            print(f"[Worker-{worker_id}]     form[{fi}]: {fd.get('title','?')!r} method={fd.get('method','?')} fields={len(fd.get('inputs',[]))}")

                    candidates = list(data.links)
                    if hasattr(data, 'angular_routes') and data.angular_routes:
                        for r in data.angular_routes:
                            ru = r.get('url', '')
                            if ru:
                                candidates.append(ru)

                    async with lock:
                        self.result.visited_pages.add(final_url)
                        self.result.all_links.update(data.links)
                        self.result.all_forms.extend(data.forms)
                        self.result.all_parameters.extend(data.parameters)
                        self.result.all_js_files.update(data.js_files)

                        added = 0
                        for link in candidates:
                            link = link.split('#')[0].rstrip('/')
                            if not link:
                                continue
                            if not self.scope.is_in_scope(link):
                                continue
                            if link in visited:
                                continue
                            if depth + 1 > max_depth:
                                continue
                            visited.add(link)
                            url_depth_map[link] = depth + 1
                            await queue.put((link, depth + 1))
                            added += 1

                        if added:
                            print(f"[Worker-{worker_id}]   → queued {added} new links (depth {depth+1}/{max_depth})")

                    if data.js_files:
                        await js_downloader.download_many(data.js_files)

                except Exception as e:
                    print(f"[Worker-{worker_id}] [!] Error on {url}: {e}")
                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass
                    queue.task_done()
                    await asyncio.sleep(self.config.rate_limit)

        print(f"[*] Starting {self.config.num_workers} workers...")
        workers = [asyncio.create_task(worker(i)) for i in range(self.config.num_workers)]

        print("[*] Waiting for queue to be fully processed...")
        await queue.join()

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        print(f"\n[*] Crawl done. Visited {len(self.result.visited_pages)} pages.")
        self.result.url_depth_map = url_depth_map

    async def _run_scanners(self, browser_context):
        for scanner in self.scanners.enabled():
            print(f"\n  [*] Running scanner: {scanner.name}")

            if scanner.name == "active":
                if self.result.sensitive_paths:
                    print(f"\n  Active scan mode:")
                    print(f"    [1] Dry-run")
                    print(f"    [2] Live scan")
                    print(f"    [3] Skip")
                    choice = input("  Choice [1/2/3] (default=1): ").strip() or "1"

                    if choice == "2":
                        confirm = input("  Type 'YES' to confirm live scan: ").strip()
                        if confirm != "YES":
                            print("  Cancelled. Using dry-run.")
                            choice = "1"
                    elif choice == "3":
                        continue

                    scanner.dry_run = (choice != "2")
                    self.result.active_scan_results = await scanner.scan(self.result.sensitive_paths)
                else:
                    print("  [!] No sensitive paths to scan.")

            elif scanner.name == "xss":
                if self.result.injection_targets:
                    vulns = await scanner.scan(self.result.injection_targets, browser_context)
                    self.result.vulnerabilities.extend(vulns)
                else:
                    print("  [!] No injection targets found for XSS testing.")

    def _generate_reports(self):
        JSONReporter().generate(self.result, self.config.output_dir)
        HTMLReporter().generate(self.result, self.config.output_dir)

    def _print_summary(self):
        print("\n" + "=" * 60)
        print("📊 CRAWL SUMMARY")
        print("=" * 60)
        print(f"  Pages crawled       : {len(self.result.visited_pages)}")
        print(f"  Unique links        : {len(self.result.all_links)}")
        print(f"  Forms               : {len(self.result.all_forms)}")
        print(f"  Parameterized URLs  : {len(self.result.all_parameters)}")
        print(f"  Injection Targets   : {len(self.result.injection_targets)}")
        print(f"  JS files analyzed   : {len(self.result.all_js_files)}")
        print(f"  Vulnerabilities     : {len(self.result.vulnerabilities)}")

    def _save_intermediate_results(self):
        print("  [*] Saving intermediate results...")
        JSONReporter().generate(self.result, self.config.output_dir)
        HTMLReporter().generate(self.result, self.config.output_dir)
        print(f"  [✓] Intermediate data saved to: {self.config.output_dir}/")
        print(f"\n✅ Results saved in: {self.config.output_dir}/")