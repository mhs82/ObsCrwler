import os
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from models import Finding


class JSAnalyzer:
    def __init__(self):

        self.sensitive_patterns = [
            # ── API Keys & Tokens ──────────────────────────────────────────────
            (r'(?:api[_\-\.]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
             'API Key', 'HIGH'),
            (r'(?:access[_\-]?token|auth[_\-]?token|bearer[_\-]?token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
             'Access Token', 'HIGH'),
            (r'(?:secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
             'Secret Key', 'CRITICAL'),
            (r'(?:private[_\-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.\/\+]{20,})["\']',
             'Private Key', 'CRITICAL'),

            # ── JWT ───────────────────────────────────────────────────────────
            (r'["\']?(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)["\']?',
             'JWT Token', 'CRITICAL'),

            # ── AWS ───────────────────────────────────────────────────────────
            (r'AKIA[0-9A-Z]{16}',
             'AWS Access Key ID', 'CRITICAL'),
            (r'(?:aws[_\-]?secret|aws[_\-]?access[_\-]?key[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9\/\+]{40})["\']',
             'AWS Secret Key', 'CRITICAL'),
            (r'(?:aws[_\-]?region|aws[_\-]?bucket)\s*[:=]\s*["\']([a-zA-Z0-9\-]+)["\']',
             'AWS Config', 'MEDIUM'),

            # ── Google ────────────────────────────────────────────────────────
            (r'AIza[0-9A-Za-z\-_]{35}',
             'Google API Key', 'CRITICAL'),
            (r'["\']?([0-9]+-[a-zA-Z0-9_]{32}\.apps\.googleusercontent\.com)["\']?',
             'Google OAuth Client ID', 'HIGH'),
            (r'(?:google[_\-]?analytics|ga[_\-]?tracking)\s*[:=]\s*["\']?(UA-\d+-\d+|G-[A-Z0-9]+)["\']?',
             'Google Analytics ID', 'LOW'),
            (r'firebase[^"\']*["\']([a-zA-Z0-9_\-]+\.firebaseapp\.com)["\']',
             'Firebase Config', 'MEDIUM'),

            # ── GitHub ────────────────────────────────────────────────────────
            (r'gh[pousr]_[A-Za-z0-9_]{36}',
             'GitHub Token', 'CRITICAL'),
            (r'github[_\-]?token\s*[:=]\s*["\']([a-zA-Z0-9_\-]{36,})["\']',
             'GitHub Token', 'CRITICAL'),

            # ── Stripe / Payment ──────────────────────────────────────────────
            (r'(?:pk_live|sk_live|pk_test|sk_test)_[a-zA-Z0-9]{24,}',
             'Stripe Key', 'CRITICAL'),
            (r'(?:paypal|braintree)[_\-]?(?:client[_\-]?id|secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
             'Payment API Key', 'CRITICAL'),

            # ── Credentials ───────────────────────────────────────────────────
            (r'(?:password|passwd|pass|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']',
             'Hardcoded Password', 'CRITICAL'),
            (r'(?:username|user|login|email)\s*[:=]\s*["\']([^"\'@]{3,}@[^"\']{3,})["\']',
             'Email/Username', 'MEDIUM'),
            (r'(?:db[_\-]?(?:password|pass|pwd)|database[_\-]?password)\s*[:=]\s*["\']([^"\']{6,})["\']',
             'Database Password', 'CRITICAL'),
            (r'(?:db[_\-]?(?:host|server|name)|database[_\-]?(?:host|name))\s*[:=]\s*["\']([^"\']{4,})["\']',
             'Database Config', 'HIGH'),
            (r'(?:connection[_\-]?string|conn[_\-]?str)\s*[:=]\s*["\']([^"\']{10,})["\']',
             'Connection String', 'CRITICAL'),

            # ── Cloud & Infrastructure ────────────────────────────────────────
            (r'(?:azure[_\-]?(?:key|secret|token|connection)|AZURE_)[A-Z_]*\s*[:=]\s*["\']([a-zA-Z0-9_\-\/\+\=]{20,})["\']',
             'Azure Credentials', 'CRITICAL'),
            (r'(?:heroku[_\-]?api[_\-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{25,})["\']',
             'Heroku API Key', 'CRITICAL'),
            (r'(?:slack[_\-]?(?:token|webhook|bot[_\-]?token))\s*[:=]\s*["\']([a-zA-Z0-9_\-\/\.]+)["\']',
             'Slack Token/Webhook', 'HIGH'),
            (r'xox[baprs]-[0-9]+-[0-9]+-[0-9a-zA-Z]+',
             'Slack Bot Token', 'CRITICAL'),
            (r'https://hooks\.slack\.com/services/[a-zA-Z0-9/_\-]+',
             'Slack Webhook URL', 'HIGH'),

            # ── Communication APIs ────────────────────────────────────────────
            (r'(?:twilio[_\-]?(?:account[_\-]?sid|auth[_\-]?token))\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
             'Twilio Credentials', 'CRITICAL'),
            (r'(?:sendgrid[_\-]?api[_\-]?key|SG\.)[a-zA-Z0-9_\-\.]{40,}',
             'SendGrid API Key', 'CRITICAL'),
            (r'(?:mailgun[_\-]?api[_\-]?key)\s*[:=]\s*["\']([a-zA-Z0-9\-]{30,})["\']',
             'Mailgun API Key', 'HIGH'),

            # ── Private Keys (PEM format) ─────────────────────────────────────
            (r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
             'PEM Private Key', 'CRITICAL'),
            (r'-----BEGIN CERTIFICATE-----',
             'Certificate', 'MEDIUM'),

            # ── Internal Paths & Debug ────────────────────────────────────────
            (r'(?:debug|dev|test|staging)\s*[:=]\s*true',
             'Debug/Dev Mode Enabled', 'MEDIUM'),
            (r'(?:console\.log|console\.error|console\.warn)\s*\([^)]{0,200}(?:password|token|secret|key|auth)[^)]{0,200}\)',
             'Sensitive Data in Console Log', 'HIGH'),
            (r'(?:\/home\/[a-zA-Z0-9_\-]+|\/root\/|\/var\/www\/|C:\\\\Users\\\\|\/etc\/)',
             'Internal Path Disclosure', 'MEDIUM'),
            (r'(?:127\.0\.0\.1|localhost|0\.0\.0\.0):(\d+)',
             'Internal Service Reference', 'LOW'),
            (r'(?:192\.168\.|10\.\d+\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+\.\d+',
             'Internal IP Address', 'MEDIUM'),

            # ── Tokens & Hashes ───────────────────────────────────────────────
            (r'(?:csrf[_\-]?token|xsrf[_\-]?token|_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
             'CSRF Token (hardcoded)', 'HIGH'),
            (r'(?:oauth[_\-]?token|oauth[_\-]?secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
             'OAuth Token', 'CRITICAL'),

            # ── Sensitive Config ──────────────────────────────────────────────
            (r'(?:encryption[_\-]?key|cipher[_\-]?key|aes[_\-]?key)\s*[:=]\s*["\']([a-zA-Z0-9_\-\/\+\=]{16,})["\']',
             'Encryption Key', 'CRITICAL'),
            (r'(?:ssh[_\-]?(?:key|password|host))\s*[:=]\s*["\']([^"\']{8,})["\']',
             'SSH Credentials', 'CRITICAL'),
            (r'(?:ftp[_\-]?(?:password|user|host))\s*[:=]\s*["\']([^"\']{4,})["\']',
             'FTP Credentials', 'HIGH'),
            (r'(?:smtp[_\-]?(?:password|user|host|port))\s*[:=]\s*["\']([^"\']{4,})["\']',
             'SMTP Credentials', 'HIGH'),
        ]

        self.api_patterns = [
            (r'["\']((https?://[\w\-\.]+)/api/[^\s"\'<>]{3,})["\']', 'FULL_API_URL'),
            (r'["\'](/api/v?\d*/?[^\s"\'<>]{2,})["\']', 'API_PATH'),
            (r'["\'](/v\d+/[^\s"\'<>]{2,})["\']', 'VERSIONED_API'),
            (r'["\'](/graphql/?[^\s"\'<>]*)["\']', 'GRAPHQL'),
            (r'["\'](/rest/[^\s"\'<>]{2,})["\']', 'REST_API'),
            (r'["\'](/ajax/[^\s"\'<>]{2,})["\']', 'AJAX_ENDPOINT'),
            (r'["\'](/wp-json/[^\s"\'<>]{2,})["\']', 'WORDPRESS_API'),
            (r'["\'](/wp-admin/admin-ajax\.php[^\s"\'<>]*)["\']', 'WP_ADMIN_AJAX'),
            (r'["\'](/third-parties/[^\s"\'<>]{2,})["\']', 'THIRD_PARTY'),
            (r'["\'](/internal/[^\s"\'<>]{2,})["\']', 'INTERNAL_API'),
            (r'["\'](/admin/[^\s"\'<>]{2,})["\']', 'ADMIN_ENDPOINT'),
            (r'fetch\s*\(\s*["\']([^\s"\'<>]{4,})["\']', 'FETCH_CALL'),
            (r'axios\.\w+\s*\(\s*["\']([^\s"\'<>]{4,})["\']', 'AXIOS_CALL'),
            (r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^\s"\'<>]{4,})["\']', 'JQUERY_AJAX'),
            (r'XMLHttpRequest[^;]*open\s*\([^,]+,\s*["\']([^\s"\'<>]{4,})["\']', 'XHR_CALL'),
        ]

        self.comment_patterns = [
            (r'//.*(?:todo|fixme|hack|bug|xxx|password|secret|token|key|credential)[^\n]*', 'Sensitive Comment', 'MEDIUM'),
            (r'/\*[\s\S]*?(?:password|secret|api.?key|token|credential)[\s\S]*?\*/', 'Sensitive Block Comment', 'HIGH'),
        ]

        self.blacklist_words = {
            'undefined', 'null', 'true', 'false', 'function', 'return',
            'Content-Type', 'application/json', 'text/html', 'example',
            'placeholder', 'your_api_key', 'YOUR_KEY', 'INSERT_KEY_HERE',
            'xxxxxxxx', '00000000', '12345678', 'test', 'demo', 'sample',
        }

        self.blacklist_domains = {
            'www.w3.org', 'schemas.microsoft.com', 'schemas.openxmlformats.org',
            'purl.org', 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com',
            'reactjs.org', 'example.com', 'localhost',
            'fonts.googleapis.com', 'fonts.gstatic.com',
        }

    def _get_line_and_context(self, content: str, pos: int) -> Tuple[int, str]:
        line_num = content[:pos].count('\n') + 1
        lines = content.split('\n')
        ctx = lines[line_num - 1].strip() if line_num <= len(lines) else ''
        return line_num, (ctx[:200] + '...') if len(ctx) > 200 else ctx

    def _is_fp(self, val: str) -> bool:
        if not val or len(val) < 4:
            return True
        vl = val.lower()
        if vl in {w.lower() for w in self.blacklist_words}:
            return True
        if vl in ('null', 'undefined', 'true', 'false', ''):
            return True
        if val.startswith(('this.', '$', '${', 'self.', 'window.')):
            return True
        if re.match(r'^[x0\s\*]+$', val):
            return True
        if re.match(r'^\d{1,4}$', val):
            return True
        return False

    def _is_valid_api(self, endpoint: str) -> bool:
        if len(endpoint) < 4:
            return False
        if endpoint.lower() in {w.lower() for w in self.blacklist_words}:
            return False
        if endpoint.startswith(('this.', '$', '${', 'window.')):
            return False
        if endpoint.startswith('http'):
            p = urlparse(endpoint)
            if any(d in p.netloc for d in self.blacklist_domains):
                return False
        if '/' not in endpoint and not endpoint.startswith('http'):
            return False
        if re.match(r'^/\d+$', endpoint):
            return False
        return True

    def analyze_all(self, js_dir: str, url_map: Dict[str, str]) -> Tuple[List[Dict], List[Finding], List[str]]:
        apis, sensitive, websockets = [], [], []
        seen_apis, seen_sensitive, seen_ws = set(), set(), set()

        if not os.path.exists(js_dir):
            print(f"  [!] JS directory not found: {js_dir}")
            return apis, sensitive, websockets

        file_count = 0
        for filename in os.listdir(js_dir):
            if not filename.endswith('.js'):
                continue
            file_count += 1
            filepath = os.path.join(js_dir, filename)
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception:
                continue

            # ── WebSocket URLs ─────────────────────────────────────────────────
            for m in re.finditer(r'wss?://[^\s"\'<>]+', content, re.IGNORECASE):
                ws = m.group(0).rstrip('",;)')
                if ws not in seen_ws:
                    seen_ws.add(ws)
                    ln, ctx = self._get_line_and_context(content, m.start())
                    websockets.append({'url': ws, 'source_file': filename, 'line': ln, 'context': ctx})

            # ── API Endpoints ──────────────────────────────────────────────────
            for pattern, ptype in self.api_patterns:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    try:
                        ep = m.group(1).strip('"\'').rstrip('",;')
                    except Exception:
                        continue
                    if not self._is_valid_api(ep):
                        continue
                    if ep in seen_apis:
                        continue
                    seen_apis.add(ep)
                    ln, ctx = self._get_line_and_context(content, m.start())
                    sev = 'HIGH' if any(k in ep.lower() for k in ['/admin', '/internal', '/graphql', '/wp-admin']) else 'MEDIUM'
                    apis.append({'endpoint': ep, 'source_file': filename, 'severity': sev,
                                 'line': ln, 'context': ctx, 'pattern_type': ptype})

            # ── Sensitive Data ─────────────────────────────────────────────────
            for pattern, category, severity in self.sensitive_patterns:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    try:
                        val = m.group(1).strip('"\'') if m.lastindex and m.lastindex >= 1 else m.group(0)
                    except Exception:
                        val = m.group(0)
                    if self._is_fp(val):
                        continue
                    key = f"{category}:{val[:40]}"
                    if key in seen_sensitive:
                        continue
                    seen_sensitive.add(key)
                    ln, ctx = self._get_line_and_context(content, m.start())
                    display = (val[:50] + '...') if len(val) > 50 else val
                    sensitive.append(Finding(
                        category=category, severity=severity,
                        match=display, source=f"JS: {filename}",
                        line=ln, context=ctx, metadata={'file': filename}
                    ))

            # ── Sensitive Comments ─────────────────────────────────────────────
            for pattern, category, severity in self.comment_patterns:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    val = m.group(0)[:100]
                    key = f"comment:{val[:40]}"
                    if key in seen_sensitive:
                        continue
                    seen_sensitive.add(key)
                    ln, ctx = self._get_line_and_context(content, m.start())
                    sensitive.append(Finding(
                        category=category, severity=severity,
                        match=val, source=f"JS: {filename}",
                        line=ln, context=ctx, metadata={'file': filename}
                    ))

        print(f"  [📊] JS Analysis: {file_count} files")
        print(f"      ├─ APIs       : {len(apis)}")
        print(f"      ├─ Sensitive  : {len(sensitive)}")
        print(f"      └─ WebSockets : {len(websockets)}")

        return apis, sensitive, websockets