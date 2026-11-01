import asyncio
import uuid
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass, field


@dataclass
class OOBCallback:
    token: str
    payload_name: str
    param_name: str
    target_url: str
    received_at: float
    raw_url: str
    extra: dict = field(default_factory=dict)


class OOBServer:
    def __init__(self, host: str = "0.0.0.0", port: int = 8877, public_host: str = None):
        self.host = host
        self.port = port
        self.public_host = public_host or f"127.0.0.1:{port}"
        self._callbacks = {}
        self._token_map = {}
        self._server = None
        self._thread = None
        self._lock = threading.Lock()

    @property
    def base_url(self) -> str:
        if self.public_host.startswith("http"):
            return self.public_host.rstrip("/")
        return f"http://{self.public_host}"

    def register_token(self, payload_name: str, param_name: str, target_url: str) -> str:
        token = uuid.uuid4().hex[:12]
        with self._lock:
            self._token_map[token] = {
                "payload_name": payload_name,
                "param_name": param_name,
                "target_url": target_url,
            }
        return token

    def get_callback(self, token: str):
        with self._lock:
            return self._callbacks.get(token)

    def get_all_callbacks(self) -> list:
        with self._lock:
            return list(self._callbacks.values())

    def build_payload_url(self, token: str) -> str:
        return f"{self.base_url}/cb/{token}"

    def start(self):
        if "127.0.0.1" in self.public_host or "localhost" in self.public_host:
            print(f"  [⚠️] WARNING: OOB base_url is using a private/local address ({self.base_url}).")

        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urlparse(self.path)
                parts = parsed.path.strip("/").split("/")

                if len(parts) >= 2 and parts[0] == "cb":
                    token = parts[1]
                    qs = parse_qs(parsed.query)
                    extra = {k: v[0] for k, v in qs.items()}

                    with server_ref._lock:
                        meta = server_ref._token_map.get(token, {})
                        if token not in server_ref._callbacks:
                            cb = OOBCallback(
                                token=token,
                                payload_name=meta.get("payload_name", "UNKNOWN"),
                                param_name=meta.get("param_name", "UNKNOWN"),
                                target_url=meta.get("target_url", "UNKNOWN"),
                                received_at=time.time(),
                                raw_url=f"{server_ref.base_url}{self.path}",
                                extra=extra,
                            )
                            server_ref._callbacks[token] = cb
                            print(f"\n  🔔 OOB CALLBACK RECEIVED!")
                            print(f"     Token   : {token}")
                            print(f"     Payload : {cb.payload_name}")
                            print(f"     Param   : {cb.param_name}")
                            print(f"     Target  : {cb.target_url[:80]}")
                            if extra:
                                print(f"     Extra   : {extra}")

                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        self._server = HTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        print(f"  [+] OOB Server listening on {self.host}:{self.port}")
        print(f"  [+] Public base URL: {self.base_url}")

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._thread.join(timeout=2)

    def summary(self) -> str:
        callbacks = self.get_all_callbacks()
        if not callbacks:
            return "  [−] No OOB callbacks received."
        lines = [f"\n  🎯 OOB CALLBACKS ({len(callbacks)} total):"]
        for cb in callbacks:
            lines.append(f"     Payload : {cb.payload_name}")
            lines.append(f"     Param   : {cb.param_name}")
            lines.append(f"     Target  : {cb.target_url[:80]}")
            if cb.extra:
                lines.append(f"     Extra   : {cb.extra}")
            lines.append("")
        return "\n".join(lines)