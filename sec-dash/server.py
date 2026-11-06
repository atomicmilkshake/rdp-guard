#!/usr/bin/env python3
"""
Security dashboard server for Windows.

- Serves the read-only dashboard on http://<lan-ip>:8099/  (LAN/Tailscale/loopback only)
- Runs collect.ps1 every REFRESH seconds in the background so data.json is always fresh
- Serves data.json (never cached) which the page polls every 10s
- Enforces canonical URL-decoded path allowlisting across GET and HEAD, Host validation,
  source-network validation, CSP headers, and bounded thread-pool request handling.

Nothing here can modify firewall/system state - it is a viewer.
"""
from concurrent.futures import ThreadPoolExecutor
import errno
import http.server
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import socket
import socketserver
import subprocess
import threading
import time
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parent
VENDOR_ROOT = (ROOT / "vendor").resolve()
PORT = 8099
REFRESH = 30                      # seconds between collector runs
MAX_WORKERS = 16
SOCKET_TIMEOUT = 10.0

PS = r"C:\Program Files\PowerShell\7\pwsh.exe"
if not os.path.exists(PS):
    PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
COLLECT = str(ROOT / "collect.ps1")
LOG = str(ROOT / "server.log")

CREATE_NO_WINDOW = 0x08000000

ALLOWED_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

ALLOWED_HOSTNAMES = {
    "localhost",
    socket.gethostname().lower(),
    f"{socket.gethostname().lower()}.local",
}

ALLOWED_VENDOR_FILES = {
    "leaflet.js": "application/javascript; charset=utf-8",
    "leaflet.css": "text/css; charset=utf-8",
}

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data: https://*.tile.openstreetmap.org https://*.basemaps.cartocdn.com; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}\n"
    try:
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def is_allowed_ip(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped
        return any(ip_obj in net for net in ALLOWED_NETWORKS)
    except ValueError:
        return False


ALLOWED_HOST_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("192.168.4.0/24"),
    ipaddress.ip_network("100.64.0.0/10"),
)


def _is_strict_int(val: object) -> bool:
    return isinstance(val, int) and not isinstance(val, bool)


def is_allowed_host_header(host_header: str | None) -> bool:
    if not host_header:
        return False
    raw = host_header.strip().lower()
    if not raw or any(c in raw for c in ("/", "\\", "@", " ", "\t", "\r", "\n")):
        return False
    port_part: str | None = None
    is_bracketed = False
    if raw.startswith("["):
        is_bracketed = True
        end = raw.find("]")
        if end == -1:
            return False
        host_part = raw[1:end]
        rest = raw[end + 1:]
        if rest:
            if not rest.startswith(":"):
                return False
            port_part = rest[1:]
    else:
        if "]" in raw or raw.count(":") > 1:
            return False
        if ":" in raw:
            host_part, port_part = raw.rsplit(":", 1)
        else:
            host_part = raw

    if not host_part:
        return False

    if port_part is not None:
        if not port_part.isdigit():
            return False
        port_num = int(port_part)
        if port_num < 1 or port_num > 65535:
            return False

    if is_bracketed:
        try:
            ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv6Address(host_part)
            if ip_obj.ipv4_mapped:
                ip_obj = ip_obj.ipv4_mapped
            return any(ip_obj in net for net in ALLOWED_HOST_NETWORKS)
        except ValueError:
            return False

    if host_part in ALLOWED_HOSTNAMES:
        return True
    try:
        ipv4_obj = ipaddress.IPv4Address(host_part)
        return any(ipv4_obj in net for net in ALLOWED_HOST_NETWORKS)
    except ValueError:
        return False


def read_file_with_retry(path: Path, retries: int = 4, delay: float = 0.04) -> bytes:
    last_err: OSError | None = None
    for attempt in range(retries):
        try:
            return path.read_bytes()
        except OSError as exc:
            last_err = exc
            if attempt + 1 < retries:
                time.sleep(delay * (attempt + 1))
    assert last_err is not None
    raise last_err


def build_health_payload(root_dir: Path | None = None) -> tuple[int, dict]:
    base = root_dir if root_dir is not None else ROOT
    data_path = base / "data.json"
    manifest_path = base / "commit-manifest.json"
    reasons: list[str] = []
    age: float | None = None
    generation_id: str | None = None
    fw_rules: int | None = None
    fw_effective_ok: bool = False

    if not data_path.is_file():
        reasons.append("data.json missing")
    else:
        try:
            age = round(time.time() - data_path.stat().st_mtime, 1)
            if age >= 300:
                reasons.append(f"data.json stale ({age}s >= 300s)")
            raw_bytes = read_file_with_retry(data_path)
            doc = json.loads(raw_bytes.decode("utf-8-sig"))
            if not isinstance(doc, dict):
                reasons.append("data.json root is not an object")
            else:
                for req_key in ("generationId", "health", "summary", "hourly", "daily", "guard"):
                    if req_key not in doc:
                        reasons.append(f"data.json missing {req_key}")
                generation_id = doc.get("generationId")
                if not isinstance(generation_id, str) or not generation_id.strip():
                    reasons.append("data.json generationId missing or empty")
                guard_obj = doc.get("guard") if isinstance(doc.get("guard"), dict) else {}
                last_res = guard_obj.get("lastResult")
                if last_res is not None and (not _is_strict_int(last_res) or last_res != 0):
                    reasons.append(f"guard.lastResult={last_res}")
                health_obj = doc.get("health")
                if not isinstance(health_obj, dict):
                    reasons.append("data.json health is not an object")
                else:
                    fw_rules_raw = health_obj.get("firewallActiveRuleCount")
                    fw_inst = health_obj.get("firewallRuleInstances")
                    fw_en_inst = health_obj.get("firewallEnabledInstances")
                    fw_eff = health_obj.get("firewallEffectiveOk")
                    inst_ok = _is_strict_int(fw_inst) and fw_inst == 1 and _is_strict_int(fw_en_inst) and fw_en_inst == 1
                    rules_ok = _is_strict_int(fw_rules_raw) and int(fw_rules_raw) >= 1
                    if rules_ok:
                        fw_rules = int(fw_rules_raw)
                    if not inst_ok:
                        reasons.append(f"firewall rule instances invalid (total={fw_inst}, enabled={fw_en_inst})")
                    if not rules_ok:
                        reasons.append(f"firewallActiveRuleCount invalid ({fw_rules_raw})")
                    if fw_eff is not True:
                        reasons.append(f"firewallEffectiveOk={fw_eff}")
                    else:
                        fw_effective_ok = inst_ok and rules_ok
        except Exception as exc:                              # noqa: BLE001
            reasons.append(f"data.json invalid: {exc}")

    if not manifest_path.is_file():
        reasons.append("commit-manifest.json missing")
    else:
        try:
            m_age = round(time.time() - manifest_path.stat().st_mtime, 1)
            if m_age >= 300:
                reasons.append(f"commit-manifest.json stale ({m_age}s >= 300s)")
            manifest = json.loads(read_file_with_retry(manifest_path).decode("utf-8-sig"))
            if not isinstance(manifest, dict):
                reasons.append("commit-manifest.json root is not an object")
            else:
                m_status = manifest.get("status")
                m_gen = manifest.get("generationId")
                if m_status != "ok":
                    reasons.append(f"commit-manifest status={m_status}")
                if not isinstance(m_gen, str) or not m_gen.strip():
                    reasons.append("commit-manifest generationId missing")
                elif generation_id != m_gen:
                    reasons.append(f"generation mismatch (data={generation_id}, manifest={m_gen})")
        except Exception as exc:                              # noqa: BLE001
            reasons.append(f"commit-manifest invalid: {exc}")

    ok = len(reasons) == 0 and fw_effective_ok
    payload = {
        "ok": ok,
        "status": "ok" if ok else "degraded",
        "service": "sec-dash",
        "data_age_seconds": age,
        "generation_id": generation_id,
        "firewall_active_rule_count": fw_rules,
        "firewall_effective_ok": fw_effective_ok,
        "reasons": reasons,
    }
    return (200 if ok else 503), payload


def collect_once() -> None:
    try:
        r = subprocess.run(
            [PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", COLLECT],
            capture_output=True, timeout=600, creationflags=CREATE_NO_WINDOW,
        )
        if r.returncode != 0:
            log(f"collector exited {r.returncode}: {r.stderr.decode(errors='ignore')[:400]}")
    except subprocess.TimeoutExpired:
        log("collector TIMED OUT after 600s")
    except Exception as exc:                                  # noqa: BLE001
        log(f"collector failed: {exc}")


def collect_loop() -> None:
    log("collector thread started")
    while True:
        collect_once()
        time.sleep(REFRESH)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "sec-dash/2.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        try:
            self.request.settimeout(SOCKET_TIMEOUT)
        except Exception:                                     # noqa: BLE001
            pass

    def log_message(self, *args) -> None:                     # keep console quiet
        pass

    def _send_security_headers(self, cache_control: str = "no-store, max-age=0") -> None:
        self.send_header("Cache-Control", cache_control)
        self.send_header("X-Robots-Tag", "noindex")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Content-Security-Policy", CSP_POLICY)

    def _send_json(self, status_code: int, payload: dict, is_head: bool) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers("no-store, max-age=0")
        self.end_headers()
        if not is_head:
            self.wfile.write(body)

    def _send_plain_error(self, status_code: int, message: str, is_head: bool) -> None:
        body = f"{status_code} {message}\n".encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers("no-store, max-age=0")
        self.end_headers()
        if not is_head:
            self.wfile.write(body)

    def _authorize_and_resolve(self) -> tuple[int, str, Path | None, str, str]:
        """
        Single canonical authorization gate shared by GET and HEAD.
        Returns (status_code, kind, resolved_path, content_type, cache_control).
        """
        client_ip = self.client_address[0] if self.client_address else ""
        if not is_allowed_ip(client_ip):
            return 403, "error", None, "Forbidden source", "no-store, max-age=0"

        if not is_allowed_host_header(self.headers.get("Host")):
            return 403, "error", None, "Forbidden Host header", "no-store, max-age=0"

        raw_target = self.path or ""
        split = urllib.parse.urlsplit(raw_target)
        raw_path = split.path or ""
        lower_raw = raw_path.lower()

        # Reject encoded path separators, backslashes, or NUL bytes before & after unquoting
        if any(tok in lower_raw for tok in ("%2f", "%5c", "%00", "\\")):
            return 400, "error", None, "Bad path", "no-store, max-age=0"

        decoded = urllib.parse.unquote(raw_path)
        if "\x00" in decoded or "\\" in decoded or "%" in urllib.parse.unquote(decoded) and any(
            tok in decoded.lower() for tok in ("%2e", "%2f", "%5c")
        ):
            return 400, "error", None, "Bad path", "no-store, max-age=0"

        # Reject any explicit dot-segment in decoded path before normalization
        segments = [seg for seg in decoded.split("/") if seg != ""]
        if any(seg in (".", "..") for seg in segments):
            return 404, "error", None, "Not served", "no-store, max-age=0"

        norm_path = posixpath.normpath(decoded)
        if not norm_path.startswith("/"):
            return 400, "error", None, "Bad path", "no-store, max-age=0"

        if norm_path in ("/health", "/healthz"):
            return 200, "health", None, "application/json; charset=utf-8", "no-store, max-age=0"

        if norm_path in ("/", "/index.html"):
            target = (ROOT / "index.html").resolve()
            if target.parent != ROOT or target.is_symlink() or not target.is_file():
                return 404, "error", None, "Not served", "no-store, max-age=0"
            return 200, "file", target, "text/html; charset=utf-8", "no-store, max-age=0"

        if norm_path == "/data.json":
            target = (ROOT / "data.json").resolve()
            if target.parent != ROOT or target.is_symlink() or not target.is_file():
                return 404, "error", None, "Not served", "no-store, max-age=0"
            return 200, "file", target, "application/json; charset=utf-8", "no-store, max-age=0"

        if norm_path.startswith("/vendor/"):
            rel_name = norm_path[len("/vendor/"):]
            if "/" in rel_name or rel_name not in ALLOWED_VENDOR_FILES:
                return 404, "error", None, "Not served", "no-store, max-age=0"
            target = (VENDOR_ROOT / rel_name).resolve()
            if (
                not target.is_relative_to(VENDOR_ROOT)
                or target.parent != VENDOR_ROOT
                or target.is_symlink()
                or not target.is_file()
            ):
                return 404, "error", None, "Not served", "no-store, max-age=0"
            return (
                200,
                "file",
                target,
                ALLOWED_VENDOR_FILES[rel_name],
                "public, max-age=86400",
            )

        return 404, "error", None, "Not served", "no-store, max-age=0"

    def _handle_request(self, is_head: bool) -> None:
        status, kind, target, content_type_or_msg, cache_control = self._authorize_and_resolve()
        if kind == "error":
            self._send_plain_error(status, content_type_or_msg, is_head=is_head)
            return
        if kind == "health":
            h_status, h_payload = build_health_payload()
            self._send_json(h_status, h_payload, is_head=is_head)
            return
        assert target is not None
        try:
            body = read_file_with_retry(target)
        except OSError:
            self._send_plain_error(503, "Resource temporarily unavailable", is_head=is_head)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type_or_msg)
        self.send_header("Content-Length", str(len(body)))
        self._send_security_headers(cache_control)
        self.end_headers()
        if not is_head:
            self.wfile.write(body)

    def do_GET(self) -> None:                                 # noqa: N802
        self._handle_request(is_head=False)

    def do_HEAD(self) -> None:                                # noqa: N802
        self._handle_request(is_head=True)

    def do_POST(self) -> None:                                # noqa: N802
        self._send_plain_error(405, "Method Not Allowed", is_head=False)

    def do_PUT(self) -> None:                                 # noqa: N802
        self._send_plain_error(405, "Method Not Allowed", is_head=False)

    def do_DELETE(self) -> None:                              # noqa: N802
        self._send_plain_error(405, "Method Not Allowed", is_head=False)

    def do_OPTIONS(self) -> None:                             # noqa: N802
        self._send_plain_error(405, "Method Not Allowed", is_head=True)


class BoundedHTTPServer(socketserver.TCPServer):
    allow_reuse_address = False      # on Windows SO_REUSEADDR lets a second process hijack the port
    request_queue_size = 32

    def __init__(self, server_address, RequestHandlerClass):
        self._gate = threading.BoundedSemaphore(MAX_WORKERS * 2)
        self._pool = ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="sec-dash-http")
        try:
            super().__init__(server_address, RequestHandlerClass)
        except Exception:
            self._pool.shutdown(wait=False, cancel_futures=True)
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:                                     # noqa: BLE001
            self.handle_error(request, client_address)
        finally:
            try:
                self.shutdown_request(request)
            finally:
                self._gate.release()

    def process_request(self, request, client_address) -> None:
        if not self._gate.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            self._pool.submit(self.process_request_thread, request, client_address)
        except Exception:
            self._gate.release()
            self.shutdown_request(request)

    def server_close(self) -> None:
        super().server_close()
        pool = getattr(self, "_pool", None)
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)


def verify_existing_sec_dash_instance(port: int) -> bool:
    url = f"http://127.0.0.1:{port}/healthz"
    req = urllib.request.Request(url, headers={"Host": f"127.0.0.1:{port}"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            doc = json.loads(raw)
            return isinstance(doc, dict) and doc.get("service") == "sec-dash"
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="ignore")
            doc = json.loads(raw)
            return isinstance(doc, dict) and doc.get("service") == "sec-dash"
        except Exception:                                     # noqa: BLE001
            return False
    except Exception:                                         # noqa: BLE001
        return False


if __name__ == "__main__":
    try:
        httpd = BoundedHTTPServer(("0.0.0.0", PORT), Handler)
    except OSError as exc:
        win_err = getattr(exc, "winerror", None)
        if win_err == 10048 or exc.errno == errno.EADDRINUSE:
            if verify_existing_sec_dash_instance(PORT):
                log(f"verified existing sec-dash instance on {PORT} - exiting cleanly")
                raise SystemExit(0)
            log(f"FATAL: port {PORT} in use by non-sec-dash or unresponsive listener: {exc!r}")
            raise SystemExit(1)
        log(f"FATAL: failed to bind 0.0.0.0:{PORT}: {exc!r}")
        raise SystemExit(1)

    with httpd:
        if not (ROOT / "data.json").is_file():
            log("no data.json yet - collecting synchronously first")
            collect_once()
        threading.Thread(target=collect_loop, daemon=True, name="sec-dash-collector").start()
        log(f"serving {ROOT} on 0.0.0.0:{PORT} (pid {os.getpid()})")
        try:
            httpd.serve_forever()
        except Exception as exc:                              # noqa: BLE001
            log(f"FATAL: server exited: {exc!r}")
            raise
