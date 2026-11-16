#!/usr/bin/env python3
"""Read server files and forge a Session JWT using a client-visible Editor JWT."""

import argparse
from pathlib import Path

from onlyoffice_chain import Chain, add_chain_args
from onlyoffice_common import (
    DocumentServer,
    add_network_args,
    entrypoint,
    network_options,
    read_token,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_network_args(parser)
    add_chain_args(parser)
    parser.add_argument("--token-file", required=True, type=Path, help="client-visible Editor JWT file")
    args = parser.parse_args()
    options = network_options(args)
    token = read_token(args.token_file)
    with Chain(args) as chain, DocumentServer(**options) as client:
        return chain.run(client, token)


if __name__ == "__main__":
    entrypoint(main)
