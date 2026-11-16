#!/usr/bin/env python3
"""Execute a command through DocBuilder SaveFile conversion parameter injection."""

import argparse
import sys
from pathlib import Path

from onlyoffice_common import DocumentServer, add_network_args, entrypoint, network_options, read_token
from onlyoffice_execution import Execution, add_execution_args


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_network_args(parser)
    add_execution_args(parser)
    parser.add_argument(
        "--token-file", required=True, type=Path, help="client-visible Editor/Browser JWT file"
    )
    parser.add_argument("--command", required=True, help="shell command to execute")
    parser.add_argument("--root", action="store_true", help="chain the sudo root-helper injection")
    args = parser.parse_args()
    options = network_options(args)
    token = read_token(args.token_file)
    with DocumentServer(**options) as client:
        with Execution(
            client,
            token,
            args.command,
            as_root=args.root,
            artifacts_dir=args.artifacts_dir,
            runtime_absent=args.runtime_absent,
            keep_artifacts=args.keep_artifacts,
        ) as execution:
            execution.install_savefile()
            output, code, cleanup = execution.wait(args.timeout)
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 4 if cleanup not in {"ok", "kept"} else 3 if code else 0


if __name__ == "__main__":
    entrypoint(main)
