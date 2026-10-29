# Maintenance and validation coverage

[English overview](../README.md) · [Resumen en español](../README_ES.md) · [Target deployment](DEPLOYMENT.md) · [Despliegue](DEPLOYMENT_ES.md)

## Standalone scripts

Keep all standalone assistants at the repository root, independently downloadable. Do not introduce runtime imports or network downloads for shared helpers. Edit `linux-ad-client-assistant.sh` as the canonical Linux client, then regenerate its RHEL-branded sibling:

```bash
python3 tools/sync_linux_clients.py
python3 tools/sync_linux_clients.py --check
```

Commit both outputs. The generator deliberately preserves the RHEL variant's product identity, version, installed CLI, watcher units and nftables table. Existing deployment state is not migrated or deleted by this maintenance change.

## Checks before merging

```bash
python3 tools/verify.py
# Complete gate (requires installed Bash, Python, ShellCheck and PowerShell):
python3 tools/verify.py --require-shellcheck --require-powershell
```

The default command reports unavailable optional analyzers as **SKIP**; it does not silently claim those checks passed. CI requires them. No verifier installs dependencies, runs an administrative mode, joins a domain or changes system policy. Bash entrypoint tests use a detached session, temporary HOME and only help, invalid arguments, preflight and an interactive launch that must stop before runtime initialization. CI runs these as an ordinary runner user.

On Windows, from a normal console:

```powershell
powershell.exe -NoProfile -File .\tools\verify_powershell.ps1
pwsh.exe -NoProfile -File .\tools\verify_powershell.ps1
```

| Check | Coverage | Limit |
|---|---|---|
| `bash -n` | Every root Bash script | Does not execute commands |
| ShellCheck, error severity | Shell static errors | Warnings/style debt are not a release gate |
| Linux client parity | Canonical and generated RHEL variant | Does not certify OS equivalence |
| Safe launch tests | Help, invalid/missing arguments, no-TTY rejection, preflight | No administrative operation executed |
| Isolated Bash regressions | IPv4 octets, malformed inputs, CIDR boundaries and leading zeros, IPS candidates | Only allowlisted pure function bodies are evaluated |
| PowerShell AST parser | Root, tools and test PowerShell files, including duplicate hash keys | Modules/cmdlets may still be absent on targets |
| PowerShell regressions | DNS/computer/IP validation, multicast/invalid IPS exclusions, preflight platform guards | Pure functions have explicit system-call stubs; assistants are never dot-sourced |
| Windows CI matrix | Windows PowerShell 5.1 and PowerShell 7 on Windows Server 2022 runner | Not an AD DC, join/reboot/recovery or GUI acceptance test |

Every subprocess check has a timeout. A missing required tool, syntax error, failed assertion or timeout makes the verifier fail. Keep a regression case when fixing a runtime defect that can be exercised safely.

## Packages

After committing and validating a clean checkout:

```bash
python3 tools/package.py
```

The package contains the exact checked-out script bytes, bilingual docs, `release.json` with the commit, and SHA-256 checksums. Dirty checkouts are rejected. ZIP metadata is deterministic for identical file bytes and revision. The packager does not itself run validation; CI only invokes it after the Linux and Windows jobs succeed. It never deploys to a host. Checksums are integrity evidence, not a code signature.

## Lab gate

Before approving a production change, exercise preflight → audit → change → reboot → validation → recovery on disposable target-family hosts and a lab domain. Preserve console access, restorable backups, the revision used and the resulting logs. A successful CI run does not certify the full scripts, OS combinations, domain operations or benchmark compliance.

## Review: 2026-10-16

- Added non-elevated, non-mutating preflight entry points to all six standalone scripts.
- Replaced filesystem permission tests for `/dev/tty` with an actual controlling-terminal check before interactive initialization.
- Fixed the Windows client parser failures: duplicate translation keys and malformed `foreach` / `return` tokens.
- Fixed malformed IPv4 acceptance, CIDR octal arithmetic and invalid/multicast IPS candidate handling.
- Made three Windows Server scheduled operation modes propagate caught errors instead of returning apparent success.
- Added offline regression tests, PowerShell engine CI coverage and revision/checksum deployment packages.
- Documented launch paths, role boundaries, SSH terminal requirements and lab acceptance in English and Spanish.

Workstation regression tests (`tests/test_workstations.ps1`) import only allowlisted
functions and mock all system writes. They cover per-edition plans, journal-before-write,
idempotency and conflict-safe recovery; live Windows 7/8.1/10/11 acceptance remains required.

## Operations-console review · 2026-10-29

- Added standalone `sysadmin.sh` with English/Spanish menu navigation and read-only
  Linux inventory, network, storage, service and log workspaces. Native command output
  keeps the target system's language. The console launches the existing AD tools;
  their role boundaries and standalone operation remain intact.
- Diagnostic probes require GNU timeout and propagate failure/timeout status.
  Missing optional tools and unavailable service managers are explicit SKIP results.
- Guided diagnostic package installation prints commands, requires literal INSTALL,
  uses native confirmations and never deletes package locks or times out a transaction.
- Added exclusive flock locking to both Linux AD clients, protected-directory/log
  initialization checks and validation of environment-controlled timeout values.
- New regressions mock diagnostics and test real temporary-file lock contention,
  timeout/command failure status, missing tools, no-systemd paths and non-TTY rejection.

See [console behavior, compatibility and examples](OPERATIONS_CONSOLE.md).
Local validation used Bash, Python and ShellCheck (error severity). PowerShell and
live package/AD/Windows/reboot/recovery checks were unavailable locally; the existing
CI matrix remains required. Automated tests are not a production certification.

Resumen: consola Linux organizada, instalación guiada, diagnósticos acotados,
resultados de error fiables y exclusión de ejecuciones AD simultáneas. La navegación
se ofrece en inglés/español; las herramientas nativas conservan el idioma del sistema.
No se certifican entornos no probados ni se sustituye la validación en laboratorio.
