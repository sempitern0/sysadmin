# sysadmin

Standalone Windows/Linux administration, Active Directory, diagnostics and recovery assistants.

**English** · [Español](README_ES.md)

RabbitMole (formerly Audit Workbench) has [its own repository](https://github.com/sempitern0/RabbitMole). This repository maintains the console assistants, with no PWA dependency.

## Choose your task

| Task | Start here |
|---|---|
| Administer a Samba AD domain on Debian/Ubuntu | `debian-ad-assistant.sh --audit` |
| Administer a Samba AD domain on Rocky/AlmaLinux | `rhel-ad-assistant.sh --audit` |
| Diagnose/manage Windows AD DS | `windows-ad-assistant.ps1 -Mode Audit` |
| Join, diagnose or recover a Linux AD client | `linux-ad-client-assistant.sh --audit` |
| Use the compatible RHEL-branded Linux client | `rhel-ad-client-assistant.sh --audit` |
| Join, diagnose or recover a Windows AD client | `windows-ad-client-assistant.ps1 -Mode Audit` |
| Plan OS upgrades or migrate files to Ubuntu/Nextcloud | `migration-assistant.ps1 -Mode Interactive` |
| Prepare corporate, classroom or legacy Windows workstations | `windows-workstation-assistant.ps1 -Mode Audit` |

See [migration scope, procedures and recovery](docs/MIGRATIONS.md).

## Start in minutes

```bash
git clone https://github.com/sempitern0/sysadmin.git
cd sysadmin
```

**AD assistants:** review the script, inspect help, then audit from an elevated console.

```bash
bash ./linux-ad-client-assistant.sh --help
bash ./linux-ad-client-assistant.sh --preflight
sudo bash ./linux-ad-client-assistant.sh --audit
# For a Debian/Ubuntu domain controller instead:
sudo bash ./debian-ad-assistant.sh --audit
```

```powershell
Get-Help .\windows-ad-client-assistant.ps1 -Detailed
# No elevation required:
powershell.exe -NoProfile -File .\windows-ad-client-assistant.ps1 -Mode Preflight
# In an elevated console:
.\windows-ad-client-assistant.ps1 -Mode Audit
# For a Windows domain controller instead:
.\windows-ad-assistant.ps1 -Mode Audit
```

Use your organization's approved script execution/signing policy on Windows.
All root scripts are standalone downloads.

## Deploy a verified revision

The [launch guide](docs/DEPLOYMENT.md) covers assistant selection, commit-pinned downloads, hash/syntax checks, SSH transfer and Windows execution. CI packages scripts with checksums only after Linux and Windows PowerShell 5.1/7 checks pass.

`--preflight` / `-Mode Preflight` checks local launch prerequisites without modifying the system. The subsequent audit may create logs and reports. Passing these checks does not replace lab change/recovery acceptance.

## Operating expectations

- Start with audit/diagnostics; apply infrastructure changes deliberately with a recovery path.
- Preserve restorable backups and console access before changing DNS, SSH, firewall or domain membership.
- RHEL Samba AD DC provisioning is guarded as an unsupported role; see the [platform notes](docs/OPERATIONS.md#control-plane-enterprise-linux).
- Platform implementations differ. Neither successful syntax checks nor a hardening run certify production readiness or benchmark compliance.

## Reference, recovery and maintenance

| Need | Guide |
|---|---|
| AD commands, DNS, GPO, IDS, backups and recovery | [Operations reference](docs/OPERATIONS.md) |
| Troubleshoot DNS, Kerberos or domain membership | [Troubleshooting](docs/OPERATIONS.md#troubleshooting) |
| Find state, snapshots and logs | [State paths](docs/OPERATIONS.md#rutas-de-estado-y-logs) |
| Change code and run offline checks | [Maintenance](docs/MAINTENANCE.md) |

```bash
python3 tools/verify.py              # Syntax, parity and regression checks
# CI also requires ShellCheck and PowerShell:
python3 tools/verify.py --require-shellcheck --require-powershell
```

[MIT license](LICENSE).

[Windows workstation preparation guide](docs/WORKSTATIONS.md).
