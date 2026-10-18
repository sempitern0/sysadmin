# Migration control center

The root `migration-assistant.ps1` is a standalone PowerShell 5.1/7 console assistant. File transfers also run on Linux with PowerShell 7 and a local/mounted source. No Python or repository checkout is needed. The Windows AD migration menu links to the companion when downloaded alongside it from the same revision.

[Full Spanish operating guide, examples and recovery procedures](MIGRATIONS_ES.md).

| Profile | Implemented | Manual boundaries |
|---|---|---|
| `Server2022To2025` | OS/roles/volumes/services inventory, DC/cluster blockers, runbook and post-upgrade version check | Setup, role/application compatibility, DC replacement, acceptance and restore |
| `UbuntuFiles` | Preview, immutable copy to configured SFTP remote and downloaded content comparison | Provision Ubuntu/Samba, map identities/ACLs, migrate other services |
| `NextcloudFiles` | Preview, immutable copy to configured WebDAV remote and downloaded content comparison | Provision Nextcloud, users/groups/shares, application metadata |

Windows-to-Linux is a service-by-service migration; Nextcloud replaces a file/collaboration workload, not an entire Windows server. Existing AD assistants retain their domain migration tools. RabbitMole is a separate repository.

## Start

```powershell
.\migration-assistant.ps1 -Mode Preflight
.\migration-assistant.ps1 -Mode Interactive
```

The console offers `Plan`, `Status`, `DryRun`, `Copy`, `Verify` and `VerifyUpgrade`. No web server or privileged background service is started. Questions include Spanish; technical output is English.

## Windows Server

```powershell
# Elevated source-host console:
.\migration-assistant.ps1 -Mode Plan -Profile Server2022To2025 -Workspace C:\Migration\upgrade-2025
.\migration-assistant.ps1 -Mode Status -Workspace C:\Migration\upgrade-2025
# After a separately executed upgrade:
.\migration-assistant.ps1 -Mode VerifyUpgrade -Workspace C:\Migration\upgrade-2025
```

Inventory must succeed. Source build 20348 identifies Server 2022; AD DS and clustering block the generic in-place route. Setup is never launched by this assistant. Review edition, language, installation type, disk space, pending reboot, hardware, drivers, licensing and application vendor support. Test full-server recovery and an isolated rehearsal, retain off-host evidence and console access, then schedule downtime. Azure and clusters require their own procedures. For AD DS use new 2025 DCs, validate functional levels, replication/DNS and system-state restore, then plan FSMO transfer and retirement. Existing domain tools: `windows-ad-assistant.ps1 -Mode Migration`.

`VerifyUpgrade` checks server build 26100 and records a new inventory. `OSVersionVerified` is only a version check: client transactions, service health, backups and acceptance remain manual. Rollback is a rehearsed full-server/application restore, not an automatic downgrade.

## Files

Install an approved rclone build on the source runner. Configure it separately with `rclone config --config C:\Secure\rclone.conf`. Ubuntu requires an `sftp` remote with a verified `known_hosts_file`; Nextcloud requires a `webdav` remote with `vendor=nextcloud`, HTTPS URL `https://cloud.example/remote.php/dav/files/USER/` and an app password. Keep TLS validation enabled. The assistant validates backend type, not server transport/security configuration.

Protect the config and workspace with OS access controls. Keep both outside source data. Use a dedicated destination subtree and pilot filename/case behavior, large files, quotas and permissions before the full job.

```powershell
.\migration-assistant.ps1 -Mode Plan -Profile NextcloudFiles -Source D:\Data -Destination nc:Migration/batch1 -ConfigPath C:\Secure\rclone.conf -Workspace C:\Migration\nextcloud-batch1
.\migration-assistant.ps1 -Mode DryRun -Workspace C:\Migration\nextcloud-batch1
# Review log; stop source writers or use a consistent read-only snapshot.
.\migration-assistant.ps1 -Mode Copy -Workspace C:\Migration\nextcloud-batch1 -BackupVerified -PermissionsReviewed -SourceFrozen -ConfirmDestination nc:Migration/batch1
.\migration-assistant.ps1 -Mode Verify -Workspace C:\Migration\nextcloud-batch1 -SourceFrozen
```

For Ubuntu choose `-Profile UbuntuFiles -Destination ubuntu:staging/batch1`. Paths are relative to the configured remote. Named remotes must start with a letter and contain at least two letters/digits/underscore/hyphen characters. Simple destination paths allow internal spaces and `/`, but no root, dot or traversal segments.

The switches are operator attestations: the assistant does not freeze applications or create/restore backups. Use application-consistent database exports, not live database file copies.

## State and recovery

`Planned → Previewed → Copied → ContentVerified`, with persistent `*Running` and `Failed` states in `plan.json`. Each operation has its own log and an exclusive workspace lock. After a failure/interruption, inspect logs then repeat `DryRun` and `Copy`. Never run different workspaces against the same destination subtree. Configuration changes require a fresh plan; the workspace is bound to the original host and config SHA256. Credentials are not copied into the plan.

Copy uses `rclone copy --immutable --checksum --create-empty-src-dirs`. It never deletes the source/destination or overwrites detected conflicting files. Partial copies can remain after failure. For changed data use a fresh batch and plan; this is not a mutable incremental sync. SFTP shell/hash probes are disabled to avoid remote command execution and automatic config mutation. Where no common hash exists, copy may compare sizes only. Therefore verification uses `rclone check --download` and rejects differences, missing files and extra destination files. It downloads content and does not verify ACLs, timestamps or empty directories. Keep the source frozen through acceptance/cutover; later writes invalidate previous evidence.

Links/junctions are rejected. NTFS ACLs/SIDs/ADS, EFS semantics, hard-link identity, shares, accounts/GPOs and Nextcloud application metadata are outside scope. Export source permissions/share definitions separately and explicitly implement/test destination permissions. Environment `RCLONE_*` overrides are rejected except `RCLONE_CONFIG_PASS` for encrypted config. Logs/plans include operational paths and host details; restrict access and retention. Do not edit state to bypass gates. No privileged agent monitors concurrent filesystem changes.

Manually test permitted/denied user access, quotas, clients, DNS/URLs, application transactions, performance and restore. Cut over only after acceptance. Retain the source read-only for the recovery window. Before new writes, redirect clients back if needed. After new writes, reconcile destination changes before rollback. No automatic deletion/rollback is performed. SMB external storage in Nextcloud can provide manual coexistence, but retains the Windows dependency and is not data migration.

## Validation and sources

PowerShell regression tests cover validation, gates, journal, locking and retry states. Real rclone loopback SFTP/WebDAV fixtures cover dry runs, copies, same-size corruption, conflicting files and recovery. These do not certify a real Windows Server upgrade or production Ubuntu/Nextcloud deployment.

Sources consulted 2026-10-18: [Microsoft upgrade](https://learn.microsoft.com/en-us/windows-server/get-started/upgrade-in-place), [DC replacement](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/upgrade-domain-controllers), [AD functional levels](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/identifying-your-functional-level-upgrade), [rclone copy](https://rclone.org/commands/rclone_copy/), [check](https://rclone.org/commands/rclone_check/), [WebDAV](https://rclone.org/webdav/), [SFTP](https://rclone.org/sftp/), [Nextcloud external storage](https://docs.nextcloud.com/server/stable/admin_manual/configuration_files/external_storage_configuration_gui.html).
