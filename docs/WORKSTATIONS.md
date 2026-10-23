# Windows workstation preparation

[Guía completa en español](WORKSTATIONS_ES.md) · [Overview](../README.md)

Download the standalone root `windows-workstation-assistant.ps1` at a reviewed
commit. No runtime helpers, downloads, installation or execution-policy bypass.
Use native **Windows PowerShell 5.1**, elevated except for Preflight. Windows 7
requires SP1 and preinstalled WMF 5.1; Windows 8 RTM is not supported by that runtime.
Windows 8.1/10/11 client editions are capability-gated; server editions are rejected.
PowerShell 7 and 32-bit processes on 64-bit Windows automatically relaunch the
same file in native Windows PowerShell, preserving parameters and exit status.
No execution-policy bypass, installation or automatic elevation is performed.

On Windows 11 Home with a default `Restricted` execution policy, run a reviewed
copy from an elevated terminal with a process-only exception:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File ".\\windows-workstation-assistant.ps1" -Mode Audit -Profile Academy
```

A local, optional CMD launcher could call
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0windows-workstation-assistant.ps1" %*`.
It is deliberately **not committed**: the documented command avoids a new script.
This does not elevate the user or override enforced MachinePolicy/UserPolicy.

EnrollmentType alone is not MDM evidence; Windows may keep placeholder registry
records. A joined domain or a nonempty enrolled ProviderID triggers guarded
Apply, before asking interactive questions. An MDM provider record may be stale,
so verify enrollment before using the approved `-AllowManaged` exception.

```powershell
.\windows-workstation-assistant.ps1 -Mode Preflight
.\windows-workstation-assistant.ps1 -Mode Audit -Profile Academy
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -WhatIf
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -CreateRestorePoint
```

No arguments opens a profile/options wizard, defaulting to audit. Profiles are
Corporate, Academy and Legacy (automatic default on pre-Windows-10 clients).
Corporate/Academy disable SMBv1 after reboot; Legacy retains it unless explicitly
requested. `-DisableLegacyProtocols` also disables old SSL/TLS in Schannel and
enables TLS 1.2: test legacy applications first. This does not control private
Java/OpenSSL implementations. Unsupported Windows remains unsupported after hardening;
verify Windows 10 LTSC/ESU and Windows 11 build lifecycle separately.

Common policy covers UAC, firewall enablement without rule deletion, remote blank
passwords, AutoRun and applicable WDigest settings. Windows Fast Startup is disabled
without disabling laptop hibernation. Balanced power is selected without changing
existing sleep/battery/lid/OEM timeout values. Academy locks idle sessions at ten
minutes and Corporate at fifteen (Windows 8.1+). Diagnostics report manufacturer,
model, chassis type, firmware/TPM/Secure Boot availability, security products,
firewall state, disk space, encryption, accounts, startup and recovery points.

Optional switches:

- `-UserExperience`: animations/transparency for the **executing account only**.
- `-DisableOptionalServices`: existing Xbox/maps service startup only; after reboot.
- `-DisableStartupName 'Exact Run value name'`: selected HKCU/HKLM/32-bit Run entries
  only, with recovery. No automatic removal of EDR, VPN, backup or startup files/tasks.
- `-StandardUserName student01`: new local standard account, secure password prompt
  and confirmation, at least 14 characters plus OS policy. Built-in Users group is
  resolved by SID. Existing accounts are rejected; no admin/RDP rights are granted.
- `-CreateRestorePoint`: require a new or verified recent recovery point; Windows
  may reuse one from the last 24 hours. Does not enable System Protection or shrink quotas.
- `-AllowManaged`: explicitly approved local exception for domain/MDM devices.
  Detection is not exhaustive; review central policy first. No GPO/MDM bypass.

Minimum diagnostics policy depends on edition; this is not total telemetry removal.
Updates and antivirus remain enabled; consumer policies may be unsupported on Home/Pro.
No app debloating, blanket service disabling, firmware writing, TPM clearing,
forced reboot, domain joins or automatic disk encryption are performed.

Each audit/application writes a protected evidence directory beneath
`%ProgramData%\WorkstationAssistant`: inventory, plan, observed values, diagnostics
and a manual handover checklist. Apply journals old values/types/absence **before**
each write and verifies registry readback. WhatIf does not write evidence or change
system settings. The report can contain internal account names and startup commands.

```powershell
.\windows-workstation-assistant.ps1 -Mode Restore -SnapshotPath 'C:\ProgramData\WorkstationAssistant\RUN\state.clixml' -WhatIf
.\windows-workstation-assistant.ps1 -Mode Restore -SnapshotPath 'C:\ProgramData\WorkstationAssistant\RUN\state.clixml'
```

Restore only your own trusted intact snapshot on the same machine/operator. Later
conflicting administrator changes are preserved and reported. Partial failure is
possible; consult the journal and retry recovery. Empty registry keys may remain.
**Created accounts and restore points are retained** and require manual review;
recovery does not delete users or their data. System Restore is not an external backup.

The manual checklist covers vendor-specific BIOS review, UEFI, TPM, boot policy,
BitLocker key escrow, classroom identities and course-folder ACLs, managed-device
policy, laptop AC/DC settings, recovery quotas and acceptance. Evidence supports
change management; **no ISO 9001/27001 or other certification is implied**.

Unit tests exercise pure plans and mocked writes/recovery, not live hardening.
Before rollout test audit → WhatIf → apply → reboot → applications/network/AD →
restore → reboot on disposable target-version systems, including a real legacy
application and a laptop. See the Spanish guide for the full compatibility matrix,
limits, deployment commands and Microsoft references.

## Console flow

Profile summaries lead into grouped pending/already-matching registry counts,
explicit optional actions and a four-stage apply flow. Audit and apply results
remain distinct; registry matches are not compliance scores. `-Detailed` exposes
technical paths/names without exposing startup values. `-NoColor` / `NO_COLOR`
and redirected output use plain text; lines wrap to the available console width.
Menus retry invalid input and retain supplied options when Enter is pressed.
The native-engine handoff preserves WhatIf, explicit Confirm false, arrays and
literal quoted paths; Windows target/interactive acceptance remains a lab gate.

### Discover previous runs and recover

Interactive mode detects this machine's journals in StateRoot and offers recovery before starting a new preparation. `-Mode Restore` without SnapshotPath opens the same chooser. Select a run to restore recorded registry values and the previous power scheme; recover multiple runs newest first. Accounts and later conflicting changes are retained. HKCU recovery requires the original operator. Corrupt journals are reported and skipped, and completed entries are not offered as pending.

The alternative opens Windows System Restore (`rstrui.exe`) for point selection and confirmation in Windows. This may affect unrelated applications and system settings. The script does not automatically restore or reboot. WhatIf prevents both configuration restoration and opening that wizard. Recovery requires surviving journals or Windows restore points; the prior state cannot be reliably inferred when both are lost.

### Compact console layout

The workstation wizard now uses compact numbered rows, clear current/default
markers, explicit enabled/disabled flags, and an ASCII matching-value meter in
the proposed registry plan. This is **not a security compliance score**.
Output wraps across narrow classic PowerShell consoles without ANSI dependence;
`-NoColor`, `NO_COLOR` and redirected output remain supported. Startup rows
show name and user by default; `-Detailed` also shows inventory locations,
without printing startup command values. Mutating behavior is unchanged.

### Actual Windows identity in Preflight

`-Mode Preflight` now reports the installed Windows family, edition, OS build,
optional DisplayVersion, OS architecture, model, manufacturer and laptop/desktop
classification from read-only WMI and registry calls. Windows 11 is identified
using the OS build (22000+), not NT 10.0 alone or the PowerShell engine version.
Preflight is non-elevated, does not modify the system, and preserves the
`No changes made.` marker consumed by checks and operators. Unsupported clients
and failed identification do not report success.
