# Windows workstation preparation

[Guía completa en español](WORKSTATIONS_ES.md) · [Overview](../README.md)

Download the standalone root `windows-workstation-assistant.ps1` at a reviewed
commit. No runtime helpers, downloads, installation or execution-policy bypass.
Use native **Windows PowerShell 5.1**, elevated except for Preflight. Windows 7
requires SP1 and preinstalled WMF 5.1; Windows 8 RTM is not supported by that runtime.
Windows 8.1/10/11 client editions are capability-gated; server editions are rejected.
PowerShell 7 can run safe Preflight only. Use native 64-bit PowerShell on 64-bit OS.

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
