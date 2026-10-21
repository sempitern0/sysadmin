#requires -Version 5.1
<#
.SYNOPSIS
Standalone workstation preparation, evidence and guarded recovery (Windows 7 SP1-11).
.DESCRIPTION
Use Windows PowerShell 5.1. Audit first; Apply supports WhatIf. No downloads,
forced reboot, application uninstall, firmware writes or domain membership changes.
.EXAMPLE
.\windows-workstation-assistant.ps1 -Mode Audit -Profile Academy
.EXAMPLE
.\windows-workstation-assistant.ps1 -Mode Apply -Profile Academy -WhatIf
.EXAMPLE
.\windows-workstation-assistant.ps1 -Mode Restore -SnapshotPath C:\ProgramData\WorkstationAssistant\RUN\state.clixml
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
    [ValidateSet('Interactive','Preflight','Audit','Apply','Restore')][string]$Mode='Interactive',
    [ValidateSet('Corporate','Academy','Legacy')][string]$Profile='Corporate',
    [switch]$DisableLegacyProtocols,
    [switch]$DisableOptionalServices,
    [switch]$UserExperience,
    [switch]$CreateRestorePoint,
    [switch]$AllowManaged,
    [string[]]$DisableStartupName=@(),
    [ValidatePattern('^$|^[a-zA-Z][a-zA-Z0-9_-]{0,19}$')][string]$StandardUserName='',
    [string]$SnapshotPath,
    [string]$StateRoot="$env:ProgramData\WorkstationAssistant"
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Get-DeviceKind {
    param([int[]]$Chassis, [int]$PCSystemType)
    if ($PCSystemType -eq 2 -or @($Chassis | Where-Object { $_ -in @(8,9,10,11,14,30,31,32) }).Count) { return 'Laptop' }
    if (@($Chassis | Where-Object { $_ -in @(3,4,5,6,7,13,15,16,23,24) }).Count) { return 'Desktop' }
    return 'Unknown'
}
function Test-WorkstationVersion {
    param([version]$Version, [int]$ProductType, [int]$ServicePack)
    if ($ProductType -ne 1) { return $false }
    if ($Version.Major -eq 6 -and $Version.Minor -eq 1) { return ($ServicePack -ge 1) }
    return ($Version -ge [version]'6.3' -and $Version.Major -le 10)
}
function New-RegSetting {
    param([string]$Path, [string]$Name, $Value, [string]$Reason, [string]$Kind='DWord')
    [pscustomobject]@{Type='Registry'; Path=$Path; Name=$Name; Value=$Value; Kind=$Kind; Reason=$Reason}
}
function Get-WorkstationPlan {
    param([version]$Version, [string]$SelectedProfile, [string]$Edition,
          [bool]$LegacyProtocols, [bool]$Visuals, [bool]$OptionalServices)
    $system='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    New-RegSetting $system 'EnableLUA' 1 'Enable UAC; reboot required'
    New-RegSetting $system 'ConsentPromptBehaviorAdmin' 2 'Administrator consent on secure desktop'
    New-RegSetting $system 'PromptOnSecureDesktop' 1 'Secure desktop for UAC'
    New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LimitBlankPasswordUse' 1 'Reject remote blank-password logons'
    New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'EveryoneIncludesAnonymous' 0 'Exclude anonymous identities from Everyone'
    New-RegSetting 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' 'NoDriveTypeAutoRun' 255 'Disable AutoRun on all drive types'
    foreach ($network in @('DomainProfile','PrivateProfile','PublicProfile')) {
        New-RegSetting "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\$network" 'EnableFirewall' 1 'Enable firewall; preserve rules'
    }
    if ($Version -ge [version]'6.2') {
        $idle=900
        if ($SelectedProfile -eq 'Academy') { $idle=600 }
        New-RegSetting $system 'InactivityTimeoutSecs' $idle 'Lock idle sessions (Academy 10 minutes, Corporate 15)'
        New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' 'HiberbootEnabled' 0 'Disable Windows Fast Startup; retain hibernation'
    }
    if ($Version -ge [version]'6.3') {
        New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0 'Do not retain WDigest plaintext credentials'
    }
    if ($Version.Major -ge 10) {
        $telemetry=1
        if ($Edition -match '^(Enterprise|Education|IoTEnterprise)') { $telemetry=0 }
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' 'AllowTelemetry' $telemetry 'Minimum supported diagnostic-data level; not zero network traffic'
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' 'DisableWindowsConsumerFeatures' 1 'Reduce consumer suggestions where supported by edition'
        New-RegSetting 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' 'DisabledByGroupPolicy' 1 'Disable advertising ID where supported'
    }
    if ($SelectedProfile -ne 'Legacy' -or $LegacyProtocols) {
        New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 'Disable SMBv1 server; reboot required'
        # Client driver/dependency edits are added after live capability checks.
    }
    if ($LegacyProtocols) {
        foreach ($protocol in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1')) {
            foreach ($side in @('Client','Server')) {
                $path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$protocol\$side"
                New-RegSetting $path 'Enabled' 0 'Disable legacy Schannel protocol; test application compatibility'
                New-RegSetting $path 'DisabledByDefault' 1 'Disable legacy Schannel protocol by default'
            }
        }
        foreach ($side in @('Client','Server')) {
            $path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\$side"
            New-RegSetting $path 'Enabled' 1 'Enable TLS 1.2 in Schannel'
            New-RegSetting $path 'DisabledByDefault' 0 'Enable TLS 1.2 by default in Schannel'
        }
    }
    if ($Visuals) {
        New-RegSetting 'HKCU:\Control Panel\Desktop\WindowMetrics' 'MinAnimate' '0' 'Disable minimize/maximize animation for executing user' 'String'
        New-RegSetting 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAnimations' 0 'Disable taskbar animation for executing user'
        if ($Version.Major -ge 10) {
            New-RegSetting 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency' 0 'Disable transparency for executing user'
        }
    }
    if ($OptionalServices) {
        foreach ($service in @('MapsBroker','XblAuthManager','XblGameSave','XboxNetApiSvc')) {
            New-RegSetting "HKLM:\SYSTEM\CurrentControlSet\Services\$service" 'Start' 4 'Optional offline maps/Xbox service; applied after reboot'
        }
    }
}
function Get-RegState {
    param([string]$Path, [string]$Name)
    if (Test-Path -LiteralPath $Path) {
        $key=Get-Item -LiteralPath $Path
        if ($key.GetValueNames() -contains $Name) {
            return [pscustomobject]@{Exists=$true; Kind=[string]$key.GetValueKind($Name); Value=$key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
        }
    }
    return [pscustomobject]@{Exists=$false; Kind=''; Value=$null}
}
function Test-SameState {
    param($Left, $Right)
    if ($Left.Exists -ne $Right.Exists) { return $false }
    if (-not $Left.Exists) { return $true }
    if ($Left.Kind -ne $Right.Kind) { return $false }
    return ((ConvertTo-Json -InputObject $Left.Value -Compress) -ceq (ConvertTo-Json -InputObject $Right.Value -Compress))
}
function Set-RegState {
    param([string]$Path, [string]$Name, $State)
    if ($State.Exists) {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $State.Value -PropertyType $State.Kind -Force | Out-Null
    } elseif ((Get-RegState $Path $Name).Exists) {
        Remove-ItemProperty -LiteralPath $Path -Name $Name
    }
}
function Get-PowerScheme {
    $output=& powercfg.exe /getactivescheme 2>&1
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read active power scheme.' }
    $match=[regex]::Match(($output -join ' '),'[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
    if (-not $match.Success) { throw 'Cannot identify active power scheme GUID.' }
    return $match.Value.ToLowerInvariant()
}
function Save-Journal {
    $script:Journal | Export-Clixml -LiteralPath "$script:JournalPath.tmp" -Depth 10
    Move-Item -LiteralPath "$script:JournalPath.tmp" -Destination $script:JournalPath -Force
}
function Restore-RecordedEntry {
    param($Entry)
    if ($Entry.Type -eq 'Registry') {
        $current=Get-RegState $Entry.Path $Entry.Name
        if (Test-SameState $current $Entry.Before) { return 'Restored' }
        if (-not (Test-SameState $current $Entry.After)) { return 'Conflict' }
        Set-RegState $Entry.Path $Entry.Name $Entry.Before
        if (-not (Test-SameState (Get-RegState $Entry.Path $Entry.Name) $Entry.Before)) { throw 'Registry recovery verification failed.' }
    } elseif ($Entry.Type -eq 'Power') {
        $current=Get-PowerScheme
        if ($current -eq $Entry.Before) { return 'Restored' }
        if ($current -ne $Entry.After) { return 'Conflict' }
        & powercfg.exe /setactive $Entry.Before | Out-Null
        if ($LASTEXITCODE -ne 0 -or (Get-PowerScheme) -ne $Entry.Before) { throw 'Power plan restore failed.' }
    } elseif ($Entry.Type -eq 'User') {
        return 'ManualReview'
    } else { throw 'Unknown journal entry type.' }
    return 'Restored'
}
function Invoke-RegistryPlan {
    param([object[]]$Plan)
    foreach ($item in $Plan) {
        $before=Get-RegState $item.Path $item.Name
        $after=[pscustomobject]@{Exists=($item.Kind -ne 'Delete');Kind=$item.Kind;Value=$item.Value}
        if (Test-SameState $before $after) { continue }
        $entry=[pscustomobject]@{Index=$script:Journal.Entries.Count;Type='Registry';Path=$item.Path;Name=$item.Name;Before=$before;After=$after;Status='Pending'}
        $script:Journal.Entries+= $entry; Save-Journal
        Set-RegState $item.Path $item.Name $after
        if (-not (Test-SameState (Get-RegState $item.Path $item.Name) $after)) { throw "Verification failed: $($item.Path) / $($item.Name)" }
        $entry.Status='Applied'; Save-Journal
    }
}
function Get-LocalGroupMembers {
    param([string]$Sid)
    $group=Get-WmiObject Win32_Group -Filter "LocalAccount=True AND SID='$Sid'"
    if (-not $group) { return @() }
    $adsi=[ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME,$group.Name)
    @($adsi.psbase.Invoke('Members') | ForEach-Object { $_.GetType().InvokeMember('Name','GetProperty',$null,$_,$null) })
}
function Get-WorkstationInventory {
    $os=Get-WmiObject Win32_OperatingSystem
    $computer=Get-WmiObject Win32_ComputerSystem
    $chassis=Get-WmiObject Win32_SystemEnclosure
    $bios=Get-WmiObject Win32_BIOS
    $edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').EditionID
    $managed=[bool]$computer.PartOfDomain
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Enrollments') {
        $enrollments=@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' | Where-Object {
            $data=Get-ItemProperty $_.PSPath
            $data.PSObject.Properties.Name -contains 'EnrollmentType'
        })
        if ($enrollments.Count) { $managed=$true }
    }
    $secureBoot='Not available (legacy BIOS, permissions or unsupported cmdlet)'
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try { $secureBoot=[string](Confirm-SecureBootUEFI) } catch { $secureBoot=$_.Exception.Message }
    }
    $tpm='Not available'
    if (Get-Command Get-Tpm -ErrorAction SilentlyContinue) {
        try { $t=Get-Tpm; $tpm="Present=$($t.TpmPresent); Ready=$($t.TpmReady)" } catch { $tpm=$_.Exception.Message }
    }
    [pscustomobject]@{
        Computer=$env:COMPUTERNAME; OS=$os.Caption; Version=[string]$os.Version
        Build=$os.BuildNumber; ProductType=[int]$os.ProductType; ServicePack=[int]$os.ServicePackMajorVersion
        Edition=$edition; Manufacturer=$computer.Manufacturer; Model=$computer.Model
        Device=Get-DeviceKind @($chassis.ChassisTypes) ([int]$computer.PCSystemType)
        BIOS=$bios.SMBIOSBIOSVersion; Managed=$managed; Domain=$computer.Domain
        User=[Security.Principal.WindowsIdentity]::GetCurrent().Name
        SecureBoot=$secureBoot; TPM=$tpm; PowerScheme=Get-PowerScheme
        Administrators=@(Get-LocalGroupMembers 'S-1-5-32-544')
        RemoteDesktopUsers=@(Get-LocalGroupMembers 'S-1-5-32-555')
        Users=@(Get-WmiObject Win32_UserAccount -Filter 'LocalAccount=True' | Select-Object Name,SID,Disabled,PasswordRequired)
        Startup=@(Get-WmiObject Win32_StartupCommand | Select-Object Name,Location,User)
        RestorePoints=@(Get-ComputerRestorePoint -ErrorAction SilentlyContinue | Select-Object SequenceNumber,Description,CreationTime)
    }
}
function Get-WorkstationDiagnostics {
    try {
        $firewall=New-Object -ComObject HNetCfg.FwPolicy2
        foreach ($id in @(1,2,4)) { "Firewall profile $id enabled: $($firewall.FirewallEnabled($id))" }
    } catch { "Firewall state UNKNOWN: $($_.Exception.Message)" }
    try {
        $antivirus=@(Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct)
        if (-not $antivirus.Count) { 'WARNING: no antivirus registered in Security Center; verify approved EDR manually.' }
        foreach ($av in $antivirus) { "Antivirus: $($av.displayName); raw productState=$($av.productState) (verify health in vendor console)" }
    } catch { "Antivirus state UNKNOWN: $($_.Exception.Message)" }
    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try { Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated | Format-List | Out-String }
        catch { "Defender health UNKNOWN: $($_.Exception.Message)" }
    }
    foreach ($name in @('wuauserv','BITS','MpsSvc','WinDefend')) {
        $service=Get-Service $name -ErrorAction SilentlyContinue
        if ($service) { "Service $name status: $($service.Status) (stopped trigger-start services are not necessarily faulty)" }
    }
    Get-WmiObject Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        "Disk $($_.DeviceID): free $([math]::Round($_.FreeSpace / 1GB,1)) GiB / $([math]::Round($_.Size / 1GB,1)) GiB"
    }
    if (Get-Command manage-bde.exe -ErrorAction SilentlyContinue) {
        & manage-bde.exe -status 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) { 'Encryption status UNKNOWN; inspect manually.' }
    } else { 'Encryption tooling unavailable; verify edition support and approved disk encryption.' }
    foreach ($path in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
                        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
        if (Test-Path $path) { "Pending reboot indicator: $path" }
    }
}
function New-ProtectedRunDirectory {
    param([string]$Root)
    $full=[IO.Path]::GetFullPath($Root)
    if ($full.StartsWith('\\')) { throw 'StateRoot must be on a local disk.' }
    # Never follow an existing redirected directory while writing privileged state.
    $cursor=$full
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'StateRoot contains a reparse point.' }
        $cursor=Split-Path -Parent $cursor
    }
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
        $identity=New-Object Security.Principal.SecurityIdentifier($sid)
        $rule=New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    if (-not (Test-Path -LiteralPath $full)) {
        New-Item -ItemType Directory -Path $full | Out-Null
        Set-Acl -LiteralPath $full -AclObject $acl
    } else {
        $existing=Get-Acl -LiteralPath $full
        $trusted=@('S-1-5-18','S-1-5-32-544',[Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        $owner=$existing.GetOwner([Security.Principal.SecurityIdentifier]).Value
        if ($owner -notin $trusted) { throw 'StateRoot owner is not trusted; choose a new dedicated local directory.' }
        foreach ($rule in $existing.Access) {
            $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            $writeMask=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
            if ($rule.AccessControlType -eq 'Allow' -and $sid -notin $trusted -and ($rule.FileSystemRights -band $writeMask)) {
                throw 'StateRoot permits non-administrative writes; choose a new dedicated directory.'
            }
        }
    }
    $run=Join-Path $full ((Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $run | Out-Null
    Set-Acl -LiteralPath $run -AclObject $acl
    return $run
}
function Write-ManualChecklist {
    param($Inventory, [string]$Destination)
    $text=@"
WORKSTATION HANDOVER / REVISION 1
Profile: $Profile | Device: $($Inventory.Device) | $($Inventory.Manufacturer) $($Inventory.Model)
OS: $($Inventory.OS) / $($Inventory.Build) | Managed: $($Inventory.Managed)
Executing user: $($Inventory.User). HKCU changes affect ONLY this account, not all students.

[ ] Lifecycle: Windows 7/8/8.1 are unsupported. Isolate legacy software (VLAN,
    restricted egress, no privileged/domain admin logons, tested offline backup).
    Windows 10 standard support ended 2025-10-14; verify exact LTSC/ESU entitlement.
    Check Windows 11 edition/build support. This tool does not verify licensing.
[ ] Apply Windows/OEM updates; verify Defender or approved AV/EDR, firewall and
    recovery environment (reagentc /info), encryption and escrowed recovery keys.
[ ] Corporate: review gpresult /r, dsregcmd /status (where available), GPO/MDM,
    LAPS, least privilege and separate named admin accounts before local changes.
[ ] Academy: individual standard student accounts, separate instructors/admins,
    NTFS ACLs for course data, restricted sharing, account lifecycle and cleanup.
    No shared administrator passwords. Local Users SID: S-1-5-32-545.
    Administrators SID: S-1-5-32-544; Remote Desktop Users: S-1-5-32-555.
    Custom course groups receive only explicit course-folder permissions.
[ ] Startup: inspect Startup folders, Run keys (32/64-bit), scheduled tasks and
    OEM utilities. Keep AV/EDR, backup, accessibility, VPN and device controls.
    DisableStartupName only removes exact Run values, never startup files/tasks.
[ ] Services: do not disable Windows Update, Defender, BITS, RPC, WLAN, printing,
    search or SysMain indiscriminately. Optional switch covers only Xbox/maps.
[ ] Firmware ($($Inventory.Manufacturer)): use vendor tools/site for this exact
    model. Check signed updates, UEFI + Secure Boot where supported, TPM 2.0,
    virtualization for course VMs, boot order and external boot policy. Escrow a
    firmware admin password separately. Never clear TPM or switch RAID/AHCI/CSM
    blindly; suspend encryption only through the approved update procedure.
    BIOS Fast Boot is a separate OEM setting: inspect manually.
[ ] Power: Balanced is selected by Apply; existing timeout values are preserved.
    $($Inventory.Device): review AC/DC display/sleep times, lid action, battery
    conservation and OEM thermal controls. Keep laptop hibernation available.
    Unknown/virtual chassis: verify physically; a UPS is not a laptop battery.
[ ] Recovery: System Protection on OS volume; review quota and free disk space
    in SystemPropertiesProtection.exe. Do not shrink quotas/delete old points.
    Use a pre-change point; Windows 8+ may reuse a point from the last 24 hours.
    System Restore is NOT a backup. Test off-device recovery and retention.
[ ] Legacy protocols: inventory old printers/NAS/apps before opting out of TLS
    1.0/1.1. Schannel controls do not cover Java/OpenSSL/private application stacks.
[ ] Privacy: edition-dependent diagnostics policy is not total telemetry removal.
    Confirm effective policy after reboot; retain security updates and AV reporting.
[ ] Sign-off: record asset ID, operator, approvals, exceptions, reboot/application
    tests and restore test. No ISO 9001/27001 certification is implied by this tool.
"@
    $text | Set-Content -LiteralPath $Destination -Encoding UTF8
}

if ($Mode -eq 'Preflight') {
    Write-Output "PowerShell: $($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition)"
    Write-Output 'Requires Windows PowerShell 5.1 (Desktop), Windows 7 SP1 or later client OS; Apply requires elevation.'
    Write-Output 'No changes made.'
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') { exit 1 }
    exit 0
}
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run with Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell to avoid redirected registry views.' }
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Open an elevated Windows PowerShell console. Preflight needs no elevation.' }
$machineId=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

if ($Mode -eq 'Restore') {
    if (-not $SnapshotPath) { throw 'Specify -SnapshotPath state.clixml from this machine.' }
    $script:Journal=Import-Clixml -LiteralPath $SnapshotPath
    if ($Journal.Schema -ne 1 -or $Journal.MachineId -ne $machineId -or $Journal.UserSid -ne $userSid) { throw 'Snapshot version, machine or operator mismatch.' }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Restore recorded settings; preserve subsequent conflicting edits')) { return }
    $script:JournalPath=[IO.Path]::GetFullPath($SnapshotPath)
    $conflicts=0
    foreach ($entry in @($Journal.Entries | Sort-Object Index -Descending)) {
        try {
            $result=Restore-RecordedEntry $entry
            if ($result -eq 'Conflict') { $conflicts++; Write-Warning "Concurrent change preserved (entry $($entry.Index))."; continue }
            if ($result -eq 'ManualReview') {
                Write-Warning "Account $($entry.Name) retained; review manually after preserving its data."
            }
            $entry.Status=$result; Save-Journal
        } catch { $conflicts++; Write-Warning $_.Exception.Message }
    }
    if ($conflicts) { throw "$conflicts restore errors/conflicts. Review journal and retry only after resolving them." }
    Write-Output 'Recorded settings restored. Reboot and validate; created accounts are retained.'
    return
}
$inventory=Get-WorkstationInventory
if (-not (Test-WorkstationVersion ([version]$inventory.Version) $inventory.ProductType $inventory.ServicePack)) { throw 'Only Windows 7 SP1 through Windows 11 client editions are supported.' }
if ([version]$inventory.Version -lt [version]'10.0' -and -not $PSBoundParameters.ContainsKey('Profile')) { $Profile='Legacy' }
if ($Mode -eq 'Interactive') {
    Write-Host ('{0} | {1} {2} | {3}' -f $inventory.OS,$inventory.Manufacturer,$inventory.Model,$inventory.Device)
    $selection=Read-Host "Profile: 1 Corporate, 2 Academy, 3 Legacy (Enter keeps $Profile)"
    switch ($selection) { '2' {$Profile='Academy'} '3' {$Profile='Legacy'} '' {} '1' {$Profile='Corporate'} default {throw 'Invalid profile.'} }
    $Mode='Audit'
    if ((Read-Host 'Type APPLY to configure; Enter only audits') -ceq 'APPLY') {
        $Mode='Apply'
        $DisableLegacyProtocols=((Read-Host 'Disable old TLS/SSL after compatibility checks? y/N') -eq 'y')
        $DisableOptionalServices=((Read-Host 'Disable Xbox/maps services? y/N') -eq 'y')
        $UserExperience=((Read-Host "Reduce animations for executing account $($inventory.User)? y/N") -eq 'y')
        $CreateRestorePoint=((Read-Host 'Request a pre-change restore point? y/N') -eq 'y')
        $inventory.Startup | Format-Table Name,Location,User -AutoSize | Out-Host
        $startupSelection=Read-Host 'Exact Run startup names to disable, separated by ; (Enter keeps all)'
        if ($startupSelection) { $DisableStartupName=@($startupSelection.Split(';') | ForEach-Object { $_.Trim() }) }
        $StandardUserName=Read-Host 'New standard local account name (Enter to skip)'
        if ($StandardUserName -and $StandardUserName -notmatch '^[a-zA-Z][a-zA-Z0-9_-]{0,19}$') { throw 'Invalid local account name.' }
    }
}
if ($Mode -eq 'Apply' -and [version]$inventory.Version -lt [version]'6.3' -and $Profile -ne 'Legacy') { throw 'Windows 7/8 requires -Profile Legacy. Protocol removal remains explicit.' }
if ($Mode -eq 'Apply' -and $inventory.Managed -and -not $AllowManaged) { throw 'Managed/domain device: audit and review GPO/MDM first; use -AllowManaged only with approved local exceptions.' }
if ($StandardUserName -and (Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Name='$StandardUserName'")) {
    throw 'Requested account already exists. No passwords or memberships will be replaced.'
}
$plan=@(Get-WorkstationPlan ([version]$inventory.Version) $Profile $inventory.Edition $DisableLegacyProtocols $UserExperience $DisableOptionalServices)
# Only disable existing optional service drivers. No fabricated service keys.
$plan=@($plan | Where-Object { $_.Name -ne 'Start' -or (Test-Path -LiteralPath $_.Path) })
if (($Profile -ne 'Legacy' -or $DisableLegacyProtocols) -and (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10')) {
    $path='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation'
    $dependencies=Get-RegState $path 'DependOnService'
    if (-not $dependencies.Exists -or $dependencies.Kind -ne 'MultiString') { throw 'Cannot safely inspect SMB client dependencies; no changes made.' }
    $plan+=New-RegSetting $path 'DependOnService' @($dependencies.Value | Where-Object { $_ -ine 'mrxsmb10' }) 'Remove only SMBv1 driver dependency' 'MultiString'
    $plan+=New-RegSetting 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' 'Start' 4 'Disable SMBv1 client driver after reboot'
}
foreach ($name in $DisableStartupName) {
    if ([string]::IsNullOrWhiteSpace($name) -or $name -match '[*?\[\]]') { throw 'Startup names must be exact nonempty Run value names, without wildcards.' }
    $matched=$false
    foreach ($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')) {
        if ((Get-RegState $path $name).Exists) {
            $plan+=[pscustomobject]@{Type='Registry';Path=$path;Name=$name;Value=$null;Kind='Delete';Reason='Explicitly selected startup Run entry'}
            $matched=$true
        }
    }
    if (-not $matched) { throw "Startup value not found: $name. Audit first; no changes made." }
}
$plan | Select-Object Path,Name,Reason | Format-Table -AutoSize | Out-Host
Write-Host "Profile=$Profile; managed=$($inventory.Managed); power=Balanced; standard user=$StandardUserName"
if ($Mode -eq 'Apply' -and -not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Apply displayed workstation plan (reboot required)')) { return }
if ($WhatIfPreference) { return }
$run=New-ProtectedRunDirectory $StateRoot
$inventory | Export-Clixml -LiteralPath (Join-Path $run 'inventory.clixml') -Depth 6
$plan | Export-Csv -LiteralPath (Join-Path $run 'plan.csv') -NoTypeInformation -Encoding UTF8
$observed=@(foreach ($item in $plan) {
    $current=Get-RegState $item.Path $item.Name
    $desired=[pscustomobject]@{Exists=($item.Kind -ne 'Delete'); Kind=$item.Kind; Value=$item.Value}
    [pscustomobject]@{Path=$item.Path;Name=$item.Name;Current=$current;Desired=$desired;Matches=(Test-SameState $current $desired)}
})
$observed | Export-Clixml -LiteralPath (Join-Path $run 'settings-audit.clixml') -Depth 6
Get-WorkstationDiagnostics | Set-Content -LiteralPath (Join-Path $run 'diagnostics.txt') -Encoding UTF8
Write-ManualChecklist $inventory (Join-Path $run 'manual-checklist.txt')
Write-Output "Evidence: $run"
if ($Mode -eq 'Audit') { return }
$script:JournalPath=Join-Path $run 'state.clixml'
$script:Journal=[pscustomobject]@{Schema=1;MachineId=$machineId;UserSid=$userSid;Profile=$Profile;Created=(Get-Date).ToString('o');Entries=@()}
Save-Journal
if ($CreateRestorePoint) {
    # Fail rather than claim that a restore point was created. No quota changes.
    $before=@(Get-ComputerRestorePoint)
    try {
        Checkpoint-Computer -Description 'Sysadmin workstation preparation' -RestorePointType MODIFY_SETTINGS -WarningAction Continue
    } catch {
        Write-Warning "Checkpoint request failed: $($_.Exception.Message). Checking for a recent existing point."
    }
    $after=@(Get-ComputerRestorePoint)
    if (-not $after.Count) { throw 'No restore point available. Enable System Protection and retry.' }
    $latest=$after | Sort-Object SequenceNumber -Descending | Select-Object -First 1
    if ($before.Count -and $latest.SequenceNumber -le ($before | Measure-Object SequenceNumber -Maximum).Maximum) {
        $date=[Management.ManagementDateTimeConverter]::ToDateTime($latest.CreationTime)
        if ($date -lt (Get-Date).AddHours(-24) -or $date -gt (Get-Date)) { throw 'No new or recent restore point verified.' }
        Write-Warning 'Windows reused a restore point from the last 24 hours; no new point created.'
    }
    $latest | Export-Clixml -LiteralPath (Join-Path $run 'restore-point.clixml')
}
try {
    Invoke-RegistryPlan $plan
    $balanced='381b4222-f694-41f0-9685-ff5bb260df2e'
    $current=Get-PowerScheme
    if ($current -ne $balanced) {
        $entry=[pscustomobject]@{Index=$Journal.Entries.Count;Type='Power';Before=$current;After=$balanced;Status='Pending'}
        $Journal.Entries+=$entry; Save-Journal
        & powercfg.exe /setactive $balanced
        if ($LASTEXITCODE -ne 0 -or (Get-PowerScheme) -ne $balanced) { throw 'Balanced plan unavailable or blocked. Review OEM power policy.' }
        $entry.Status='Applied'; Save-Journal
    }
    if ($StandardUserName) {
        if (Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True AND Name='$StandardUserName'") { throw 'Account exists; no passwords or memberships will be replaced.' }
        $password=Read-Host "Password for new standard user $StandardUserName" -AsSecureString
        $confirmation=Read-Host 'Repeat password' -AsSecureString
        $a=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $b=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmation)
        try {
            $plain=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($a)
            if ($plain.Length -lt 14 -or $plain -cne [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b)) { throw 'Passwords must match and contain at least 14 characters.' }
            $computer=[ADSI]("WinNT://{0},computer" -f $env:COMPUTERNAME)
            $entry=[pscustomobject]@{Index=$Journal.Entries.Count;Type='User';Name=$StandardUserName;Status='Pending'}
            $Journal.Entries+=$entry; Save-Journal
            $account=$computer.Create('user',$StandardUserName)
            $account.SetPassword($plain)
            $account.Put('UserFlags',514) # Normal account, initially disabled until group assignment succeeds.
            $account.SetInfo()
            $users=Get-WmiObject Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-545'"
            $group=[ADSI]("WinNT://{0}/{1},group" -f $env:COMPUTERNAME,$users.Name)
            $group.Add("WinNT://$env:COMPUTERNAME/$StandardUserName,user")
            $account.Put('UserFlags',512); $account.SetInfo()
            $entry.Status='Applied'; Save-Journal
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($a)
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b)
            $plain=$null; $password.Dispose(); $confirmation.Dispose()
        }
    }
    Write-Output "Applied. Journal: $JournalPath. Reboot manually, audit again and validate applications."
} catch {
    Write-Warning "Partial application; recorded changes can be restored using -Mode Restore -SnapshotPath '$JournalPath'."
    throw
}
