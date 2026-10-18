#requires -Version 5.1
<#
.SYNOPSIS
Standalone migration console: Windows Server upgrade planning and verified file transfers.
.DESCRIPTION
Plan/Status/Preflight never change services. DryRun contacts the destination but does not
copy data. Copy requires explicit backup, permissions and frozen-source attestations.
UbuntuFiles uses a configured SFTP remote; NextcloudFiles uses a configured WebDAV remote.
No OS installation, account/ACL conversion, source deletion or automatic cutover is performed.
.EXAMPLE
.\migration-assistant.ps1 -Mode Interactive
.EXAMPLE
.\migration-assistant.ps1 -Mode Plan -Profile Server2022To2025 -Workspace C:\Migration\upgrade
.EXAMPLE
.\migration-assistant.ps1 -Mode Plan -Profile NextcloudFiles -Source D:\Data -Destination nc:Migration/batch1 -ConfigPath C:\Secure\rclone.conf -Workspace C:\Migration\files
#>
[CmdletBinding()]
param(
    [ValidateSet('Interactive','Preflight','Plan','Status','DryRun','Copy','Verify','VerifyUpgrade')]
    [string]$Mode = 'Interactive',
    [ValidateSet('Server2022To2025','UbuntuFiles','NextcloudFiles')]
    [string]$Profile = 'Server2022To2025',
    [string]$Workspace = '',
    [string]$Source = '',
    [string]$Destination = '',
    [string]$ConfigPath = '',
    [switch]$BackupVerified,
    [switch]$PermissionsReviewed,
    [switch]$SourceFrozen,
    [string]$ConfirmDestination = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$script:Schema = 1

function Assert-FileTarget {
    param([string]$Value)
    # Named remote plus a dedicated subtree. No inline backend, URL, root or traversal.
    if ($Value -notmatch '^[A-Za-z][A-Za-z0-9_-]{1,63}:[A-Za-z0-9_][A-Za-z0-9_ ./-]*$') {
        throw 'Destination must be a named rclone remote and dedicated folder, e.g. nc:Migration/batch1.'
    }
    $parts = ($Value.Split(':',2)[1]).Split('/')
    if (@($parts | Where-Object { $_ -eq '' -or $_ -eq '.' -or $_ -eq '..' -or $_ -ne $_.Trim() }).Count) {
        throw 'Empty, dot, traversal and surrounding-space path segments are forbidden.'
    }
}

function Get-LocalFolder {
    param([string]$Value)
    if (-not $Value -or -not [IO.Path]::IsPathRooted($Value)) { throw 'Source must be an absolute local or UNC directory.' }
    Assert-NoReparseAncestors $Value
    $item = Get-Item -LiteralPath $Value -Force
    if (-not $item.PSIsContainer -or $item.PSProvider.Name -ne 'FileSystem') { throw 'Source must be a filesystem directory.' }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Source cannot be a link or junction.' }
    return $item.FullName
}

function Assert-NoReparseAncestors {
    param([string]$Path)
    while ($Path) {
        if (Test-Path -LiteralPath $Path) {
            $item = Get-Item -LiteralPath $Path -Force
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Path traverses a link/junction: $Path" }
        }
        $parent = Split-Path -Path $Path -Parent
        if ($parent -eq $Path) { break }
        $Path = $parent
    }
}

function Assert-NoLinks {
    param([string]$Folder)
    # Do not silently omit links/junctions from a supposedly verified migration.
    $links = @(Get-ChildItem -LiteralPath $Folder -Recurse -Force -ErrorAction Stop |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } | Select-Object -First 1)
    if ($links.Count) { throw ('Source contains a link/junction: ' + $links[0].FullName) }
}

function Get-ServerInventory {
    if ($env:OS -ne 'Windows_NT') { throw 'Windows is required for Windows Server inventory.' }
    $os = Get-CimInstance Win32_OperatingSystem
    $computer = Get-CimInstance Win32_ComputerSystem
    $features = @(Get-WindowsFeature -ErrorAction Stop | Where-Object Installed | Select-Object -ExpandProperty Name)
    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Select-Object DeviceID,Size,FreeSpace)
    return [pscustomobject]@{
        Caption = $os.Caption; Build = [string]$os.BuildNumber; ProductType = [int]$os.ProductType
        DomainRole = [int]$computer.DomainRole; Domain = $computer.Domain
        Features = $features; Volumes = $volumes
        Services = @(Get-Service | Select-Object Name,Status,StartType)
    }
}

function Get-UpgradeBlockers {
    param($Inventory)
    if ($Inventory.Build -ne '20348' -or $Inventory.ProductType -eq 1) { 'Source must be Windows Server 2022 (build 20348).' }
    if ($Inventory.DomainRole -ge 4 -or 'AD-Domain-Services' -in $Inventory.Features) {
        'AD DS: use new 2025 DCs, validate replication/DNS, transfer FSMO and then demote old DCs. No in-place route.'
    }
    if ('Failover-Clustering' -in $Inventory.Features) { 'Cluster: use a role-specific cluster rolling upgrade procedure.' }
}

function Get-Runbook {
    param([string]$Kind)
    if ($Kind -eq 'Server2022To2025') {
        return @(
            'Inventory roles/apps, editions, language, installation type, drivers, activation and vendor support for 2025.'
            'For AD DS: use windows-ad-assistant.ps1 -Mode Migration; validate DFL/FFL, DNS, replication and system-state restore before introducing 2025 DCs.'
            'For a nonclustered member server: test full OS/app/data/VM backup restoration, retain off-host evidence and console access.'
            'Rehearse on an isolated clone; validate disk capacity, pending reboot, hardware and all role-specific prerequisites.'
            'Schedule outage; stop or migrate VMs and quiesce applications. Use the platform-specific upgrade process for Azure.'
            'Mount approved 2025 media and run Setup manually; require compatible edition and Keep files, settings and apps. Cancel if unavailable.'
            'After reboot run VerifyUpgrade, then test application transactions, DNS, shares, permissions, backups and monitoring from clients.'
            'Rollback is a tested full-server/application restore during the agreed window, not an automatic OS downgrade.'
        )
    }
    $targetStep = if ($Kind -eq 'UbuntuFiles') {
        'Provision Ubuntu/SFTP separately; pin the SSH host key in rclone known_hosts_file; map AD identities and Samba/POSIX ACLs explicitly.'
    } else {
        'Provision Nextcloud separately; use HTTPS WebDAV with vendor=nextcloud and an app password; create users/groups/quotas and sharing policies.'
    }
    return @(
        $targetStep
        'Configure rclone outside this assistant. Keep credentials in a restricted config; reserve a dedicated destination subtree for this job.'
        'Scope is ordinary file contents. NTFS ACLs, SIDs, ADS, EFS, hard-link identity, shares, accounts and application databases are not migrated.'
        'Export source ACLs/share definitions separately. Test filenames, case collisions, locks, file sizes, quota and user access on a pilot.'
        'Stop writers or use a consistent read-only snapshot; verify a restorable backup and destination permissions before Copy.'
        'Run DryRun, review its output, then Copy with explicit attestations. Existing different files are rejected, not overwritten.'
        'Run Verify while the source remains frozen. Content is downloaded for comparison; this can be expensive.'
        'After verification, perform client acceptance and switch service endpoints manually. Retain the old source read-only for the recovery window.'
        'Rollback before new writes: return clients to the retained source. After new writes: reconcile destination changes before reverting. Never blindly delete either side.'
    )
}

function Save-Plan {
    param($Plan, [string]$Folder)
    $path = Join-Path $Folder 'plan.json'
    $temp = Join-Path $Folder ('plan-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $json = $Plan | ConvertTo-Json -Depth 12
        [IO.File]::WriteAllText($temp, $json, (New-Object Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $path) {
            $backup = $temp + '.previous'
            [IO.File]::Replace($temp,$path,$backup)
            Remove-Item -LiteralPath $backup
        }
        else { [IO.File]::Move($temp,$path) }
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp } }
}

function Add-Event {
    param($Plan,[string]$Phase,[string]$Detail)
    $Plan.Phase = $Phase
    $Plan.History = @($Plan.History) + @([pscustomobject]@{
        Utc = [DateTime]::UtcNow.ToString('o'); Phase = $Phase; Detail = $Detail
    })
}

function Assert-Plan {
    param($Plan)
    if ($Plan.Schema -ne $script:Schema -or $Plan.Profile -notin @('Server2022To2025','UbuntuFiles','NextcloudFiles')) { throw 'Unsupported plan schema/profile.' }
    if ($Plan.HostName -ne [Environment]::MachineName) { throw 'Run this workspace on the original source host.' }
    if ($Plan.Profile -ne 'Server2022To2025') {
        Assert-FileTarget $Plan.Destination
        $actual = Get-LocalFolder $Plan.Source
        if ($actual -ne $Plan.Source) { throw 'Source location changed.' }
        Assert-NoReparseAncestors $Plan.ConfigPath
        if ((Get-FileHash -LiteralPath $Plan.ConfigPath -Algorithm SHA256).Hash -ne $Plan.ConfigHash) {
            throw 'rclone configuration changed. Create a new plan and review the new destination.'
        }
    }
}

function Invoke-Rclone {
    param([string[]]$Arguments)
    $exe = (Get-Command rclone -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    & $exe @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "rclone failed (exit $LASTEXITCODE); see the operation log." }
}

function Assert-RcloneEnvironment {
    # Environment flags can silently change copy/check semantics or destination credentials.
    $overrides = @(Get-ChildItem Env: | Where-Object { $_.Name -like 'RCLONE_*' -and $_.Name -ne 'RCLONE_CONFIG_PASS' })
    if ($overrides.Count) { throw 'Remove RCLONE_* environment overrides (except RCLONE_CONFIG_PASS) before running this assistant.' }
}

function Assert-RemoteType {
    param($Plan)
    $exe = (Get-Command rclone -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
    $listing = @(& $exe listremotes --long --config $Plan.ConfigPath)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect configured rclone remotes.' }
    $name = $Plan.Destination.Split(':',2)[0]
    $expected = if ($Plan.Profile -eq 'UbuntuFiles') { 'sftp' } else { 'webdav' }
    $pattern = '^\s*' + [regex]::Escape($name) + ':\s+' + $expected + '(\s|$)'
    if (-not @($listing | Where-Object { $_ -cmatch $pattern }).Count) {
        throw "Profile requires a configured $expected remote named ${name}."
    }
}

function Invoke-MigrationAction {
    param([string]$Action)
    if (-not $Workspace) { throw 'Specify -Workspace outside the source data tree.' }
    $folder = [IO.Path]::GetFullPath($Workspace)
    Assert-NoReparseAncestors $folder
    if ($Action -eq 'Plan') {
        if (Test-Path -LiteralPath $folder) { throw 'Use a new, nonexistent workspace for each plan.' }
        $inventory = $null; $blockers = @(); $configHash = ''; $resolvedSource = ''; $resolvedConfig = ''
        if ($Profile -eq 'Server2022To2025') {
            $inventory = Get-ServerInventory
            $blockers = @(Get-UpgradeBlockers $inventory)
        } else {
            Assert-FileTarget $Destination
            $resolvedSource = Get-LocalFolder $Source
            $prefix = $resolvedSource.TrimEnd([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
            if ($folder -eq $resolvedSource -or $folder.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Workspace must be outside the source tree.' }
            $resolvedConfig = (Get-Item -LiteralPath $ConfigPath).FullName
            Assert-NoReparseAncestors $resolvedConfig
            if ($resolvedConfig.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Credential config must be outside the source tree.' }
            $configHash = (Get-FileHash -LiteralPath $resolvedConfig -Algorithm SHA256).Hash
            Assert-NoLinks $resolvedSource
        }
        $plan = [pscustomobject]@{
            Schema = $script:Schema; Id = [guid]::NewGuid().ToString(); HostName = [Environment]::MachineName
            Profile = $Profile; Source = $resolvedSource; Destination = $Destination
            ConfigPath = $resolvedConfig; ConfigHash = $configHash; Inventory = $inventory
            Blockers = $blockers; Runbook = @(Get-Runbook $Profile); Phase = 'Planned'; History = @()
        }
        [void][IO.Directory]::CreateDirectory($folder)
        Add-Event $plan 'Planned' 'Plan only; no compatibility certification or destination writes.'
        Save-Plan $plan $folder
        Write-Output "Plan created: $folder"
        $plan.Runbook | ForEach-Object { Write-Output "- $_" }
        $plan.Blockers | ForEach-Object { Write-Warning $_ }
        return
    }
    # Exclusive workspace lock prevents concurrent copy/check or lost journal updates.
    $lock = [IO.File]::Open((Join-Path $folder '.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $plan = Get-Content -LiteralPath (Join-Path $folder 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Plan $plan
        if ($Action -eq 'Status') { $plan | ConvertTo-Json -Depth 12; return }
        if ($Action -eq 'VerifyUpgrade') {
            if ($plan.Profile -ne 'Server2022To2025') { throw 'VerifyUpgrade requires an upgrade plan.' }
            $now = Get-ServerInventory
            if ($now.Build -ne '26100' -or $now.ProductType -eq 1) { throw 'Expected Windows Server 2025 build 26100; upgrade not verified.' }
            $now | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $folder 'post-upgrade.json') -Encoding UTF8
            Add-Event $plan 'OSVersionVerified' 'OS version only. Application/client acceptance and backup checks remain mandatory.'
            Save-Plan $plan $folder
            Write-Output $plan.History[-1].Detail
            return
        }
        if ($plan.Profile -eq 'Server2022To2025') { throw 'Upgrade is guided: follow the runbook and run VerifyUpgrade afterward. No file-copy action applies.' }
        Assert-RcloneEnvironment
        Assert-RemoteType $plan
        Assert-NoLinks $plan.Source
        if ($Action -eq 'Copy') {
            if ($plan.Phase -ne 'Previewed') { throw 'Run and review a successful DryRun immediately before Copy.' }
            if (-not ($BackupVerified -and $PermissionsReviewed -and $SourceFrozen) -or $ConfirmDestination -cne $plan.Destination) {
                throw 'Copy requires -BackupVerified -PermissionsReviewed -SourceFrozen and -ConfirmDestination matching the plan exactly.'
            }
        }
        if ($Action -eq 'Verify' -and $plan.Phase -notin @('Copied','ContentVerified')) { throw 'A successful Copy is required before Verify; retry DryRun/Copy after failures.' }
        if ($Action -eq 'Verify' -and -not $SourceFrozen) { throw 'Verify requires -SourceFrozen.' }
        $log = Join-Path $folder ($Action + '-' + [guid]::NewGuid().ToString('N') + '.log')
        $common = @('--config',$plan.ConfigPath,'--log-file',$log,'--log-level','INFO')
        # No remote shell probes or automatic shell_type persistence in the pinned config.
        # SFTP integrity is established by the subsequent downloaded comparison.
        if ($plan.Profile -eq 'UbuntuFiles') { $common += @('--sftp-shell-type','none','--sftp-disable-hashcheck') }
        $arguments = if ($Action -eq 'Verify') {
            @('check',$plan.Source,$plan.Destination,'--download') + $common
        } else {
            @('copy',$plan.Source,$plan.Destination,'--immutable','--checksum','--create-empty-src-dirs') + $common
        }
        if ($Action -eq 'DryRun') { $arguments += '--dry-run' }
        Add-Event $plan ($Action + 'Running') ('Started; log: ' + [IO.Path]::GetFileName($log))
        Save-Plan $plan $folder
        try {
            Invoke-Rclone $arguments
            $phase = switch ($Action) { 'DryRun' {'Previewed'} 'Copy' {'Copied'} 'Verify' {'ContentVerified'} }
            Add-Event $plan $phase 'Command succeeded. Service cutover and permissions acceptance are separate manual steps.'
            Save-Plan $plan $folder
            Write-Output "State: $phase. Review $log"
        } catch {
            Add-Event $plan 'Failed' "$Action failed or was interrupted; review log, then repeat DryRun/Copy."
            Save-Plan $plan $folder
            throw
        }
    } finally { $lock.Dispose() }
}

try {
    if ($Mode -eq 'Preflight') {
        Write-Output ('PowerShell: ' + $PSVersionTable.PSVersion)
        Write-Output ('Windows inventory: ' + ($env:OS -eq 'Windows_NT'))
        Write-Output ('rclone available: ' + [bool](Get-Command rclone -CommandType Application -ErrorAction SilentlyContinue))
        Write-Output 'No changes made. Transfer needs rclone/config; upgrade inventory needs Windows Server/Get-WindowsFeature.'
        return
    }
    if ($Mode -eq 'Interactive') {
        if ([Console]::IsInputRedirected) { throw 'Interactive mode requires a terminal.' }
        Write-Host 'MIGRATION CONTROL CENTER / CENTRO DE MIGRACIONES'
        Write-Host '1 Server 2022 -> 2025 (guided) | 2 Windows -> Ubuntu files | 3 Windows -> Nextcloud files'
        switch (Read-Host 'Profile / Perfil') {
            '1' { $Profile = 'Server2022To2025' }
            '2' { $Profile = 'UbuntuFiles' }
            '3' { $Profile = 'NextcloudFiles' }
            default { throw 'Invalid profile.' }
        }
        $Workspace = Read-Host 'Workspace outside source / Carpeta de trabajo fuera del origen'
        while ($true) {
            Write-Host 'Plan | Status | DryRun | Copy | Verify | VerifyUpgrade | Exit'
            $action = Read-Host 'Action / Accion'
            if ($action -eq 'Exit') { break }
            if ($action -notin @('Plan','Status','DryRun','Copy','Verify','VerifyUpgrade')) { Write-Warning 'Invalid action'; continue }
            try {
                if ($action -eq 'Plan' -and $Profile -ne 'Server2022To2025') {
                    $Source = Read-Host 'Source absolute path / Ruta absoluta origen'
                    $Destination = Read-Host 'Destination remote:folder / Destino remote:carpeta'
                    $ConfigPath = Read-Host 'rclone config path / Ruta configuracion rclone'
                }
                # Reset every action so an earlier confirmation cannot authorize later copies.
                $BackupVerified = $false; $PermissionsReviewed = $false; $SourceFrozen = $false; $ConfirmDestination = ''
                if ($action -eq 'Copy') {
                    $BackupVerified = (Read-Host 'Restorable backup tested? / Backup restaurado en prueba? Type YES') -ceq 'YES'
                    $PermissionsReviewed = (Read-Host 'Target permissions and transport reviewed? / Permisos y transporte revisados? Type YES') -ceq 'YES'
                    $ConfirmDestination = Read-Host 'Type exact destination / Escribe destino exacto'
                }
                if ($action -in @('Copy','Verify')) { $SourceFrozen = (Read-Host 'Source writers stopped/snapshot? / Origen congelado? Type YES') -ceq 'YES' }
                Invoke-MigrationAction $action
            } catch { Write-Warning $_.Exception.Message }
        }
    } else { Invoke-MigrationAction $Mode }
} catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 1
}
