#requires -Version 5.1
<#
.SYNOPSIS
    Windows Server AD Control Plane - v1.8.3-runtime-sanitization

.DESCRIPTION
    Professional, audit-first assistant for Windows Server and Active Directory.

    Primary targets:
      - Windows Server 2019
      - Windows Server 2022
      - Windows Server 2025
      - Windows PowerShell 5.1+

    Core principles:
      - Detect before modify.
      - Preserve remote administration paths.
      - Create a change-set before remediation.
      - Require explicit confirmation for every material change.
      - Require the literal word APPLY for destructive/high-impact actions.
      - Prefer Microsoft-native modules and tools.
      - Be role-aware: Domain Controller != member server.
      - Keep host hardening separate from directory administration.
      - Re-audit after hardening.
      - Never claim blanket CIS compliance.
      - Provide a professional console UI with clear operational context.

    Modes:
      Interactive  Full control-plane menu
      Audit        Read-only host + AD audit
      Validate     Domain Controller functional validation
      Harden       Audit + interactive host hardening
      Backup       Create configuration change-set
      ADAdmin      Active Directory operations console
      Provision    Guided NEW forest provisioning
      Migration    Domain migration assessment and tooling
      DirectorySecurity  Kerberos/LDAP/SMB protocol security center
      Dependencies       Official Windows feature/module dependency center
      Reset              Supported AD DS demotion + post-reboot cleanup
      IDS                Optional Suricata IDS integration, EVE analytics and native GUI dashboard
      IDSReport          Non-interactive 24h IDS report target for Task Scheduler
      RemoteOps          Remote endpoint operations center

.EXAMPLE
    .\windows-ad-assistant.ps1

.EXAMPLE
    .\windows-ad-assistant.ps1 -Mode Audit

.EXAMPLE
    .\windows-ad-assistant.ps1 -Mode ADAdmin

.EXAMPLE
    .\windows-ad-assistant.ps1 -Mode Validate

.EXAMPLE
    .\windows-ad-assistant.ps1 -Mode Preflight
    Check local launch prerequisites without elevation or configuration changes.

.NOTES
    Validate in a lab before production deployment.
#>

[CmdletBinding()]
param(
    [ValidateSet('Preflight','Interactive','Audit','Validate','Harden','Backup','ADAdmin','Provision','Migration','DirectorySecurity','Dependencies','Reset','IDS','IDSReport','IDSResponseCleanup','IDSAwarenessCheck','RemoteOps')]
    [string]$Mode = 'Interactive',

    [ValidateSet('en','es')]
    [string]$Language = 'en',

    [string]$ExportPath = "$env:ProgramData\WindowsADControlPlane",

    [switch]$NoColor,

    # Firewall default-policy changes during RDP/WinRM are skipped unless this
    # switch is supplied. HIGH-impact confirmation is still required.
    [switch]$AllowRemoteFirewallChange
)

# Preflight must run before path construction, logging, discovery or elevation.
# A standalone download needs no helper modules for this check.
function Invoke-LaunchPreflight {
    $failed = $false
    Write-Output 'Preflight: Windows domain controller'
    Write-Output ("PowerShell: {0}" -f $PSVersionTable.PSVersion)
    if ($env:OS -ne 'Windows_NT') {
        Write-Output '[FAIL] Windows is required.'
        return 1
    }
    foreach ($command in @('Get-CimInstance','Get-NetAdapter','Get-DnsClientServerAddress')) {
        if (Get-Command $command -ErrorAction SilentlyContinue) {
            Write-Output ("[OK] {0}" -f $command)
        } else {
            Write-Output ("[FAIL] Missing launch prerequisite: {0}" -f $command)
            $failed = $true
        }
    }
    foreach ($module in @('ActiveDirectory','DnsServer')) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Output ("[WARN] Module {0} is absent; relevant role operations require it." -f $module)
        }
    }
    Write-Output '[INFO] Operational modes require an elevated Windows console.'
    Write-Output 'No changes made. Next: review warnings, then run -Mode Audit on the target host.'
    if ($failed) { return 1 }
    return 0
}

if ($Mode -eq 'Preflight') {
    $result = @(Invoke-LaunchPreflight)
    $result | Select-Object -SkipLast 1 | Write-Output
    exit ([int]$result[-1])
}
if ($env:OS -ne 'Windows_NT') { throw 'This assistant requires Windows. Use -Mode Preflight for launch checks.' }
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required. Preflight is the only non-elevated mode.'
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ===========================================================================
# Runtime state
# ===========================================================================

$script:ProductName = 'Windows Server AD Control Plane'
$script:Version = '1.8.3-runtime-sanitization'
$script:Started = Get-Date

$script:Results = New-Object 'System.Collections.Generic.List[object]'
$script:Changes = New-Object 'System.Collections.Generic.List[object]'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'

$script:Step = 0
$script:TotalSteps = 1
$script:LogFile = $null
$script:ReportFile = $null
$script:RunPath = $null
$script:BackupPath = $null
$script:SnapshotCreated = $false

$script:IsRemoteSession = $false
$script:RemoteKind = 'Local/Console'
$script:IsDomainController = $false
$script:ServerInfo = $null
$script:RoleInfo = @()
$script:PowerShellMajor = $PSVersionTable.PSVersion.Major
$script:DomainInfo = $null
$script:ForestInfo = $null
$script:MainMenuRequested = $false
$script:ResetCompleted = $false
$script:ResetRecoveryRoot = Join-Path $env:SystemDrive 'WindowsAD-ControlPlane-Recovery'
$script:PreProvisionStateFile = Join-Path $ExportPath 'pre-provisioning-state.json'
$script:IdsStatePath = Join-Path $ExportPath 'ids'
$script:IdsReportPath = Join-Path $script:IdsStatePath 'reports'
$script:IdsIntegrationFile = Join-Path $script:IdsStatePath 'suricata-integration.json'
$script:IdsTaskName = 'WindowsADControlPlane-SuricataDaily'
$script:WazuhIntegrationFile = Join-Path $script:IdsStatePath 'wazuh-integration.json'
$script:GuardedIpsStateFile = Join-Path $script:IdsStatePath 'guarded-ips.json'
$script:GuardedIpsTaskName = 'WindowsADControlPlane-GuardedIpsCleanup'
$script:GuardedIpsRulePrefix = 'WindowsADControlPlane-IPS-'
$script:DefenseOpsConfigFile = Join-Path $script:IdsStatePath 'defense-ops.json'
$script:TelegramTokenFile = Join-Path $script:IdsStatePath 'telegram-token.dpapi'
$script:RemoteOpsPath = Join-Path $ExportPath 'remote-ops'
$script:RemoteOpsEvidencePath = Join-Path $script:RemoteOpsPath 'evidence'
$script:RemoteOpsLog = Join-Path $script:RemoteOpsPath 'operations.tsv'
$script:RemoteTarget = $null
$script:RemoteOpsCredential = $null
$script:RemoteSshUser = $null
$script:DnsExternalProbeName = 'www.microsoft.com'
$script:DnsExternalHealth = 'UNKNOWN'
$script:DnsExternalHealthChecked = $null
$script:SuricataUpdateTimeoutSeconds = 1200

$script:UiWidth = 96
$script:UiLanguage = $Language.ToLowerInvariant()

$script:UiSpanish = @{
 'AD/DC CONTROL PLANE'='PLANO DE CONTROL AD/DC'; 'Workspace navigation · stable letters for daily muscle memory'='Navegación por áreas · letras estables para memoria muscular';
 'Daily operations'='Operaciones diarias'; 'Directory'='Directorio'; 'Policy / DNS'='Política / DNS'; 'Policy / GPO / DNS'='Política / GPO / DNS'; 'Security'='Seguridad'; 'Remote operations'='Operaciones remotas'; 'Insights / IDS'='Información / IDS'; 'Maintenance'='Mantenimiento'; 'All modules'='Todos los módulos'; 'Exit'='Salir'; 'Close control plane'='Cerrar plano de control'; 'Workspace'='Área de trabajo'; 'Invalid workspace.'='Área de trabajo no válida.';
 'Back'='Volver'; 'Main menu'='Menú principal'; 'Return to previous console'='Volver a la consola anterior'; 'Jump directly to the Windows Server Control Plane'='Ir directamente al plano de control de Windows Server'; 'Select operation'='Selecciona operación'; 'Press ENTER to continue'='Pulsa ENTER para continuar';
 'IDS / Suricata'='IDS / Suricata'; 'Wazuh integration'='Integración Wazuh'; 'Defense operations'='Operaciones de defensa'; 'Guarded IPS response'='Respuesta IPS controlada'; 'Blocked IP addresses'='Direcciones IP bloqueadas'; 'Unblock selected IP'='Desbloquear IP seleccionada'; 'Emergency unblock all'='Desbloqueo de emergencia total'; 'Temporarily block IP'='Bloquear IP temporalmente'; 'Trust selected IP'='Confiar en IP seleccionada'; 'Trusted IP addresses'='Direcciones IP de confianza'; 'Awareness schedule'='Horario de vigilancia'; 'Telegram notifications'='Notificaciones de Telegram';
 'Suricata IDS readiness'='Preparación IDS de Suricata'; 'Suricata sensor health'='Salud del sensor Suricata'; 'Wazuh + Suricata integration'='Integración Wazuh + Suricata'; 'Recent Wazuh agent signals:'='Señales recientes del agente Wazuh:'; 'Configure Wazuh manager'='Configurar manager Wazuh'; 'Integrate Suricata EVE with Wazuh'='Integrar EVE de Suricata con Wazuh'; 'Open graphical Defense Center'='Abrir Centro de Defensa gráfico';
 'Windows AD Defense Center - Suricata + Wazuh'='Centro de Defensa AD de Windows - Suricata + Wazuh'; 'Windows AD Control Plane - Suricata IDS'='Plano de control AD de Windows - IDS Suricata'; 'Blocks'='Bloqueos'; 'Alerts'='Alertas'; 'Refresh'='Actualizar'; 'Unblock'='Desbloquear'; 'Unblock selected'='Desbloquear seleccionado'; 'Unblock all'='Desbloquear todo'; 'Block IP'='Bloquear IP'; 'Trust IP'='Confiar en IP'; 'Trust selected'='Confiar en seleccionado'; 'Run IPS now'='Ejecutar IPS ahora'; 'Blocked / trusted IPs'='IPs bloqueadas / confiables'; 'Awareness alerts'='Alertas de vigilancia'; 'Operations'='Operaciones'; 'Apply guarded response'='Aplicar respuesta controlada'; 'Close'='Cerrar'; 'Language / Idioma'='Idioma / Language'
}
function Get-UiText { param([Parameter(Mandatory=$true)][string]$Text) if($script:UiLanguage -eq 'es' -and $script:UiSpanish.ContainsKey($Text)){ return [string]$script:UiSpanish[$Text] }; return $Text }
function Switch-UiLanguage { $script:UiLanguage = if($script:UiLanguage -eq 'en'){'es'}else{'en'} }

function Test-IsInteractiveConsole {
    try {
        return (-not [Console]::IsOutputRedirected)
    }
    catch {
        return $true
    }
}

$script:UseColor = (-not $NoColor) -and (Test-IsInteractiveConsole) -and (-not $env:NO_COLOR)

# ===========================================================================
# Console UI
# ===========================================================================

function Write-Console {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text,
        [ValidateSet('Default','Cyan','Green','Yellow','Red','Magenta','Gray','White','DarkCyan')]
        [string]$Color = 'Default',
        [switch]$NoNewline
    )

    if (-not $script:UseColor -or $Color -eq 'Default') {
        if ($NoNewline) { Write-Host $Text -NoNewline }
        else { Write-Host $Text }
        return
    }

    if ($NoNewline) {
        Write-Host $Text -ForegroundColor $Color -NoNewline
    }
    else {
        Write-Host $Text -ForegroundColor $Color
    }
}

function Clear-ControlPlane {
    if (Test-IsInteractiveConsole) {
        try { Clear-Host } catch {}
    }
}

function Write-Rule {
    Write-Console ('─' * $script:UiWidth) Gray
}

function Write-Section {
    param([Parameter(Mandatory=$true)][string]$Title)

    Write-Console ''
    Write-Rule
    Write-Console ('  {0}' -f (Get-UiText $Title).ToUpperInvariant()) White
    Write-Rule
}

function Get-ServiceBadge {
    param([Parameter(Mandatory=$true)][string]$Name)

    try {
        $svc = Get-Service -Name $Name -ErrorAction Stop
        if ($svc.Status -eq 'Running') { return 'ONLINE' }
        return ([string]$svc.Status).ToUpperInvariant()
    }
    catch {
        return 'N/A'
    }
}

function Write-Badge {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [ValidateSet('Good','Warn','Bad','Info')]
        [string]$Kind = 'Info',
        [switch]$NoNewline
    )

    $color = switch ($Kind) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Bad'  { 'Red' }
        default { 'Cyan' }
    }

    Write-Console ('[{0}]' -f $Text) $color -NoNewline:$NoNewline
}

function Write-ContextPanel {
    $hostName = if ($script:ServerInfo) { $script:ServerInfo.ComputerName } else { $env:COMPUTERNAME }
    $osText = if ($script:ServerInfo) {
        '{0} / build {1}' -f (Get-WindowsServerGeneration -Info $script:ServerInfo), $script:ServerInfo.Build
    }
    else {
        'discovering'
    }

    $domain = if ($script:ServerInfo -and $script:ServerInfo.PartOfDomain) {
        $script:ServerInfo.Domain
    }
    else {
        'WORKGROUP / unjoined'
    }

    $role = if ($script:IsDomainController) { 'Domain Controller' } else { 'Member / standalone' }

    Write-Console ('  {0}' -f $domain) White -NoNewline
    Write-Console ('  |  {0}' -f $hostName) Cyan -NoNewline
    Write-Console ('  |  {0}' -f $role) Gray
    Write-Console ('  {0}  |  Session={1}  |  PowerShell={2}' -f `
        $osText, $script:RemoteKind, $PSVersionTable.PSVersion) Gray

    if ($script:IsDomainController) {
        Write-Console '  ' -NoNewline
        Write-ServiceStatusInline -Label 'AD' -ServiceName 'NTDS'
        Write-ServiceStatusInline -Label 'DNS' -ServiceName 'DNS'
        Write-ServiceStatusInline -Label 'KRB' -ServiceName 'Kdc'
        Write-ServiceStatusInline -Label 'NETLOGON' -ServiceName 'Netlogon'
        Write-ServiceStatusInline -Label 'ADWS' -ServiceName 'ADWS'
        Write-ServiceStatusInline -Label 'SMB' -ServiceName 'LanmanServer'
        Write-ServiceStatusInline -Label 'WINRM' -ServiceName 'WinRM'

        $idsState = Get-ServiceBadge -Name 'suricata'
        $idsKind = if ($idsState -eq 'ONLINE') { 'Good' } elseif ($idsState -eq 'N/A') { 'Info' } else { 'Warn' }
        Write-Console 'IDS=' Gray -NoNewline
        Write-Badge -Text $idsState -Kind $idsKind -NoNewline
        Write-Console ' ' -NoNewline

        $extKind = if ($script:DnsExternalHealth -eq 'OK') { 'Good' } `
            elseif ($script:DnsExternalHealth -eq 'CHECK') { 'Warn' } else { 'Info' }
        Write-Console 'EXTDNS=' Gray -NoNewline
        Write-Badge -Text $script:DnsExternalHealth -Kind $extKind
    }
}

function Write-MenuHeader {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [string]$Subtitle = ''
    )

    Clear-ControlPlane
    Write-Console '  WINDOWS SERVER AD CONTROL PLANE' Cyan
    Write-Console ('  v{0}  |  Native Microsoft tooling  |  Audit-first operations' -f $script:Version) Gray
    Write-Rule
    Write-ContextPanel
    Write-Rule
    Write-Console ('  {0}' -f (Get-UiText $Title).ToUpperInvariant()) White
    if ($Subtitle) {
        Write-Console ('  {0}' -f (Get-UiText $Subtitle)) Gray
    }
    Write-Console ''
}


function Write-WorkspaceRow {
    param(
        [Parameter(Mandatory=$true)][string]$Key1,
        [Parameter(Mandatory=$true)][string]$Title1,
        [ValidateSet('Cyan','Green','Yellow','Red','Magenta','DarkCyan','Gray')]
        [string]$Color1 = 'Cyan',
        [string]$Key2 = '',
        [string]$Title2 = '',
        [ValidateSet('Cyan','Green','Yellow','Red','Magenta','DarkCyan','Gray')]
        [string]$Color2 = 'Cyan'
    )

    Write-Console ('  [{0}] ' -f $Key1) $Color1 -NoNewline
    Write-Console ('{0,-31}' -f (Get-UiText $Title1)) White -NoNewline

    if ($Key2) {
        Write-Console ('[{0}] ' -f $Key2) $Color2 -NoNewline
        Write-Console (Get-UiText $Title2) White
    }
    else {
        Write-Console ''
    }
}

function Write-ServiceStatusInline {
    param(
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][string]$ServiceName
    )

    $state = Get-ServiceBadge -Name $ServiceName
    $kind = if ($state -eq 'ONLINE') { 'Good' } elseif ($state -eq 'N/A') { 'Info' } else { 'Bad' }
    Write-Console ("{0}=" -f $Label) Gray -NoNewline
    Write-Badge -Text $state -Kind $kind -NoNewline
    Write-Console ' ' -NoNewline
}

function Write-MenuItem {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][string]$Description,
        [ValidateSet('Normal','Good','Warn','Danger')]
        [string]$Kind = 'Normal'
    )

    $color = switch ($Kind) {
        'Good' { 'Green' }
        'Warn' { 'Yellow' }
        'Danger' { 'Red' }
        default { 'Cyan' }
    }

    Write-Console ('  [{0,2}]  ' -f $Key) Gray -NoNewline
    Write-Console ('{0,-31}' -f (Get-UiText $Title)) $color -NoNewline
    Write-Console (Get-UiText $Description) Gray
}


function Write-MenuNavigation {
    param([string]$BackDescription = 'Return to previous console')

    Write-MenuItem '0' 'Back' $BackDescription Danger
    Write-MenuItem 'H' 'Main menu' 'Jump directly to the Windows Server Control Plane' Warn
}

function Read-MenuChoice {
    param(
        [string]$Prompt = 'Select operation',
        [string]$Default = ''
    )

    if ($Default) {
        $value = (Read-Host ('{0} [{1}]' -f (Get-UiText $Prompt), $Default)).Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            return $Default
        }
        return $value
    }

    return (Read-Host (Get-UiText $Prompt)).Trim()
}


function Read-BooleanChoice {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [bool]$Default = $false
    )

    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }

    while ($true) {
        $answer = (Read-Host ("{0} {1}" -f (Get-UiText $Prompt), $suffix)).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
        if ($answer -in @('Y','YES','S','SI','SÍ')) { return $true }
        if ($answer -in @('N','NO')) { return $false }
        Write-Console 'Please answer yes or no.' Yellow
    }
}

function Read-OptionalBooleanChoice {
    param([Parameter(Mandatory=$true)][string]$Prompt)

    while ($true) {
        $answer = (Read-Host ("{0} [K/y/n]" -f $Prompt)).Trim().ToUpperInvariant()
        if ([string]::IsNullOrWhiteSpace($answer) -or $answer -eq 'K') { return $null }
        if ($answer -in @('Y','YES','S','SI','SÍ')) { return $true }
        if ($answer -in @('N','NO')) { return $false }
        Write-Console 'Use K to keep, Y for yes, or N for no.' Yellow
    }
}

function Pause-ControlPlane {
    if (Test-IsInteractiveConsole) {
        Write-Console ''
        Write-Rule
        [void](Read-Host (Get-UiText 'Press ENTER to continue'))
    }
}

function Write-Banner {
    Clear-ControlPlane

    Write-Console @'
       ██╗    ██╗██╗███╗   ██╗    █████╗ ██████╗
       ██║    ██║██║████╗  ██║   ██╔══██╗██╔══██╗
       ██║ █╗ ██║██║██╔██╗ ██║   ███████║██║  ██║
       ██║███╗██║██║██║╚██╗██║   ██╔══██║██║  ██║
       ╚███╔███╔╝██║██║ ╚████║   ██║  ██║██████╔╝
        ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝   ╚═╝  ╚═╝╚═════╝
'@ Cyan

    Write-Console '                     WINDOWS SERVER AD CONTROL PLANE' White
    Write-Console '              Provisioning · security · operations · recovery' Gray
    Write-Rule
    Write-Console ('  Version       {0}' -f $script:Version) Cyan
    Write-Console ('  Mode          {0}' -f $Mode)
    Write-Console ('  Session       {0}' -f $script:RemoteKind)
    Write-Console ('  PowerShell    {0}' -f $PSVersionTable.PSVersion)
    Write-Rule
    Write-Console ''
}

# ===========================================================================
# Runtime / logging / reporting
# ===========================================================================

function Initialize-Runtime {
    if (-not (Test-Path -LiteralPath $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $script:RunPath = Join-Path $ExportPath "runs\$timestamp-$PID"
    $script:BackupPath = Join-Path $script:RunPath 'backup'

    New-Item -ItemType Directory -Path $script:BackupPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:RemoteOpsPath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:RemoteOpsEvidencePath -Force | Out-Null
    if (-not (Test-Path -LiteralPath $script:RemoteOpsLog)) {
        New-Item -ItemType File -Path $script:RemoteOpsLog -Force | Out-Null
    }

    $script:LogFile = Join-Path $ExportPath "control-plane-$timestamp-$PID.log"
    $script:ReportFile = Join-Path $ExportPath "control-plane-report-$timestamp-$PID.json"

    New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR','CHANGE','DEBUG')]
        [string]$Level = 'INFO'
    )

    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8

    switch ($Level) {
        'OK'     { Write-Console $line Green }
        'WARN'   { Write-Console $line Yellow }
        'ERROR'  { Write-Console $line Red }
        'CHANGE' { Write-Console $line Magenta }
        'DEBUG'  { Write-Console $line Gray }
        default  { Write-Console $line }
    }
}

function Add-Warning {
    param([Parameter(Mandatory=$true)][string]$Message)

    [void]$script:Warnings.Add($Message)
    Write-Log $Message WARN
}

function Add-Change {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [ValidateSet('APPLIED','SKIPPED','FAILED')]
        [Parameter(Mandatory=$true)][string]$Status,
        [Parameter(Mandatory=$true)][string]$Reason,
        [string]$ErrorMessage = ''
    )

    [void]$script:Changes.Add([pscustomobject]@{
        Time   = Get-Date
        Name   = $Name
        Status = $Status
        Reason = $Reason
        Error  = $ErrorMessage
    })
}

function Add-Result {
    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [Parameter(Mandatory=$true)][string]$Control,
        [ValidateSet('PASS','WARN','FAIL','INFO','SKIP','ERROR','MANAGED')]
        [Parameter(Mandatory=$true)][string]$Status,
        [Parameter(Mandatory=$true)][string]$Current,
        [Parameter(Mandatory=$true)][string]$Expected,
        [string]$Remediation = '',
        [string]$Reference = ''
    )

    [void]$script:Results.Add([pscustomobject]@{
        Category    = $Category
        Control     = $Control
        Status      = $Status
        Current     = $Current
        Expected    = $Expected
        Remediation = $Remediation
        Reference   = $Reference
    })

    $prefix = switch ($Status) {
        'PASS'    { '[ OK ]' }
        'WARN'    { '[WARN]' }
        'FAIL'    { '[FAIL]' }
        'ERROR'   { '[ERR ]' }
        'SKIP'    { '[SKIP]' }
        'MANAGED' { '[MGMT]' }
        default   { '[INFO]' }
    }

    $color = switch ($Status) {
        'PASS'    { 'Green' }
        'WARN'    { 'Yellow' }
        'FAIL'    { 'Red' }
        'ERROR'   { 'Red' }
        'SKIP'    { 'Gray' }
        'MANAGED' { 'Cyan' }
        default   { 'Gray' }
    }

    Write-Console ('  {0,-6}  {1,-35} {2}' -f $prefix, $Control, $Current) $color
}

function Set-StepPlan {
    param([Parameter(Mandatory=$true)][int]$Total)

    $script:TotalSteps = [Math]::Max(1, $Total)
    $script:Step = 0
}

function Write-Step {
    param([Parameter(Mandatory=$true)][string]$Title)

    $script:Step++
    $percent = [Math]::Min(100, [int](($script:Step / $script:TotalSteps) * 100))

    if (Test-IsInteractiveConsole) {
        Write-Progress -Activity $script:ProductName -Status $Title -PercentComplete $percent
    }

    Write-Console ''
    Write-Console ('  [{0:d2}/{1:d2}] {2}' -f $script:Step, $script:TotalSteps, $Title) Cyan
}

function Complete-Progress {
    try { Write-Progress -Activity $script:ProductName -Completed } catch {}
}

function Test-Command {
    param([Parameter(Mandatory=$true)][string]$Name)

    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Confirm-Action {
    param(
        [Parameter(Mandatory=$true)][string]$Action,
        [Parameter(Mandatory=$true)][string]$Reason,
        [ValidateSet('LOW','MEDIUM','HIGH')]
        [string]$Impact = 'LOW'
    )

    if ($Mode -eq 'Audit' -or $Mode -eq 'Backup' -or $Mode -eq 'Validate') {
        return $false
    }

    Write-Console ''
    Write-Rule

    $color = if ($Impact -eq 'HIGH') { 'Red' } elseif ($Impact -eq 'MEDIUM') { 'Yellow' } else { 'Cyan' }
    Write-Console ('  {0} IMPACT OPERATION' -f $Impact) $color
    Write-Console ('  Action : {0}' -f $Action)
    Write-Console ('  Reason : {0}' -f $Reason)
    Write-Rule

    if ($Impact -eq 'HIGH') {
        $answer = Read-Host 'Type APPLY to authorize'
        return ($answer -ceq 'APPLY')
    }

    do {
        $answer = (Read-Host 'Apply this change? [Y/N]').Trim().ToUpperInvariant()
    } while ($answer -notin @('Y','N'))

    return ($answer -eq 'Y')
}


function Confirm-ExactText {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][string]$Expected
    )

    Write-Console ''
    Write-Rule
    Write-Console $Prompt Red
    Write-Console ("Type exactly: {0}" -f $Expected) White
    $answer = Read-Host '>'
    return ($answer -ceq $Expected)
}

function Invoke-Change {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Reason,
        [Parameter(Mandatory=$true)][scriptblock]$Action,
        [ValidateSet('LOW','MEDIUM','HIGH')]
        [string]$Impact = 'LOW',
        [scriptblock]$PostCheck
    )

    if (-not (Confirm-Action -Action $Name -Reason $Reason -Impact $Impact)) {
        Add-Change -Name $Name -Status SKIPPED -Reason $Reason
        Write-Log "Skipped: $Name" WARN
        return $false
    }

    if (-not $script:SnapshotCreated) {
        New-ChangeSet
    }

    try {
        & $Action

        if ($PostCheck) {
            $ok = & $PostCheck
            if (-not $ok) {
                throw 'Post-change validation failed.'
            }
        }

        Add-Change -Name $Name -Status APPLIED -Reason $Reason
        Write-Log "Applied: $Name" CHANGE
        return $true
    }
    catch {
        Add-Change -Name $Name -Status FAILED -Reason $Reason -ErrorMessage $_.Exception.Message
        Write-Log ("Failed: {0} :: {1}" -f $Name, $_.Exception.Message) ERROR
        return $false
    }
}

# ===========================================================================
# Discovery
# ===========================================================================

function Get-ServerInfo {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem

    return [pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Domain       = $cs.Domain
        PartOfDomain = [bool]$cs.PartOfDomain
        DomainRole   = [int]$cs.DomainRole
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
        OS           = $os.Caption
        Version      = $os.Version
        Build        = [int]$os.BuildNumber
        InstallDate  = $os.InstallDate
        LastBoot     = $os.LastBootUpTime
        Architecture = $os.OSArchitecture
    }
}

function Test-IsDomainController {
    param($Info = $script:ServerInfo)

    if ($null -eq $Info) { return $false }
    return ($Info.DomainRole -in @(4,5))
}

function Get-SessionContext {
    $remote = $false
    $kind = 'Local/Console'

    if ($env:SESSIONNAME -like 'RDP-*') {
        $remote = $true
        $kind = 'RDP'
    }

    $sender = Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    if ($sender -and $sender.Value) {
        $remote = $true
        $kind = 'PowerShell Remoting'
    }

    return [pscustomobject]@{
        IsRemote = $remote
        Kind     = $kind
    }
}

function Get-WindowsServerGeneration {
    param([Parameter(Mandatory=$true)]$Info)

    if ($Info.Build -ge 26100) { return '2025' }
    if ($Info.Build -ge 20348) { return '2022' }
    if ($Info.Build -ge 17763) { return '2019' }
    return 'UNTESTED'
}

function Get-InstalledServerRoles {
    $roles = @()

    if (Test-Command 'Get-WindowsFeature') {
        try {
            $roles = @(Get-WindowsFeature | Where-Object {
                $_.Installed -and (
                    $_.Name -in @(
                        'AD-Domain-Services',
                        'DNS',
                        'DHCP',
                        'FS-FileServer',
                        'Hyper-V',
                        'Web-Server',
                        'RDS-RD-Server',
                        'Failover-Clustering',
                        'Windows-Server-Backup'
                    )
                )
            } | Select-Object Name, DisplayName, Installed)
        }
        catch {
            Add-Warning ("Role discovery failed: {0}" -f $_.Exception.Message)
        }
    }

    return $roles
}

function Import-ADModules {
    if (-not $script:IsDomainController -and -not (Test-Command 'Get-ADDomain')) {
        return $false
    }

    try {
        if (-not (Get-Module -Name ActiveDirectory)) {
            Import-Module ActiveDirectory -ErrorAction Stop
        }
        return $true
    }
    catch {
        Add-Warning ("ActiveDirectory module unavailable: {0}" -f $_.Exception.Message)
        return $false
    }
}

function Initialize-Discovery {
    $ctx = Get-SessionContext
    $script:IsRemoteSession = $ctx.IsRemote
    $script:RemoteKind = $ctx.Kind
    $script:ServerInfo = Get-ServerInfo
    $script:IsDomainController = Test-IsDomainController
    $script:RoleInfo = @(Get-InstalledServerRoles)

    if ($script:IsDomainController -and (Import-ADModules)) {
        try { $script:DomainInfo = Get-ADDomain -ErrorAction Stop } catch {}
        try { $script:ForestInfo = Get-ADForest -ErrorAction Stop } catch {}
    }
}

function Assert-DomainController {
    if (-not $script:IsDomainController) {
        throw 'This operation requires a Domain Controller.'
    }

    if (-not (Import-ADModules)) {
        [void](Ensure-WindowsServerFeature `
            -Name 'RSAT-AD-Tools' `
            -Purpose 'Active Directory PowerShell administration' `
            -Required)

        if (-not (Import-ADModules)) {
            throw 'The ActiveDirectory PowerShell module is required and could not be repaired.'
        }
    }
}


# ===========================================================================
# Official Windows Server dependencies / servicing
# ===========================================================================

function Get-ServerFeatureSafe {
    param([Parameter(Mandatory=$true)][string]$Name)

    if (-not (Test-Command 'Get-WindowsFeature')) { return $null }
    try { return Get-WindowsFeature -Name $Name -ErrorAction Stop }
    catch { return $null }
}

function Test-ServerFeatureInstalled {
    param([Parameter(Mandatory=$true)][string]$Name)

    $feature = Get-ServerFeatureSafe -Name $Name
    return [bool]($feature -and $feature.Installed)
}

function Ensure-WindowsServerFeature {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Purpose,
        [switch]$IncludeManagementTools,
        [switch]$Required,
        [switch]$NoPrompt
    )

    if (Test-ServerFeatureInstalled -Name $Name) { return $true }

    if (-not (Test-Command 'Install-WindowsFeature')) {
        if ($Required) {
            Write-Console ("Required Windows feature '{0}' is missing and ServerManager is unavailable." -f $Name) Red
        }
        return $false
    }

    $feature = Get-ServerFeatureSafe -Name $Name
    if (-not $feature) {
        if ($Required) {
            Write-Console ("Required Windows feature '{0}' is not available on this OS image." -f $Name) Red
        }
        return $false
    }

    $install = $NoPrompt
    if (-not $NoPrompt) {
        $install = Read-BooleanChoice `
            -Prompt ("Install official Windows feature '{0}' for {1}?" -f $Name, $Purpose) `
            -Default $true
    }

    if (-not $install) { return $false }

    $params = @{
        Name        = $Name
        ErrorAction = 'Stop'
    }
    if ($IncludeManagementTools) {
        $params.IncludeManagementTools = $true
    }

    try {
        Write-Console ("Installing Windows feature: {0}" -f $Name) Cyan
        $result = Install-WindowsFeature @params
        $result | Out-Host

        if (-not (Test-ServerFeatureInstalled -Name $Name)) {
            Write-Console ("Feature installation did not leave '{0}' installed." -f $Name) Red
            return $false
        }

        if ($result.RestartNeeded -eq 'Yes') {
            Add-Warning ("Windows feature '{0}' requests a reboot." -f $Name)
        }

        Write-Log ("Installed official Windows feature: {0}" -f $Name) CHANGE
        return $true
    }
    catch {
        Write-Console ("Feature installation failed for {0}: {1}" -f $Name, $_.Exception.Message) Red
        Write-Log ("Feature installation failed for {0}: {1}" -f $Name, $_.Exception.Message) ERROR
        return $false
    }
}

function Get-WindowsDependencyInventory {
    $items = @(
        [pscustomobject]@{ Name='AD-Domain-Services'; Kind='Windows feature'; Purpose='Domain Controller role / provisioning'; RequiredOnDC=$true },
        [pscustomobject]@{ Name='RSAT-AD-Tools'; Kind='Windows feature'; Purpose='ActiveDirectory module and AD DS administration'; RequiredOnDC=$true },
        [pscustomobject]@{ Name='GPMC'; Kind='Windows feature'; Purpose='GroupPolicy module / GPO management'; RequiredOnDC=$true },
        [pscustomobject]@{ Name='RSAT-DNS-Server'; Kind='Windows feature'; Purpose='DnsServer module / AD DNS administration'; RequiredOnDC=$false },
        [pscustomobject]@{ Name='Windows-Server-Backup'; Kind='Windows feature'; Purpose='wbadmin system-state backup'; RequiredOnDC=$false }
    )

    foreach ($item in $items) {
        $feature = Get-ServerFeatureSafe -Name $item.Name
        [pscustomobject]@{
            Name         = $item.Name
            Kind         = $item.Kind
            Installed    = [bool]($feature -and $feature.Installed)
            Available    = [bool]$feature
            InstallState = $(if ($feature) { [string]$feature.InstallState } else { 'Unavailable' })
            Purpose      = $item.Purpose
            RequiredNow  = [bool]($script:IsDomainController -and $item.RequiredOnDC)
            Origin       = 'Windows Server / Microsoft component store'
        }
    }
}

function Show-WindowsDependencyAudit {
    Write-Section 'Official dependency inventory'

    $inventory = @(Get-WindowsDependencyInventory)
    $inventory |
        Select-Object Name, Installed, Available, RequiredNow, Purpose |
        Format-Table -AutoSize

    Write-Console ''
    Write-Console 'PowerShell/module requirements:' Cyan

    $modules = @(
        @{ Name='ActiveDirectory'; Purpose='AD users/groups/computers/domain operations' },
        @{ Name='GroupPolicy'; Purpose='GPO operations' },
        @{ Name='DnsServer'; Purpose='DNS zones/records' },
        @{ Name='ADDSDeployment'; Purpose='DC promotion/demotion' },
        @{ Name='ServerManager'; Purpose='Windows role/feature installation' },
        @{ Name='NetSecurity'; Purpose='Windows Firewall' }
    )

    foreach ($m in $modules) {
        $available = [bool](Get-Module -ListAvailable -Name $m.Name)
        $status = if ($available) { 'AVAILABLE' } else { 'MISSING/NOT APPLICABLE' }
        Write-Console ('  {0,-20} {1,-24} {2}' -f $m.Name, $status, $m.Purpose) $(if ($available) { 'Green' } else { 'Yellow' })
    }

    Write-Console ''
    Write-Console 'External package managers/modules required by this assistant: NONE' Green
    Write-Console '  No Chocolatey, winget, NuGet or PowerShell Gallery dependency is required.' Gray
    Write-Console '  Windows roles/modules are serviced through Windows Update / WSUS according to organization policy.' Gray
}

function Repair-WindowsDependencies {
    param(
        [ValidateSet('ExistingDC','Provisioning')]
        [string]$Profile = 'ExistingDC'
    )

    if ($Profile -eq 'Provisioning') {
        if (-not (Ensure-WindowsServerFeature `
            -Name 'AD-Domain-Services' `
            -Purpose 'new forest provisioning' `
            -IncludeManagementTools `
            -Required `
            -NoPrompt)) {
            throw 'AD-Domain-Services could not be installed.'
        }

        # These are management surfaces used by the control plane after the
        # promotion reboot. Install only when available and currently missing.
        [void](Ensure-WindowsServerFeature -Name 'GPMC' -Purpose 'Group Policy administration' -NoPrompt)
        [void](Ensure-WindowsServerFeature -Name 'RSAT-DNS-Server' -Purpose 'DNS administration' -NoPrompt)
        return
    }

    if (-not $script:IsDomainController) {
        Write-Console 'ExistingDC profile is only applicable to a Domain Controller.' Yellow
        return
    }

    [void](Ensure-WindowsServerFeature `
        -Name 'RSAT-AD-Tools' `
        -Purpose 'Active Directory administration' `
        -Required)

    [void](Ensure-WindowsServerFeature `
        -Name 'GPMC' `
        -Purpose 'Group Policy administration' `
        -Required)

    if (Test-ServerFeatureInstalled -Name 'DNS') {
        [void](Ensure-WindowsServerFeature `
            -Name 'RSAT-DNS-Server' `
            -Purpose 'DNS administration')
    }
}

function Show-WindowsServicingStatus {
    Write-Section 'Windows servicing status'

    try {
        $wu = Get-Service -Name wuauserv -ErrorAction Stop
        Add-Result 'Dependencies' 'Windows Update service' 'INFO' `
            ("{0}; StartType={1}" -f $wu.Status, $wu.StartType) `
            'Managed by organizational Windows Update/WSUS policy'
    }
    catch {
        Add-Result 'Dependencies' 'Windows Update service' 'WARN' 'wuauserv unavailable' 'Available'
    }

    $hotfixes = @()
    try {
        $hotfixes = @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10)
    }
    catch {}

    if ($hotfixes.Count -gt 0) {
        $hotfixes | Select-Object HotFixID, Description, InstalledOn | Format-Table -AutoSize
    }

    $rebootPending = $false
    foreach ($path in @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    )) {
        if (Test-Path $path) { $rebootPending = $true }
    }

    Add-Result 'Dependencies' 'Pending reboot' `
        $(if ($rebootPending) { 'WARN' } else { 'PASS' }) `
        $(if ($rebootPending) { 'YES' } else { 'NO' }) `
        'No pending reboot before AD DS role/configuration changes'

    Write-Console ''
    Write-Console 'The control plane intentionally does not install a third-party Windows Update module.' Gray
    Write-Console 'OS component updates remain under the normal Windows Update / WSUS / enterprise servicing workflow.' Gray
}

function Show-DependencyMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }

        Write-MenuHeader 'DEPENDENCIES & SERVICING' 'Official Windows Server features only; no third-party package manager'
        Write-MenuItem '1' 'Dependency audit' 'Roles, RSAT features and PowerShell modules used by the control plane'
        Write-MenuItem '2' 'Repair DC management tools' 'Install only missing RSAT/GPMC/DNS tools' Good
        Write-MenuItem '3' 'Windows Server Backup' 'Install optional Windows-Server-Backup feature for wbadmin'
        Write-MenuItem '4' 'Servicing status' 'Windows Update service, latest hotfixes and pending reboot'
        Write-MenuNavigation
        Write-Rule

        try {
        switch (Read-MenuChoice -Default '1') {
            '1' { Show-WindowsDependencyAudit; Pause-ControlPlane }
            '2' { Repair-WindowsDependencies -Profile ExistingDC; Pause-ControlPlane }
            '3' {
                [void](Ensure-WindowsServerFeature `
                    -Name 'Windows-Server-Backup' `
                    -Purpose 'system-state backup')
                Pause-ControlPlane
            }
            '4' { Show-WindowsServicingStatus; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ('Show-DependencyMenu: operation failed: {0}' -f $message) Red
            Write-Log ('Recoverable menu error in Show-DependencyMenu: {0}' -f $message) ERROR
            Pause-ControlPlane
        }
    }
}

# ===========================================================================
# Change-set / recovery
# ===========================================================================

function Export-RegistryKey {
    param(
        [Parameter(Mandatory=$true)][string]$RegistryPath,
        [Parameter(Mandatory=$true)][string]$FileName
    )

    if (-not (Test-Command 'reg.exe')) { return }

    $dest = Join-Path $script:BackupPath $FileName
    & reg.exe export $RegistryPath $dest /y *> $null
}

function New-ChangeSet {
    if ($script:SnapshotCreated) {
        return
    }

    Write-Log ("Creating change-set backup: {0}" -f $script:BackupPath) INFO

    $script:ServerInfo | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $script:BackupPath 'server-info.json') -Encoding UTF8

    $script:RoleInfo | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $script:BackupPath 'server-roles.json') -Encoding UTF8

    try {
        Get-NetIPConfiguration |
            Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv4DefaultGateway, DnsServer |
            ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath (Join-Path $script:BackupPath 'network.json') -Encoding UTF8
    }
    catch {
        Add-Warning ("Network snapshot failed: {0}" -f $_.Exception.Message)
    }

    if (Test-Command 'netsh.exe') {
        & netsh.exe advfirewall export (Join-Path $script:BackupPath 'firewall.wfw') *> $null
    }

    if (Test-Command 'Get-NetFirewallProfile') {
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, NotifyOnListen, LogFileName |
            ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $script:BackupPath 'firewall-profiles.json') -Encoding UTF8
    }

    if (Test-Command 'Get-SmbServerConfiguration') {
        Get-SmbServerConfiguration |
            ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $script:BackupPath 'smb-server.json') -Encoding UTF8
    }

    if (Test-Command 'Get-SmbClientConfiguration') {
        Get-SmbClientConfiguration |
            ConvertTo-Json -Depth 5 |
            Set-Content -LiteralPath (Join-Path $script:BackupPath 'smb-client.json') -Encoding UTF8
    }

    if (Test-Command 'Get-MpPreference') {
        try {
            Get-MpPreference |
                ConvertTo-Json -Depth 8 |
                Set-Content -LiteralPath (Join-Path $script:BackupPath 'defender-preference.json') -Encoding UTF8
        }
        catch {
            Add-Warning ("Defender preference snapshot failed: {0}" -f $_.Exception.Message)
        }
    }

    if ($script:IsDomainController) {
        if (Import-ADModules) {
            try {
                Get-ADDomain | ConvertTo-Json -Depth 6 |
                    Set-Content -LiteralPath (Join-Path $script:BackupPath 'ad-domain.json') -Encoding UTF8
                Get-ADForest | ConvertTo-Json -Depth 6 |
                    Set-Content -LiteralPath (Join-Path $script:BackupPath 'ad-forest.json') -Encoding UTF8
            }
            catch {
                Add-Warning ("AD metadata snapshot failed: {0}" -f $_.Exception.Message)
            }
        }

        if (Test-Command 'Get-GPO') {
            try {
                $previousProgress = $ProgressPreference
                $ProgressPreference = 'SilentlyContinue'
                Get-GPO -All |
                    Select-Object DisplayName, Id, GpoStatus, CreationTime, ModificationTime |
                    ConvertTo-Json -Depth 5 |
                    Set-Content -LiteralPath (Join-Path $script:BackupPath 'gpo-inventory.json') -Encoding UTF8
            }
            catch {
                Add-Warning ("GPO inventory snapshot failed: {0}" -f $_.Exception.Message)
            }
            finally {
                $ProgressPreference = $previousProgress
            }
        }

        if (Test-Command 'Get-DnsServerZone') {
            try {
                Get-DnsServerZone |
                    Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone |
                    ConvertTo-Json -Depth 5 |
                    Set-Content -LiteralPath (Join-Path $script:BackupPath 'dns-zones.json') -Encoding UTF8
            }
            catch {
                Add-Warning ("DNS inventory snapshot failed: {0}" -f $_.Exception.Message)
            }
        }
    }

    Export-RegistryKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'reg-dnsclient.reg'
    Export-RegistryKey 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' 'reg-powershell.reg'
    Export-RegistryKey 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' 'reg-terminal-server.reg'

    if (Test-Command 'secedit.exe') {
        try {
            & secedit.exe /export /cfg (Join-Path $script:BackupPath 'local-security-policy.inf') /quiet *> $null
        }
        catch {
            Add-Warning ("secedit export failed: {0}" -f $_.Exception.Message)
        }
    }

    @'
CHANGE-SET RESTORE NOTES
========================

This directory is a safety snapshot, not a one-click full restore.

Firewall:
  netsh advfirewall import .\firewall.wfw

Registry:
  Review .reg files before importing.

SMB / Defender:
  JSON files capture previous state. Restore deliberately with native cmdlets.

Active Directory:
  AD/GPO/DNS JSON files are inventory evidence only.
  Use supported AD backup/recovery procedures for actual directory recovery.

For a Domain Controller, a verified Windows Server system-state backup remains
the recovery-grade backup mechanism.

Always validate connectivity, DNS, authentication, replication and SYSVOL
after rollback or recovery.
'@ | Set-Content -LiteralPath (Join-Path $script:BackupPath 'RESTORE.txt') -Encoding UTF8

    $script:SnapshotCreated = $true
    Write-Log 'Change-set backup completed.' OK
}

function Invoke-ConfigurationBackup {
    Write-Step 'Configuration change-set'
    New-ChangeSet
    Add-Result 'Recovery' 'Configuration change-set' 'PASS' $script:BackupPath 'Snapshot available before changes'
}

function Invoke-SystemStateBackup {
    param([string]$Target = '')

    Assert-DomainController

    if (-not (Test-Command 'wbadmin.exe')) {
        [void](Ensure-WindowsServerFeature `
            -Name 'Windows-Server-Backup' `
            -Purpose 'Domain Controller system-state backup')

        if (-not (Test-Command 'wbadmin.exe')) {
            Add-Result 'Recovery' 'System-state backup' 'ERROR' `
                'wbadmin.exe unavailable' `
                'Windows-Server-Backup feature installed'
            return $false
        }
    }

    if ([string]::IsNullOrWhiteSpace($Target)) {
        $Target = Read-Host 'Backup target (example F: or \\server\share)'
    }

    if ([string]::IsNullOrWhiteSpace($Target)) {
        Write-Console 'Backup cancelled: target is required.' Yellow
        return $false
    }

    if (-not (Confirm-Action `
        -Action ("Create Domain Controller system-state backup at {0}" -f $Target) `
        -Reason 'Create recovery-grade backup of AD DS/SYSVOL/system state.' `
        -Impact LOW)) {
        return $false
    }

    Write-Console ''
    Write-Console 'Starting wbadmin system-state backup...' Cyan

    & wbadmin.exe start systemstatebackup "-backupTarget:$Target" -quiet

    if ($LASTEXITCODE -eq 0) {
        Add-Result 'Recovery' 'System-state backup' 'PASS' $Target 'Completed'
        return $true
    }

    Add-Result 'Recovery' 'System-state backup' 'FAIL' `
        ("wbadmin exit={0}" -f $LASTEXITCODE) `
        'Completed'
    return $false
}
# ===========================================================================
# Registry helpers
# ===========================================================================

function Get-RegistryValueSafe {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Test-RegistryEquals {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)]$ExpectedValue
    )

    $value = Get-RegistryValueSafe -Path $Path -Name $Name
    if ($null -eq $value) { return $false }
    return ($value -eq $ExpectedValue)
}

# ===========================================================================
# Host audit
# ===========================================================================

function Audit-Compatibility {
    Write-Step 'Compatibility / runtime'

    $generation = Get-WindowsServerGeneration -Info $script:ServerInfo
    $supported = $generation -in @('2019','2022','2025')

    Add-Result 'System' 'Windows Server generation' `
        $(if ($supported) { 'PASS' } else { 'WARN' }) `
        ("{0}; build {1}" -f $generation, $script:ServerInfo.Build) `
        'Windows Server 2019/2022/2025'

    Add-Result 'System' 'Windows PowerShell' `
        $(if ($script:PowerShellMajor -ge 5) { 'PASS' } else { 'WARN' }) `
        $PSVersionTable.PSVersion.ToString() `
        '5.1+'

    Add-Result 'System' 'Session context' 'INFO' $script:RemoteKind 'Known before network changes'

    Add-Result 'System' 'Domain Controller role' 'INFO' `
        $(if ($script:IsDomainController) { 'YES' } else { 'NO' }) `
        'Role-aware configuration'

    foreach ($role in $script:RoleInfo) {
        Add-Result 'System' ("Role {0}" -f $role.Name) 'INFO' 'Installed' 'Role-aware hardening'
    }

    if ($generation -eq '2025') {
        $osConfig = if (Get-Module -ListAvailable -Name Microsoft.OSConfig -ErrorAction SilentlyContinue) {
            'Microsoft.OSConfig module available'
        } else {
            'OSConfig module not detected'
        }
        Add-Result 'Baseline' 'Windows Server 2025 OSConfig' 'INFO' $osConfig 'Evaluate role-aware Microsoft baseline'
    }
}

function Audit-Network {
    Write-Step 'Network / Firewall'

    try {
        $adapters = @(Get-NetIPConfiguration | Where-Object {
            $_.IPv4Address -and $_.NetAdapter.Status -eq 'Up'
        })

        foreach ($a in $adapters) {
            $ips = @($a.IPv4Address | ForEach-Object { $_.IPv4Address }) -join ', '
            $dns = @($a.DnsServer.ServerAddresses) -join ', '
            $gw = @($a.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '

            Add-Result 'Network' ("Adapter {0}" -f $a.InterfaceAlias) 'INFO' `
                ("IPv4={0}; Gateway={1}; DNS={2}" -f $ips, $gw, $dns) `
                'Documented expected configuration'
        }
    }
    catch {
        Add-Result 'Network' 'Network configuration' 'ERROR' $_.Exception.Message 'Readable'
    }

    if (-not (Test-Command 'Get-NetFirewallProfile')) {
        Add-Result 'Network' 'Firewall cmdlets' 'ERROR' 'Unavailable' 'Available'
        return
    }

    try {
        foreach ($p in Get-NetFirewallProfile) {
            $status = if ($p.Enabled -and $p.DefaultInboundAction -eq 'Block') { 'PASS' } else { 'FAIL' }

            Add-Result 'Network' ("Firewall {0}" -f $p.Name) $status `
                ("Enabled={0}; Inbound={1}; Outbound={2}" -f $p.Enabled, $p.DefaultInboundAction, $p.DefaultOutboundAction) `
                'Enabled; default inbound Block'
        }
    }
    catch {
        Add-Result 'Network' 'Firewall profiles' 'ERROR' $_.Exception.Message 'Readable'
    }
}

function Audit-Defender {
    Write-Step 'Microsoft Defender'

    if (-not (Test-Command 'Get-MpComputerStatus')) {
        Add-Result 'Endpoint' 'Microsoft Defender' 'WARN' 'Cmdlets unavailable' 'Managed AV/EDR known'
        return
    }

    try {
        $d = Get-MpComputerStatus

        $runningMode = 'Unknown'
        if ($d.PSObject.Properties.Name -contains 'AMRunningMode') {
            $runningMode = [string]$d.AMRunningMode
        }

        Add-Result 'Endpoint' 'Defender running mode' 'INFO' $runningMode 'Understand active/passive/managed state'

        $managedOrPassive = $runningMode -match 'Passive|EDR Block|SxS'

        foreach ($check in @(
            @{ Name='Defender service'; Property='AMServiceEnabled' },
            @{ Name='Realtime protection'; Property='RealTimeProtectionEnabled' },
            @{ Name='Behavior monitoring'; Property='BehaviorMonitorEnabled' },
            @{ Name='IOAV protection'; Property='IOAVProtectionEnabled' }
        )) {
            $value = $d.($check.Property)
            $status = if ($value) { 'PASS' } elseif ($managedOrPassive) { 'MANAGED' } else { 'FAIL' }

            Add-Result 'Endpoint' $check.Name $status `
                ("{0}={1}" -f $check.Property, $value) `
                'Enabled or intentionally managed'
        }

        if ($d.PSObject.Properties.Name -contains 'IsTamperProtected') {
            Add-Result 'Endpoint' 'Tamper protection' `
                $(if ($d.IsTamperProtected) { 'PASS' } else { 'WARN' }) `
                ("IsTamperProtected={0}" -f $d.IsTamperProtected) `
                'Enabled where supported/managed'
        }

        if (Test-Command 'Get-MpPreference') {
            $p = Get-MpPreference
            Add-Result 'Endpoint' 'PUA protection' `
                $(if ([int]$p.PUAProtection -eq 1) { 'PASS' } else { 'WARN' }) `
                ("PUAProtection={0}" -f $p.PUAProtection) `
                'Enabled'
        }
    }
    catch {
        Add-Result 'Endpoint' 'Defender state' 'ERROR' $_.Exception.Message 'Readable'
    }
}

function Audit-StoragePlatform {
    Write-Step 'BitLocker / TPM / Secure Boot'

    if (Test-Command 'Get-BitLockerVolume') {
        try {
            foreach ($v in Get-BitLockerVolume) {
                $encrypted = $v.VolumeStatus -eq 'FullyEncrypted'
                $protected = $v.ProtectionStatus -eq 'On'
                $status = if ($encrypted -and $protected) { 'PASS' } else { 'WARN' }

                Add-Result 'Storage' ("BitLocker {0}" -f $v.MountPoint) $status `
                    ("Status={0}; Protection={1}; Method={2}" -f $v.VolumeStatus, $v.ProtectionStatus, $v.EncryptionMethod) `
                    'Encrypted and protected where policy requires'
            }
        }
        catch {
            Add-Result 'Storage' 'BitLocker' 'ERROR' $_.Exception.Message 'Readable'
        }
    }

    if (Test-Command 'Get-Tpm') {
        try {
            $tpm = Get-Tpm
            Add-Result 'Platform' 'TPM' `
                $(if ($tpm.TpmPresent -and $tpm.TpmReady) { 'PASS' } else { 'WARN' }) `
                ("Present={0}; Ready={1}" -f $tpm.TpmPresent, $tpm.TpmReady) `
                'Present and ready where supported'
        }
        catch {}
    }

    if (Test-Command 'Confirm-SecureBootUEFI') {
        try {
            $secure = Confirm-SecureBootUEFI -ErrorAction Stop
            Add-Result 'Platform' 'Secure Boot' `
                $(if ($secure) { 'PASS' } else { 'WARN' }) `
                ([string]$secure) `
                'Enabled where supported'
        }
        catch {
            Add-Result 'Platform' 'Secure Boot' 'INFO' 'Unavailable/legacy/unsupported' 'Hardware dependent'
        }
    }
}

function Audit-SMB {
    Write-Step 'SMB / legacy protocols'

    if (Test-Command 'Get-WindowsOptionalFeature') {
        try {
            $smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop

            Add-Result 'Network' 'SMBv1 feature' `
                $(if ($smb1.State -eq 'Disabled') { 'PASS' } else { 'FAIL' }) `
                ("State={0}" -f $smb1.State) `
                'Disabled'
        }
        catch {
            Add-Result 'Network' 'SMBv1 feature' 'INFO' 'Feature query unavailable' 'Disabled'
        }
    }

    if (Test-Command 'Get-SmbServerConfiguration') {
        try {
            $smb = Get-SmbServerConfiguration

            Add-Result 'Network' 'SMB server signing enabled' `
                $(if ($smb.EnableSecuritySignature) { 'PASS' } else { 'WARN' }) `
                ("Enable={0}; Require={1}" -f $smb.EnableSecuritySignature, $smb.RequireSecuritySignature) `
                'Enabled; requirement role/baseline dependent'

            Add-Result 'Network' 'SMB server signing required' `
                $(if ($smb.RequireSecuritySignature) { 'PASS' } elseif ($smb.EnableSecuritySignature) { 'WARN' } else { 'FAIL' }) `
                ("RequireSecuritySignature={0}" -f $smb.RequireSecuritySignature) `
                'Evaluate against role/version baseline'
        }
        catch {
            Add-Result 'Network' 'SMB server configuration' 'ERROR' $_.Exception.Message 'Readable'
        }
    }

    if (Test-Command 'Get-SmbClientConfiguration') {
        try {
            $c = Get-SmbClientConfiguration
            Add-Result 'Network' 'SMB insecure guest logons' `
                $(if (-not $c.EnableInsecureGuestLogons) { 'PASS' } else { 'FAIL' }) `
                ("EnableInsecureGuestLogons={0}" -f $c.EnableInsecureGuestLogons) `
                'False'
        }
        catch {}
    }
}


function Get-KerberosCryptoInventory {
    Assert-DomainController
    if (-not (Import-ADModules)) { return @() }

    $objects = @()
    try {
        $objects += @(Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes,ServicePrincipalName,PasswordLastSet,DNSHostName)
    }
    catch {}

    try {
        $objects += @(Get-ADUser -LDAPFilter '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))' `
            -Properties msDS-SupportedEncryptionTypes,ServicePrincipalName,PasswordLastSet)
    }
    catch {}

    foreach ($obj in $objects) {
        $mask = 0
        $raw = $obj.'msDS-SupportedEncryptionTypes'
        if ($null -ne $raw) {
            try { $mask = [int]$raw } catch { $mask = 0 }
        }

        $hasRc4 = (($mask -band 0x4) -ne 0)
        $hasAes = (($mask -band 0x18) -ne 0)

        $classification = if ($mask -eq 0) {
            'IMPLICIT_DEFAULT'
        }
        elseif ($hasRc4 -and $hasAes) {
            'RC4_AND_AES'
        }
        elseif ($hasRc4) {
            'RC4_ONLY'
        }
        elseif ($hasAes) {
            'AES_READY'
        }
        else {
            'OTHER'
        }

        [pscustomobject]@{
            Account                    = $obj.SamAccountName
            ObjectClass                = $obj.ObjectClass
            SupportedEncryptionTypes   = $raw
            Classification             = $classification
            PasswordLastSet            = $obj.PasswordLastSet
            SPNCount                   = @($obj.ServicePrincipalName).Count
        }
    }
}

function Get-KdcHardeningEvents {
    param([int]$Days = 30)

    if (-not $script:IsDomainController) { return @() }

    $ids = 201..209
    try {
        return @(Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Kdcsvc'
            StartTime    = (Get-Date).AddDays(-1 * $Days)
        } -ErrorAction Stop | Where-Object { $_.Id -in $ids })
    }
    catch {
        return @()
    }
}

function Audit-DirectoryProtocolSecurity {
    Write-Step 'Directory protocol security'

    if (-not $script:IsDomainController) {
        Add-Result 'AD Security' 'Directory protocol security' 'SKIP' 'Not a Domain Controller' 'DC only'
        return
    }

    $generation = Get-WindowsServerGeneration -Info $script:ServerInfo

    # SMB signing - both directions matter for a DC.
    if (Test-Command 'Get-SmbServerConfiguration') {
        try {
            $s = Get-SmbServerConfiguration
            Add-Result 'AD Security' 'SMB server signing required' `
                $(if ($s.RequireSecuritySignature) { 'PASS' } else { 'FAIL' }) `
                ("RequireSecuritySignature={0}" -f $s.RequireSecuritySignature) `
                'True on a Domain Controller'
        }
        catch {}
    }

    if (Test-Command 'Get-SmbClientConfiguration') {
        try {
            $c = Get-SmbClientConfiguration
            Add-Result 'AD Security' 'SMB client signing required' `
                $(if ($c.RequireSecuritySignature) { 'PASS' } else { 'WARN' }) `
                ("RequireSecuritySignature={0}" -f $c.RequireSecuritySignature) `
                'True for privileged/DC outbound SMB'
        }
        catch {}
    }

    # LDAP signing and channel binding.
    $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
    $ldapSigning = Get-RegistryValueSafe -Path $ntds -Name 'LDAPServerIntegrity'
    $ldapCbt = Get-RegistryValueSafe -Path $ntds -Name 'LdapEnforceChannelBinding'

    if ($null -eq $ldapSigning -and $generation -eq '2025') {
        Add-Result 'AD Security' 'LDAP server signing' 'INFO' `
            'No explicit LDAPServerIntegrity value; Server 2025 enforcement/default policy may apply' `
            'Require signing'
    }
    else {
        Add-Result 'AD Security' 'LDAP server signing' `
            $(if ($ldapSigning -eq 2) { 'PASS' } elseif ($null -eq $ldapSigning) { 'WARN' } else { 'FAIL' }) `
            ("LDAPServerIntegrity={0}" -f $(if ($null -eq $ldapSigning) { '<not set>' } else { $ldapSigning })) `
            '2 (Require signing)'
    }

    Add-Result 'AD Security' 'LDAP channel binding' `
        $(if ($ldapCbt -eq 2) { 'PASS' } elseif ($ldapCbt -eq 1) { 'WARN' } elseif ($null -eq $ldapCbt) { 'INFO' } else { 'FAIL' }) `
        ("LdapEnforceChannelBinding={0}" -f $(if ($null -eq $ldapCbt) { '<not set>' } else { $ldapCbt })) `
        '2 after compatibility validation'

    # LAN Manager / NTLMv1 posture.
    $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lm = Get-RegistryValueSafe -Path $lsaPath -Name 'LmCompatibilityLevel'
    Add-Result 'AD Security' 'LAN Manager authentication level' `
        $(if ($lm -ge 5) { 'PASS' } elseif ($null -eq $lm) { 'INFO' } else { 'WARN' }) `
        ("LmCompatibilityLevel={0}" -f $(if ($null -eq $lm) { '<not set>' } else { $lm })) `
        '5 where legacy NTLMv1 compatibility is not required'

    # 2026 Kerberos RC4 enforcement / explicit overrides.
    $kdcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    $ddset = Get-RegistryValueSafe -Path $kdcPath -Name 'DefaultDomainSupportedEncTypes'
    if ($null -eq $ddset) {
        Add-Result 'Kerberos' 'DefaultDomainSupportedEncTypes' 'INFO' `
            'Not explicitly configured; current Windows Update KDC default applies' `
            'AES-first/AES-only on current patched DCs'
    }
    else {
        $ddsetInt = [int]$ddset
        $hasRc4 = (($ddsetInt -band 0x4) -ne 0)
        $hasAes = (($ddsetInt -band 0x18) -ne 0)
        Add-Result 'Kerberos' 'DefaultDomainSupportedEncTypes' `
            $(if (-not $hasRc4 -and $hasAes) { 'PASS' } elseif ($hasRc4) { 'WARN' } else { 'INFO' }) `
            ('0x{0:X}' -f $ddsetInt) `
            'AES128/AES256 without RC4 (0x18) unless an explicit exception is required'
    }

    $phase = Get-RegistryValueSafe -Path $kdcPath -Name 'RC4DefaultDisablementPhase'
    if ($null -ne $phase) {
        Add-Result 'Kerberos' 'RC4DefaultDisablementPhase' 'WARN' `
            ("Explicit legacy transition value={0}" -f $phase) `
            'Removed/obsolete after July 2026 enforcement on current patched DCs'
    }

    $events = @(Get-KdcHardeningEvents -Days 30)
    $eventPath = Join-Path $script:RunPath 'kdc-hardening-events-30d.csv'
    if ($events.Count -gt 0) {
        $events |
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Csv -LiteralPath $eventPath -NoTypeInformation -Encoding UTF8
        Add-Result 'Kerberos' 'KDC hardening events 201-209' 'WARN' `
            ("{0} event(s); {1}" -f $events.Count, $eventPath) `
            '0 unresolved compatibility events'
    }
    else {
        Add-Result 'Kerberos' 'KDC hardening events 201-209' 'PASS' `
            'No events found in last 30 days' `
            'No unresolved RC4 compatibility events'
    }

    $inventory = @(Get-KerberosCryptoInventory)
    if ($inventory.Count -gt 0) {
        $inventoryPath = Join-Path $script:RunPath 'kerberos-crypto-inventory.csv'
        $inventory | Export-Csv -LiteralPath $inventoryPath -NoTypeInformation -Encoding UTF8

        $rc4Only = @($inventory | Where-Object Classification -eq 'RC4_ONLY').Count
        $mixed = @($inventory | Where-Object Classification -eq 'RC4_AND_AES').Count
        $implicit = @($inventory | Where-Object Classification -eq 'IMPLICIT_DEFAULT').Count
        $aesReady = @($inventory | Where-Object Classification -eq 'AES_READY').Count

        Add-Result 'Kerberos' 'Explicit RC4-only principals' `
            $(if ($rc4Only -eq 0) { 'PASS' } else { 'FAIL' }) `
            ("Count={0}" -f $rc4Only) `
            '0 before AES-only enforcement'

        Add-Result 'Kerberos' 'Explicit RC4+AES principals' `
            $(if ($mixed -eq 0) { 'PASS' } else { 'WARN' }) `
            ("Count={0}" -f $mixed) `
            'Remove RC4 after validation'

        Add-Result 'Kerberos' 'Implicit/default enctype principals' 'INFO' `
            ("Count={0}" -f $implicit) `
            'Validate against current KDC enforcement and third-party clients'

        Add-Result 'Kerberos' 'Explicit AES-ready principals' 'INFO' `
            ("Count={0}; report={1}" -f $aesReady, $inventoryPath) `
            'Informational'
    }
}

function Remediate-SmbSigningStrict {
    $impact = if ($script:IsDomainController) { 'MEDIUM' } else { 'HIGH' }

    if (Test-Command 'Set-SmbServerConfiguration') {
        [void](Invoke-Change `
            -Name 'Require SMB server signing' `
            -Reason 'Reject unsigned inbound SMB and reduce relay/tampering exposure.' `
            -Impact $impact `
            -Action {
                Set-SmbServerConfiguration -EnableSecuritySignature $true -RequireSecuritySignature $true -Force
            } `
            -PostCheck {
                $s = Get-SmbServerConfiguration
                return ($s.EnableSecuritySignature -and $s.RequireSecuritySignature)
            })
    }

    if (Test-Command 'Set-SmbClientConfiguration') {
        [void](Invoke-Change `
            -Name 'Require SMB client signing' `
            -Reason 'Require integrity protection for outbound SMB from this privileged server/DC.' `
            -Impact $impact `
            -Action {
                Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
            } `
            -PostCheck {
                return [bool](Get-SmbClientConfiguration).RequireSecuritySignature
            })
    }
}

function Remediate-LdapSigning {
    Assert-DomainController
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

    [void](Invoke-Change `
        -Name 'Require LDAP server signing' `
        -Reason 'Reject unsigned LDAP binds to the Domain Controller. Validate legacy LDAP clients first.' `
        -Impact HIGH `
        -Action {
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'LDAPServerIntegrity' -PropertyType DWord -Value 2 -Force | Out-Null
        } `
        -PostCheck {
            return ((Get-RegistryValueSafe -Path $path -Name 'LDAPServerIntegrity') -eq 2)
        })
}

function Remediate-LdapChannelBinding {
    Assert-DomainController
    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'

    [void](Invoke-Change `
        -Name 'Enforce LDAP channel binding' `
        -Reason 'Require valid TLS channel binding for LDAP over TLS. This can break legacy LDAP clients.' `
        -Impact HIGH `
        -Action {
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'LdapEnforceChannelBinding' -PropertyType DWord -Value 2 -Force | Out-Null
        } `
        -PostCheck {
            return ((Get-RegistryValueSafe -Path $path -Name 'LdapEnforceChannelBinding') -eq 2)
        })
}

function Remediate-KerberosAesDefault {
    Assert-DomainController

    $inventory = @(Get-KerberosCryptoInventory)
    $rc4Only = @($inventory | Where-Object Classification -eq 'RC4_ONLY')
    $events = @(Get-KdcHardeningEvents -Days 30)

    Write-Console ''
    Write-Console ('RC4-only principals : {0}' -f $rc4Only.Count) $(if ($rc4Only.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Console ('KDC 201-209 events  : {0} in last 30 days' -f $events.Count) $(if ($events.Count -gt 0) { 'Yellow' } else { 'Green' })

    if ($rc4Only.Count -gt 0) {
        $path = Join-Path $script:RunPath 'kerberos-rc4-only-principals.csv'
        $rc4Only | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        Write-Console ("AES-only change blocked. Remediate explicit RC4-only principals first: {0}" -f $path) Red
        return
    }

    if ($events.Count -gt 0) {
        Write-Console 'Recent KDC compatibility events exist. Review them before enforcement.' Yellow
    }

    $path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc'
    [void](Invoke-Change `
        -Name 'Set Kerberos KDC default to AES128 + AES256 (0x18)' `
        -Reason 'Remove RC4 from the default KDC service-ticket encryption assumption after compatibility review.' `
        -Impact HIGH `
        -Action {
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'DefaultDomainSupportedEncTypes' -PropertyType DWord -Value 0x18 -Force | Out-Null
        } `
        -PostCheck {
            return ((Get-RegistryValueSafe -Path $path -Name 'DefaultDomainSupportedEncTypes') -eq 0x18)
        })
}

function Show-DirectorySecurityMenu {
    Assert-DomainController

    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'DIRECTORY PROTOCOL SECURITY' 'Kerberos RC4/AES posture, LDAP signing/channel binding and strict SMB integrity'
        Write-MenuItem '1' 'Full protocol audit' 'Kerberos principal inventory, KDC events, LDAP and SMB signing'
        Write-MenuItem '2' 'Require SMB signing' 'Require inbound + outbound SMB signing on this server/DC' Good
        Write-MenuItem '3' 'Require LDAP signing' 'Reject unsigned LDAP binds after client compatibility review' Warn
        Write-MenuItem '4' 'LDAP channel binding' 'Require TLS channel binding; high compatibility impact' Danger
        Write-MenuItem '5' 'Kerberos RC4 readiness' 'Show service/computer encryption inventory and KDC events'
        Write-MenuItem '6' 'Explicit AES-only KDC default' 'Set DefaultDomainSupportedEncTypes=0x18 after readiness scan' Danger
        Write-MenuNavigation
        Write-Rule

        try {
        switch (Read-MenuChoice -Default '1') {
            '1' { Audit-DirectoryProtocolSecurity; Pause-ControlPlane }
            '2' { Remediate-SmbSigningStrict; Pause-ControlPlane }
            '3' { Remediate-LdapSigning; Pause-ControlPlane }
            '4' { Remediate-LdapChannelBinding; Pause-ControlPlane }
            '5' {
                $script:Results.Clear()
                Audit-DirectoryProtocolSecurity
                Pause-ControlPlane
            }
            '6' { Remediate-KerberosAesDefault; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ('Show-DirectorySecurityMenu: operation failed: {0}' -f $message) Red
            Write-Log ('Recoverable menu error in Show-DirectorySecurityMenu: {0}' -f $message) ERROR
            Pause-ControlPlane
        }
    }
}

function Audit-RemoteAccess {
    Write-Step 'Remote access'

    try {
        $ts = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        $rdpEnabled = ($ts.fDenyTSConnections -eq 0)

        Add-Result 'Remote Access' 'RDP enabled' 'INFO' `
            ("Enabled={0}" -f $rdpEnabled) `
            'Documented and network-restricted'

        $nlaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
        $nla = Get-RegistryValueSafe -Path $nlaPath -Name 'UserAuthentication'

        Add-Result 'Remote Access' 'RDP NLA' `
            $(if ($nla -eq 1) { 'PASS' } else { 'FAIL' }) `
            ("UserAuthentication={0}" -f $nla) `
            '1'
    }
    catch {
        Add-Result 'Remote Access' 'RDP configuration' 'ERROR' $_.Exception.Message 'Readable'
    }

    foreach ($svcName in @('WinRM','TermService')) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop
            Add-Result 'Remote Access' ("Service {0}" -f $svcName) 'INFO' ([string]$svc.Status) 'Documented'
        }
        catch {}
    }
}

function Audit-Administrators {
    Write-Step 'Administrative access / LAPS'

    if ($script:IsDomainController) {
        if (Import-ADModules) {
            foreach ($groupName in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators')) {
                try {
                    $members = @(Get-ADGroupMember -Identity $groupName -Recursive:$false -ErrorAction Stop)
                    Add-Result 'Identity' $groupName 'INFO' `
                        ("{0} direct member(s)" -f $members.Count) `
                        'Minimum necessary membership'
                }
                catch {
                    Add-Result 'Identity' $groupName 'WARN' $_.Exception.Message 'Review privileged membership'
                }
            }
        }
    }
    elseif (Test-Command 'Get-LocalGroupMember') {
        try {
            $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
            Add-Result 'Identity' 'Local Administrators' 'INFO' `
                ("{0} member(s)" -f $members.Count) `
                'Minimum necessary membership'
        }
        catch {}
    }

    if (Test-Command 'Get-LapsADPasswordPolicy') {
        try {
            $null = Get-LapsADPasswordPolicy -ErrorAction Stop
            Add-Result 'Identity' 'Windows LAPS' 'INFO' 'AD LAPS policy cmdlets available' 'Managed and verified'
        }
        catch {
            Add-Result 'Identity' 'Windows LAPS' 'WARN' 'Policy query failed' 'Managed and verified'
        }
    }
    else {
        Add-Result 'Identity' 'Windows LAPS' 'INFO' 'LAPS cmdlets not detected' 'Evaluate where applicable'
    }
}

function Audit-LoggingNameResolution {
    Write-Step 'PowerShell logging / name resolution'

    $psBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

    $scriptBlock = Test-RegistryEquals `
        -Path "$psBase\ScriptBlockLogging" `
        -Name 'EnableScriptBlockLogging' `
        -ExpectedValue 1

    $moduleEnabled = Test-RegistryEquals `
        -Path "$psBase\ModuleLogging" `
        -Name 'EnableModuleLogging' `
        -ExpectedValue 1

    $moduleNamesPresent = Test-Path -LiteralPath "$psBase\ModuleLogging\ModuleNames"

    Add-Result 'Logging' 'PowerShell Script Block Logging' `
        $(if ($scriptBlock) { 'PASS' } else { 'WARN' }) `
        $(if ($scriptBlock) { 'Enabled' } else { 'Not detected' }) `
        'Enabled where logging/privacy policy permits'

    Add-Result 'Logging' 'PowerShell Module Logging' `
        $(if ($moduleEnabled -and $moduleNamesPresent) { 'PASS' } else { 'WARN' }) `
        ("Enabled={0}; ModuleNames={1}" -f $moduleEnabled, $moduleNamesPresent) `
        'Enabled + module list configured'

    $llmnrPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
    $llmnrValue = Get-RegistryValueSafe -Path $llmnrPath -Name 'EnableMulticast'

    Add-Result 'Network' 'LLMNR' `
        $(if ($llmnrValue -eq 0) { 'PASS' } else { 'WARN' }) `
        ("EnableMulticast={0}" -f $(if ($null -eq $llmnrValue) { '<not set>' } else { $llmnrValue })) `
        '0 (disabled)'
}

function Audit-Updates {
    Write-Step 'Updates / baseline context'

    try {
        $latest = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $current = if ($latest) {
            '{0} - {1}' -f $latest.HotFixID, $latest.InstalledOn
        }
        else {
            'No Get-HotFix data'
        }

        Add-Result 'Maintenance' 'Most recent installed hotfix' 'INFO' $current 'Managed patch compliance'
    }
    catch {
        Add-Result 'Maintenance' 'Hotfix evidence' 'WARN' $_.Exception.Message 'Readable'
    }

    $generation = Get-WindowsServerGeneration -Info $script:ServerInfo
    $reference = switch ($generation) {
        '2025' { 'Microsoft Windows Server 2025 role-aware OSConfig baseline' }
        '2022' { 'Microsoft Windows Server 2022 Security Compliance Toolkit baseline' }
        '2019' { 'Microsoft Windows Server 2019 Security Compliance Toolkit baseline' }
        default { 'Vendor baseline matching OS version' }
    }

    Add-Result 'Baseline' 'Baseline reference' 'INFO' $reference 'External baseline tooling required for compliance claims'
}

function Invoke-HostAudit {
    Set-StepPlan 10

    Audit-Compatibility
    Audit-Network
    Audit-Defender
    Audit-StoragePlatform
    Audit-SMB
    Audit-RemoteAccess
    Audit-Administrators
    Audit-LoggingNameResolution
    Audit-DirectoryProtocolSecurity
    Audit-Updates

    Complete-Progress
}

# ===========================================================================
# Domain Controller health
# ===========================================================================

function Test-RequiredDcServices {
    foreach ($serviceName in @('NTDS','DNS','Netlogon','Kdc','ADWS')) {
        try {
            $svc = Get-Service -Name $serviceName -ErrorAction Stop
            Add-Result 'AD Health' ("Service {0}" -f $serviceName) `
                $(if ($svc.Status -eq 'Running') { 'PASS' } else { 'FAIL' }) `
                ([string]$svc.Status) `
                'Running'
        }
        catch {
            Add-Result 'AD Health' ("Service {0}" -f $serviceName) 'ERROR' $_.Exception.Message 'Running'
        }
    }
}

function Test-DcDiag {
    if (-not (Test-Command 'dcdiag.exe')) {
        Add-Result 'AD Health' 'DCDiag' 'ERROR' 'dcdiag.exe unavailable' 'Available'
        return
    }

    $output = & dcdiag.exe /q 2>&1
    if ($LASTEXITCODE -eq 0 -and @($output).Count -eq 0) {
        Add-Result 'AD Health' 'DCDiag /q' 'PASS' 'No failures reported' 'No failures'
    }
    else {
        $path = Join-Path $script:RunPath 'dcdiag.txt'
        $output | Set-Content -LiteralPath $path -Encoding UTF8
        Add-Result 'AD Health' 'DCDiag /q' 'FAIL' ("Issues reported; saved to {0}" -f $path) 'No failures'
    }
}

function Test-ReplicationHealth {
    if (Import-ADModules -and (Test-Command 'Get-ADReplicationFailure')) {
        try {
            $failures = @(Get-ADReplicationFailure -Target * -Scope Forest -ErrorAction Stop)
            Add-Result 'AD Replication' 'Replication failures' `
                $(if ($failures.Count -eq 0) { 'PASS' } else { 'FAIL' }) `
                ("{0} failure object(s)" -f $failures.Count) `
                '0 failures'

            if ($failures.Count -gt 0) {
                $failures |
                    Select-Object Server, Partner, FirstFailureTime, FailureCount, LastError |
                    Export-Csv -LiteralPath (Join-Path $script:RunPath 'replication-failures.csv') -NoTypeInformation -Encoding UTF8
            }
        }
        catch {
            Add-Result 'AD Replication' 'Replication PowerShell query' 'WARN' $_.Exception.Message 'Readable'
        }
    }

    if (Test-Command 'repadmin.exe') {
        $summary = & repadmin.exe /replsummary 2>&1
        $summary | Set-Content -LiteralPath (Join-Path $script:RunPath 'repadmin-replsummary.txt') -Encoding UTF8

        if ($LASTEXITCODE -eq 0) {
            Add-Result 'AD Replication' 'Repadmin summary' 'PASS' 'Command completed' 'Review saved summary'
        }
        else {
            Add-Result 'AD Replication' 'Repadmin summary' 'WARN' ("Exit={0}" -f $LASTEXITCODE) 'Review saved summary'
        }
    }
}


function Test-WindowsDnsExternalResolution {
    param(
        [string]$Server = '127.0.0.1',
        [string]$ProbeName = $script:DnsExternalProbeName
    )

    try {
        $answers = @(Resolve-DnsName -Name $ProbeName -Type A -Server $Server `
            -DnsOnly -QuickTimeout -ErrorAction Stop |
            Where-Object { $_.Type -eq 'A' -and $_.IPAddress })
        return ($answers.Count -gt 0)
    }
    catch {
        return $false
    }
}

function Get-DnsForwarderSnapshot {
    if (-not (Test-Command 'Get-DnsServerForwarder')) { return $null }
    try { return Get-DnsServerForwarder -ErrorAction Stop }
    catch { return $null }
}

function Show-DnsExternalResolutionHealth {
    Write-Section 'DNS external resolution / forwarders'

    Assert-DnsServerModule

    $forwarder = Get-DnsForwarderSnapshot
    if ($forwarder) {
        $ips = @($forwarder.IPAddress | ForEach-Object { [string]$_ })
        Write-Console ("  Forwarders     : {0}" -f $(if ($ips.Count) { $ips -join ', ' } else { '(none)' }))
        if ($forwarder.PSObject.Properties['UseRootHint']) {
            Write-Console ("  Use root hints : {0}" -f $forwarder.UseRootHint)
        }
        if ($forwarder.PSObject.Properties['Timeout']) {
            Write-Console ("  Timeout        : {0}s" -f $forwarder.Timeout)
        }

        foreach ($ip in $ips) {
            if (Test-WindowsDnsExternalResolution -Server $ip) {
                Write-Badge -Text ("UPSTREAM {0} OK" -f $ip) -Kind Good
            }
            else {
                Write-Badge -Text ("UPSTREAM {0} FAIL" -f $ip) -Kind Warn
            }
        }
    }
    else {
        Write-Console '  Forwarder state could not be read or no forwarders are configured.' Yellow
    }

    $localOk = Test-WindowsDnsExternalResolution -Server '127.0.0.1'
    $script:DnsExternalHealth = if ($localOk) { 'OK' } else { 'CHECK' }
    $script:DnsExternalHealthChecked = Get-Date

    if ($localOk) {
        Write-Badge -Text 'LOCAL DNS EXTERNAL RESOLUTION OK' -Kind Good
        Add-Result 'DNS' 'External recursive resolution' 'PASS' `
            ("{0} resolved through local DNS" -f $script:DnsExternalProbeName) `
            'External names resolvable when Internet access is expected'
    }
    else {
        Write-Badge -Text 'LOCAL DNS EXTERNAL RESOLUTION FAILED' -Kind Bad
        Write-Console '  AD zones may still work while clients lose Internet name resolution.' Yellow
        Write-Console '  If this is not an isolated environment, inspect forwarders/root hints and outbound DNS policy.' Yellow
        Add-Result 'DNS' 'External recursive resolution' 'WARN' `
            ("{0} did not resolve through local DNS" -f $script:DnsExternalProbeName) `
            'External names resolvable when Internet access is expected'
    }

    return $localOk
}

function Convert-ToIpAddressArray {
    param([Parameter(Mandatory=$true)][string]$Text)

    $values = @($Text -split '[,;\s]+' | Where-Object { $_ })
    $parsed = New-Object 'System.Collections.Generic.List[System.Net.IPAddress]'
    foreach ($value in $values) {
        $ip = $null
        if (-not [System.Net.IPAddress]::TryParse($value, [ref]$ip)) {
            throw ("Invalid DNS forwarder IP address: {0}" -f $value)
        }
        $parsed.Add($ip)
    }
    return @($parsed)
}

function Repair-DnsForwardersInteractive {
    Assert-DnsServerModule

    $current = Get-DnsForwarderSnapshot
    $currentIps = @()
    if ($current) {
        $currentIps = @($current.IPAddress | ForEach-Object { [string]$_ })
    }

    Write-Section 'Repair DNS forwarders'
    if (Test-WindowsDnsExternalResolution -Server '127.0.0.1') {
        Write-Console 'Local DNS already resolves external names. No forwarder repair is required.' Green
        if (-not (Read-BooleanChoice -Prompt 'Change forwarders anyway?' -Default $false)) {
            $script:DnsExternalHealth = 'OK'
            return
        }
    }

    Write-Console ("Current forwarders: {0}" -f $(if ($currentIps.Count) { $currentIps -join ', ' } else { '(none)' }))
    Write-Console 'Enter only DNS servers that this DC is intentionally allowed to use for recursion.' Yellow
    $raw = (Read-Host 'New forwarder IPs (comma separated)').Trim()
    if (-not $raw) { return }

    try { $newIps = @(Convert-ToIpAddressArray -Text $raw) }
    catch {
        Write-Console $_.Exception.Message Red
        return
    }
    if ($newIps.Count -eq 0) { return }

    foreach ($ip in $newIps) {
        if (-not (Test-WindowsDnsExternalResolution -Server ([string]$ip))) {
            Write-Console ("Forwarder {0} did not resolve {1}; no DNS change was made." -f `
                $ip,$script:DnsExternalProbeName) Red
            return
        }
    }

    if (-not (Confirm-Action `
        -Action ("Replace DNS forwarders with: {0}" -f (($newIps | ForEach-Object { [string]$_ }) -join ', ')) `
        -Reason 'Restore external DNS resolution for domain clients while keeping AD DNS authoritative internally.' `
        -Impact MEDIUM)) {
        return
    }

    $backup = Join-Path $script:RunPath 'dns-forwarders-before.json'
    if ($current) {
        $current | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $backup -Encoding UTF8
    }

    try {
        Set-DnsServerForwarder -IPAddress $newIps -PassThru -ErrorAction Stop | Out-Host
        Clear-DnsServerCache -Force -ErrorAction SilentlyContinue

        if (Test-WindowsDnsExternalResolution -Server '127.0.0.1') {
            $script:DnsExternalHealth = 'OK'
            $script:DnsExternalHealthChecked = Get-Date
            Write-Log 'DNS forwarders updated and external resolution validated.' CHANGE
            return
        }

        throw 'Local DNS still cannot resolve the external probe after changing forwarders.'
    }
    catch {
        Write-Console ("Forwarder repair failed validation: {0}" -f $_.Exception.Message) Red
        Write-Console 'Attempting to restore the previous forwarder list.' Yellow
        try {
            if ($currentIps.Count -gt 0) {
                $restoreIps = @($currentIps | ForEach-Object { [System.Net.IPAddress]$_ })
                Set-DnsServerForwarder -IPAddress $restoreIps -ErrorAction Stop | Out-Null
            }
            elseif (Test-Command 'Remove-DnsServerForwarder') {
                Remove-DnsServerForwarder -IPAddress $newIps -Force -ErrorAction Stop | Out-Null
            }
            Write-Console 'Previous forwarder state restored.' Green
        }
        catch {
            Write-Console ("Automatic forwarder rollback failed: {0}" -f $_.Exception.Message) Red
            if (Test-Path -LiteralPath $backup) {
                Write-Console ("Backup metadata: {0}" -f $backup) Yellow
            }
        }
        $script:DnsExternalHealth = 'CHECK'
    }
}

function Test-DcDnsHealth {
    if (-not (Test-Command 'Resolve-DnsName')) {
        Add-Result 'DNS' 'Resolve-DnsName' 'ERROR' 'Cmdlet unavailable' 'Available'
        return
    }

    try {
        $domainName = if ($script:DomainInfo) { $script:DomainInfo.DNSRoot } else { $script:ServerInfo.Domain }

        $ldap = Resolve-DnsName -Name ("_ldap._tcp.dc._msdcs.{0}" -f $domainName) -Type SRV -ErrorAction Stop
        Add-Result 'DNS' 'LDAP DC locator SRV' `
            $(if (@($ldap).Count -gt 0) { 'PASS' } else { 'FAIL' }) `
            ("{0} record(s)" -f @($ldap).Count) `
            'At least one SRV record'

        $kerberos = Resolve-DnsName -Name ("_kerberos._tcp.{0}" -f $domainName) -Type SRV -ErrorAction Stop
        Add-Result 'DNS' 'Kerberos SRV' `
            $(if (@($kerberos).Count -gt 0) { 'PASS' } else { 'FAIL' }) `
            ("{0} record(s)" -f @($kerberos).Count) `
            'At least one SRV record'
    }
    catch {
        Add-Result 'DNS' 'AD DNS records' 'FAIL' $_.Exception.Message 'Resolvable SRV records'
    }

    [void](Show-DnsExternalResolutionHealth)

    if (Test-Command 'Get-DnsServerZone') {
        try {
            $zones = @(Get-DnsServerZone -ErrorAction Stop)
            Add-Result 'DNS' 'DNS zones' 'PASS' ("{0} zone(s)" -f $zones.Count) 'Readable'
        }
        catch {
            Add-Result 'DNS' 'DNS zones' 'WARN' $_.Exception.Message 'Readable'
        }
    }
}

function Test-SysvolNetlogonShares {
    if (-not (Test-Command 'Get-SmbShare')) {
        Add-Result 'AD Health' 'SYSVOL / NETLOGON shares' 'SKIP' 'Get-SmbShare unavailable' 'Readable'
        return
    }

    $shares = @(Get-SmbShare -Name 'SYSVOL','NETLOGON' -ErrorAction SilentlyContinue)
    foreach ($name in @('SYSVOL','NETLOGON')) {
        Add-Result 'AD Health' ("Share {0}" -f $name) `
            $(if ($shares.Name -contains $name) { 'PASS' } else { 'FAIL' }) `
            $(if ($shares.Name -contains $name) { 'Present' } else { 'Missing' }) `
            'Present'
    }
}

function Show-FsmoRoles {
    Assert-DomainController

    $forest = Get-ADForest
    $domain = Get-ADDomain

    [pscustomobject]@{
        SchemaMaster         = $forest.SchemaMaster
        DomainNamingMaster   = $forest.DomainNamingMaster
        PDCEmulator          = $domain.PDCEmulator
        RIDMaster            = $domain.RIDMaster
        InfrastructureMaster = $domain.InfrastructureMaster
    } | Format-List
}

function Invoke-DcValidation {
    Assert-DomainController

    $script:Results.Clear()
    Set-StepPlan 5

    Write-Step 'Required DC services'
    Test-RequiredDcServices

    Write-Step 'DCDiag'
    Test-DcDiag

    Write-Step 'Replication'
    Test-ReplicationHealth

    Write-Step 'DNS / DC locator'
    Test-DcDnsHealth

    Write-Step 'SYSVOL / NETLOGON'
    Test-SysvolNetlogonShares

    Complete-Progress
}

# ===========================================================================
# Host remediation
# ===========================================================================

function Remediate-Firewall {
    if ($script:IsRemoteSession -and -not $AllowRemoteFirewallChange) {
        Add-Result 'Network' 'Firewall remediation' 'SKIP' `
            ("Remote session detected ({0})" -f $script:RemoteKind) `
            'Run locally/out-of-band or explicitly allow remote firewall change'

        Write-Log 'Firewall remediation skipped to preserve remote availability.' WARN
        return
    }

    $impact = if ($script:IsRemoteSession) { 'HIGH' } else { 'MEDIUM' }

    [void](Invoke-Change `
        -Name 'Enable Windows Firewall and block inbound by default' `
        -Reason 'Reduce unsolicited inbound exposure while preserving existing allow rules.' `
        -Impact $impact `
        -Action {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block
        } `
        -PostCheck {
            $profiles = @(Get-NetFirewallProfile)
            return (($profiles | Where-Object {
                -not $_.Enabled -or $_.DefaultInboundAction -ne 'Block'
            }).Count -eq 0)
        })
}

function Remediate-Defender {
    if (-not (Test-Command 'Get-MpComputerStatus') -or -not (Test-Command 'Set-MpPreference')) {
        Write-Log 'Defender remediation unavailable.' WARN
        return
    }

    $d = Get-MpComputerStatus
    $runningMode = if ($d.PSObject.Properties.Name -contains 'AMRunningMode') {
        [string]$d.AMRunningMode
    } else {
        'Unknown'
    }

    if ($runningMode -match 'Passive|SxS') {
        Write-Log ("Defender mode is '{0}'. Core remediation skipped to avoid EDR/AV conflict." -f $runningMode) WARN
        return
    }

    [void](Invoke-Change `
        -Name 'Enable core Microsoft Defender protections' `
        -Reason 'Enable realtime, behavior, IOAV and script scanning.' `
        -Impact MEDIUM `
        -Action {
            Set-MpPreference `
                -DisableRealtimeMonitoring $false `
                -DisableBehaviorMonitoring $false `
                -DisableIOAVProtection $false `
                -DisableScriptScanning $false
        })

    [void](Invoke-Change `
        -Name 'Enable Microsoft Defender PUA protection' `
        -Reason 'Block potentially unwanted applications.' `
        -Impact MEDIUM `
        -Action {
            Set-MpPreference -PUAProtection Enabled
        })
}

function Remediate-RdpNla {
    [void](Invoke-Change `
        -Name 'Enable RDP Network Level Authentication' `
        -Reason 'Require authentication before a full RDP session is established.' `
        -Impact MEDIUM `
        -Action {
            Set-ItemProperty `
                -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'UserAuthentication' `
                -Type DWord `
                -Value 1
        } `
        -PostCheck {
            return (Test-RegistryEquals `
                -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
                -Name 'UserAuthentication' `
                -ExpectedValue 1)
        })
}

function Remediate-Smb {
    Remediate-SmbSigningStrict

    if (Test-Command 'Set-SmbClientConfiguration') {
        [void](Invoke-Change `
            -Name 'Disable insecure SMB guest logons' `
            -Reason 'Reduce anonymous/guest SMB exposure.' `
            -Impact MEDIUM `
            -Action {
                Set-SmbClientConfiguration -EnableInsecureGuestLogons $false -Force
            })
    }

    if ($script:IsDomainController) {
        Write-Log 'Automated SMBv1 feature removal is intentionally skipped on a DC.' WARN
        return
    }

    [void](Invoke-Change `
        -Name 'Disable/remove SMBv1' `
        -Reason 'SMBv1 is obsolete; remove after validating legacy compatibility.' `
        -Impact HIGH `
        -Action {
            if (Test-Command 'Get-WindowsFeature') {
                $feature = Get-WindowsFeature -Name 'FS-SMB1' -ErrorAction SilentlyContinue
                if ($feature -and $feature.Installed) {
                    Uninstall-WindowsFeature -Name 'FS-SMB1' -Restart:$false | Out-Null
                }
                elseif (Test-Command 'Disable-WindowsOptionalFeature') {
                    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
                }
            }
            elseif (Test-Command 'Disable-WindowsOptionalFeature') {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart | Out-Null
            }
        })
}

function Remediate-Llmnr {
    [void](Invoke-Change `
        -Name 'Disable LLMNR' `
        -Reason 'Reduce multicast name-resolution spoofing exposure.' `
        -Impact MEDIUM `
        -Action {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'EnableMulticast' -PropertyType DWord -Value 0 -Force | Out-Null
        } `
        -PostCheck {
            return (Test-RegistryEquals `
                -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                -Name 'EnableMulticast' `
                -ExpectedValue 0)
        })
}

function Remediate-PowerShellLogging {
    [void](Invoke-Change `
        -Name 'Enable PowerShell Script Block Logging' `
        -Reason 'Improve visibility into PowerShell execution.' `
        -Impact MEDIUM `
        -Action {
            $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            New-Item -Path $path -Force | Out-Null
            New-ItemProperty -Path $path -Name 'EnableScriptBlockLogging' -PropertyType DWord -Value 1 -Force | Out-Null
        })

    [void](Invoke-Change `
        -Name 'Enable PowerShell Module Logging' `
        -Reason 'Improve visibility into PowerShell module activity.' `
        -Impact MEDIUM `
        -Action {
            $base = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            $names = Join-Path $base 'ModuleNames'
            New-Item -Path $base -Force | Out-Null
            New-ItemProperty -Path $base -Name 'EnableModuleLogging' -PropertyType DWord -Value 1 -Force | Out-Null
            New-Item -Path $names -Force | Out-Null
            New-ItemProperty -Path $names -Name '*' -PropertyType String -Value '*' -Force | Out-Null
        })
}

function Invoke-Hardening {
    Write-Console ''
    Write-Console 'Host hardening changes are proposed individually; the first applied change creates a change-set.' Cyan

    Remediate-Firewall
    Remediate-Defender
    Remediate-RdpNla
    Remediate-Smb
    Remediate-Llmnr
    Remediate-PowerShellLogging

    Write-Log 'Hardening pass complete; re-running host audit.' INFO
    $script:Results.Clear()
    Invoke-HostAudit
}

# ===========================================================================
# Active Directory user management
# ===========================================================================

function Show-AdUsers {
    Assert-DomainController

    Get-ADUser -Filter * -Properties Enabled, DisplayName, LastLogonDate, PasswordLastSet |
        Sort-Object SamAccountName |
        Select-Object SamAccountName, DisplayName, Enabled, LastLogonDate, PasswordLastSet |
        Format-Table -AutoSize
}


function Select-EnumeratedValue {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][object[]]$Options,
        [int]$DefaultIndex = 1
    )

    Write-Console ''
    Write-Console $Title Cyan
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Console ('  [{0}] {1,-22} {2}' -f ($i + 1), $Options[$i].Value, $Options[$i].Description)
    }
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = Read-MenuChoice -Prompt 'Select value' -Default ([string]$DefaultIndex)
        if ($choice -eq '0') { return $null }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $Options.Count) {
                return [string]$Options[$index].Value
            }
        }
        Write-Console 'Invalid selection.' Yellow
    }
}

function Select-AdUserIdentity {
    param([string]$Prompt = 'Select user')

    Assert-DomainController
    $filterText = ''

    while ($true) {
        $users = @(Get-ADUser -Filter * -Properties DisplayName,Enabled |
            Sort-Object SamAccountName)

        if ($filterText) {
            $users = @($users | Where-Object {
                $_.SamAccountName -like ("*{0}*" -f $filterText) -or
                $_.DisplayName -like ("*{0}*" -f $filterText)
            })
        }

        Write-Console ''
        Write-Console 'Domain users:' Cyan
        for ($i = 0; $i -lt $users.Count; $i++) {
            Write-Console ('  [{0,3}] {1,-28} {2,-34} Enabled={3}' -f
                ($i + 1), $users[$i].SamAccountName, $users[$i].DisplayName, $users[$i].Enabled)
        }
        if ($users.Count -eq 0) { Write-Console '  No users matched.' Yellow }

        Write-Console '  [S] Search/filter' Gray
        Write-Console '  [M] Enter identity manually' Gray
        Write-Console '  [0] Cancel' Gray

        $choice = (Read-Host $Prompt).Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }

        switch ($choice.ToUpperInvariant()) {
            'S' { $filterText = (Read-Host 'User filter').Trim(); continue }
            'M' {
                $manual = (Read-Host 'User identity / sAMAccountName').Trim()
                if (-not $manual) { continue }
                try { return (Get-ADUser -Identity $manual -ErrorAction Stop).SamAccountName }
                catch { Write-Console $_.Exception.Message Red; continue }
            }
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $users.Count) { return $users[$index].SamAccountName }
        }
        Write-Console 'Invalid user selection.' Yellow
    }
}

function Select-AdGroupIdentity {
    param([string]$Prompt = 'Select group')

    Assert-DomainController
    $filterText = ''

    while ($true) {
        $groups = @(Get-ADGroup -Filter * | Sort-Object Name)
        if ($filterText) {
            $groups = @($groups | Where-Object {
                $_.Name -like ("*{0}*" -f $filterText) -or
                $_.SamAccountName -like ("*{0}*" -f $filterText)
            })
        }

        Write-Console ''
        Write-Console 'Domain groups:' Cyan
        for ($i = 0; $i -lt $groups.Count; $i++) {
            Write-Console ('  [{0,3}] {1,-38} {2,-12} {3}' -f
                ($i + 1), $groups[$i].Name, $groups[$i].GroupScope, $groups[$i].GroupCategory)
        }
        if ($groups.Count -eq 0) { Write-Console '  No groups matched.' Yellow }

        Write-Console '  [S] Search/filter' Gray
        Write-Console '  [M] Enter group manually' Gray
        Write-Console '  [0] Cancel' Gray

        $choice = (Read-Host $Prompt).Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }

        switch ($choice.ToUpperInvariant()) {
            'S' { $filterText = (Read-Host 'Group filter').Trim(); continue }
            'M' {
                $manual = (Read-Host 'Group identity').Trim()
                if (-not $manual) { continue }
                try { return (Get-ADGroup -Identity $manual -ErrorAction Stop).SamAccountName }
                catch { Write-Console $_.Exception.Message Red; continue }
            }
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $groups.Count) { return $groups[$index].SamAccountName }
        }
        Write-Console 'Invalid group selection.' Yellow
    }
}

function Select-AdComputerIdentity {
    param([string]$Prompt = 'Select computer')

    Assert-DomainController
    $filterText = ''

    while ($true) {
        $computers = @(Get-ADComputer -Filter * -Properties Enabled,DNSHostName,IPv4Address,OperatingSystem,LastLogonDate |
            Sort-Object Name)

        if ($filterText) {
            $computers = @($computers | Where-Object {
                $_.Name -like ("*{0}*" -f $filterText) -or
                $_.DNSHostName -like ("*{0}*" -f $filterText) -or
                $_.IPv4Address -like ("*{0}*" -f $filterText)
            })
        }

        Write-Console ''
        Write-Console 'Domain computers:' Cyan
        Write-Console ('  {0,-6} {1,-22} {2,-34} {3,-16} {4}' -f '#','NAME','DNS','IP','OS') Gray
        for ($i = 0; $i -lt $computers.Count; $i++) {
            Write-Console ('  [{0,3}]  {1,-22} {2,-34} {3,-16} {4}' -f
                ($i + 1), $computers[$i].Name, $computers[$i].DNSHostName,
                $computers[$i].IPv4Address, $computers[$i].OperatingSystem)
        }
        if ($computers.Count -eq 0) { Write-Console '  No computers matched.' Yellow }

        Write-Console '  [S] Search/filter' Gray
        Write-Console '  [M] Enter computer manually' Gray
        Write-Console '  [0] Cancel' Gray

        $choice = (Read-Host $Prompt).Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }

        switch ($choice.ToUpperInvariant()) {
            'S' { $filterText = (Read-Host 'Computer filter').Trim(); continue }
            'M' {
                $manual = (Read-Host 'Computer name / identity').Trim()
                if (-not $manual) { continue }
                try { return (Get-ADComputer -Identity $manual -ErrorAction Stop).SamAccountName }
                catch { Write-Console $_.Exception.Message Red; continue }
            }
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $computers.Count) { return $computers[$index].SamAccountName }
        }
        Write-Console 'Invalid computer selection.' Yellow
    }
}

function Select-AdPrincipalIdentity {
    Assert-DomainController

    Write-Console ''
    Write-Console 'Security principal type:' Cyan
    Write-Console '  [1] User'
    Write-Console '  [2] Group'
    Write-Console '  [3] Computer'
    Write-Console '  [M] Enter identity manually'
    Write-Console '  [0] Cancel'

    $choice = Read-MenuChoice -Prompt 'Select principal type' -Default '1'
    switch ($choice.ToUpperInvariant()) {
        '1' {
            $id = Select-AdUserIdentity
            if ($id) { return [pscustomobject]@{ Identity=$id; TargetType='User' } }
        }
        '2' {
            $id = Select-AdGroupIdentity
            if ($id) { return [pscustomobject]@{ Identity=$id; TargetType='Group' } }
        }
        '3' {
            $id = Select-AdComputerIdentity
            if ($id) { return [pscustomobject]@{ Identity=$id; TargetType='Computer' } }
        }
        'M' {
            $id = (Read-Host 'User/group/computer identity').Trim()
            if (-not $id) { return $null }
            $kind = Select-EnumeratedValue -Title 'PRINCIPAL TYPE' -DefaultIndex 2 -Options @(
                [pscustomobject]@{ Value='User'; Description='User account' },
                [pscustomobject]@{ Value='Group'; Description='Group object' },
                [pscustomobject]@{ Value='Computer'; Description='Computer account' }
            )
            if ($kind) { return [pscustomobject]@{ Identity=$id; TargetType=$kind } }
        }
    }
    return $null
}

function Select-AdGroupMemberIdentity {
    param([Parameter(Mandatory=$true)][string]$Group)

    $members = @(Get-ADGroupMember -Identity $Group -ErrorAction Stop | Sort-Object Name)
    Write-Console ''
    Write-Console ("Current members of '{0}':" -f $Group) Cyan
    for ($i = 0; $i -lt $members.Count; $i++) {
        Write-Console ('  [{0,3}] {1,-36} {2,-12} {3}' -f
            ($i + 1), $members[$i].Name, $members[$i].ObjectClass, $members[$i].SamAccountName)
    }
    if ($members.Count -eq 0) {
        Write-Console '  No direct members returned.' Yellow
        return $null
    }

    Write-Console '  [M] Enter member manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host 'Select member').Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }
        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'Existing member identity').Trim()
            if ($manual) { return $manual }
            continue
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $members.Count) {
                return $members[$index].DistinguishedName
            }
        }
        Write-Console 'Invalid member selection.' Yellow
    }
}

function Select-AdOuDn {
    param(
        [string]$Prompt = 'Select OU',
        [switch]$IncludeDomainRoot,
        [switch]$AllowDefault
    )

    Assert-DomainController
    $domain = Get-ADDomain
    $ous = @(Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName)
    $offset = 1

    Write-Console ''
    Write-Console 'Directory containers:' Cyan
    if ($AllowDefault) { Write-Console '  [D] Use default container' Green }
    if ($IncludeDomainRoot) {
        Write-Console ('  [1] DOMAIN ROOT  {0}' -f $domain.DistinguishedName) Green
        $offset = 2
    }
    for ($i = 0; $i -lt $ous.Count; $i++) {
        Write-Console ('  [{0,3}] OU  {1}' -f ($i + $offset), $ous[$i].DistinguishedName)
    }
    Write-Console '  [M] Enter DN manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host $Prompt).Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }
        if ($AllowDefault -and $choice.ToUpperInvariant() -eq 'D') { return '__DEFAULT__' }
        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'Container distinguished name').Trim()
            if ($manual) { return $manual }
            continue
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            if ($IncludeDomainRoot -and $number -eq 1) { return $domain.DistinguishedName }
            $index = $number - $offset
            if ($index -ge 0 -and $index -lt $ous.Count) { return $ous[$index].DistinguishedName }
        }
        Write-Console 'Invalid OU/container selection.' Yellow
    }
}

function Select-AdDirectoryObjectIdentity {
    Assert-DomainController

    Write-Console ''
    Write-Console 'Directory object type:' Cyan
    Write-Console '  [1] User'
    Write-Console '  [2] Group'
    Write-Console '  [3] Computer'
    Write-Console '  [4] Organizational Unit'
    Write-Console '  [M] Enter DN/identity manually'
    Write-Console '  [0] Cancel'

    $choice = Read-MenuChoice -Prompt 'Select object type' -Default '1'
    switch ($choice.ToUpperInvariant()) {
        '1' {
            $id = Select-AdUserIdentity
            if ($id) { return (Get-ADUser -Identity $id).DistinguishedName }
        }
        '2' {
            $id = Select-AdGroupIdentity
            if ($id) { return (Get-ADGroup -Identity $id).DistinguishedName }
        }
        '3' {
            $id = Select-AdComputerIdentity
            if ($id) { return (Get-ADComputer -Identity $id).DistinguishedName }
        }
        '4' { return (Select-AdOuDn -Prompt 'Select OU') }
        'M' { return (Read-Host 'Object distinguished name or identity').Trim() }
    }
    return $null
}

function Select-DnsZoneName {
    Assert-DomainController
    Assert-DnsServerModule

    $zones = @(Get-DnsServerZone | Sort-Object ZoneName)
    Write-Console ''
    Write-Console 'DNS zones:' Cyan
    for ($i = 0; $i -lt $zones.Count; $i++) {
        Write-Console ('  [{0,3}] {1,-42} {2,-10} AD-integrated={3}' -f
            ($i + 1), $zones[$i].ZoneName, $zones[$i].ZoneType, $zones[$i].IsDsIntegrated)
    }
    Write-Console '  [M] Enter zone manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host 'Select DNS zone').Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }
        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'DNS zone').Trim()
            if ($manual) { return $manual }
            continue
        }
        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $zones.Count) { return $zones[$index].ZoneName }
        }
        Write-Console 'Invalid DNS zone selection.' Yellow
    }
}


function Select-DnsRecordInteractive {
    param([Parameter(Mandatory=$true)][string]$ZoneName)

    Assert-DomainController
    Assert-DnsServerModule

    $filterText = ''

    while ($true) {
        $records = @(Get-DnsServerResourceRecord -ZoneName $ZoneName -ErrorAction Stop |
            Sort-Object HostName,RecordType)

        if ($filterText) {
            $records = @($records | Where-Object {
                $_.HostName -like ("*{0}*" -f $filterText) -or
                $_.RecordType -like ("*{0}*" -f $filterText)
            })
        }

        $displayRecords = @($records | Select-Object -First 150)

        Write-Console ''
        Write-Console ("DNS records in {0}:" -f $ZoneName) Cyan
        if ($records.Count -gt 150) {
            Write-Console ("  Showing first 150 of {0}. Use [S] to filter before selecting." -f $records.Count) Yellow
        }

        for ($i = 0; $i -lt $displayRecords.Count; $i++) {
            Write-Console ('  [{0,3}] {1,-36} {2,-8} TTL={3}' -f
                ($i + 1), $displayRecords[$i].HostName, $displayRecords[$i].RecordType, $displayRecords[$i].TimeToLive)
        }

        if ($displayRecords.Count -eq 0) { Write-Console '  No records matched.' Yellow }
        Write-Console '  [S] Search/filter by node name or record type' Gray
        Write-Console '  [0] Cancel' Gray

        $choice = (Read-Host 'Select DNS record').Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }
        if ($choice.ToUpperInvariant() -eq 'S') {
            $filterText = (Read-Host 'Record filter').Trim()
            continue
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $displayRecords.Count) {
                return $displayRecords[$index]
            }
        }
        Write-Console 'Invalid DNS record selection.' Yellow
    }
}

function Select-AdTrustName {
    Assert-DomainController
    if (-not (Test-Command 'Get-ADTrust')) { return $null }

    $trusts = @(Get-ADTrust -Filter * | Sort-Object Name)
    Write-Console ''
    Write-Console 'Domain/forest trusts:' Cyan
    for ($i = 0; $i -lt $trusts.Count; $i++) {
        Write-Console ('  [{0,3}] {1,-36} {2,-14} {3}' -f
            ($i + 1), $trusts[$i].Name, $trusts[$i].Direction, $trusts[$i].TrustType)
    }
    if ($trusts.Count -eq 0) { Write-Console '  No trusts found.' Yellow }
    Write-Console '  [M] Enter trusted domain manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host 'Select trust').Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }
        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'Trusted domain/forest DNS name').Trim()
            if ($manual) { return $manual }
            continue
        }
        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $trusts.Count) { return $trusts[$index].Name }
        }
        Write-Console 'Invalid trust selection.' Yellow
    }
}

function Show-AdUserDetail {
    Assert-DomainController

    $identity = Select-AdUserIdentity -Prompt 'Select user to inspect'
    if (-not $identity) { return }
    Get-ADUser -Identity $identity -Properties * |
        Select-Object SamAccountName, UserPrincipalName, DisplayName, GivenName, Surname,
            Enabled, LockedOut, PasswordLastSet, PasswordNeverExpires, LastLogonDate,
            Mail, Department, Title, DistinguishedName |
        Format-List
}


function Select-AdOuPathInteractive {
    Assert-DomainController

    $domain = Get-ADDomain
    $ous = @(Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName)

    Write-Console ''
    Write-Console 'Available user containers / OUs:' Cyan
    Write-Console ('  [1] {0}  (default Users container)' -f $domain.UsersContainer)

    for ($i = 0; $i -lt $ous.Count; $i++) {
        Write-Console ('  [{0}] {1}' -f ($i + 2), $ous[$i].DistinguishedName)
    }

    Write-Console '  [M] Enter distinguished name manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host 'Select target container [1]').Trim()
        if ([string]::IsNullOrWhiteSpace($choice)) { return $domain.UsersContainer }
        if ($choice -eq '0') { return $null }
        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'Container distinguished name').Trim()
            if ($manual) { return $manual }
            continue
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            if ($number -eq 1) { return $domain.UsersContainer }
            $ouIndex = $number - 2
            if ($ouIndex -ge 0 -and $ouIndex -lt $ous.Count) {
                return $ous[$ouIndex].DistinguishedName
            }
        }

        Write-Console 'Invalid container selection.' Yellow
    }
}

function New-AdGroupForSelector {
    Assert-DomainController

    $name = (Read-Host 'New group name').Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }

    $scope = Select-EnumeratedValue -Title 'GROUP SCOPE' -DefaultIndex 1 -Options @(
        [pscustomobject]@{ Value='Global'; Description='Typical domain role/application group' },
        [pscustomobject]@{ Value='Universal'; Description='Forest-wide group' },
        [pscustomobject]@{ Value='DomainLocal'; Description='Resource permission scope in this domain' }
    )
    if (-not $scope) { return $null }

    $category = Select-EnumeratedValue -Title 'GROUP CATEGORY' -DefaultIndex 1 -Options @(
        [pscustomobject]@{ Value='Security'; Description='Can be used for access control' },
        [pscustomobject]@{ Value='Distribution'; Description='Distribution-only group' }
    )
    if (-not $category) { return $null }

    $path = Select-AdOuDn -Prompt 'Select group container' -AllowDefault
    if ($null -eq $path) { return $null }

    if (-not (Confirm-Action `
        -Action ("Create AD group '{0}'" -f $name) `
        -Reason 'Create a group requested during user membership assignment.' `
        -Impact LOW)) {
        return $null
    }

    New-ChangeSet

    $params = @{
        Name          = $name
        GroupScope    = $scope
        GroupCategory = $category
        PassThru      = $true
    }
    if ($path -and $path -ne '__DEFAULT__') { $params.Path = $path }

    try {
        return (New-ADGroup @params)
    }
    catch {
        Write-Console ("Group creation failed: {0}" -f $_.Exception.Message) Red
        return $null
    }
}

function Select-AdGroupsInteractive {
    param([switch]$AllowCreate)

    Assert-DomainController
    $selected = New-Object 'System.Collections.Generic.List[object]'

    while ($true) {
        $filterText = (Read-Host 'Filter group names (blank = all)').Trim()
        $groups = @(Get-ADGroup -Filter * | Sort-Object Name)

        if ($filterText) {
            $groups = @($groups | Where-Object { $_.Name -like ("*{0}*" -f $filterText) })
        }

        if ($groups.Count -eq 0) {
            Write-Console 'No groups matched the filter.' Yellow
        }
        else {
            Write-Console ''
            Write-Console 'Available groups:' Cyan
            for ($i = 0; $i -lt $groups.Count; $i++) {
                Write-Console ('  [{0,3}] {1,-38} {2}/{3}' -f ($i + 1), $groups[$i].Name, $groups[$i].GroupScope, $groups[$i].GroupCategory)
            }
        }

        Write-Console ''
        Write-Console 'Enter one or more indexes separated by commas.' Gray
        Write-Console '  [S] Search/filter again' Gray
        Write-Console '  [M] Add an existing group by name/GUID/DN manually' Gray
        if ($AllowCreate) { Write-Console '  [N] Create a new group and select it' Green }
        Write-Console '  [0] Finish selection' Gray

        $choice = (Read-Host 'Group selection').Trim()
        if ([string]::IsNullOrWhiteSpace($choice) -or $choice -eq '0') { break }

        switch ($choice.ToUpperInvariant()) {
            'S' { continue }
            'M' {
                $manual = (Read-Host 'Existing group identity').Trim()
                if ($manual) {
                    try {
                        $group = Get-ADGroup -Identity $manual -ErrorAction Stop
                        if (-not ($selected | Where-Object { $_.DistinguishedName -eq $group.DistinguishedName })) {
                            [void]$selected.Add($group)
                        }
                    }
                    catch { Write-Console $_.Exception.Message Red }
                }
                continue
            }
            'N' {
                if (-not $AllowCreate) {
                    Write-Console 'Group creation is disabled in this selector.' Yellow
                    continue
                }
                $group = New-AdGroupForSelector
                if ($group -and -not ($selected | Where-Object { $_.DistinguishedName -eq $group.DistinguishedName })) {
                    [void]$selected.Add($group)
                }
                continue
            }
        }

        foreach ($part in ($choice -split ',')) {
            $number = 0
            if ([int]::TryParse($part.Trim(), [ref]$number)) {
                $index = $number - 1
                if ($index -ge 0 -and $index -lt $groups.Count) {
                    $group = $groups[$index]
                    if (-not ($selected | Where-Object { $_.DistinguishedName -eq $group.DistinguishedName })) {
                        [void]$selected.Add($group)
                    }
                }
                else {
                    Write-Console ("Index out of range: {0}" -f $number) Yellow
                }
            }
            else {
                Write-Console ("Invalid group index: {0}" -f $part) Yellow
            }
        }

        if ($selected.Count -gt 0) {
            Write-Console ''
            Write-Console ('Selected groups: {0}' -f (($selected | ForEach-Object { $_.Name }) -join ', ')) Green
        }

        if (-not (Read-BooleanChoice -Prompt 'Add more groups?' -Default $false)) { break }
    }

    return @($selected)
}


function Test-AdUserEffectiveGroupMembership {
    param(
        [Parameter(Mandatory)][Microsoft.ActiveDirectory.Management.ADUser]$User,
        [Parameter(Mandatory)][Microsoft.ActiveDirectory.Management.ADGroup]$Group
    )

    try {
        $memberships = @(Get-ADPrincipalGroupMembership -Identity $User -ErrorAction Stop)
        return [bool]($memberships | Where-Object { $_.DistinguishedName -eq $Group.DistinguishedName })
    }
    catch {
        Write-Log ("Could not verify existing membership {0} -> {1}: {2}" -f
            $User.SamAccountName, $Group.Name, $_.Exception.Message) WARN
        return $false
    }
}

function Add-AdUserGroupMembershipSafe {
    param(
        [Parameter(Mandatory)]$User,
        [Parameter(Mandatory)]$Group
    )

    if ($User -isnot [Microsoft.ActiveDirectory.Management.ADUser]) {
        $User = Get-ADUser -Identity $User -ErrorAction Stop
    }
    if ($Group -isnot [Microsoft.ActiveDirectory.Management.ADGroup]) {
        $Group = Get-ADGroup -Identity $Group -ErrorAction Stop
    }

    if (Test-AdUserEffectiveGroupMembership -User $User -Group $Group) {
        if ($Group.Name -eq 'Domain Users') {
            Write-Console ("SKIP: {0} already has effective membership in Domain Users (normally its primary group)." -f
                $User.SamAccountName) Yellow
        }
        else {
            Write-Console ("SKIP: {0} is already a member of {1}." -f
                $User.SamAccountName, $Group.Name) Yellow
        }
        Write-Log ("Skipped duplicate/effective membership: {0} -> {1}" -f
            $User.SamAccountName, $Group.Name) INFO
        return $true
    }

    try {
        Add-ADGroupMember -Identity $Group -Members $User -ErrorAction Stop
        Write-Log ("Added {0} to group {1}" -f $User.SamAccountName, $Group.Name) CHANGE
        return $true
    }
    catch {
        # Re-check to tolerate races or provider-specific "already a member"
        # errors without treating an idempotent end state as a failure.
        if (Test-AdUserEffectiveGroupMembership -User $User -Group $Group) {
            Write-Console ("SKIP: {0} already has effective membership in {1}." -f
                $User.SamAccountName, $Group.Name) Yellow
            return $true
        }

        Write-Console ("Could not add {0} to {1}: {2}" -f
            $User.SamAccountName, $Group.Name, $_.Exception.Message) Red
        Write-Log ("Failed group membership: {0} -> {1}: {2}" -f
            $User.SamAccountName, $Group.Name, $_.Exception.Message) ERROR
        return $false
    }
}

function Manage-AdUserGroupsInteractive {
    param([string]$Identity)

    Assert-DomainController

    if ([string]::IsNullOrWhiteSpace($Identity)) {
        $Identity = Select-AdUserIdentity -Prompt 'Select user'
    }
    if ([string]::IsNullOrWhiteSpace($Identity)) { return }

    $user = Get-ADUser -Identity $Identity -ErrorAction Stop

    while ($true) {
        if ($script:MainMenuRequested) { return }
        $current = @(Get-ADPrincipalGroupMembership -Identity $user | Sort-Object Name)

        Write-MenuHeader 'USER GROUP MEMBERSHIP' ("Account: {0}" -f $user.SamAccountName)
        if ($current.Count -eq 0) {
            Write-Console '  No direct group memberships returned.' Yellow
        }
        else {
            for ($i = 0; $i -lt $current.Count; $i++) {
                Write-Console ('  [{0,3}] {1,-42} {2}' -f ($i + 1), $current[$i].Name, $current[$i].GroupScope)
            }
        }
        Write-Console ''
        Write-MenuItem 'A' 'Add memberships' 'Choose existing groups or create a new one' Good
        Write-MenuItem 'R' 'Remove memberships' 'Choose one or more current memberships' Warn
        Write-MenuNavigation -BackDescription 'Return to user directory'
        Write-Rule

        $choice = (Read-Host 'Select operation').Trim().ToUpperInvariant()
        switch ($choice) {
            'H' { $script:MainMenuRequested = $true; return }
            'A' {
                $groups = @(Select-AdGroupsInteractive -AllowCreate)
                foreach ($group in $groups) {
                    if (-not (Confirm-Action `
                        -Action ("Add '{0}' to group '{1}'" -f $user.SamAccountName, $group.Name) `
                        -Reason 'Grant domain group membership.' `
                        -Impact MEDIUM)) { continue }

                    New-ChangeSet
                    [void](Add-AdUserGroupMembershipSafe -User $user -Group $group)
                }
            }
            'R' {
                if ($current.Count -eq 0) {
                    Write-Console 'No memberships are available to remove.' Yellow
                    Pause-ControlPlane
                    continue
                }

                $raw = (Read-Host 'Indexes to remove (comma-separated)').Trim()
                foreach ($part in ($raw -split ',')) {
                    $number = 0
                    if (-not [int]::TryParse($part.Trim(), [ref]$number)) { continue }
                    $index = $number - 1
                    if ($index -lt 0 -or $index -ge $current.Count) { continue }
                    $group = $current[$index]

                    if (Confirm-Action `
                        -Action ("Remove '{0}' from group '{1}'" -f $user.SamAccountName, $group.Name) `
                        -Reason 'Revoke domain group membership.' `
                        -Impact MEDIUM) {

                        New-ChangeSet
                        Remove-ADGroupMember -Identity $group -Members $user -Confirm:$false
                        Write-Log ("Removed {0} from group {1}" -f $user.SamAccountName, $group.Name) CHANGE
                    }
                }
            }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function New-AdUserInteractive {
    Assert-DomainController

    $sam = (Read-Host 'sAMAccountName').Trim()
    if ([string]::IsNullOrWhiteSpace($sam)) { return }

    if (Get-ADUser -Identity $sam -ErrorAction SilentlyContinue) {
        Write-Console 'User already exists.' Yellow
        return
    }

    $domain = Get-ADDomain
    $given = Read-Host 'Given name'
    $surname = Read-Host 'Surname'
    $display = Read-Host 'Display name'
    if ([string]::IsNullOrWhiteSpace($display)) {
        $display = ("{0} {1}" -f $given, $surname).Trim()
    }

    $defaultUpn = "{0}@{1}" -f $sam, $domain.DNSRoot
    $upn = (Read-Host ("User principal name [{0}]" -f $defaultUpn)).Trim()
    if ([string]::IsNullOrWhiteSpace($upn)) { $upn = $defaultUpn }

    $description = Read-Host 'Description / purpose'
    $mail = Read-Host 'Email address'
    $department = Read-Host 'Department'
    $title = Read-Host 'Title / role'
    $company = Read-Host 'Company'
    $office = Read-Host 'Office'
    $phone = Read-Host 'Office phone'

    $path = Select-AdOuPathInteractive
    if (-not $path) { return }

    $password = Read-Host 'Initial password' -AsSecureString

    $enabled = Read-BooleanChoice -Prompt 'Enable account immediately?' -Default $true
    $changeAtLogon = Read-BooleanChoice -Prompt 'Require password change at first logon?' -Default $true
    $passwordNeverExpires = Read-BooleanChoice -Prompt 'Password never expires?' -Default $false
    $cannotChangePassword = Read-BooleanChoice -Prompt 'Prevent user from changing password?' -Default $false

    if ($passwordNeverExpires -and $changeAtLogon) {
        Write-Console 'PasswordNeverExpires conflicts with ChangePasswordAtLogon; first-logon change has been disabled.' Yellow
        $changeAtLogon = $false
    }

    Write-Console ''
    Write-Console 'User creation plan:' Cyan
    Write-Console ("  Account       : {0}" -f $sam)
    Write-Console ("  UPN           : {0}" -f $upn)
    Write-Console ("  Display name  : {0}" -f $display)
    Write-Console ("  Container     : {0}" -f $path)
    Write-Console ("  Enabled       : {0}" -f $enabled)
    Write-Console ("  Change @ logon: {0}" -f $changeAtLogon)
    Write-Console ("  Never expires : {0}" -f $passwordNeverExpires)
    Write-Console ("  Cannot change : {0}" -f $cannotChangePassword)

    if (-not (Confirm-Action `
        -Action ("Create AD user '{0}'" -f $sam) `
        -Reason 'Create the configured domain identity.' `
        -Impact LOW)) {
        return
    }

    New-ChangeSet

    $params = @{
        SamAccountName        = $sam
        UserPrincipalName     = $upn
        Name                  = $display
        DisplayName           = $display
        GivenName             = $given
        Surname               = $surname
        Enabled               = $enabled
        AccountPassword       = $password
        ChangePasswordAtLogon = $changeAtLogon
        PasswordNeverExpires  = $passwordNeverExpires
        CannotChangePassword  = $cannotChangePassword
        Path                  = $path
    }

    if ($description) { $params.Description = $description }
    if ($mail) { $params.EmailAddress = $mail }
    if ($department) { $params.Department = $department }
    if ($title) { $params.Title = $title }
    if ($company) { $params.Company = $company }
    if ($office) { $params.Office = $office }
    if ($phone) { $params.OfficePhone = $phone }

    New-ADUser @params
    Write-Log ("Created AD user: {0}" -f $sam) CHANGE

    if (Read-BooleanChoice -Prompt 'Assign domain group memberships now?' -Default $true) {
        Write-Console 'Note: new AD users already use Domain Users as their primary group; it does not need to be added again.' Cyan
        $createdUser = Get-ADUser -Identity $sam -ErrorAction Stop
        $groups = @(Select-AdGroupsInteractive -AllowCreate)
        foreach ($group in $groups) {
            [void](Add-AdUserGroupMembershipSafe -User $createdUser -Group $group)
        }
    }
}

function Edit-AdUserInteractive {
    Assert-DomainController

    $identity = Select-AdUserIdentity -Prompt 'Select user to edit'
    if ([string]::IsNullOrWhiteSpace($identity)) { return }

    $user = Get-ADUser -Identity $identity -Properties DisplayName, Mail, Department, Title, Company,
        Office, OfficePhone, Description, UserPrincipalName, PasswordNeverExpires, CannotChangePassword, Enabled

    Write-Console 'Leave text values blank to keep the current value.' Gray
    Write-Console 'For boolean options use K=keep, Y=yes, N=no.' Gray

    $display = Read-Host ("Display name [{0}]" -f $user.DisplayName)
    $upn = Read-Host ("User principal name [{0}]" -f $user.UserPrincipalName)
    $mail = Read-Host ("Email [{0}]" -f $user.Mail)
    $description = Read-Host ("Description [{0}]" -f $user.Description)
    $department = Read-Host ("Department [{0}]" -f $user.Department)
    $title = Read-Host ("Title [{0}]" -f $user.Title)
    $company = Read-Host ("Company [{0}]" -f $user.Company)
    $office = Read-Host ("Office [{0}]" -f $user.Office)
    $phone = Read-Host ("Office phone [{0}]" -f $user.OfficePhone)

    $changeAtLogon = Read-OptionalBooleanChoice -Prompt 'Require password change at next logon?'
    $passwordNeverExpires = Read-OptionalBooleanChoice -Prompt 'Password never expires?'
    $cannotChangePassword = Read-OptionalBooleanChoice -Prompt 'Prevent user from changing password?'
    $enabled = Read-OptionalBooleanChoice -Prompt ("Account enabled? (currently {0})" -f $user.Enabled)

    if ($passwordNeverExpires -eq $true -and $changeAtLogon -eq $true) {
        Write-Console 'PasswordNeverExpires conflicts with ChangePasswordAtLogon; first-logon change will be disabled.' Yellow
        $changeAtLogon = $false
    }

    if (-not (Confirm-Action `
        -Action ("Update AD user '{0}'" -f $identity) `
        -Reason 'Modify selected directory attributes and account controls.' `
        -Impact LOW)) {
        return
    }

    New-ChangeSet

    $params = @{ Identity = $identity }
    if ($display) { $params.DisplayName = $display }
    if ($upn) { $params.UserPrincipalName = $upn }
    if ($mail) { $params.EmailAddress = $mail }
    if ($description) { $params.Description = $description }
    if ($department) { $params.Department = $department }
    if ($title) { $params.Title = $title }
    if ($company) { $params.Company = $company }
    if ($office) { $params.Office = $office }
    if ($phone) { $params.OfficePhone = $phone }
    if ($null -ne $changeAtLogon) { $params.ChangePasswordAtLogon = [bool]$changeAtLogon }
    if ($null -ne $passwordNeverExpires) { $params.PasswordNeverExpires = [bool]$passwordNeverExpires }
    if ($null -ne $cannotChangePassword) { $params.CannotChangePassword = [bool]$cannotChangePassword }

    if ($params.Count -gt 1) {
        Set-ADUser @params
        Write-Log ("Updated AD user: {0}" -f $identity) CHANGE
    }

    if ($null -ne $enabled) {
        if ([bool]$enabled) { Enable-ADAccount -Identity $identity }
        else { Disable-ADAccount -Identity $identity }
    }

    if (Read-BooleanChoice -Prompt 'Manage this user''s group memberships now?' -Default $false) {
        Manage-AdUserGroupsInteractive -Identity $identity
    }
}

function Reset-AdUserPassword {
    Assert-DomainController

    $identity = Select-AdUserIdentity -Prompt 'Select user for password reset'
    if (-not $identity) { return }
    $password = Read-Host 'New password' -AsSecureString

    if (-not (Confirm-Action `
        -Action ("Reset password for '{0}'" -f $identity) `
        -Reason 'Administrative password reset.' `
        -Impact MEDIUM)) {
        return
    }

    New-ChangeSet
    Set-ADAccountPassword -Identity $identity -Reset -NewPassword $password
    Set-ADUser -Identity $identity -ChangePasswordAtLogon $true
}

function Set-AdUserEnabledState {
    param([Parameter(Mandatory=$true)][bool]$Enabled)

    Assert-DomainController

    $identity = Select-AdUserIdentity -Prompt $(if ($Enabled) { 'Select user to enable' } else { 'Select user to disable' })
    if (-not $identity) { return }
    $verb = if ($Enabled) { 'Enable' } else { 'Disable' }
    $impact = if ($Enabled) { 'LOW' } else { 'MEDIUM' }

    if (-not (Confirm-Action `
        -Action ("{0} AD user '{1}'" -f $verb, $identity) `
        -Reason 'Change authentication eligibility for this account.' `
        -Impact $impact)) {
        return
    }

    New-ChangeSet

    if ($Enabled) {
        Enable-ADAccount -Identity $identity
    }
    else {
        Disable-ADAccount -Identity $identity
    }
}

function Unlock-AdUserInteractive {
    Assert-DomainController

    $identity = Select-AdUserIdentity -Prompt 'Select user to unlock'
    if (-not $identity) { return }

    if (Confirm-Action `
        -Action ("Unlock AD user '{0}'" -f $identity) `
        -Reason 'Clear the account lockout state.' `
        -Impact LOW) {

        Unlock-ADAccount -Identity $identity
    }
}

function Remove-AdUserInteractive {
    Assert-DomainController

    $identity = Select-AdUserIdentity -Prompt 'Select user to delete'
    if (-not $identity) { return }

    if (-not (Confirm-Action `
        -Action ("PERMANENTLY delete AD user '{0}'" -f $identity) `
        -Reason 'Delete the directory object. This is destructive.' `
        -Impact HIGH)) {
        return
    }

    New-ChangeSet
    Remove-ADUser -Identity $identity -Confirm:$false
    Write-Log ("Deleted AD user: {0}" -f $identity) CHANGE
}

# ===========================================================================
# AD groups / access
# ===========================================================================

function Show-AdGroups {
    Assert-DomainController

    Get-ADGroup -Filter * |
        Sort-Object Name |
        Select-Object Name, GroupScope, GroupCategory, DistinguishedName |
        Format-Table -AutoSize
}

function New-AdGroupInteractive {
    Assert-DomainController

    $name = Read-Host 'Group name'
    $scope = Select-EnumeratedValue -Title 'GROUP SCOPE' -DefaultIndex 1 -Options @(
        [pscustomobject]@{ Value='Global'; Description='Typical domain role/application group' },
        [pscustomobject]@{ Value='Universal'; Description='Forest-wide group' },
        [pscustomobject]@{ Value='DomainLocal'; Description='Resource permission scope in this domain' }
    )
    if (-not $scope) { return $null }

    $category = Select-EnumeratedValue -Title 'GROUP CATEGORY' -DefaultIndex 1 -Options @(
        [pscustomobject]@{ Value='Security'; Description='Can be used for access control' },
        [pscustomobject]@{ Value='Distribution'; Description='Distribution-only group' }
    )
    if (-not $category) { return $null }

    $path = Select-AdOuDn -Prompt 'Select group container' -AllowDefault
    if ($null -eq $path) { return $null }

    if (-not (Confirm-Action `
        -Action ("Create AD group '{0}'" -f $name) `
        -Reason 'Create a new group object.' `
        -Impact LOW)) {
        return
    }

    New-ChangeSet

    $params = @{
        Name          = $name
        GroupScope    = $scope
        GroupCategory = $category
    }

    if ($path -and $path -ne '__DEFAULT__') { $params.Path = $path }

    New-ADGroup @params
}

function Show-AdGroupMembers {
    Assert-DomainController

    $group = Select-AdGroupIdentity -Prompt 'Select group to inspect'
    if (-not $group) { return }
    Get-ADGroupMember -Identity $group |
        Select-Object Name, SamAccountName, ObjectClass, DistinguishedName |
        Format-Table -AutoSize
}

function Add-AdGroupMemberInteractive {
    Assert-DomainController

    $group = Select-AdGroupIdentity -Prompt 'Select target group'
    if (-not $group) { return }
    $principal = Select-AdPrincipalIdentity
    if (-not $principal) { return }
    $member = $principal.Identity

    if (Confirm-Action `
        -Action ("Add '{0}' to '{1}'" -f $member, $group) `
        -Reason 'Grant group membership.' `
        -Impact MEDIUM) {

        New-ChangeSet
        Add-ADGroupMember -Identity $group -Members $member
    }
}

function Remove-AdGroupMemberInteractive {
    Assert-DomainController

    $group = Select-AdGroupIdentity -Prompt 'Select target group'
    if (-not $group) { return }
    $member = Select-AdGroupMemberIdentity -Group $group
    if (-not $member) { return }

    if (Confirm-Action `
        -Action ("Remove '{0}' from '{1}'" -f $member, $group) `
        -Reason 'Revoke group membership.' `
        -Impact MEDIUM) {

        New-ChangeSet
        Remove-ADGroupMember -Identity $group -Members $member -Confirm:$false
    }
}

function Remove-AdGroupInteractive {
    Assert-DomainController

    $group = Select-AdGroupIdentity -Prompt 'Select group to delete'
    if (-not $group) { return }

    if ($group -in @('Domain Admins','Enterprise Admins','Schema Admins','Domain Users','Domain Controllers','Administrators')) {
        Write-Console 'Protected/core AD group: deletion refused.' Red
        return
    }

    if (Confirm-Action `
        -Action ("PERMANENTLY delete AD group '{0}'" -f $group) `
        -Reason 'Delete the directory group object.' `
        -Impact HIGH) {

        New-ChangeSet
        Remove-ADGroup -Identity $group -Confirm:$false
    }
}

function Show-PrivilegedGroups {
    Assert-DomainController

    foreach ($group in @('Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators')) {
        Write-Console ''
        Write-Console ("{0}:" -f $group) Cyan
        try {
            Get-ADGroupMember -Identity $group -Recursive:$false |
                Select-Object Name, SamAccountName, ObjectClass |
                Format-Table -AutoSize
        }
        catch {
            Write-Console $_.Exception.Message Yellow
        }
    }
}

# ===========================================================================
# AD computers / OUs
# ===========================================================================

function Show-AdComputers {
    Assert-DomainController

    Get-ADComputer -Filter * -Properties Enabled, LastLogonDate, OperatingSystem, IPv4Address |
        Sort-Object Name |
        Select-Object Name, Enabled, OperatingSystem, IPv4Address, LastLogonDate |
        Format-Table -AutoSize
}

function Show-AdComputerDetail {
    Assert-DomainController

    $identity = Select-AdComputerIdentity -Prompt 'Select computer to inspect'
    if (-not $identity) { return }
    Get-ADComputer -Identity $identity -Properties * |
        Select-Object Name, Enabled, DNSHostName, IPv4Address, OperatingSystem,
            OperatingSystemVersion, LastLogonDate, PasswordLastSet, DistinguishedName |
        Format-List
}

function Set-AdComputerEnabledState {
    param([Parameter(Mandatory=$true)][bool]$Enabled)

    Assert-DomainController

    $identity = Select-AdComputerIdentity -Prompt $(if ($Enabled) { 'Select computer to enable' } else { 'Select computer to disable' })
    if (-not $identity) { return }
    $verb = if ($Enabled) { 'Enable' } else { 'Disable' }

    if (-not (Confirm-Action `
        -Action ("{0} computer account '{1}'" -f $verb, $identity) `
        -Reason 'Change whether the machine account can authenticate.' `
        -Impact MEDIUM)) {
        return
    }

    New-ChangeSet

    if ($Enabled) {
        Enable-ADAccount -Identity $identity
    }
    else {
        Disable-ADAccount -Identity $identity
    }
}

function Remove-AdComputerInteractive {
    Assert-DomainController

    $identity = Select-AdComputerIdentity -Prompt 'Select computer to delete'
    if (-not $identity) { return }

    if (Confirm-Action `
        -Action ("PERMANENTLY delete computer account '{0}'" -f $identity) `
        -Reason 'Remove an obsolete machine object from Active Directory.' `
        -Impact HIGH) {

        New-ChangeSet
        Remove-ADComputer -Identity $identity -Confirm:$false
    }
}

function Show-AdOrganizationalUnits {
    Assert-DomainController

    Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
        Sort-Object DistinguishedName |
        Select-Object Name, ProtectedFromAccidentalDeletion, DistinguishedName |
        Format-Table -AutoSize
}

function New-AdOrganizationalUnitInteractive {
    Assert-DomainController

    $name = Read-Host 'OU name'
    $path = Select-AdOuDn -Prompt 'Select parent container' -IncludeDomainRoot
    if (-not $path) { return }

    if (Confirm-Action `
        -Action ("Create OU '{0}' under '{1}'" -f $name, $path) `
        -Reason 'Create an organizational container protected from accidental deletion.' `
        -Impact LOW) {

        New-ChangeSet
        New-ADOrganizationalUnit -Name $name -Path $path -ProtectedFromAccidentalDeletion $true
    }
}

function Move-AdObjectInteractive {
    Assert-DomainController

    $identity = Select-AdDirectoryObjectIdentity
    if (-not $identity) { return }
    $target = Select-AdOuDn -Prompt 'Select destination OU' -IncludeDomainRoot
    if (-not $target) { return }

    if (Confirm-Action `
        -Action ("Move object to '{0}'" -f $target) `
        -Reason 'Change the directory location and therefore potentially its GPO/delegation scope.' `
        -Impact MEDIUM) {

        New-ChangeSet
        Move-ADObject -Identity $identity -TargetPath $target
    }
}

function Remove-AdOrganizationalUnitInteractive {
    Assert-DomainController

    $identity = Select-AdOuDn -Prompt 'Select OU to delete'
    if (-not $identity) { return }

    if (-not (Confirm-Action `
        -Action ("PERMANENTLY delete OU '{0}'" -f $identity) `
        -Reason 'Delete an organizational container. It must be empty and unprotected.' `
        -Impact HIGH)) {
        return
    }

    New-ChangeSet
    Set-ADOrganizationalUnit -Identity $identity -ProtectedFromAccidentalDeletion $false
    Remove-ADOrganizationalUnit -Identity $identity -Confirm:$false
}

# ===========================================================================
# Group Policy operations
# ===========================================================================

function Import-GroupPolicyModule {
    if (-not (Test-Command 'Get-GPO')) {
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            [void](Ensure-WindowsServerFeature `
                -Name 'GPMC' `
                -Purpose 'Group Policy administration' `
                -Required)
        }

        $previousProgress = $ProgressPreference
        try {
            $ProgressPreference = 'SilentlyContinue'
            Import-Module GroupPolicy -ErrorAction Stop -DisableNameChecking
        }
        catch {
            throw ("GroupPolicy module unavailable after dependency repair: {0}" -f $_.Exception.Message)
        }
        finally {
            $ProgressPreference = $previousProgress
        }
    }
}


function Get-GpoInventory {
    Assert-DomainController
    Import-GroupPolicyModule

    $previousProgress = $ProgressPreference
    try {
        # GroupPolicy cmdlets can render a progress UI that behaves badly in
        # redirected/embedded consoles. Inventory is intentionally quiet.
        $ProgressPreference = 'SilentlyContinue'
        return @(Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName)
    }
    finally {
        $ProgressPreference = $previousProgress
    }
}

function Show-GpoInventoryIndexed {
    $gpos = @(Get-GpoInventory)

    Write-Console ''
    Write-Console 'Existing GPOs:' Cyan
    if ($gpos.Count -eq 0) {
        Write-Console '  No GPOs returned.' Yellow
        return @()
    }

    for ($i = 0; $i -lt $gpos.Count; $i++) {
        Write-Console ('  [{0,3}] {1,-38} {2}  {3}' -f `
            ($i + 1), $gpos[$i].DisplayName, $gpos[$i].Id, $gpos[$i].GpoStatus)
    }

    return $gpos
}

function Select-GpoInteractive {
    param([string]$Prompt = 'Select GPO')

    $gpos = @(Show-GpoInventoryIndexed)
    Write-Console ''
    Write-Console '  [M] Enter a GPO name or GUID manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host $Prompt).Trim()
        if ($choice -eq '0' -or [string]::IsNullOrWhiteSpace($choice)) { return $null }

        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'GPO display name or GUID').Trim()
            if (-not $manual) { continue }

            try {
                $parsed = [guid]::Empty
                if ([guid]::TryParse($manual, [ref]$parsed)) {
                    return (Get-GPO -Guid $parsed -ErrorAction Stop)
                }
                return (Get-GPO -Name $manual -ErrorAction Stop)
            }
            catch {
                Write-Console ("GPO not found: {0}" -f $_.Exception.Message) Red
                continue
            }
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            $index = $number - 1
            if ($index -ge 0 -and $index -lt $gpos.Count) {
                return $gpos[$index]
            }
        }

        Write-Console 'Invalid GPO selection.' Yellow
    }
}

function Select-GpoTargetInteractive {
    Assert-DomainController

    $domain = Get-ADDomain
    $ous = @(Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName)

    Write-Console ''
    Write-Console 'GPO link targets:' Cyan
    Write-Console ('  [1] DOMAIN ROOT  {0}' -f $domain.DistinguishedName) Green

    for ($i = 0; $i -lt $ous.Count; $i++) {
        Write-Console ('  [{0,3}] OU  {1}' -f ($i + 2), $ous[$i].DistinguishedName)
    }

    Write-Console '  [M] Enter target distinguished name manually' Gray
    Write-Console '  [0] Cancel' Gray

    while ($true) {
        $choice = (Read-Host 'Select GPO target [1]').Trim()
        if ([string]::IsNullOrWhiteSpace($choice)) { return $domain.DistinguishedName }
        if ($choice -eq '0') { return $null }
        if ($choice.ToUpperInvariant() -eq 'M') {
            $manual = (Read-Host 'Target distinguished name').Trim()
            if ($manual) { return $manual }
            continue
        }

        $number = 0
        if ([int]::TryParse($choice, [ref]$number)) {
            if ($number -eq 1) { return $domain.DistinguishedName }
            $index = $number - 2
            if ($index -ge 0 -and $index -lt $ous.Count) {
                return $ous[$index].DistinguishedName
            }
        }

        Write-Console 'Invalid target selection.' Yellow
    }
}

function Get-SecurityGpoCatalog {
    return @(
        [pscustomobject]@{
            Key='1'; Name='SEC - PowerShell Logging'; Impact='LOW'; Scope='Computer';
            Description='Script block and module logging for administrative visibility.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; ValueName='EnableScriptBlockLogging'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; ValueName='EnableModuleLogging'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'; ValueName='*'; Type='String'; Value='*' }
            )
        },
        [pscustomobject]@{
            Key='2'; Name='SEC - Disable LLMNR'; Impact='MEDIUM'; Scope='Computer';
            Description='Disable multicast name resolution; prefer AD DNS.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; ValueName='EnableMulticast'; Type='DWord'; Value=0 }
            )
        },
        [pscustomobject]@{
            Key='3'; Name='SEC - SMB Guest Hardening'; Impact='MEDIUM'; Scope='Computer';
            Description='Reject insecure unauthenticated SMB guest logons.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'; ValueName='AllowInsecureGuestAuth'; Type='DWord'; Value=0 }
            )
        },
        [pscustomobject]@{
            Key='4'; Name='SEC - RDP Network Level Authentication'; Impact='MEDIUM'; Scope='Computer';
            Description='Require NLA for Remote Desktop Session Host connections.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'; ValueName='UserAuthentication'; Type='DWord'; Value=1 }
            )
        },
        [pscustomobject]@{
            Key='5'; Name='SEC - Microsoft Defender Core'; Impact='MEDIUM'; Scope='Computer';
            Description='Enable PUA protection and core Defender realtime policy values; review third-party EDR coexistence first.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender'; ValueName='PUAProtection'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName='DisableRealtimeMonitoring'; Type='DWord'; Value=0 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName='DisableBehaviorMonitoring'; Type='DWord'; Value=0 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName='DisableIOAVProtection'; Type='DWord'; Value=0 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'; ValueName='DisableScriptScanning'; Type='DWord'; Value=0 }
            )
        },
        [pscustomobject]@{
            Key='6'; Name='SEC - Windows Firewall Baseline'; Impact='HIGH'; Scope='Computer';
            Description='Enable Domain/Private/Public firewalls; block inbound by default and allow outbound by default.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName='EnableFirewall'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName='DefaultInboundAction'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'; ValueName='DefaultOutboundAction'; Type='DWord'; Value=0 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; ValueName='EnableFirewall'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; ValueName='DefaultInboundAction'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'; ValueName='DefaultOutboundAction'; Type='DWord'; Value=0 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName='EnableFirewall'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName='DefaultInboundAction'; Type='DWord'; Value=1 },
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'; ValueName='DefaultOutboundAction'; Type='DWord'; Value=0 }
            )
        },
        [pscustomobject]@{
            Key='7'; Name='SEC - Secure Screen Lock'; Impact='LOW'; Scope='User';
            Description='Enable password-protected screen saver with a 15-minute timeout.';
            Settings=@(
                @{ Key='HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; ValueName='ScreenSaveActive'; Type='String'; Value='1' },
                @{ Key='HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; ValueName='ScreenSaveTimeOut'; Type='String'; Value='900' },
                @{ Key='HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop'; ValueName='ScreenSaverIsSecure'; Type='String'; Value='1' }
            )
        },
        [pscustomobject]@{
            Key='8'; Name='SEC - Disable AlwaysInstallElevated'; Impact='LOW'; Scope='Computer + User';
            Description='Explicitly disable the risky AlwaysInstallElevated Windows Installer policy in both scopes.';
            Settings=@(
                @{ Key='HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer'; ValueName='AlwaysInstallElevated'; Type='DWord'; Value=0 },
                @{ Key='HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer'; ValueName='AlwaysInstallElevated'; Type='DWord'; Value=0 }
            )
        }
    )
}

function Show-SecurityGpoCatalog {
    $catalog = @(Get-SecurityGpoCatalog)

    Write-Console ''
    Write-Console 'Curated security GPO templates:' Cyan
    foreach ($item in $catalog) {
        $color = if ($item.Impact -eq 'HIGH') { 'Red' } elseif ($item.Impact -eq 'MEDIUM') { 'Yellow' } else { 'Green' }
        Write-Console ('  [{0}] {1,-42} {2,-15} Impact={3}' -f $item.Key, $item.Name, $item.Scope, $item.Impact) $color
        Write-Console ('      {0}' -f $item.Description) Gray
    }

    Write-Console ''
    Write-Console '  [A] Recommended starter pack: 1,2,3,4,7,8' Green
    Write-Console '  [M] Microsoft baseline guidance only (SCT / OSConfig; no automatic import)' Cyan
    Write-Console '  [H] Main menu' Yellow
    Write-Console '  [0] Cancel' Gray

    return $catalog
}

function Apply-SecurityGpoTemplate {
    param(
        [Parameter(Mandatory=$true)]$Template,
        [Parameter(Mandatory=$true)][string]$Target
    )

    Import-GroupPolicyModule
    $previousProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'

    try {
        $gpo = $null
        try {
            $gpo = Get-GPO -Name $Template.Name -ErrorAction Stop
            Write-Console ("Updating existing GPO: {0} [{1}]" -f $gpo.DisplayName, $gpo.Id) Yellow

            $backupPath = Join-Path $script:RunPath 'gpo-backups'
            New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
            Backup-GPO -Guid $gpo.Id -Path $backupPath -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            $gpo = New-GPO -Name $Template.Name -Comment $Template.Description -ErrorAction Stop
            Write-Console ("Created GPO: {0} [{1}]" -f $gpo.DisplayName, $gpo.Id) Green
        }

        foreach ($setting in $Template.Settings) {
            Set-GPRegistryValue `
                -Guid $gpo.Id `
                -Key $setting.Key `
                -ValueName $setting.ValueName `
                -Type $setting.Type `
                -Value $setting.Value `
                -ErrorAction Stop | Out-Null
        }

        try {
            New-GPLink -Guid $gpo.Id -Target $Target -LinkEnabled Yes -ErrorAction Stop | Out-Null
        }
        catch {
            Set-GPLink -Guid $gpo.Id -Target $Target -LinkEnabled Yes -ErrorAction Stop | Out-Null
        }

        Write-Log ("Applied security GPO template: {0} -> {1}" -f $Template.Name, $Target) CHANGE
        return $gpo
    }
    finally {
        $ProgressPreference = $previousProgress
    }
}

function Invoke-SecurityGpoWizard {
    Assert-DomainController
    Import-GroupPolicyModule

    Write-MenuHeader 'SECURITY GPO CATALOG' 'Curated common domain GPOs; choose templates and target scope instead of typing GUIDs'
    $catalog = @(Show-SecurityGpoCatalog)

    $raw = (Read-Host 'Template selection (comma-separated)').Trim().ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($raw) -or $raw -eq '0') { return }
    if ($raw -eq 'H') { $script:MainMenuRequested = $true; return }

    if ($raw -eq 'M') {
        Write-Console ''
        Write-Console 'For a complete vendor baseline, use Microsoft Security Compliance Toolkit (Server 2019/2022/2025)' Cyan
        Write-Console 'or Windows Server 2025 OSConfig role-aware baselines. This assistant intentionally does not fabricate' Gray
        Write-Console 'a complete Microsoft baseline from a handful of registry values.' Gray
        Pause-ControlPlane
        return
    }

    $keys = if ($raw -eq 'A') { @('1','2','3','4','7','8') } else { @($raw -split ',' | ForEach-Object { $_.Trim() }) }
    $selected = @($catalog | Where-Object { $_.Key -in $keys })

    if ($selected.Count -eq 0) {
        Write-Console 'No valid templates selected.' Yellow
        return
    }

    $target = Select-GpoTargetInteractive
    if (-not $target) { return }

    Write-Console ''
    Write-Console 'GPO deployment plan:' Cyan
    foreach ($template in $selected) {
        Write-Console ('  - {0}  [Impact={1}]' -f $template.Name, $template.Impact)
    }
    Write-Console ("  Target: {0}" -f $target)

    $impact = if (@($selected | Where-Object { $_.Impact -eq 'HIGH' }).Count -gt 0) { 'HIGH' } `
        elseif (@($selected | Where-Object { $_.Impact -eq 'MEDIUM' }).Count -gt 0) { 'MEDIUM' } `
        else { 'LOW' }

    if (-not (Confirm-Action `
        -Action ("Create/update {0} security GPO template(s) and link them to '{1}'" -f $selected.Count, $target) `
        -Reason 'Deploy selected common domain security policies.' `
        -Impact $impact)) {
        return
    }

    New-ChangeSet

    foreach ($template in $selected) {
        try {
            [void](Apply-SecurityGpoTemplate -Template $template -Target $target)
        }
        catch {
            Write-Console ("Failed template '{0}': {1}" -f $template.Name, $_.Exception.Message) Red
        }
    }

    Write-Console ''
    Write-Console 'Security GPO deployment pass completed.' Green
    Show-GpoInventoryIndexed | Out-Null
}

function Show-Gpos {
    Assert-DomainController
    [void](Show-GpoInventoryIndexed)
}

function Show-GpoDetail {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO to inspect'
    if (-not $gpo) { return }

    $gpo | Format-List DisplayName, Id, DomainName, Owner, GpoStatus, CreationTime, ModificationTime, Description
}

function New-GpoInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $name = (Read-Host 'New GPO display name').Trim()
    if ([string]::IsNullOrWhiteSpace($name)) { return }

    $comment = Read-Host 'Comment / purpose'

    if (-not (Confirm-Action `
        -Action ("Create GPO '{0}'" -f $name) `
        -Reason 'Create an empty Group Policy Object.' `
        -Impact LOW)) {
        return
    }

    New-ChangeSet

    $previousProgress = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        $gpo = New-GPO -Name $name -Comment $comment -ErrorAction Stop
    }
    finally {
        $ProgressPreference = $previousProgress
    }

    Write-Console ("Created GPO: {0}" -f $gpo.DisplayName) Green
    Write-Console ("GUID       : {0}" -f $gpo.Id) Cyan

    if (Read-BooleanChoice -Prompt 'Link this GPO now?' -Default $true) {
        $target = Select-GpoTargetInteractive
        if ($target) {
            try {
                New-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes -ErrorAction Stop | Out-Null
                Write-Console ("Linked to: {0}" -f $target) Green
            }
            catch {
                Write-Console ("GPO created but link failed: {0}" -f $_.Exception.Message) Yellow
            }
        }
    }
}

function Backup-GpoInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO to back up'
    if (-not $gpo) { return }

    $path = Join-Path $script:RunPath 'gpo-backups'
    New-Item -ItemType Directory -Path $path -Force | Out-Null

    $previousProgress = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        $backup = Backup-GPO -Guid $gpo.Id -Path $path -ErrorAction Stop
    }
    finally {
        $ProgressPreference = $previousProgress
    }

    Write-Console ("GPO        : {0}" -f $backup.DisplayName) Green
    Write-Console ("GPO GUID   : {0}" -f $backup.Id) Cyan
    Write-Console ("Backup GUID: {0}" -f $backup.BackupId) Cyan
    Write-Console ("Directory  : {0}" -f $backup.BackupDirectory)
}

function Set-GpoRegistryValueInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO to edit'
    if (-not $gpo) { return }

    $key = Read-Host 'Registry key (example HKLM\Software\Policies\...)'
    $valueName = Read-Host 'Value name'
    $type = Read-Host 'Type [String/ExpandString/Binary/DWord/MultiString/QWord]'
    if ([string]::IsNullOrWhiteSpace($type)) { $type = 'DWord' }
    $rawValue = Read-Host 'Value'

    $value = $rawValue
    if ($type -in @('DWord','QWord')) {
        $number = 0L
        if (-not [Int64]::TryParse($rawValue, [ref]$number)) {
            Write-Console 'Numeric value required for DWord/QWord.' Red
            return
        }
        $value = $number
    }

    if (Confirm-Action `
        -Action ("Set registry policy '{0}' in GPO '{1}' [{2}]" -f $valueName, $gpo.DisplayName, $gpo.Id) `
        -Reason 'Edit a registry-based Group Policy setting.' `
        -Impact MEDIUM) {

        New-ChangeSet
        Set-GPRegistryValue -Guid $gpo.Id -Key $key -ValueName $valueName -Type $type -Value $value | Out-Null
    }
}

function Link-GpoInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO to link'
    if (-not $gpo) { return }

    $target = Select-GpoTargetInteractive
    if (-not $target) { return }

    if (Confirm-Action `
        -Action ("Link GPO '{0}' [{1}] to '{2}'" -f $gpo.DisplayName, $gpo.Id, $target) `
        -Reason 'Change Group Policy scope.' `
        -Impact MEDIUM) {

        New-ChangeSet

        try {
            New-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes -ErrorAction Stop | Out-Null
        }
        catch {
            Set-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes | Out-Null
        }
    }
}

function Unlink-GpoInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO link to remove'
    if (-not $gpo) { return }

    $target = Select-GpoTargetInteractive
    if (-not $target) { return }

    if (Confirm-Action `
        -Action ("Remove link for GPO '{0}' [{1}] from '{2}'" -f $gpo.DisplayName, $gpo.Id, $target) `
        -Reason 'Remove Group Policy scope from a container.' `
        -Impact MEDIUM) {

        New-ChangeSet
        Remove-GPLink -Guid $gpo.Id -Target $target -Confirm:$false
    }
}

function Set-GpoPermissionInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO for delegation/security filtering'
    if (-not $gpo) { return }

    $principal = Select-AdPrincipalIdentity
    if (-not $principal) { return }

    $permission = Select-EnumeratedValue -Title 'GPO PERMISSION LEVEL' -DefaultIndex 1 -Options @(
        [pscustomobject]@{ Value='GpoRead'; Description='Read the GPO' },
        [pscustomobject]@{ Value='GpoApply'; Description='Read and apply policy' },
        [pscustomobject]@{ Value='GpoEdit'; Description='Edit settings' },
        [pscustomobject]@{ Value='GpoEditDeleteModifySecurity'; Description='Full GPO administration' },
        [pscustomobject]@{ Value='None'; Description='Remove explicit permission' }
    )
    if (-not $permission) { return }

    if (Confirm-Action `
        -Action ("Set GPO permission for '{0}' on '{1}' [{2}]" -f $principal.Identity, $gpo.DisplayName, $gpo.Id) `
        -Reason 'Modify GPO delegation/security filtering permissions.' `
        -Impact MEDIUM) {

        New-ChangeSet
        Set-GPPermission `
            -Guid $gpo.Id `
            -TargetName $principal.Identity `
            -TargetType $principal.TargetType `
            -PermissionLevel $permission `
            -Replace
    }
}

function Remove-GpoInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO to delete'
    if (-not $gpo) { return }

    Write-Console 'A best-effort backup will be created before deletion.' Yellow
    $gpoBackupPath = Join-Path $script:RunPath 'gpo-backups'
    New-Item -ItemType Directory -Path $gpoBackupPath -Force | Out-Null

    $previousProgress = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        Backup-GPO -Guid $gpo.Id -Path $gpoBackupPath -ErrorAction SilentlyContinue | Out-Null
    }
    finally {
        $ProgressPreference = $previousProgress
    }

    if (Confirm-Action `
        -Action ("PERMANENTLY delete GPO '{0}' [{1}]" -f $gpo.DisplayName, $gpo.Id) `
        -Reason 'Delete the Group Policy Object after creating a best-effort backup.' `
        -Impact HIGH) {

        New-ChangeSet
        Remove-GPO -Guid $gpo.Id -Confirm:$false
    }
}

function Export-GpoReportInteractive {
    Assert-DomainController
    Import-GroupPolicyModule

    $gpo = Select-GpoInteractive -Prompt 'Select GPO for HTML report'
    if (-not $gpo) { return }

    $safe = ($gpo.DisplayName -replace '[^A-Za-z0-9._-]', '_')
    $path = Join-Path $script:RunPath ("gpo-{0}.html" -f $safe)

    $previousProgress = $ProgressPreference
    try {
        $ProgressPreference = 'SilentlyContinue'
        Get-GPOReport -Guid $gpo.Id -ReportType Html -Path $path
    }
    finally {
        $ProgressPreference = $previousProgress
    }

    Write-Console ("HTML report: {0}" -f $path) Green
}

# ===========================================================================
# DNS operations
# ===========================================================================

function Assert-DnsServerModule {
    if (-not (Test-Command 'Get-DnsServerZone')) {
        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            [void](Ensure-WindowsServerFeature `
                -Name 'RSAT-DNS-Server' `
                -Purpose 'DNS Server administration' `
                -Required)
        }

        try {
            Import-Module DnsServer -ErrorAction Stop
        }
        catch {
            throw ("DnsServer module unavailable after dependency repair: {0}" -f $_.Exception.Message)
        }
    }
}

function Show-DnsZones {
    Assert-DomainController
    Assert-DnsServerModule

    Get-DnsServerZone |
        Sort-Object ZoneName |
        Select-Object ZoneName, ZoneType, IsDsIntegrated, IsReverseLookupZone, DynamicUpdate |
        Format-Table -AutoSize
}

function Show-DnsRecords {
    Assert-DomainController
    Assert-DnsServerModule

    $zone = Select-DnsZoneName
    if (-not $zone) { return }
    $name = Read-Host 'Record/node name (blank = all records)'

    if ($name) {
        Get-DnsServerResourceRecord -ZoneName $zone -Name $name |
            Format-Table HostName, RecordType, TimeToLive, Timestamp, RecordData -AutoSize
    }
    else {
        Get-DnsServerResourceRecord -ZoneName $zone |
            Format-Table HostName, RecordType, TimeToLive, Timestamp, RecordData -AutoSize
    }
}

function Add-DnsARecordInteractive {
    Assert-DomainController
    Assert-DnsServerModule

    $zone = Select-DnsZoneName
    if (-not $zone) { return }
    $name = Read-Host 'Host name'
    $ip = Read-Host 'IPv4 address'

    if (Confirm-Action `
        -Action ("Create A record {0}.{1} -> {2}" -f $name, $zone, $ip) `
        -Reason 'Add a DNS host record.' `
        -Impact LOW) {

        New-ChangeSet
        Add-DnsServerResourceRecordA -ZoneName $zone -Name $name -IPv4Address $ip
    }
}

function Remove-DnsRecordInteractive {
    Assert-DomainController
    Assert-DnsServerModule

    $zone = Select-DnsZoneName
    if (-not $zone) { return }

    $record = Select-DnsRecordInteractive -ZoneName $zone
    if (-not $record) { return }

    $record | Format-List HostName,RecordType,TimeToLive,Timestamp,RecordData

    if (Confirm-Action `
        -Action ("Delete DNS record {0} [{1}] from {2}" -f $record.HostName, $record.RecordType, $zone) `
        -Reason 'Delete the selected DNS resource record.' `
        -Impact HIGH) {

        New-ChangeSet
        $record | Remove-DnsServerResourceRecord -ZoneName $zone -Force
    }
}

function Get-PrimaryIpv4Configuration {
    try {
        return Get-NetIPConfiguration |
            Where-Object {
                $_.IPv4Address -and
                $_.IPv4DefaultGateway -and
                $_.NetAdapter.Status -eq 'Up'
            } |
            Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Test-StaticIpv4 {
    $config = Get-PrimaryIpv4Configuration
    if ($null -eq $config) { return $false }

    try {
        $iface = Get-NetIPInterface -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
        return ($iface.Dhcp -eq 'Disabled')
    }
    catch {
        return $false
    }
}


function Save-PreProvisionState {
    $features = @()
    if (Test-Command 'Get-WindowsFeature') {
        $features = @(Get-WindowsFeature |
            Where-Object Installed |
            Select-Object Name, DisplayName, InstallState)
    }

    $network = @()
    try {
        $network = @(Get-NetIPConfiguration |
            Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv4DefaultGateway, DnsServer)
    }
    catch {}

    [pscustomobject]@{
        CapturedAt   = Get-Date
        ComputerName = $env:COMPUTERNAME
        PartOfDomain = [bool]$script:ServerInfo.PartOfDomain
        Domain       = $script:ServerInfo.Domain
        Features     = $features
        Network      = $network
    } | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $script:PreProvisionStateFile -Encoding UTF8

    Write-Log ("Saved pre-provisioning state: {0}" -f $script:PreProvisionStateFile) OK
}

function Invoke-NewForestProvisioning {
    if ($script:IsDomainController) {
        Write-Console 'This server is already a Domain Controller. Provisioning is blocked.' Red
        return
    }

    if ($script:ServerInfo.PartOfDomain) {
        Write-Console 'This server is already joined to a domain. New-forest provisioning is blocked.' Red
        return
    }

    Write-MenuHeader 'NEW ACTIVE DIRECTORY FOREST' 'Guided first-DC provisioning with prechecks and explicit high-impact authorization'

    $primary = Get-PrimaryIpv4Configuration
    if ($primary) {
        Write-Console ("  Interface      {0}" -f $primary.InterfaceAlias)
        Write-Console ("  IPv4           {0}" -f (@($primary.IPv4Address.IPAddress) -join ', '))
        Write-Console ("  Gateway        {0}" -f (@($primary.IPv4DefaultGateway.NextHop) -join ', '))
        Write-Console ("  DNS            {0}" -f (@($primary.DnsServer.ServerAddresses) -join ', '))
    }

    $static = Test-StaticIpv4
    Write-Console ("  Static IPv4    {0}" -f $static) $(if ($static) { 'Green' } else { 'Yellow' })

    if (-not $static) {
        Write-Console ''
        Write-Console 'A production Domain Controller should use a persistent/static address.' Yellow
        Write-Console 'This assistant deliberately does not rewrite live network configuration.' Yellow
        Write-Console 'Configure networking first, then rerun provisioning.' Yellow
        return
    }

    $domainName = (Read-Host 'New forest DNS domain (example corp.example.com)').Trim()
    if ([string]::IsNullOrWhiteSpace($domainName) -or $domainName -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') {
        Write-Console 'Invalid DNS domain name.' Red
        return
    }

    $defaultNetbios = ($domainName.Split('.')[0]).ToUpperInvariant()
    if ($defaultNetbios.Length -gt 15) { $defaultNetbios = $defaultNetbios.Substring(0,15) }

    $netbios = Read-Host ("NetBIOS domain [{0}]" -f $defaultNetbios)
    if ([string]::IsNullOrWhiteSpace($netbios)) { $netbios = $defaultNetbios }

    $dsrm = Read-Host 'Directory Services Restore Mode password' -AsSecureString

    Write-Console ''
    Write-Console 'Provisioning plan:' Cyan
    Write-Console ("  Forest/domain : {0}" -f $domainName)
    Write-Console ("  NetBIOS       : {0}" -f $netbios)
    Write-Console ("  DC hostname   : {0}" -f $env:COMPUTERNAME)
    Write-Console '  DNS           : Install integrated DNS server'
    Write-Console '  Reboot        : Deferred; operator decides after completion'

    if (-not (Confirm-Action `
        -Action ("Create NEW Active Directory forest '{0}'" -f $domainName) `
        -Reason 'Promote this server as the first Domain Controller of a new forest.' `
        -Impact HIGH)) {
        return
    }

    New-ChangeSet

    Save-PreProvisionState
    Repair-WindowsDependencies -Profile Provisioning

    Import-Module ADDSDeployment -ErrorAction Stop

    Write-Console 'Running AD DS prerequisite checks...' Cyan

    Test-ADDSForestInstallation `
        -DomainName $domainName `
        -DomainNetbiosName $netbios `
        -InstallDns `
        -SafeModeAdministratorPassword $dsrm `
        -ErrorAction Stop | Out-Host

    Write-Console 'Prerequisite checks completed.' Green
    Write-Console ''
    Write-Console 'The server will reboot automatically when AD DS promotion completes.' Yellow
    Write-Console 'The control-plane process will therefore terminate during promotion.' Yellow

    if (-not (Confirm-Action `
        -Action ("Start final forest promotion for '{0}' and allow automatic reboot" -f $domainName) `
        -Reason 'Complete AD DS forest creation using the supported reboot behavior.' `
        -Impact HIGH)) {
        return
    }

    Install-ADDSForest `
        -DomainName $domainName `
        -DomainNetbiosName $netbios `
        -InstallDns `
        -SafeModeAdministratorPassword $dsrm `
        -Force `
        -ErrorAction Stop
}


# ===========================================================================
# Domain migration center
# ===========================================================================

function Get-MigrationRoot {
    $path = Join-Path $ExportPath 'migration'
    if (-not (Test-Path -LiteralPath $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
    }
    return $path
}

function Get-MigrationPlanPath {
    return (Join-Path (Get-MigrationRoot) 'migration-plan.json')
}

function Show-MigrationPlan {
    $path = Get-MigrationPlanPath
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Console 'No migration plan has been saved yet.' Yellow
        return
    }

    $plan = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    Write-Section 'Domain migration plan'
    Write-Console ('  Type          : {0}' -f $plan.Type)
    Write-Console ('  Source domain : {0}' -f $plan.SourceDomain)
    Write-Console ('  Target domain : {0}' -f $plan.TargetDomain)
    Write-Console ('  Target NetBIOS: {0}' -f $plan.TargetNetBIOS)
    Write-Console ('  Notes         : {0}' -f $plan.Notes)
    Write-Console ('  Updated       : {0}' -f $plan.UpdatedAt)

    switch ($plan.Type) {
        'BrandingOnly' {
            Write-Console '  AD membership normally remains unchanged for web/mail/public-brand changes.' Gray
        }
        'DcReplacement' {
            Write-Console '  Member computers stay in the same AD domain; migrate DC/DNS/FSMO services instead.' Gray
        }
        'DomainMigration' {
            Write-Console '  Member computers need migration/rejoin to establish a secure channel with the target domain.' Yellow
        }
        'NewForest' {
            Write-Console '  Treat the destination as a separate forest and migrate in controlled batches.' Yellow
        }
        'DomainRenameAssessment' {
            Write-Console '  Domain rename is an advanced change and is not performed automatically by this assistant.' Red
        }
    }
}

function Invoke-MigrationAssessment {
    Write-MenuHeader 'MIGRATION ASSESSMENT' 'Classify the business request before changing Active Directory identity'

    $source = if ($script:DomainInfo) { [string]$script:DomainInfo.DNSRoot } else { [string]$script:ServerInfo.Domain }
    Write-Console ('  Current domain : {0}' -f $source)
    Write-Console ''
    Write-MenuItem '1' 'Branding / mail / web only' 'Keep AD domain identity; change public names/services'
    Write-MenuItem '2' 'Replace Domain Controller' 'Keep domain; add/replace DC infrastructure'
    Write-MenuItem '3' 'Migrate to new AD domain' 'Coexistence/trust + identity/client migration' Warn
    Write-MenuItem '4' 'New forest migration' 'Build a separate forest and migrate in phases' Warn
    Write-MenuItem '5' 'AD domain rename assessment' 'Advanced assessment only; no automatic rendom execution' Danger
    Write-MenuNavigation
    Write-Rule

    $choice = Read-MenuChoice -Default '1'
    if ($choice -eq 'H') { $script:MainMenuRequested = $true; return }
    if ($choice -eq '0') { return }

    $type = ''
    $target = ''
    $netbios = ''
    $notes = ''

    switch ($choice) {
        '1' {
            $type = 'BrandingOnly'
            $notes = Read-Host 'Public/company naming note'
        }
        '2' {
            $type = 'DcReplacement'
            $target = $source
            if ($script:DomainInfo) { $netbios = [string]$script:DomainInfo.NetBIOSName }
            $notes = 'Domain identity remains unchanged'
        }
        '3' {
            $type = 'DomainMigration'
            $target = (Read-Host 'Target AD DNS domain').Trim()
            $netbios = (Read-Host 'Target NetBIOS domain').Trim().ToUpperInvariant()
            $notes = 'Coexistence and client rejoin required'
        }
        '4' {
            $type = 'NewForest'
            $target = (Read-Host 'Target forest root DNS domain').Trim()
            $netbios = (Read-Host 'Target NetBIOS domain').Trim().ToUpperInvariant()
            $notes = 'Separate forest migration'
        }
        '5' {
            $type = 'DomainRenameAssessment'
            $target = (Read-Host 'Requested target AD DNS domain').Trim()
            $netbios = (Read-Host 'Requested target NetBIOS domain').Trim().ToUpperInvariant()
            $notes = 'Advanced domain rename assessment only'
        }
        default {
            Write-Console 'Invalid assessment option.' Yellow
            return
        }
    }

    if ($target -and $target -notmatch '^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$') {
        Write-Console 'Invalid target DNS domain syntax.' Red
        return
    }

    $plan = [pscustomobject]@{
        Type          = $type
        SourceDomain  = $source
        TargetDomain  = $target
        TargetNetBIOS = $netbios
        Notes         = $notes
        UpdatedAt     = Get-Date
    }
    $plan | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Get-MigrationPlanPath) -Encoding UTF8
    Write-Console ('Migration plan saved: {0}' -f (Get-MigrationPlanPath)) Green
    Show-MigrationPlan
}

function Export-DomainMigrationInventory {
    Assert-DomainController

    $root = Join-Path (Get-MigrationRoot) ('inventory-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $root -Force | Out-Null

    Get-ADDomain | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $root 'domain.json') -Encoding UTF8
    Get-ADForest | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $root 'forest.json') -Encoding UTF8

    Get-ADUser -Filter * -Properties Enabled,UserPrincipalName,Mail,LastLogonDate |
        Select-Object SamAccountName,UserPrincipalName,Mail,Enabled,LastLogonDate,DistinguishedName |
        Export-Csv -LiteralPath (Join-Path $root 'users.csv') -NoTypeInformation -Encoding UTF8

    Get-ADGroup -Filter * |
        Select-Object Name,SamAccountName,GroupScope,GroupCategory,DistinguishedName |
        Export-Csv -LiteralPath (Join-Path $root 'groups.csv') -NoTypeInformation -Encoding UTF8

    Get-ADComputer -Filter * -Properties Enabled,OperatingSystem,LastLogonDate,DNSHostName |
        Select-Object Name,DNSHostName,Enabled,OperatingSystem,LastLogonDate,DistinguishedName |
        Export-Csv -LiteralPath (Join-Path $root 'computers.csv') -NoTypeInformation -Encoding UTF8

    Get-ADOrganizationalUnit -Filter * -Properties ProtectedFromAccidentalDeletion |
        Select-Object Name,ProtectedFromAccidentalDeletion,DistinguishedName |
        Export-Csv -LiteralPath (Join-Path $root 'ous.csv') -NoTypeInformation -Encoding UTF8

    if (Test-Command 'Get-ADTrust') {
        Get-ADTrust -Filter * |
            Select-Object Name,Direction,TrustType,ForestTransitive,SelectiveAuthentication |
            Export-Csv -LiteralPath (Join-Path $root 'trusts.csv') -NoTypeInformation -Encoding UTF8
    }

    if (Test-Command 'Get-GPO') {
        Get-GPO -All |
            Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime |
            Export-Csv -LiteralPath (Join-Path $root 'gpos.csv') -NoTypeInformation -Encoding UTF8
    }

    if (Test-Command 'Get-DnsServerZone') {
        Get-DnsServerZone |
            Select-Object ZoneName,ZoneType,IsDsIntegrated,IsReverseLookupZone,DynamicUpdate |
            Export-Csv -LiteralPath (Join-Path $root 'dns-zones.csv') -NoTypeInformation -Encoding UTF8
    }

    [pscustomobject]@{
        Generated = Get-Date
        Domain = $script:DomainInfo.DNSRoot
        Forest = $script:ForestInfo.Name
        Users = @(Get-ADUser -Filter *).Count
        Groups = @(Get-ADGroup -Filter *).Count
        Computers = @(Get-ADComputer -Filter *).Count
        OUs = @(Get-ADOrganizationalUnit -Filter *).Count
        Output = $root
    } | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath (Join-Path $root 'summary.json') -Encoding UTF8

    Write-Console ('Migration inventory: {0}' -f $root) Green
}

function Show-ComputerMigrationReadiness {
    Assert-DomainController

    $computers = @(Get-ADComputer -Filter * -Properties DNSHostName,Enabled,LastLogonDate |
        Sort-Object Name)

    Write-Section 'Computer migration readiness'
    Write-Console ('  {0,-24} {1,-34} {2,-10} {3}' -f 'COMPUTER','DNS HOST','PING','LAST LOGON') Cyan

    foreach ($computer in $computers) {
        $target = if ($computer.DNSHostName) { $computer.DNSHostName } else { $computer.Name }
        $alive = $false
        try {
            $alive = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue
        }
        catch {}

        Write-Console ('  {0,-24} {1,-34} {2,-10} {3}' -f
            $computer.Name,
            $target,
            $(if ($alive) { 'ONLINE' } else { 'NO REPLY' }),
            $computer.LastLogonDate)
    }

    Write-Console ''
    Write-Console 'Ping is a readiness hint only. Firewall policy can block ICMP on otherwise healthy clients.' Gray
}

function Show-DomainTrusts {
    Assert-DomainController

    if (-not (Test-Command 'Get-ADTrust')) {
        Write-Console 'Get-ADTrust is unavailable.' Yellow
        return
    }

    Get-ADTrust -Filter * |
        Sort-Object Name |
        Select-Object Name,Direction,TrustType,ForestTransitive,SelectiveAuthentication,Source,Target |
        Format-Table -AutoSize
}

function Test-DomainTrustInteractive {
    Assert-DomainController

    $name = Select-AdTrustName
    if (-not $name) { return }

    try {
        $trust = Get-ADTrust -Identity $name -ErrorAction Stop
        $trust | Format-List Name,Direction,TrustType,ForestTransitive,SelectiveAuthentication,Source,Target
        Write-Console 'The trust object is readable. Validate authentication/resource access from both sides before migration.' Green
    }
    catch {
        Write-Console ("Trust lookup failed: {0}" -f $_.Exception.Message) Red
    }
}

function New-WindowsMigrationPackage {
    Assert-DomainController

    $planPath = Get-MigrationPlanPath
    if (-not (Test-Path -LiteralPath $planPath)) {
        Write-Console 'Run Migration assessment first.' Yellow
        return
    }

    $plan = Get-Content -LiteralPath $planPath -Raw | ConvertFrom-Json
    if (-not $plan.TargetDomain) {
        Write-Console 'The saved migration plan does not define a target AD domain.' Yellow
        return
    }

    $dir = Join-Path (Get-MigrationRoot) ('windows-package-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $scriptPath = Join-Path $dir 'Move-ToNewDomain.ps1'
    @"
[CmdletBinding()]
param(
    [string]`$TargetDomain = '$($plan.TargetDomain)',
    [string]`$TargetOU = '',
    [string]`$TargetDC = ''
)

`$ErrorActionPreference = 'Stop'
`$computer = Get-CimInstance Win32_ComputerSystem

Write-Host "Computer       : `$env:COMPUTERNAME"
Write-Host "Current domain : `$(`$computer.Domain)"
Write-Host "Target domain  : `$TargetDomain"

`$oldCredential = Get-Credential -Message 'Credential allowed to unjoin the current domain'
`$newCredential = Get-Credential -Message 'Credential delegated to join computers to the target domain'

`$params = @{
    DomainName = `$TargetDomain
    UnjoinDomainCredential = `$oldCredential
    Credential = `$newCredential
    Restart = `$true
    Force = `$true
    PassThru = `$true
}
if (`$TargetOU) { `$params.OUPath = `$TargetOU }
if (`$TargetDC) { `$params.Server = `$TargetDC }

Add-Computer @params
"@ | Set-Content -LiteralPath $scriptPath -Encoding UTF8

    $netdomPath = Join-Path $dir 'netdom-move-template.cmd'
    @"
@echo off
REM No passwords are stored. Replace TARGET-OUDN if required.
netdom move %COMPUTERNAME% /domain:$($plan.TargetDomain) /userd:* /passwordd:* /usero:* /passwordo:* /reboot:30
"@ | Set-Content -LiteralPath $netdomPath -Encoding ASCII

    @"
WINDOWS DOMAIN MIGRATION PACKAGE
================================
Source domain : $($plan.SourceDomain)
Target domain : $($plan.TargetDomain)

Move-ToNewDomain.ps1 uses Add-Computer and prompts for credentials at runtime.
No password is written into the generated files.

Run only after target-domain DNS/SRV discovery works and after testing on a
pilot OU/batch.
"@ | Set-Content -LiteralPath (Join-Path $dir 'README.txt') -Encoding UTF8

    Write-Console ("Windows migration package: {0}" -f $dir) Green
}

function Export-GpoMigrationSet {
    Assert-DomainController
    Import-GroupPolicyModule

    $dir = Join-Path (Get-MigrationRoot) ('gpo-backup-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    Backup-GPO -All -Path $dir | Out-Null
    Get-GPO -All |
        Select-Object DisplayName,Id,GpoStatus,CreationTime,ModificationTime |
        Export-Csv -LiteralPath (Join-Path $dir 'gpo-inventory.csv') -NoTypeInformation -Encoding UTF8

    Write-Console ("GPO migration backup set: {0}" -f $dir) Green
}

function Show-DomainRenameAssessment {
    Write-Section 'AD domain rename assessment'

    Write-Console 'A domain DNS-name change is not equivalent to changing a DNS alias.' Yellow
    Write-Console 'Clients, Kerberos/SPNs, applications, certificates, trusts and management systems require validation.'
    Write-Console ''

    if (Test-Command 'rendom.exe') {
        Write-Console 'rendom.exe: AVAILABLE on this server' Green
    }
    else {
        Write-Console 'rendom.exe: not detected' Yellow
    }

    Write-Console ''
    Write-Console 'This control plane deliberately does not execute rendom automatically.' Gray
    Write-Console 'For most business migrations, a parallel target domain/forest plus staged client migration is easier to test and roll back.' Gray
}

function Show-DomainMigrationMenu {
    Assert-DomainController

    while ($true) {
        if ($script:MainMenuRequested) { return }

        Write-MenuHeader 'DOMAIN MIGRATION CENTER' 'Assessment, inventory, coexistence evidence and credential-free client migration tooling'
        Write-MenuItem '1' 'Migration assessment' 'Classify branding, DC replacement, new domain/forest or rename'
        Write-MenuItem '2' 'Show migration plan' 'Display saved source/target intent'
        Write-MenuItem '3' 'Export source inventory' 'Users, groups, computers, OUs, GPOs, DNS and trusts'
        Write-MenuItem '4' 'Computer readiness' 'Current-domain computer DNS/ping readiness'
        Write-MenuItem '5' 'List trusts' 'Inventory configured domain/forest trusts'
        Write-MenuItem '6' 'Inspect trust' 'Read one trust and its direction/type'
        Write-MenuItem '7' 'Windows migration package' 'Generate Add-Computer/netdom templates without stored secrets' Good
        Write-MenuItem '8' 'GPO migration backup' 'Back up all GPOs plus inventory' Good
        Write-MenuItem '9' 'Domain rename assessment' 'Inspect advanced rename capability without executing it' Warn
        Write-MenuItem '10' 'System-state backup' 'Create recovery-grade DC backup before migration work'
        Write-MenuItem '11' 'OS and file migrations' 'Open standalone migration-assistant.ps1 (download alongside this script)'
        Write-MenuNavigation
        Write-Rule

        try {
        switch (Read-MenuChoice -Prompt 'Select migration module' -Default '1') {
            '1' { Invoke-MigrationAssessment; Pause-ControlPlane }
            '2' { Show-MigrationPlan; Pause-ControlPlane }
            '3' { Export-DomainMigrationInventory; Pause-ControlPlane }
            '4' { Show-ComputerMigrationReadiness; Pause-ControlPlane }
            '5' { Show-DomainTrusts; Pause-ControlPlane }
            '6' { Test-DomainTrustInteractive; Pause-ControlPlane }
            '7' { New-WindowsMigrationPackage; Pause-ControlPlane }
            '8' { Export-GpoMigrationSet; Pause-ControlPlane }
            '9' { Show-DomainRenameAssessment; Pause-ControlPlane }
            '10' { Invoke-SystemStateBackup; Pause-ControlPlane }
            '11' {
                $companion = Join-Path $PSScriptRoot 'migration-assistant.ps1'
                if (Test-Path -LiteralPath $companion) { & $companion -Mode Interactive }
                else { Write-Console 'Download migration-assistant.ps1 from the same sysadmin revision, or run it standalone.' Yellow }
                Pause-ControlPlane
            }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ('Show-DomainMigrationMenu: operation failed: {0}' -f $message) Red
            Write-Log ('Recoverable menu error in Show-DomainMigrationMenu: {0}' -f $message) ERROR
            Pause-ControlPlane
        }
    }
}



# ===========================================================================
# Supported AD DS decommission / reset
# ===========================================================================

function Get-DomainResetContext {
    $cs = Get-CimInstance Win32_ComputerSystem
    $domainName = if ($script:DomainInfo) { $script:DomainInfo.DNSRoot } else { [string]$cs.Domain }
    $forestName = if ($script:ForestInfo) { $script:ForestInfo.Name } else { '' }

    $dcs = @()
    $roles = @()
    $forestDomains = @()

    if ($script:IsDomainController -and (Import-ADModules)) {
        try { $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop) } catch {}
        try {
            $localDc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction Stop
            $roles = @($localDc.OperationMasterRoles)
        }
        catch {}
        try { $forestDomains = @(Get-ADForest -ErrorAction Stop).Domains } catch {}
    }

    [pscustomobject]@{
        ComputerName       = $env:COMPUTERNAME
        IsDomainController = [bool]$script:IsDomainController
        PartOfDomain       = [bool]$cs.PartOfDomain
        DomainName         = $domainName
        ForestName         = $forestName
        DomainDcCount      = $dcs.Count
        OtherDCs           = @($dcs | Where-Object HostName -ne $env:COMPUTERNAME)
        IsLastDcInDomain   = [bool]($script:IsDomainController -and $dcs.Count -eq 1)
        IsLastDomainForest = [bool]($forestDomains.Count -eq 1)
        OperationMasterRoles = $roles
        AdDsInstalled      = Test-ServerFeatureInstalled -Name 'AD-Domain-Services'
        DnsInstalled       = Test-ServerFeatureInstalled -Name 'DNS'
        GpmcInstalled      = Test-ServerFeatureInstalled -Name 'GPMC'
        BackupInstalled    = Test-ServerFeatureInstalled -Name 'Windows-Server-Backup'
        RecoveryRoot       = $script:ResetRecoveryRoot
    }
}

function Show-DomainResetAssessment {
    Write-Section 'Domain decommission / reset assessment'
    $ctx = Get-DomainResetContext

    $ctx |
        Select-Object ComputerName, IsDomainController, PartOfDomain, DomainName, ForestName,
            DomainDcCount, IsLastDcInDomain, IsLastDomainForest, AdDsInstalled, DnsInstalled,
            GpmcInstalled, BackupInstalled |
        Format-List

    Write-Console 'Operation master roles on this DC:' Cyan
    if ($ctx.OperationMasterRoles.Count -gt 0) {
        $ctx.OperationMasterRoles | ForEach-Object { Write-Console ("  - {0}" -f $_) Yellow }
    }
    else {
        Write-Console '  none detected'
    }

    Write-Console ''
    if ($ctx.IsDomainController) {
        if ($ctx.IsLastDcInDomain) {
            Write-Console 'This is the LAST DC in the domain.' Red
            if ($ctx.IsLastDomainForest) {
                Write-Console 'Removing it removes the final domain and therefore the forest.' Red
            }
        }
        else {
            Write-Console ("{0} other DC(s) exist. Supported graceful demotion is required." -f $ctx.OtherDCs.Count) Green
        }
    }
    else {
        Write-Console 'This host is not currently a Domain Controller.' Yellow
        if ($ctx.PartOfDomain) {
            Write-Console 'It is still joined to a domain and can be moved to WORKGROUP during final cleanup.' Yellow
        }
    }

    Write-Console ''
    Write-Console 'Reset model:' Cyan
    Write-Console '  Phase 1  recovery bundle + optional system-state backup'
    Write-Console '  Phase 2  supported Uninstall-ADDSDomainController demotion + reboot'
    Write-Console '  Phase 3  post-reboot AD DS role cleanup / optional DNS-workgroup cleanup'
    Write-Console ''
    Write-Console 'The assistant never deletes NTDS.dit/SYSVOL manually and never uses DISM to remove AD DS from a live DC.' Green
}

function New-DomainResetRecoveryBundle {
    param([Parameter(Mandatory=$true)]$Context)

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $root = Join-Path $script:ResetRecoveryRoot ("domain-reset-{0}" -f $stamp)
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'evidence') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $root 'gpo') -Force | Out-Null

    New-ChangeSet
    Copy-Item -LiteralPath $script:BackupPath `
        -Destination (Join-Path $root 'control-plane-backup') `
        -Recurse -Force

    # Preserve the complete assistant state outside ExportPath so the final
    # cleanup can remove ProgramData\WindowsADControlPlane without losing
    # historical evidence.
    if (Test-Path -LiteralPath $ExportPath) {
        Copy-Item -LiteralPath $ExportPath `
            -Destination (Join-Path $root 'control-plane-state') `
            -Recurse -Force -ErrorAction SilentlyContinue
    }

    $Context | ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath (Join-Path $root 'reset-context.json') -Encoding UTF8

    if (Test-Path $script:PreProvisionStateFile) {
        Copy-Item -LiteralPath $script:PreProvisionStateFile `
            -Destination (Join-Path $root 'pre-provisioning-state.json') -Force
    }

    if (Test-Command 'Get-WindowsFeature') {
        Get-WindowsFeature |
            Select-Object Name, DisplayName, Installed, InstallState |
            Export-Csv -LiteralPath (Join-Path $root 'evidence\windows-features.csv') `
                -NoTypeInformation -Encoding UTF8
    }

    try {
        Get-NetIPConfiguration |
            ConvertTo-Json -Depth 10 |
            Set-Content -LiteralPath (Join-Path $root 'evidence\network.json') -Encoding UTF8
    }
    catch {}

    if ($script:IsDomainController) {
        if (Test-Command 'dcdiag.exe') {
            & dcdiag.exe /v *> (Join-Path $root 'evidence\dcdiag.txt')
        }
        if (Test-Command 'repadmin.exe') {
            & repadmin.exe /replsummary *> (Join-Path $root 'evidence\repadmin-replsummary.txt')
            & repadmin.exe /showrepl *> (Join-Path $root 'evidence\repadmin-showrepl.txt')
        }

        try {
            Import-GroupPolicyModule
            $previousProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            Backup-GPO -All -Path (Join-Path $root 'gpo') -ErrorAction Stop | Out-Null
            $ProgressPreference = $previousProgress
        }
        catch {
            Add-Warning ("GPO pre-reset backup failed: {0}" -f $_.Exception.Message)
        }
    }

    $state = [pscustomobject]@{
        Stage        = 'Prepared'
        CreatedAt    = Get-Date
        RecoveryPath = $root
        Domain       = $Context.DomainName
        ComputerName = $Context.ComputerName
        LastDC       = $Context.IsLastDcInDomain
        LastForestDomain = $Context.IsLastDomainForest
    }
    $state | ConvertTo-Json -Depth 6 |
        Set-Content -LiteralPath (Join-Path $root 'reset-state.json') -Encoding UTF8

    return $root
}

function Get-LatestPendingDomainReset {
    if (-not (Test-Path $script:ResetRecoveryRoot)) { return $null }

    $files = @(Get-ChildItem -Path $script:ResetRecoveryRoot `
        -Filter reset-state.json -Recurse -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending)

    foreach ($file in $files) {
        try {
            $state = Get-Content -LiteralPath $file.FullName -Raw | ConvertFrom-Json
            if ($state.Stage -notin @('Complete','Cancelled')) {
                $state | Add-Member -NotePropertyName StateFile -NotePropertyValue $file.FullName -Force
                return $state
            }
        }
        catch {}
    }

    return $null
}

function Set-DomainResetStage {
    param(
        [Parameter(Mandatory=$true)]$State,
        [Parameter(Mandatory=$true)][string]$Stage
    )

    $State.Stage = $Stage
    $State | ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath $State.StateFile -Encoding UTF8
}

function Select-DemotionTargetDC {
    $dcs = @(Get-ADDomainController -Filter * -ErrorAction Stop |
        Where-Object HostName -ne $env:COMPUTERNAME |
        Sort-Object HostName)

    if ($dcs.Count -eq 0) { return $null }

    Write-Console ''
    Write-Console 'Healthy target DC for FSMO transfer:' Cyan
    for ($i = 0; $i -lt $dcs.Count; $i++) {
        Write-Console ('  [{0,2}] {1,-40} {2}' -f ($i + 1), $dcs[$i].HostName, $dcs[$i].IPv4Address)
    }
    Write-Console '  [ 0] Cancel'

    $choice = Read-MenuChoice -Prompt 'Select target DC' -Default '0'
    $n = 0
    if (-not [int]::TryParse($choice, [ref]$n)) { return $null }
    if ($n -lt 1 -or $n -gt $dcs.Count) { return $null }
    return $dcs[$n - 1]
}

function Move-FsmoRolesBeforeDemotion {
    param([Parameter(Mandatory=$true)]$Context)

    if ($Context.OperationMasterRoles.Count -eq 0 -or $Context.IsLastDcInDomain) {
        return $true
    }

    Write-Console ''
    Write-Console 'This DC owns FSMO role(s); transfer them before demotion:' Yellow
    $Context.OperationMasterRoles | ForEach-Object { Write-Console ("  - {0}" -f $_) Yellow }

    $target = Select-DemotionTargetDC
    if (-not $target) {
        Write-Console 'FSMO transfer cancelled.' Yellow
        return $false
    }

    if (-not (Confirm-Action `
        -Action ("Transfer FSMO roles to {0}" -f $target.HostName) `
        -Reason 'A planned DC decommission should transfer operations-master roles before demotion.' `
        -Impact HIGH)) {
        return $false
    }

    try {
        Move-ADDirectoryServerOperationMasterRole `
            -Identity $target.HostName `
            -OperationMasterRole $Context.OperationMasterRoles `
            -Confirm:$false `
            -ErrorAction Stop | Out-Host

        $remaining = @(Get-ADDomainController -Identity $env:COMPUTERNAME `
            -ErrorAction Stop).OperationMasterRoles

        if ($remaining.Count -gt 0) {
            Write-Console 'One or more FSMO roles are still reported on this DC.' Red
            return $false
        }

        Write-Log ("Transferred FSMO roles to {0}" -f $target.HostName) CHANGE
        return $true
    }
    catch {
        Write-Console ("FSMO transfer failed: {0}" -f $_.Exception.Message) Red
        return $false
    }
}

function Start-SupportedDomainReset {
    Assert-DomainController
    Import-Module ADDSDeployment -ErrorAction Stop

    $ctx = Get-DomainResetContext
    Show-DomainResetAssessment

    Write-Console ''
    Write-Console 'This operation uses the Microsoft-supported AD DS demotion workflow.' Yellow
    Write-Console 'A reboot is expected and the current PowerShell session will terminate.' Yellow

    if (-not (Confirm-ExactText `
        -Prompt 'Confirm the AD DNS domain being modified.' `
        -Expected $ctx.DomainName)) {
        Write-Console 'Domain confirmation mismatch. Reset cancelled.' Yellow
        return
    }

    $finalText = if ($ctx.IsLastDcInDomain) {
        "ERASE DOMAIN {0}" -f $ctx.DomainName
    }
    else {
        "DEMOTE DC {0}" -f $env:COMPUTERNAME
    }

    if (-not (Confirm-ExactText `
        -Prompt 'Final authorization for the irreversible demotion phase.' `
        -Expected $finalText)) {
        Write-Console 'Reset cancelled.' Yellow
        return
    }

    $recovery = New-DomainResetRecoveryBundle -Context $ctx
    Write-Console ("Recovery bundle: {0}" -f $recovery) Green

    if (Read-BooleanChoice `
        -Prompt 'Create a Windows Server system-state backup before demotion?' `
        -Default $true) {

        if (-not (Invoke-SystemStateBackup)) {
            if (-not (Confirm-ExactText `
                -Prompt 'System-state backup was not completed.' `
                -Expected 'CONTINUE WITHOUT SYSTEM STATE')) {
                Write-Console 'Reset cancelled before demotion.' Yellow
                return
            }
        }
    }
    else {
        if (-not (Confirm-ExactText `
            -Prompt 'Skipping recovery-grade system state is a high-risk choice.' `
            -Expected 'CONTINUE WITHOUT SYSTEM STATE')) {
            Write-Console 'Reset cancelled before demotion.' Yellow
            return
        }
    }

    if (-not (Move-FsmoRolesBeforeDemotion -Context $ctx)) {
        Write-Console 'Reset stopped before demotion because FSMO placement is unresolved.' Red
        return
    }

    $localPassword = Read-Host `
        'New local Administrator password after demotion' `
        -AsSecureString
    $credential = Get-Credential `
        -Message 'Credential authorized to demote this Domain Controller'

    $params = @{
        LocalAdministratorPassword = $localPassword
        Credential                 = $credential
        ErrorAction                = 'Stop'
    }

    if ($ctx.IsLastDcInDomain) {
        $params.LastDomainControllerInDomain = $true
        $params.RemoveApplicationPartitions = $true
    }

    Write-Console ''
    Write-Console 'Running Microsoft prerequisite checks for DC demotion...' Cyan
    try {
        Test-ADDSDomainControllerUninstallation @params | Out-Host
    }
    catch {
        Write-Console ("Demotion prerequisite check failed: {0}" -f $_.Exception.Message) Red
        return
    }

    $stateFile = Join-Path $recovery 'reset-state.json'
    $state = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
    $state | Add-Member -NotePropertyName StateFile -NotePropertyValue $stateFile -Force
    Set-DomainResetStage -State $state -Stage 'DemotionStarted'

    Write-Console ''
    Write-Console 'Starting supported AD DS demotion. The server is expected to reboot.' Red
    Uninstall-ADDSDomainController @params -Confirm:$false
}

function Reset-DnsClientAfterDomainRemoval {
    Write-Console ''
    Write-Console 'DNS client configuration after domain removal:' Cyan
    Write-Console '  [1] Reset DNS server addresses to DHCP/interface defaults'
    Write-Console '  [2] Set explicit DNS server addresses'
    Write-Console '  [3] Keep current DNS client configuration'
    Write-Console '  [0] Cancel cleanup'

    $choice = Read-MenuChoice -Default '3'
    switch ($choice) {
        '1' {
            Get-NetAdapter |
                Where-Object Status -eq 'Up' |
                ForEach-Object {
                    Set-DnsClientServerAddress `
                        -InterfaceIndex $_.InterfaceIndex `
                        -ResetServerAddresses `
                        -ErrorAction SilentlyContinue
                }
            Write-Log 'Reset DNS client addresses to interface defaults.' CHANGE
        }
        '2' {
            $raw = Read-Host 'DNS server IPs separated by comma'
            $servers = @($raw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            if ($servers.Count -eq 0) {
                Write-Console 'No DNS servers provided.' Yellow
                return
            }

            $up = @(Get-NetAdapter | Where-Object Status -eq 'Up')
            if ($up.Count -eq 0) {
                Write-Console 'No active network adapter found.' Yellow
                return
            }

            for ($i = 0; $i -lt $up.Count; $i++) {
                Write-Console ('  [{0}] {1}' -f ($i + 1), $up[$i].Name)
            }
            $n = [int](Read-Host 'Interface number')
            if ($n -lt 1 -or $n -gt $up.Count) { return }

            Set-DnsClientServerAddress `
                -InterfaceIndex $up[$n - 1].InterfaceIndex `
                -ServerAddresses $servers `
                -ErrorAction Stop
            Write-Log ("Set DNS client servers: {0}" -f ($servers -join ',')) CHANGE
        }
        '3' { return }
        default { return }
    }
}

function Complete-PostDemotionReset {
    if ($script:IsDomainController) {
        Write-Console 'This server is still a Domain Controller; post-demotion cleanup is not available.' Red
        return
    }

    $state = Get-LatestPendingDomainReset
    if (-not $state) {
        Write-Console 'No pending domain-reset recovery state was found.' Yellow
        return
    }

    Write-Section 'Post-demotion cleanup'
    Write-Console ("Recovery bundle : {0}" -f $state.RecoveryPath)
    Write-Console ("Reset stage     : {0}" -f $state.Stage)
    Write-Console ("Current domain  : {0}" -f (Get-CimInstance Win32_ComputerSystem).Domain)

    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        Write-Console ''
        Write-Console 'The demoted server is still a member of the surviving domain.' Yellow
        if (Read-BooleanChoice -Prompt 'Move this server to WORKGROUP now?' -Default $true) {
            $credential = Get-Credential -Message 'Domain credential authorized to unjoin this server'
            Set-DomainResetStage -State $state -Stage 'WorkgroupPending'
            Remove-Computer `
                -UnjoinDomainCredential $credential `
                -WorkgroupName 'WORKGROUP' `
                -Force `
                -Restart
            return
        }
    }

    if (Test-ServerFeatureInstalled -Name 'AD-Domain-Services') {
        if (-not (Confirm-Action `
            -Action 'Remove AD-Domain-Services role binaries' `
            -Reason 'The host is no longer a DC; remove the AD DS role payload.' `
            -Impact HIGH)) {
            return
        }

        $result = Uninstall-WindowsFeature `
            -Name 'AD-Domain-Services' `
            -ErrorAction Stop
        $result | Out-Host

        if ($result.RestartNeeded -eq 'Yes') {
            Add-Warning 'AD DS role removal requests another reboot.'
        }
    }

    if (Test-ServerFeatureInstalled -Name 'DNS') {
        Write-Console ''
        Write-Console 'DNS Server role is still installed.' Yellow
        Write-Console 'It may contain non-AD zones, so it is never removed automatically.' Gray

        if (Read-BooleanChoice `
            -Prompt 'Remove the DNS Server role as part of this decommission?' `
            -Default $false) {

            if (Confirm-ExactText `
                -Prompt 'This removes the Windows DNS Server role.' `
                -Expected 'REMOVE DNS ROLE') {

                Uninstall-WindowsFeature -Name 'DNS' -ErrorAction Stop | Out-Host
                Write-Log 'Removed DNS Server role by explicit operator authorization.' CHANGE
            }
        }
    }

    Reset-DnsClientAfterDomainRemoval

    if (Test-Path $script:LogFile) {
        Copy-Item -LiteralPath $script:LogFile `
            -Destination (Join-Path $state.RecoveryPath 'control-plane-reset.log') `
            -Force -ErrorAction SilentlyContinue
    }

    Set-DomainResetStage -State $state -Stage 'Complete'

    Write-Console ''
    Write-Console ("Assistant runtime state is stored under: {0}" -f $ExportPath) Gray
    Write-Console 'A copy of that state is already preserved in the external recovery bundle.' Gray
    if (Read-BooleanChoice -Prompt 'Remove WindowsADControlPlane runtime state from this host?' -Default $true) {
        if (Test-Path -LiteralPath $script:LogFile) {
            Copy-Item -LiteralPath $script:LogFile `
                -Destination (Join-Path $state.RecoveryPath 'control-plane-final.log') `
                -Force -ErrorAction SilentlyContinue
        }

        Remove-Item -LiteralPath $ExportPath -Recurse -Force -ErrorAction SilentlyContinue
        $script:LogFile = $null
        $script:ReportFile = $null
    }

    $script:ResetCompleted = $true

    Write-Console ''
    Write-Rule
    Write-Console '  DOMAIN RESET COMPLETE' Green
    Write-Console ("  Recovery bundle : {0}" -f $state.RecoveryPath)
    Write-Console ("  Domain joined   : {0}" -f (Get-CimInstance Win32_ComputerSystem).PartOfDomain)
    Write-Console ("  AD DS feature   : {0}" -f (Test-ServerFeatureInstalled -Name 'AD-Domain-Services'))
    Write-Console '  Management tools: retained unless independently removed'
    Write-Console '  Network/IP      : retained; DNS client reviewed interactively'
    Write-Console '  Next action     : reboot if Windows reports one pending'
    Write-Rule
}

function Show-DomainResetMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }

        Write-MenuHeader 'DOMAIN DECOMMISSION / RESET' 'Supported AD DS demotion, recovery evidence and post-reboot host cleanup'
        Write-MenuItem '1' 'Reset assessment' 'DC count, FSMO ownership, roles and reset scope'
        if ($script:IsDomainController) {
            Write-MenuItem '2' 'Start supported reset' 'Recovery bundle + optional system-state + graceful DC demotion' Danger
        }
        else {
            Write-MenuItem '2' 'Start supported reset' 'Unavailable: host is not currently a Domain Controller' Warn
        }
        Write-MenuItem '3' 'Finalize after reboot' 'Remove AD DS role, optional domain membership/DNS cleanup' Good
        Write-MenuItem '4' 'Dependency audit' 'Verify official Microsoft features needed by the reset workflow'
        Write-MenuNavigation
        Write-Rule

        try {
        switch (Read-MenuChoice -Default '1') {
            '1' { Show-DomainResetAssessment; Pause-ControlPlane }
            '2' {
                if ($script:IsDomainController) { Start-SupportedDomainReset }
                else { Write-Console 'This server is not a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            '3' { Complete-PostDemotionReset; if (-not $script:ResetCompleted) { Pause-ControlPlane } }
            '4' { Show-WindowsDependencyAudit; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ('Show-DomainResetMenu: operation failed: {0}' -f $message) Red
            Write-Log ('Recoverable menu error in Show-DomainResetMenu: {0}' -f $message) ERROR
            Pause-ControlPlane
        }

        if ($script:ResetCompleted) { return }
    }
}


# ===========================================================================
# Optional Suricata IDS integration / EVE analytics / native GUI
# ===========================================================================

function Initialize-IdsState {
    New-Item -ItemType Directory -Path $script:IdsStatePath -Force | Out-Null
    New-Item -ItemType Directory -Path $script:IdsReportPath -Force | Out-Null
}

function Get-ObjectPropertyValue {
    param(
        $Object,
        [Parameter(Mandatory=$true)][string]$Name
    )

    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Add-CounterValue {
    param(
        [Parameter(Mandatory=$true)][hashtable]$Table,
        $Key
    )

    if ($null -eq $Key) { return }
    $text = [string]$Key
    if ([string]::IsNullOrWhiteSpace($text)) { return }

    if ($Table.ContainsKey($text)) { $Table[$text]++ }
    else { $Table[$text] = 1 }
}

function Convert-CounterToRows {
    param(
        [Parameter(Mandatory=$true)][hashtable]$Table,
        [string]$KeyName = 'Name',
        [int]$Limit = 20
    )

    return @(
        $Table.GetEnumerator() |
            Sort-Object Value -Descending |
            Select-Object -First $Limit |
            ForEach-Object {
                $row = [ordered]@{ Count = [int]$_.Value }
                $row[$KeyName] = [string]$_.Key
                [pscustomobject]$row
            }
    )
}

function Get-WindowsSuricataService {
    try {
        return Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object {
                $_.Name -match 'suricata' -or
                $_.DisplayName -match 'suricata'
            } |
            Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Get-WindowsSuricataInfo {
    Initialize-IdsState

    $service = Get-WindowsSuricataService
    $servicePath = if ($service) { [string]$service.PathName } else { '' }

    $exe = $null
    if ($servicePath -match '^\s*"([^"]*suricata\.exe)"') {
        $exe = $Matches[1]
    }
    elseif ($servicePath -match '([A-Za-z]:\\[^\r\n"]*?suricata\.exe)') {
        $exe = $Matches[1]
    }

    $commonExe = @(
        "$env:ProgramFiles\Suricata\suricata.exe",
        "${env:ProgramFiles(x86)}\Suricata\suricata.exe",
        'C:\Suricata\suricata.exe'
    )
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
        $exe = $commonExe | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    }

    $config = $null
    if ($servicePath -match '(?:^|\s)-c\s+"([^"]+)"') {
        $config = $Matches[1]
    }
    elseif ($servicePath -match '(?:^|\s)-c\s+([^\s]+)') {
        $config = $Matches[1]
    }

    $commonConfig = @(
        "$env:ProgramFiles\Suricata\suricata.yaml",
        "$env:ProgramFiles\Suricata\etc\suricata\suricata.yaml",
        "$env:ProgramData\Suricata\suricata.yaml",
        'C:\Suricata\suricata.yaml'
    )
    if (-not $config -or -not (Test-Path -LiteralPath $config)) {
        $config = $commonConfig | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    }

    $savedEve = $null
    if (Test-Path -LiteralPath $script:IdsIntegrationFile) {
        try {
            $saved = Get-Content -LiteralPath $script:IdsIntegrationFile -Raw | ConvertFrom-Json
            if ($saved.EvePath -and (Test-Path -LiteralPath $saved.EvePath)) {
                $savedEve = [string]$saved.EvePath
            }
        }
        catch {}
    }

    $logDir = $null
    if ($config -and (Test-Path -LiteralPath $config)) {
        try {
            foreach ($line in Get-Content -LiteralPath $config -ErrorAction Stop) {
                if ($line -match '^\s*default-log-dir:\s*["'']?([^"''#]+)') {
                    $candidate = $Matches[1].Trim()
                    if ($candidate) { $logDir = $candidate; break }
                }
            }
        }
        catch {}
    }

    $eveCandidates = New-Object 'System.Collections.Generic.List[string]'
    if ($savedEve) { $eveCandidates.Add($savedEve) }
    if ($logDir) { $eveCandidates.Add((Join-Path $logDir 'eve.json')) }

    foreach ($candidate in @(
        "$env:ProgramFiles\Suricata\log\eve.json",
        "$env:ProgramFiles\Suricata\logs\eve.json",
        "$env:ProgramData\Suricata\log\eve.json",
        "$env:ProgramData\Suricata\logs\eve.json",
        'C:\Suricata\log\eve.json',
        'C:\Suricata\logs\eve.json'
    )) {
        if ($candidate) { $eveCandidates.Add($candidate) }
    }

    $eve = $eveCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    $npcap = $null
    foreach ($name in @('npcap','npf')) {
        try {
            $npcap = Get-Service -Name $name -ErrorAction Stop
            if ($npcap) { break }
        }
        catch {}
    }

    $update = $null
    try {
        $cmd = Get-Command suricata-update -ErrorAction Stop
        $update = $cmd.Source
    }
    catch {
        foreach ($candidate in @(
            "$env:ProgramFiles\Suricata\suricata-update.exe",
            "$env:ProgramFiles\Suricata\suricata-update",
            'C:\Suricata\suricata-update.exe'
        )) {
            if ($candidate -and (Test-Path -LiteralPath $candidate)) {
                $update = $candidate
                break
            }
        }
    }

    $captureMode = 'unknown'
    if ($servicePath -match '--windivert') { $captureMode = 'WinDivert / inline-active indicators' }
    elseif ($servicePath -match '(?:--pcap|-i\s)') { $captureMode = 'Npcap/PCAP passive indicators' }
    elseif ($npcap) { $captureMode = 'Npcap present; service mode not explicit' }

    [pscustomobject]@{
        Installed         = [bool]($exe -and (Test-Path -LiteralPath $exe))
        Executable        = $exe
        Config            = $config
        Service           = $service
        ServiceName       = $(if ($service) { $service.Name } else { $null })
        ServiceState      = $(if ($service) { $service.State } else { 'Not installed' })
        ServicePath       = $servicePath
        NpcapInstalled    = [bool]$npcap
        NpcapState        = $(if ($npcap) { $npcap.Status } else { 'Not installed' })
        EvePath           = $eve
        SuricataUpdate    = $update
        CaptureMode       = $captureMode
    }
}

function Set-WindowsSuricataEvePath {
    Initialize-IdsState
    $info = Get-WindowsSuricataInfo

    Write-Console ''
    if ($info.EvePath) {
        Write-Console ("Detected EVE path: {0}" -f $info.EvePath) Green
    }

    $path = (Read-Host 'EVE JSON path').Trim('"').Trim()
    if (-not (Test-Path -LiteralPath $path)) {
        Write-Console 'The selected EVE JSON file does not exist.' Red
        return
    }

    [pscustomobject]@{
        EvePath    = (Resolve-Path -LiteralPath $path).Path
        Configured = Get-Date
    } | ConvertTo-Json |
        Set-Content -LiteralPath $script:IdsIntegrationFile -Encoding UTF8

    Write-Log ("Stored Suricata EVE integration path: {0}" -f $path) CHANGE
}


function Write-WindowsSuricataConfigDiagnosis {
    param([Parameter(Mandatory=$true)][string[]]$Output)

    $joined = $Output -join "`n"
    if ($joined -match '(?i)No rule files match|rule files.*not found') {
        Write-Console '  Diagnosis: the configured Suricata ruleset is missing or does not match rule-files.' Yellow
        Write-Console '  Run the rule updater, then test the configuration again.' Yellow
    }
    if ($joined -match '(?i)Configuration node .* redefined') {
        Write-Console '  Diagnosis: the YAML configuration redefines a node. Review custom includes/overlays.' Yellow
    }
    if ($joined -match '(?i)Variable .* is not defined') {
        Write-Console '  Diagnosis: a rule variable expected by the active rules/configuration is missing.' Yellow
        Write-Console '  The Windows assistant will not rewrite third-party Suricata YAML automatically.' Yellow
    }
}

function Invoke-ExternalProcessWithHeartbeat {
    param(
        [Parameter(Mandatory=$true)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory=$true)][string]$Activity,
        [int]$TimeoutSeconds = 1200,
        [int]$HeartbeatSeconds = 30
    )

    $stdout = Join-Path $script:RunPath ("process-{0}-stdout.txt" -f ([guid]::NewGuid().ToString('N')))
    $stderr = Join-Path $script:RunPath ("process-{0}-stderr.txt" -f ([guid]::NewGuid().ToString('N')))

    $startParams = @{
        FilePath               = $FilePath
        NoNewWindow            = $true
        PassThru               = $true
        RedirectStandardOutput = $stdout
        RedirectStandardError  = $stderr
    }
    if ($ArgumentList.Count -gt 0) {
        $startParams.ArgumentList = $ArgumentList
    }
    $proc = Start-Process @startParams

    $watch = [Diagnostics.Stopwatch]::StartNew()
    $nextHeartbeat = $HeartbeatSeconds
    $timedOut = $false

    while (-not $proc.HasExited) {
        Start-Sleep -Seconds 2
        $proc.Refresh()

        if ($watch.Elapsed.TotalSeconds -ge $nextHeartbeat) {
            Write-Console ("  {0} still running · {1:mm\:ss}" -f $Activity,$watch.Elapsed) Gray
            $nextHeartbeat += $HeartbeatSeconds
        }

        if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            $timedOut = $true
            Write-Console ("  {0} exceeded {1} minutes; stopping the updater." -f `
                $Activity,[math]::Round($TimeoutSeconds / 60,0)) Red
            try { $proc.Kill() } catch {}
            break
        }
    }

    try { $proc.WaitForExit() } catch {}
    $watch.Stop()

    $output = New-Object 'System.Collections.Generic.List[string]'
    if (Test-Path -LiteralPath $stdout) {
        foreach ($line in Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue) {
            $output.Add([string]$line)
        }
    }
    if (Test-Path -LiteralPath $stderr) {
        foreach ($line in Get-Content -LiteralPath $stderr -ErrorAction SilentlyContinue) {
            $output.Add([string]$line)
        }
    }

    $output | Select-Object -Last 60 | ForEach-Object { Write-Console ([string]$_) Gray }

    $exitCode = if ($timedOut) { -1 } else {
        try { [int]$proc.ExitCode } catch { -1 }
    }

    [pscustomobject]@{
        ExitCode = $exitCode
        TimedOut = $timedOut
        Elapsed  = $watch.Elapsed
        Output   = @($output)
    }
}

function Test-WindowsSuricataConfiguration {
    $info = Get-WindowsSuricataInfo
    if (-not $info.Executable) {
        Write-Console 'Suricata executable was not detected.' Yellow
        return $false
    }
    if (-not $info.Config) {
        Write-Console 'suricata.yaml was not detected.' Yellow
        return $false
    }

    Write-Console ("Testing: {0} -T -c {1}" -f $info.Executable, $info.Config) Cyan
    $output = & $info.Executable -T -c $info.Config 2>&1
    $exit = $LASTEXITCODE
    $output | Select-Object -Last 50 | ForEach-Object { Write-Console ([string]$_) Gray }

    if ($exit -eq 0) {
        Add-Result 'IDS' 'Suricata configuration' 'PASS' $info.Config 'Valid'
        return $true
    }

    Write-WindowsSuricataConfigDiagnosis -Output @($output)
    Add-Result 'IDS' 'Suricata configuration' 'FAIL' ("exit={0}" -f $exit) 'Valid'
    return $false
}

function Show-WindowsIdsReadiness {
    Write-Section 'Suricata IDS readiness'
    $info = Get-WindowsSuricataInfo

    Add-Result 'IDS' 'Suricata executable' `
        $(if ($info.Installed) { 'PASS' } else { 'WARN' }) `
        $(if ($info.Executable) { $info.Executable } else { 'not detected' }) `
        'Official Suricata Windows installation when IDS is desired'

    Add-Result 'IDS' 'Suricata service' `
        $(if ($info.ServiceState -eq 'Running') { 'PASS' } else { 'WARN' }) `
        $info.ServiceState `
        'Running for continuous monitoring'

    Add-Result 'IDS' 'Npcap live capture' `
        $(if ($info.NpcapInstalled) { 'PASS' } else { 'WARN' }) `
        $info.NpcapState `
        'Npcap required for live passive capture on Windows'

    Add-Result 'IDS' 'Capture posture' `
        $(if ($info.CaptureMode -match 'inline|active') { 'WARN' } else { 'INFO' }) `
        $info.CaptureMode `
        'Passive IDS preferred on a Domain Controller'

    Add-Result 'IDS' 'EVE JSON' `
        $(if ($info.EvePath) { 'PASS' } else { 'WARN' }) `
        $(if ($info.EvePath) { $info.EvePath } else { 'not detected' }) `
        'eve.json for local analytics'

    Write-Console ''
    Write-Console 'Windows integration policy:' Cyan
    Write-Console '  - The assistant does not silently install Suricata or packet-capture drivers.' Gray
    Write-Console '  - Suricata and Npcap are external components on Windows; installation remains explicit.' Gray
    Write-Console '  - Once EVE JSON exists, analytics and the native GUI use only Windows PowerShell/.NET.' Gray
    Write-Console '  - No Elasticsearch, Logstash, jq, Chocolatey or third-party dashboard is required.' Gray
}

function Get-WindowsIdsEveFiles {
    param([Parameter(Mandatory=$true)][string]$EvePath)

    $dir = Split-Path -Parent $EvePath
    $name = Split-Path -Leaf $EvePath
    if (-not (Test-Path -LiteralPath $dir)) { return @() }

    return @(
        Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like ("{0}*" -f $name) -and $_.Extension -ne '.gz' } |
            Sort-Object LastWriteTime
    )
}

function Get-WindowsIdsSummary {
    param(
        [int]$Hours = 24,
        [int]$MaxRecentAlerts = 100
    )

    $info = Get-WindowsSuricataInfo
    if (-not $info.EvePath) {
        throw 'Suricata EVE JSON was not detected. Configure the EVE path first.'
    }

    $cutoff = [DateTimeOffset]::Now.AddHours(-1 * [Math]::Abs($Hours))
    $eventTypes = @{}
    $alertSeverity = @{}
    $alertSignatures = @{}
    $alertSources = @{}
    $dnsSources = @{}
    $krbEncryption = @{}
    $krbClients = @{}
    $krbSources = @{}
    $krbErrors = @{}
    $ldapOperations = @{}
    $ldapSources = @{}
    $ldapResultCodes = @{}
    $smbDialects = @{}
    $ntlmUsers = @{}
    $ntlmHosts = @{}

    $weakKerberos = New-Object 'System.Collections.Generic.List[object]'
    $recentKrbErrors = New-Object 'System.Collections.Generic.List[object]'
    $recentLdapFailures = New-Object 'System.Collections.Generic.List[object]'
    $recentAlerts = New-Object 'System.Collections.Generic.List[object]'
    $latestStats = $null
    $latestTimestamp = $null
    $parsed = 0
    $badJson = 0
    $dnsEvents = 0
    $nxdomain = 0

    $files = @(Get-WindowsIdsEveFiles -EvePath $info.EvePath)
    foreach ($file in $files) {
        foreach ($line in [System.IO.File]::ReadLines($file.FullName)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }

            try { $event = $line | ConvertFrom-Json -ErrorAction Stop }
            catch { $badJson++; continue }

            $rawTimestamp = Get-ObjectPropertyValue -Object $event -Name 'timestamp'
            $timestamp = [DateTimeOffset]::MinValue
            if ($rawTimestamp) {
                $parsedTimestamp = [DateTimeOffset]::TryParse([string]$rawTimestamp, [ref]$timestamp)
                if ($parsedTimestamp -and $timestamp -lt $cutoff) { continue }
                if ($parsedTimestamp -and ($null -eq $latestTimestamp -or $timestamp -gt $latestTimestamp)) {
                    $latestTimestamp = $timestamp
                }
            }

            $parsed++
            $type = Get-ObjectPropertyValue -Object $event -Name 'event_type'
            if (-not $type) { $type = 'unknown' }
            Add-CounterValue -Table $eventTypes -Key $type

            $srcIp = Get-ObjectPropertyValue -Object $event -Name 'src_ip'

            switch ([string]$type) {
                'alert' {
                    $alert = Get-ObjectPropertyValue -Object $event -Name 'alert'
                    $sig = Get-ObjectPropertyValue -Object $alert -Name 'signature'
                    $severity = Get-ObjectPropertyValue -Object $alert -Name 'severity'
                    $dst = Get-ObjectPropertyValue -Object $event -Name 'dest_ip'

                    Add-CounterValue -Table $alertSignatures -Key $sig
                    Add-CounterValue -Table $alertSeverity -Key $severity
                    Add-CounterValue -Table $alertSources -Key $srcIp

                    $recentAlerts.Add([pscustomobject]@{
                        Timestamp   = [string]$rawTimestamp
                        Severity    = [string]$severity
                        Source      = [string]$srcIp
                        Destination = [string]$dst
                        Signature   = [string]$sig
                    })
                    while ($recentAlerts.Count -gt $MaxRecentAlerts) {
                        $recentAlerts.RemoveAt(0)
                    }
                }

                'dns' {
                    $dnsEvents++
                    Add-CounterValue -Table $dnsSources -Key $srcIp
                    $dns = Get-ObjectPropertyValue -Object $event -Name 'dns'
                    $rcode = Get-ObjectPropertyValue -Object $dns -Name 'rcode_name'
                    if (-not $rcode) { $rcode = Get-ObjectPropertyValue -Object $dns -Name 'rcode' }
                    if (([string]$rcode).ToUpperInvariant() -match 'NXDOMAIN|^3$') { $nxdomain++ }
                }

                'krb5' {
                    Add-CounterValue -Table $krbSources -Key $srcIp
                    $krb = Get-ObjectPropertyValue -Object $event -Name 'krb5'
                    $enc = Get-ObjectPropertyValue -Object $krb -Name 'ticket_encryption'
                    if (-not $enc) { $enc = Get-ObjectPropertyValue -Object $krb -Name 'encryption' }
                    Add-CounterValue -Table $krbEncryption -Key $enc

                    $client = Get-ObjectPropertyValue -Object $krb -Name 'cname'
                    Add-CounterValue -Table $krbClients -Key $client

                    $errorCode = Get-ObjectPropertyValue -Object $krb -Name 'error_code'
                    if ($null -ne $errorCode -and [string]$errorCode -ne '') {
                        Add-CounterValue -Table $krbErrors -Key $errorCode
                        $recentKrbErrors.Add([pscustomobject]@{
                            Timestamp = [string]$rawTimestamp
                            Source    = [string]$srcIp
                            Client    = [string]$client
                            Service   = [string](Get-ObjectPropertyValue -Object $krb -Name 'sname')
                            ErrorCode = [string]$errorCode
                        })
                        while ($recentKrbErrors.Count -gt 100) { $recentKrbErrors.RemoveAt(0) }
                    }

                    $weak = Get-ObjectPropertyValue -Object $krb -Name 'weak_encryption'
                    $ticketWeak = Get-ObjectPropertyValue -Object $krb -Name 'ticket_weak_encryption'
                    if ($weak -eq $true -or $ticketWeak -eq $true) {
                        $weakKerberos.Add([pscustomobject]@{
                            Timestamp  = [string]$rawTimestamp
                            Source     = [string]$srcIp
                            Client     = [string]$client
                            Service    = [string](Get-ObjectPropertyValue -Object $krb -Name 'sname')
                            Encryption = [string]$enc
                        })
                    }
                }

                'ldap' {
                    Add-CounterValue -Table $ldapSources -Key $srcIp
                    $ldap = Get-ObjectPropertyValue -Object $event -Name 'ldap'
                    $requests = @(Get-ObjectPropertyValue -Object $ldap -Name 'requests')
                    foreach ($req in $requests) {
                        if ($null -eq $req) { continue }
                        $op = Get-ObjectPropertyValue -Object $req -Name 'operation'
                        if (-not $op) { $op = Get-ObjectPropertyValue -Object $req -Name 'type' }
                        Add-CounterValue -Table $ldapOperations -Key $op
                    }

                    $responses = @(Get-ObjectPropertyValue -Object $ldap -Name 'responses')
                    foreach ($resp in $responses) {
                        if ($null -eq $resp) { continue }
                        $code = Get-ObjectPropertyValue -Object $resp -Name 'result_code'
                        if ($null -eq $code) { $code = Get-ObjectPropertyValue -Object $resp -Name 'resultCode' }
                        Add-CounterValue -Table $ldapResultCodes -Key $code

                        $codeText = [string]$code
                        if ($codeText -and $codeText -notmatch '^(0|success)$') {
                            $recentLdapFailures.Add([pscustomobject]@{
                                Timestamp  = [string]$rawTimestamp
                                Source     = [string]$srcIp
                                ResultCode = $codeText
                            })
                            while ($recentLdapFailures.Count -gt 100) {
                                $recentLdapFailures.RemoveAt(0)
                            }
                        }
                    }
                }

                'smb' {
                    $smb = Get-ObjectPropertyValue -Object $event -Name 'smb'
                    $dialect = Get-ObjectPropertyValue -Object $smb -Name 'dialect'
                    Add-CounterValue -Table $smbDialects -Key $dialect

                    $ntlm = Get-ObjectPropertyValue -Object $smb -Name 'ntlmssp'
                    if ($ntlm) {
                        $user = Get-ObjectPropertyValue -Object $ntlm -Name 'user'
                        $host = Get-ObjectPropertyValue -Object $ntlm -Name 'host'
                        if (-not $host) { $host = $srcIp }
                        Add-CounterValue -Table $ntlmUsers -Key $(if ($user) { $user } else { '<unknown>' })
                        Add-CounterValue -Table $ntlmHosts -Key $(if ($host) { $host } else { '<unknown>' })
                    }
                }

                'stats' {
                    $latestStats = Get-ObjectPropertyValue -Object $event -Name 'stats'
                }
            }
        }
    }

    $kernelPackets = 0
    $kernelDrops = 0
    if ($latestStats) {
        $capture = Get-ObjectPropertyValue -Object $latestStats -Name 'capture'
        $kp = Get-ObjectPropertyValue -Object $capture -Name 'kernel_packets'
        $kd = Get-ObjectPropertyValue -Object $capture -Name 'kernel_drops'
        if ($kp -ne $null) { $kernelPackets = [double]$kp }
        if ($kd -ne $null) { $kernelDrops = [double]$kd }
    }

    $dropRate = 0.0
    if ($kernelPackets -gt 0) {
        $dropRate = ($kernelDrops * 100.0 / $kernelPackets)
    }

    $smb1 = 0
    foreach ($key in $smbDialects.Keys) {
        if ($key -match 'NT LM 0\.12|SMB1') { $smb1 += [int]$smbDialects[$key] }
    }

    $severity12 = 0
    foreach ($key in @('1','2')) {
        if ($alertSeverity.ContainsKey($key)) { $severity12 += [int]$alertSeverity[$key] }
    }

    # KRB5 error 25 / PREAUTH_REQUIRED is commonly part of normal negotiation.
    $actionableKrbErrors = 0
    foreach ($key in $krbErrors.Keys) {
        if ([string]$key -notmatch '^(25|KDC_ERR_PREAUTH_REQUIRED|PREAUTH_REQUIRED)$') {
            $actionableKrbErrors += [int]$krbErrors[$key]
        }
    }

    $actions = New-Object 'System.Collections.Generic.List[string]'
    if ($dropRate -gt 1.0) {
        $actions.Add(("HIGH sensor packet loss: kernel drop rate {0:N3}%" -f $dropRate))
    }
    elseif ($dropRate -gt 0.1) {
        $actions.Add(("REVIEW sensor packet loss: kernel drop rate {0:N3}%" -f $dropRate))
    }
    if ($weakKerberos.Count -gt 0) {
        $actions.Add(("REVIEW {0} weak Kerberos observation(s) before AES-only enforcement" -f $weakKerberos.Count))
    }
    if ($actionableKrbErrors -gt 0) {
        $actions.Add(("INVESTIGATE {0} actionable Kerberos error observation(s)" -f $actionableKrbErrors))
    }
    if ($recentLdapFailures.Count -gt 0) {
        $actions.Add(("INVESTIGATE {0} LDAP non-success response observation(s)" -f $recentLdapFailures.Count))
    }
    if ($smb1 -gt 0) {
        $actions.Add(("REVIEW {0} SMB1 observation(s); identify legacy clients" -f $smb1))
    }
    if ($severity12 -gt 0) {
        $actions.Add(("INVESTIGATE {0} alert(s) with severity value 1/2" -f $severity12))
    }
    if ($actions.Count -eq 0) {
        $actions.Add('No automatic high-priority decision trigger detected in this window')
    }

    [pscustomobject]@{
        Hours               = $Hours
        EvePath             = $info.EvePath
        ParsedEvents        = $parsed
        BadJsonLines        = $badJson
        LatestTimestamp     = $latestTimestamp
        EventTypes          = @(Convert-CounterToRows -Table $eventTypes -KeyName 'EventType' -Limit 30)
        AlertSeverities     = @(Convert-CounterToRows -Table $alertSeverity -KeyName 'Severity' -Limit 10)
        TopAlerts           = @(Convert-CounterToRows -Table $alertSignatures -KeyName 'Signature' -Limit 20)
        TopAlertSources     = @(Convert-CounterToRows -Table $alertSources -KeyName 'Source' -Limit 20)
        RecentAlerts        = @($recentAlerts)
        DnsEvents           = $dnsEvents
        NxDomain            = $nxdomain
        DnsSources          = @(Convert-CounterToRows -Table $dnsSources -KeyName 'Source' -Limit 20)
        KerberosEncryption  = @(Convert-CounterToRows -Table $krbEncryption -KeyName 'Encryption' -Limit 20)
        KerberosClients     = @(Convert-CounterToRows -Table $krbClients -KeyName 'Client' -Limit 20)
        KerberosSources     = @(Convert-CounterToRows -Table $krbSources -KeyName 'Source' -Limit 20)
        KerberosErrors      = @(Convert-CounterToRows -Table $krbErrors -KeyName 'ErrorCode' -Limit 20)
        RecentKrbErrors     = @($recentKrbErrors)
        WeakKerberos        = @($weakKerberos)
        LdapOperations      = @(Convert-CounterToRows -Table $ldapOperations -KeyName 'Operation' -Limit 20)
        LdapSources         = @(Convert-CounterToRows -Table $ldapSources -KeyName 'Source' -Limit 20)
        LdapResultCodes     = @(Convert-CounterToRows -Table $ldapResultCodes -KeyName 'ResultCode' -Limit 20)
        RecentLdapFailures  = @($recentLdapFailures)
        SmbDialects         = @(Convert-CounterToRows -Table $smbDialects -KeyName 'Dialect' -Limit 20)
        NtlmUsers           = @(Convert-CounterToRows -Table $ntlmUsers -KeyName 'User' -Limit 20)
        NtlmHosts           = @(Convert-CounterToRows -Table $ntlmHosts -KeyName 'Host' -Limit 20)
        Smb1Observations    = $smb1
        KernelPackets       = [long]$kernelPackets
        KernelDrops         = [long]$kernelDrops
        KernelDropRate      = $dropRate
        ActionableFindings  = @($actions)
    }
}

function Format-WindowsIdsSummaryText {
    param([Parameter(Mandatory=$true)]$Summary)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine(("SECURITY OPERATIONS SUMMARY — LAST {0}H" -f $Summary.Hours))
    [void]$sb.AppendLine(('=' * 76))
    [void]$sb.AppendLine(("EVE path                 {0}" -f $Summary.EvePath))
    [void]$sb.AppendLine(("Parsed events            {0}" -f $Summary.ParsedEvents))
    [void]$sb.AppendLine(("Malformed JSON lines     {0}" -f $Summary.BadJsonLines))
    [void]$sb.AppendLine(("Latest event             {0}" -f $Summary.LatestTimestamp))
    [void]$sb.AppendLine(("Kernel packets           {0}" -f $Summary.KernelPackets))
    [void]$sb.AppendLine(("Kernel drops             {0}" -f $Summary.KernelDrops))
    [void]$sb.AppendLine(("Kernel drop rate         {0:N3}%" -f $Summary.KernelDropRate))
    [void]$sb.AppendLine(("DNS events               {0}" -f $Summary.DnsEvents))
    [void]$sb.AppendLine(("DNS NXDOMAIN             {0}" -f $Summary.NxDomain))
    [void]$sb.AppendLine(("Kerberos errors          {0}" -f (($Summary.KerberosErrors | Measure-Object Count -Sum).Sum)))
    [void]$sb.AppendLine(("Weak Kerberos            {0}" -f $Summary.WeakKerberos.Count))
    [void]$sb.AppendLine(("LDAP failures observed   {0}" -f $Summary.RecentLdapFailures.Count))
    [void]$sb.AppendLine(("SMB1 observations        {0}" -f $Summary.Smb1Observations))
    [void]$sb.AppendLine(("NTLMSSP observations     {0}" -f (($Summary.NtlmUsers | Measure-Object Count -Sum).Sum)))

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('TOP ALERTS')
    foreach ($row in $Summary.TopAlerts) {
        [void]$sb.AppendLine(("{0,6}  {1}" -f $row.Count, $row.Signature))
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('KERBEROS CLIENTS / ERRORS')
    foreach ($row in $Summary.KerberosClients) {
        [void]$sb.AppendLine(("{0,6}  client {1}" -f $row.Count, $row.Client))
    }
    foreach ($row in $Summary.KerberosErrors) {
        [void]$sb.AppendLine(("{0,6}  error  {1}" -f $row.Count, $row.ErrorCode))
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('LDAP RESULT CODES')
    foreach ($row in $Summary.LdapResultCodes) {
        [void]$sb.AppendLine(("{0,6}  {1}" -f $row.Count, $row.ResultCode))
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('SMB DIALECTS')
    foreach ($row in $Summary.SmbDialects) {
        [void]$sb.AppendLine(("{0,6}  {1}" -f $row.Count, $row.Dialect))
    }

    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('ACTIONABLE FINDINGS')
    foreach ($item in $Summary.ActionableFindings) {
        [void]$sb.AppendLine(("  - {0}" -f $item))
    }

    return $sb.ToString()
}

function Show-WindowsIdsSummary {
    param([int]$Hours = 24)

    Write-Section ("Suricata security summary — last {0}h" -f $Hours)
    try {
        $summary = Get-WindowsIdsSummary -Hours $Hours
        Write-Console (Format-WindowsIdsSummaryText -Summary $summary)
    }
    catch {
        Write-Console $_.Exception.Message Red
    }
}

function Show-WindowsIdsRecentAlerts {
    param([int]$Hours = 24)

    Write-Section ("Recent Suricata alerts — last {0}h" -f $Hours)
    try {
        $summary = Get-WindowsIdsSummary -Hours $Hours -MaxRecentAlerts 200
        if ($summary.RecentAlerts.Count -eq 0) {
            Write-Console 'No alerts observed in the selected window.' Green
            return
        }

        $summary.RecentAlerts |
            Select-Object Timestamp, Severity, Source, Destination, Signature |
            Format-Table -AutoSize
    }
    catch {
        Write-Console $_.Exception.Message Red
    }
}

function Show-WindowsIdsAdIntelligence {
    param([int]$Hours = 24)

    Write-Section ("AD protocol intelligence — last {0}h" -f $Hours)
    try {
        $summary = Get-WindowsIdsSummary -Hours $Hours

        Write-Console 'Kerberos encryption:' Cyan
        $summary.KerberosEncryption | Format-Table -AutoSize

        Write-Console ''
        Write-Console ("Weak Kerberos observations: {0}" -f $summary.WeakKerberos.Count) `
            $(if ($summary.WeakKerberos.Count -gt 0) { 'Yellow' } else { 'Green' })
        if ($summary.WeakKerberos.Count -gt 0) {
            $summary.WeakKerberos |
                Select-Object -Last 30 |
                Format-Table Timestamp, Source, Client, Service, Encryption -AutoSize
        }

        Write-Console ''
        Write-Console 'SMB dialects:' Cyan
        $summary.SmbDialects | Format-Table -AutoSize
        Write-Console ("SMB1 observations: {0}" -f $summary.Smb1Observations) `
            $(if ($summary.Smb1Observations -gt 0) { 'Yellow' } else { 'Green' })

        Write-Console ''
        Write-Console 'SMB NTLMSSP users:' Cyan
        $summary.NtlmUsers | Format-Table -AutoSize
        Write-Console 'SMB NTLMSSP source hosts:' Cyan
        $summary.NtlmHosts | Format-Table -AutoSize
    }
    catch {
        Write-Console $_.Exception.Message Red
    }
}

function Show-WindowsIdsSensorHealth {
    Write-Section 'Suricata sensor health'
    $info = Get-WindowsSuricataInfo

    Add-Result 'IDS' 'Suricata service' `
        $(if ($info.ServiceState -eq 'Running') { 'PASS' } else { 'WARN' }) `
        $info.ServiceState 'Running'

    Add-Result 'IDS' 'Npcap' `
        $(if ($info.NpcapInstalled) { 'PASS' } else { 'WARN' }) `
        $info.NpcapState 'Installed/running for live capture'

    Add-Result 'IDS' 'Capture posture' `
        $(if ($info.CaptureMode -match 'inline|active') { 'WARN' } else { 'INFO' }) `
        $info.CaptureMode 'Passive preferred on a DC'

    if ($info.EvePath) {
        $item = Get-Item -LiteralPath $info.EvePath
        $age = (New-TimeSpan -Start $item.LastWriteTime -End (Get-Date)).TotalSeconds
        Add-Result 'IDS' 'EVE freshness' `
            $(if ($age -lt 600) { 'PASS' } else { 'WARN' }) `
            ("{0:N0}s old; {1:N1} MB" -f $age, ($item.Length / 1MB)) `
            '<600s while sensor is active'

        try {
            $summary = Get-WindowsIdsSummary -Hours 1
            Add-Result 'IDS' 'Kernel drop rate' `
                $(if ($summary.KernelDropRate -gt 1) { 'WARN' } else { 'PASS' }) `
                ("{0:N3}%" -f $summary.KernelDropRate) `
                'Low packet loss'
        }
        catch {}
    }
    else {
        Add-Result 'IDS' 'EVE log' 'WARN' 'not detected' 'Configured'
    }

    if ($info.Installed -and $info.Config) {
        [void](Test-WindowsSuricataConfiguration)
    }
}

function Test-WindowsFormsAvailable {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        return [bool][Environment]::UserInteractive
    }
    catch {
        return $false
    }
}

function Show-WindowsIdsDashboardGui {
    if (-not (Test-WindowsFormsAvailable)) {
        Write-Console 'Windows Forms is unavailable (Server Core/non-interactive session). Falling back to console summary.' Yellow
        Show-WindowsIdsSummary -Hours 24
        return
    }

    $info = Get-WindowsSuricataInfo
    if (-not $info.EvePath) {
        [System.Windows.Forms.MessageBox]::Show(
            'Suricata EVE JSON was not detected. Configure the EVE path from the IDS menu first.',
            'Windows AD Control Plane - IDS',
            'OK',
            'Warning'
        ) | Out-Null
        return
    }

    $form = New-Object System.Windows.Forms.Form
    $form.Text = (Get-UiText 'Windows AD Control Plane - Suricata IDS')
    $form.Width = 1180
    $form.Height = 760
    $form.StartPosition = 'CenterScreen'

    $top = New-Object System.Windows.Forms.FlowLayoutPanel
    $top.Dock = 'Top'
    $top.Height = 48
    $top.Padding = New-Object System.Windows.Forms.Padding(8)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Analysis window:'
    $label.AutoSize = $true
    $label.Padding = New-Object System.Windows.Forms.Padding(0,7,0,0)

    $hoursBox = New-Object System.Windows.Forms.ComboBox
    $hoursBox.DropDownStyle = 'DropDownList'
    [void]$hoursBox.Items.Add('1 hour')
    [void]$hoursBox.Items.Add('24 hours')
    [void]$hoursBox.Items.Add('7 days')
    $hoursBox.SelectedIndex = 1

    $refresh = New-Object System.Windows.Forms.Button
    $refresh.Text = 'Refresh'
    $refresh.AutoSize = $true

    $openLogs = New-Object System.Windows.Forms.Button
    $openLogs.Text = 'Open log folder'
    $openLogs.AutoSize = $true

    [void]$top.Controls.Add($label)
    [void]$top.Controls.Add($hoursBox)
    [void]$top.Controls.Add($refresh)
    [void]$top.Controls.Add($openLogs)

    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = 'Fill'

    $overviewTab = New-Object System.Windows.Forms.TabPage
    $overviewTab.Text = 'Overview'
    $overview = New-Object System.Windows.Forms.TextBox
    $overview.Dock = 'Fill'
    $overview.Multiline = $true
    $overview.ReadOnly = $true
    $overview.ScrollBars = 'Both'
    $overview.WordWrap = $false
    $overview.Font = New-Object System.Drawing.Font('Consolas', 10)
    [void]$overviewTab.Controls.Add($overview)

    $alertsTab = New-Object System.Windows.Forms.TabPage
    $alertsTab.Text = 'Alerts'
    $alertsGrid = New-Object System.Windows.Forms.DataGridView
    $alertsGrid.Dock = 'Fill'
    $alertsGrid.ReadOnly = $true
    $alertsGrid.AutoSizeColumnsMode = 'Fill'
    $alertsGrid.AllowUserToAddRows = $false
    [void]$alertsTab.Controls.Add($alertsGrid)

    $adTab = New-Object System.Windows.Forms.TabPage
    $adTab.Text = 'AD protocol intelligence'
    $adText = New-Object System.Windows.Forms.TextBox
    $adText.Dock = 'Fill'
    $adText.Multiline = $true
    $adText.ReadOnly = $true
    $adText.ScrollBars = 'Both'
    $adText.WordWrap = $false
    $adText.Font = New-Object System.Drawing.Font('Consolas', 10)
    [void]$adTab.Controls.Add($adText)

    $sensorTab = New-Object System.Windows.Forms.TabPage
    $sensorTab.Text = 'Sensor'
    $sensor = New-Object System.Windows.Forms.TextBox
    $sensor.Dock = 'Fill'
    $sensor.Multiline = $true
    $sensor.ReadOnly = $true
    $sensor.ScrollBars = 'Vertical'
    $sensor.Font = New-Object System.Drawing.Font('Consolas', 10)
    [void]$sensorTab.Controls.Add($sensor)

    [void]$tabs.TabPages.Add($overviewTab)
    [void]$tabs.TabPages.Add($alertsTab)
    [void]$tabs.TabPages.Add($adTab)
    [void]$tabs.TabPages.Add($sensorTab)

    [void]$form.Controls.Add($tabs)
    [void]$form.Controls.Add($top)

    $refreshAction = {
        try {
            $hours = switch ($hoursBox.SelectedIndex) {
                0 { 1 }
                2 { 168 }
                default { 24 }
            }

            $summary = Get-WindowsIdsSummary -Hours $hours -MaxRecentAlerts 200
            $overview.Text = Format-WindowsIdsSummaryText -Summary $summary

            $alertsGrid.DataSource = $null
            $alertsGrid.DataSource = @($summary.RecentAlerts |
                Sort-Object Timestamp -Descending |
                Select-Object -First 100)

            $sb = New-Object System.Text.StringBuilder
            [void]$sb.AppendLine('KERBEROS CLIENTS')
            foreach ($row in $summary.KerberosClients) {
                [void]$sb.AppendLine(("{0,7}  {1}" -f $row.Count, $row.Client))
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('KERBEROS ERRORS')
            foreach ($row in $summary.KerberosErrors) {
                [void]$sb.AppendLine(("{0,7}  {1}" -f $row.Count, $row.ErrorCode))
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('KERBEROS ENCRYPTION')
            foreach ($row in $summary.KerberosEncryption) {
                [void]$sb.AppendLine(("{0,7}  {1}" -f $row.Count, $row.Encryption))
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('LDAP RESULT CODES')
            foreach ($row in $summary.LdapResultCodes) {
                [void]$sb.AppendLine(("{0,7}  {1}" -f $row.Count, $row.ResultCode))
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine(("WEAK KERBEROS: {0}" -f $summary.WeakKerberos.Count))
            foreach ($row in ($summary.WeakKerberos | Select-Object -Last 30)) {
                [void]$sb.AppendLine(("{0} | {1} | {2} | {3} | {4}" -f
                    $row.Timestamp, $row.Source, $row.Client, $row.Service, $row.Encryption))
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('SMB DIALECTS')
            foreach ($row in $summary.SmbDialects) {
                [void]$sb.AppendLine(("{0,7}  {1}" -f $row.Count, $row.Dialect))
            }
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine(("SMB1 observations: {0}" -f $summary.Smb1Observations))
            [void]$sb.AppendLine('')
            [void]$sb.AppendLine('NTLMSSP USERS')
            foreach ($row in $summary.NtlmUsers) {
                [void]$sb.AppendLine(("{0,7}  {1}" -f $row.Count, $row.User))
            }
            $adText.Text = $sb.ToString()

            $infoNow = Get-WindowsSuricataInfo
            $sensor.Text = @"
Service        : $($infoNow.ServiceState)
Service name   : $($infoNow.ServiceName)
Executable     : $($infoNow.Executable)
Config         : $($infoNow.Config)
Npcap          : $($infoNow.NpcapState)
Capture posture: $($infoNow.CaptureMode)
EVE            : $($infoNow.EvePath)
Kernel packets : $($summary.KernelPackets)
Kernel drops   : $($summary.KernelDrops)
Drop rate      : $("{0:N3}%" -f $summary.KernelDropRate)
"@
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show(
                $_.Exception.Message,
                'IDS dashboard error',
                'OK',
                'Error'
            ) | Out-Null
        }
    }.GetNewClosure()

    $refresh.Add_Click($refreshAction)
    $hoursBox.Add_SelectedIndexChanged($refreshAction)
    $openLogs.Add_Click({
        $current = Get-WindowsSuricataInfo
        if ($current.EvePath) {
            Start-Process explorer.exe -ArgumentList ('"{0}"' -f (Split-Path -Parent $current.EvePath))
        }
    }.GetNewClosure())

    & $refreshAction
    [void]$form.ShowDialog()
    $form.Dispose()
}

function Invoke-WindowsSuricataRuleUpdate {
    $info = Get-WindowsSuricataInfo
    if (-not $info.SuricataUpdate) {
        Write-Console 'suricata-update was not detected. The assistant will not install a separate Python/package stack on Windows.' Yellow
        return
    }

    if (-not (Confirm-Action `
        -Action 'Update Suricata detection rules' `
        -Reason 'Refresh IDS signatures, show progress while the updater works, then validate the configuration.' `
        -Impact MEDIUM)) {
        return
    }

    Write-Console ("Running: {0}" -f $info.SuricataUpdate) Cyan
    Write-Console ("Timeout safety: {0} minutes. A heartbeat is printed every 30 seconds." -f `
        [math]::Round($script:SuricataUpdateTimeoutSeconds / 60,0)) Gray

    $run = Invoke-ExternalProcessWithHeartbeat `
        -FilePath $info.SuricataUpdate `
        -Activity 'Suricata rule update' `
        -TimeoutSeconds $script:SuricataUpdateTimeoutSeconds `
        -HeartbeatSeconds 30

    if ($run.TimedOut) {
        Write-Console 'suricata-update was stopped after exceeding the safety timeout.' Red
        Write-Console 'Existing rules/configuration were not replaced by the control plane.' Yellow
        return
    }
    if ($run.ExitCode -ne 0) {
        Write-Console ("suricata-update failed with exit code {0}." -f $run.ExitCode) Red
        return
    }

    Write-Console ("Rule update completed in {0:mm\:ss}." -f $run.Elapsed) Green

    if (-not (Test-WindowsSuricataConfiguration)) {
        Write-Console 'Rules were updated but the configuration test failed. Service restart was not attempted.' Red
        return
    }

    if ($info.ServiceName) {
        try {
            Restart-Service -Name $info.ServiceName -ErrorAction Stop
            Write-Log 'Suricata rules updated, validated and service restarted.' CHANGE
        }
        catch {
            Write-Console ("Rule update validated, but service restart failed: {0}" -f $_.Exception.Message) Red
        }
    }
}

function Export-WindowsIdsDailyReport {
    param([int]$Hours = 24)

    Initialize-IdsState
    $summary = Get-WindowsIdsSummary -Hours $Hours -MaxRecentAlerts 100

    $path = Join-Path $script:IdsReportPath ("ids-report-{0}.txt" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('WINDOWS AD CONTROL PLANE — SURICATA IDS REPORT')
    [void]$sb.AppendLine(("Generated : {0}" -f (Get-Date)))
    [void]$sb.AppendLine(("Server    : {0}" -f $env:COMPUTERNAME))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine((Format-WindowsIdsSummaryText -Summary $summary))
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('WEAK KERBEROS DETAILS')
    foreach ($row in $summary.WeakKerberos) {
        [void]$sb.AppendLine(("{0} | {1} | {2} | {3} | {4}" -f
            $row.Timestamp, $row.Source, $row.Client, $row.Service, $row.Encryption))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('RECENT ALERTS')
    foreach ($row in $summary.RecentAlerts) {
        [void]$sb.AppendLine(("{0} | sev={1} | {2} -> {3} | {4}" -f
            $row.Timestamp, $row.Severity, $row.Source, $row.Destination, $row.Signature))
    }

    $sb.ToString() | Set-Content -LiteralPath $path -Encoding UTF8
    Write-Log ("Generated IDS report: {0}" -f $path) OK
    return $path
}

function Register-WindowsIdsDailyTask {
    if (-not (Test-Command 'Register-ScheduledTask')) {
        Write-Console 'ScheduledTasks module is unavailable.' Red
        return
    }

    $info = Get-WindowsSuricataInfo
    if (-not $info.EvePath) {
        Write-Console 'EVE JSON must be configured before creating a daily report task.' Yellow
        return
    }

    Initialize-IdsState

    $raw = (Read-Host 'Daily report time [07:00]').Trim()
    if ([string]::IsNullOrWhiteSpace($raw)) { $raw = '07:00' }

    $at = [datetime]::MinValue
    if (-not [datetime]::TryParseExact(
        $raw,
        'HH:mm',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$at)) {
        Write-Console 'Invalid time; expected HH:mm.' Red
        return
    }

    if (-not $PSCommandPath -or -not (Test-Path -LiteralPath $PSCommandPath)) {
        Write-Console 'Unable to resolve the current script path for Task Scheduler.' Red
        return
    }

    $managedScript = Join-Path $script:IdsStatePath 'windows-server-ad-assistant-ids.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $managedScript -Force

    $args = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode IDSReport -NoColor -ExportPath "{1}"' -f `
        $managedScript, $ExportPath

    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument $args
    $trigger = New-ScheduledTaskTrigger -Daily -At $at
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable

    Register-ScheduledTask `
        -TaskName $script:IdsTaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Force | Out-Null

    Write-Log ("Registered daily IDS report task at {0}" -f $raw) CHANGE
    Write-Console ("Daily IDS report task registered at {0}." -f $raw) Green
}

function Show-WindowsIdsReports {
    Initialize-IdsState
    $reports = @(Get-ChildItem -LiteralPath $script:IdsReportPath -Filter 'ids-report-*.txt' -File |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 50)

    if ($reports.Count -eq 0) {
        Write-Console 'No IDS reports have been generated yet.' Yellow
        return
    }

    Write-Console ''
    for ($i = 0; $i -lt $reports.Count; $i++) {
        Write-Console ('  [{0,2}] {1}  {2}' -f ($i + 1), $reports[$i].Name, $reports[$i].LastWriteTime)
    }
    Write-Console '  [ 0] Cancel'

    $n = 0
    $raw = (Read-Host 'Select report').Trim()
    if (-not [int]::TryParse($raw, [ref]$n)) { return }
    if ($n -lt 1 -or $n -gt $reports.Count) { return }

    if (Test-WindowsFormsAvailable) {
        Start-Process notepad.exe -ArgumentList ('"{0}"' -f $reports[$n - 1].FullName)
    }
    else {
        Get-Content -LiteralPath $reports[$n - 1].FullName
    }
}

function Show-WindowsIdsInstallationGuidance {
    Write-Section 'Suricata Windows installation guidance'
    Write-Console 'For Windows end users, use the official Suricata Windows installer.' Cyan
    Write-Console 'Npcap is required for live passive packet capture.' Cyan
    Write-Console ''
    Write-Console 'The control plane intentionally does not download or silently install either component:' Gray
    Write-Console '  - Suricata is external to Windows Server servicing.' Gray
    Write-Console '  - Npcap installs a packet-capture driver on the Domain Controller.' Gray
    Write-Console '  - Driver installation/replacement should remain an explicit administrator action.' Gray
    Write-Console ''
    Write-Console 'Official documentation:' White
    Write-Console '  https://docs.suricata.io/en/latest/install/windows.html'
    Write-Console '  https://suricata.io/download/'

    if (Test-WindowsFormsAvailable) {
        if (Read-BooleanChoice -Prompt 'Open the official Suricata Windows documentation in the browser?' -Default $false) {
            Start-Process 'https://docs.suricata.io/en/latest/install/windows.html'
        }
    }
}

function Read-IdsAnalysisHours {
    Write-Console ''
    Write-Console '  [1] Last hour'
    Write-Console '  [2] Last 24 hours'
    Write-Console '  [3] Last 7 days'
    Write-Console '  [C] Custom hours'
    Write-Console '  [0] Cancel'

    $choice = (Read-Host 'Select analysis window [2]').Trim().ToUpperInvariant()
    if (-not $choice) { $choice = '2' }

    switch ($choice) {
        '1' { return 1 }
        '2' { return 24 }
        '3' { return 168 }
        'C' {
            $n = 0
            if ([int]::TryParse((Read-Host 'Hours'), [ref]$n) -and $n -ge 1 -and $n -le 8760) {
                return $n
            }
            return 0
        }
        default { return 0 }
    }
}

# ===========================================================================
# Wazuh + Suricata unified defense / guarded IPS
# ===========================================================================

function Get-WazuhWindowsInfo {
    $service = $null
    foreach ($name in @('WazuhSvc','wazuh','ossec-agent')) {
        try {
            $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name) -ErrorAction Stop
            if ($service) { break }
        }
        catch {}
    }
    if (-not $service) {
        try {
            $service = Get-CimInstance Win32_Service -ErrorAction Stop |
                Where-Object { $_.Name -match '(?i)wazuh|ossec' -or $_.DisplayName -match '(?i)wazuh|ossec' } |
                Select-Object -First 1
        }
        catch {}
    }

    $roots = @(
        "${env:ProgramFiles(x86)}\ossec-agent",
        "$env:ProgramFiles\Wazuh Agent",
        "$env:ProgramFiles\ossec-agent",
        'C:\Program Files (x86)\ossec-agent'
    ) | Where-Object { $_ }

    $root = $roots | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $config = $null
    $log = $null
    if ($root) {
        foreach ($candidate in @((Join-Path $root 'ossec.conf'),(Join-Path $root 'etc\ossec.conf'))) {
            if (Test-Path -LiteralPath $candidate) { $config = $candidate; break }
        }
        foreach ($candidate in @((Join-Path $root 'ossec.log'),(Join-Path $root 'logs\ossec.log'))) {
            if (Test-Path -LiteralPath $candidate) { $log = $candidate; break }
        }
    }

    $manager = $null
    $eveConfigured = $false
    if ($config -and (Test-Path -LiteralPath $config)) {
        try {
            $raw = Get-Content -LiteralPath $config -Raw -ErrorAction Stop
            if ($raw -match '(?is)<client>.*?<server>.*?<address>\s*([^<]+)\s*</address>') {
                $manager = $Matches[1].Trim()
            }
            $suricata = Get-WindowsSuricataInfo
            if ($suricata.EvePath -and $raw -match [regex]::Escape([string]$suricata.EvePath)) {
                $eveConfigured = $true
            }
        }
        catch {}
    }

    [pscustomobject]@{
        Installed     = [bool]($service -or $root)
        Service       = $service
        ServiceName   = $(if ($service) { [string]$service.Name } else { $null })
        ServiceState  = $(if ($service) { [string]$service.State } else { 'Not installed' })
        Root          = $root
        Config        = $config
        Log           = $log
        Manager       = $manager
        EveConfigured = $eveConfigured
    }
}

function Backup-SecurityIntegrationConfig {
    param([Parameter(Mandatory=$true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $backupDir = Join-Path $script:IdsStatePath 'backups'
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    $dest = Join-Path $backupDir ('{0}.{1}.bak' -f ([IO.Path]::GetFileName($Path)),(Get-Date -Format 'yyyyMMdd-HHmmss'))
    Copy-Item -LiteralPath $Path -Destination $dest -Force
    Write-Log ("Backed up security integration config: {0}" -f $dest) CHANGE
    return $dest
}

function Set-WazuhManagerAddress {
    $info = Get-WazuhWindowsInfo
    if (-not $info.Config) {
        Write-Console 'Wazuh agent configuration was not detected.' Yellow
        return
    }

    Write-Console ("Current Wazuh manager: {0}" -f $(if ($info.Manager) { $info.Manager } else { 'not configured' })) Gray
    $manager = (Read-Host 'Wazuh manager FQDN or IP').Trim()
    if ([string]::IsNullOrWhiteSpace($manager)) { return }
    if ($manager -notmatch '^[A-Za-z0-9._:-]+$') {
        Write-Console 'Manager value contains unsupported characters.' Red
        return
    }

    if (-not (Confirm-HighImpact -Action 'Change Wazuh manager address' -Reason ("Point the local Wazuh agent at {0}." -f $manager) -Impact 'The Wazuh service will restart.')) { return }

    $backup = Backup-SecurityIntegrationConfig -Path $info.Config
    try {
        $raw = Get-Content -LiteralPath $info.Config -Raw -ErrorAction Stop
        if ($raw -match '(?is)(<client>.*?<server>.*?<address>)(.*?)(</address>)') {
            $updated = [regex]::Replace(
                $raw,
                '(?is)(<client>.*?<server>.*?<address>)(.*?)(</address>)',
                ('$1' + $manager + '$3'),
                1
            )
        }
        else {
            $block = "<ossec_config>`r`n  <client>`r`n    <server>`r`n      <address>$manager</address>`r`n    </server>`r`n  </client>`r`n</ossec_config>`r`n"
            $updated = $raw.TrimEnd() + "`r`n" + $block
        }

        Set-Content -LiteralPath $info.Config -Value $updated -Encoding UTF8
        if ($info.ServiceName) {
            Restart-Service -Name $info.ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $svc = Get-Service -Name $info.ServiceName -ErrorAction Stop
            if ($svc.Status -ne 'Running') { throw 'Wazuh service did not return to Running state.' }
        }
        Write-Console 'Wazuh manager configuration updated and service is healthy.' Green
        Write-Log ("Wazuh manager changed to {0}." -f $manager) CHANGE
    }
    catch {
        Write-Console ("Wazuh manager update failed: {0}" -f $_.Exception.Message) Red
        if ($backup -and (Test-Path -LiteralPath $backup)) {
            Copy-Item -LiteralPath $backup -Destination $info.Config -Force
            if ($info.ServiceName) { try { Restart-Service -Name $info.ServiceName -Force -ErrorAction SilentlyContinue } catch {} }
            Write-Console 'Original Wazuh configuration restored.' Yellow
        }
    }
}

function Enable-WazuhSuricataIngestion {
    $wazuh = Get-WazuhWindowsInfo
    $suricata = Get-WindowsSuricataInfo
    if (-not $wazuh.Config) { Write-Console 'Wazuh agent is not installed/configured on this host.' Yellow; return }
    if (-not $suricata.EvePath) { Write-Console 'Suricata EVE JSON was not detected. Configure the EVE path first.' Yellow; return }

    $raw = Get-Content -LiteralPath $wazuh.Config -Raw -ErrorAction Stop
    if ($raw -match [regex]::Escape([string]$suricata.EvePath)) {
        Write-Console 'Wazuh already ingests the detected Suricata EVE file.' Green
        return
    }

    if (-not (Confirm-HighImpact -Action 'Integrate Suricata EVE with Wazuh' -Reason 'Add the local Suricata JSON event stream to the Wazuh agent configuration.' -Impact 'The Wazuh configuration will be backed up and the agent restarted.')) { return }

    $backup = Backup-SecurityIntegrationConfig -Path $wazuh.Config
    try {
        $block = "  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$($suricata.EvePath)</location>`r`n  </localfile>`r`n"
        if ($raw -notmatch '(?i)</ossec_config>\s*$') { throw 'Wazuh ossec.conf does not contain a closing ossec_config element.' }
        $updated = [regex]::Replace($raw,'(?i)</ossec_config>\s*$',($block + '</ossec_config>' + "`r`n"),1)
        Set-Content -LiteralPath $wazuh.Config -Value $updated -Encoding UTF8
        if ($wazuh.ServiceName) {
            Restart-Service -Name $wazuh.ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $svc = Get-Service -Name $wazuh.ServiceName -ErrorAction Stop
            if ($svc.Status -ne 'Running') { throw 'Wazuh service did not return to Running state.' }
        }
        [pscustomobject]@{ EvePath=[string]$suricata.EvePath; Configured=(Get-Date).ToString('o'); WazuhConfig=[string]$wazuh.Config } |
            ConvertTo-Json | Set-Content -LiteralPath $script:WazuhIntegrationFile -Encoding UTF8
        Write-Console 'Wazuh now ingests Suricata EVE JSON.' Green
        Write-Log 'Enabled Wazuh ingestion of Suricata EVE JSON.' CHANGE
    }
    catch {
        Write-Console ("Wazuh/Suricata integration failed: {0}" -f $_.Exception.Message) Red
        if ($backup -and (Test-Path -LiteralPath $backup)) {
            Copy-Item -LiteralPath $backup -Destination $wazuh.Config -Force
            Write-Console 'Original Wazuh configuration restored.' Yellow
        }
    }
}

function Show-WazuhIntegrationStatus {
    Write-Section 'Wazuh + Suricata integration'
    $wazuh = Get-WazuhWindowsInfo
    $suricata = Get-WindowsSuricataInfo
    Write-Console ("Wazuh installed : {0}" -f $wazuh.Installed)
    Write-Console ("Wazuh service   : {0}" -f $wazuh.ServiceState)
    Write-Console ("Wazuh manager   : {0}" -f $(if ($wazuh.Manager) { $wazuh.Manager } else { 'not detected' }))
    Write-Console ("Wazuh config    : {0}" -f $(if ($wazuh.Config) { $wazuh.Config } else { 'not detected' }))
    Write-Console ("Suricata        : {0}" -f $(if ($suricata.Installed) { 'installed' } else { 'not detected' }))
    Write-Console ("Suricata EVE    : {0}" -f $(if ($suricata.EvePath) { $suricata.EvePath } else { 'not detected' }))
    Write-Console ("EVE -> Wazuh    : {0}" -f $(if ($wazuh.EveConfigured) { 'configured' } else { 'not configured' }))
    if ($wazuh.Log -and (Test-Path -LiteralPath $wazuh.Log)) {
        Write-Console ''
        Write-Console 'Recent Wazuh agent signals:' Cyan
        Get-Content -LiteralPath $wazuh.Log -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object { Write-Console ("  {0}" -f $_) Gray }
    }
    Write-Console ''
    Write-Console 'Recommended posture: passive Suricata IDS + Wazuh correlation + guarded temporary firewall response.' Cyan
    Write-Console 'Inline Suricata/WinDivert blocking remains disabled by default on a Domain Controller.' Yellow
}

function Get-GuardedIpsState {
    Initialize-IdsState
    if (-not (Test-Path -LiteralPath $script:GuardedIpsStateFile)) {
        return [pscustomobject]@{ Enabled=$false; BlockMinutes=30; MaxRules=20; LastRun=$null; Rules=@() }
    }
    try { return Get-Content -LiteralPath $script:GuardedIpsStateFile -Raw -ErrorAction Stop | ConvertFrom-Json }
    catch { return [pscustomobject]@{ Enabled=$false; BlockMinutes=30; MaxRules=20; LastRun=$null; Rules=@() } }
}

function Save-GuardedIpsState {
    param([Parameter(Mandatory=$true)]$State)
    $State | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:GuardedIpsStateFile -Encoding UTF8
}

function Test-PublicIpForGuardedIps {
    param([Parameter(Mandatory=$true)][string]$Address)
    if (Test-DefenseIpTrusted -Address $Address) { return $false }
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address,[ref]$ip)) { return $false }
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    $b = $ip.GetAddressBytes()
    if ($b[0] -eq 10 -or $b[0] -eq 127) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 0 -or $b[0] -ge 224) { return $false }
    try {
        $local = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress)
        if ($local -contains $Address) { return $false }
    }
    catch {}
    return $true
}

function Get-GuardedIpsCandidates {
    param([int]$Hours=1,[int]$MaxEvents=5000)
    $info = Get-WindowsSuricataInfo
    if (-not $info.EvePath) { return @() }
    $cutoff = (Get-Date).ToUniversalTime().AddHours(-1 * $Hours)
    $events = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in Get-Content -LiteralPath $info.EvePath -Tail $MaxEvents -ErrorAction SilentlyContinue) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $evt = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($evt.event_type -ne 'alert' -or -not $evt.alert) { continue }
        $severity = 99
        try { $severity = [int]$evt.alert.severity } catch {}
        if ($severity -gt 1) { continue }
        $ts = $null
        try { $ts = ([datetime]$evt.timestamp).ToUniversalTime() } catch {}
        if ($ts -and $ts -lt $cutoff) { continue }
        $src = [string]$evt.src_ip
        if (-not (Test-PublicIpForGuardedIps -Address $src)) { continue }
        $events.Add([pscustomobject]@{ SourceIp=$src; Signature=[string]$evt.alert.signature; Severity=$severity; Timestamp=[string]$evt.timestamp })
    }
    return @($events | Group-Object SourceIp | Sort-Object Count -Descending | ForEach-Object {
        $sample = $_.Group | Select-Object -First 1
        [pscustomobject]@{ SourceIp=$_.Name; Count=$_.Count; Signature=$sample.Signature; Severity=$sample.Severity }
    })
}

function Remove-ExpiredGuardedIpsRules {
    $state = Get-GuardedIpsState
    $now = Get-Date
    $keep = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in @($state.Rules)) {
        $expires = $null
        try { $expires = [datetime]$entry.Expires } catch {}
        if (-not $expires -or $expires -le $now) {
            try { Remove-NetFirewallRule -Name ([string]$entry.RuleName) -ErrorAction SilentlyContinue } catch {}
        }
        else { $keep.Add($entry) }
    }
    $state.Rules = @($keep)
    $state.LastRun = (Get-Date).ToString('o')
    Save-GuardedIpsState -State $state
    return $keep.Count
}

function Register-GuardedIpsCleanupTask {
    if (-not (Test-Command 'Register-ScheduledTask')) { return }
    $scriptPath = $PSCommandPath
    if (-not $scriptPath -or -not (Test-Path -LiteralPath $scriptPath)) { return }
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode IDSResponseCleanup -NoColor -ExportPath "{1}"' -f $scriptPath,$ExportPath)
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $script:GuardedIpsTaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    }
    catch { Write-Log ("Could not register guarded IPS cleanup task: {0}" -f $_.Exception.Message) WARN }
}

function Invoke-GuardedIpsResponse {
    param([switch]$NonInteractive)
    [void](Remove-ExpiredGuardedIpsRules)
    $state = Get-GuardedIpsState
    if (-not $state.Enabled) { if (-not $NonInteractive) { Write-Console 'Guarded IPS is disabled.' Yellow }; return }
    $candidates = @(Get-GuardedIpsCandidates -Hours 1)
    if ($candidates.Count -eq 0) { if (-not $NonInteractive) { Write-Console 'No high-confidence public-source candidates were found.' Green }; return }
    $activeIps = @($state.Rules | ForEach-Object { [string]$_.SourceIp })
    $remaining = [math]::Max(0,[int]$state.MaxRules - @($state.Rules).Count)
    $newRules = New-Object 'System.Collections.Generic.List[object]'
    foreach ($candidate in $candidates) {
        if ($remaining -le 0) { break }
        if ($activeIps -contains [string]$candidate.SourceIp) { continue }
        $safeIp = ([string]$candidate.SourceIp) -replace '[^0-9A-Fa-f\.:]','_'
        $ruleName = '{0}{1}-{2}' -f $script:GuardedIpsRulePrefix,$safeIp,([guid]::NewGuid().ToString('N').Substring(0,8))
        $expires = (Get-Date).AddMinutes([int]$state.BlockMinutes)
        try {
            New-NetFirewallRule -Name $ruleName -DisplayName ("Windows AD Guarded IPS - {0}" -f $candidate.SourceIp) -Description ("Temporary Suricata severity-1 response; expires {0}; {1}" -f $expires.ToString('o'),$candidate.Signature) -Direction Inbound -Action Block -RemoteAddress ([string]$candidate.SourceIp) -Profile Any -ErrorAction Stop | Out-Null
            $newRules.Add([pscustomobject]@{ RuleName=$ruleName; SourceIp=[string]$candidate.SourceIp; Created=(Get-Date).ToString('o'); Expires=$expires.ToString('o'); Signature=[string]$candidate.Signature; AlertCount=[int]$candidate.Count })
            $remaining--
            Write-Log ("Guarded IPS temporarily blocked {0}; signature={1}" -f $candidate.SourceIp,$candidate.Signature) CHANGE
        }
        catch { Write-Log ("Guarded IPS could not block {0}: {1}" -f $candidate.SourceIp,$_.Exception.Message) WARN }
    }
    $state.Rules = @($state.Rules) + @($newRules)
    $state.LastRun = (Get-Date).ToString('o')
    Save-GuardedIpsState -State $state
    if (-not $NonInteractive) { Write-Console ("Created {0} temporary firewall block rule(s)." -f $newRules.Count) Green }
}

function Enable-GuardedIps {
    $suricata = Get-WindowsSuricataInfo
    if (-not $suricata.EvePath) { Write-Console 'Suricata EVE JSON is required before guarded IPS can be enabled.' Yellow; return }
    Write-Section 'Guarded IPS safety profile'
    Write-Console 'Only Suricata severity-1 alerts from public IPv4 sources are eligible.' Cyan
    Write-Console 'Private/local/domain infrastructure is never auto-blocked. Rules expire after 30 minutes.' Gray
    Write-Console 'At most 20 assistant-managed block rules may coexist.' Gray
    Write-Console 'Inline Suricata/WinDivert blocking remains disabled on the Domain Controller.' Yellow
    $preview = @(Get-GuardedIpsCandidates -Hours 1)
    Write-Console ("Current eligible candidates: {0}" -f $preview.Count) Gray
    $preview | Select-Object -First 10 | ForEach-Object { Write-Console ("  {0,-16} alerts={1,-3} {2}" -f $_.SourceIp,$_.Count,$_.Signature) Gray }
    if (-not (Confirm-HighImpact -Action 'Enable guarded IPS response' -Reason 'Permit temporary Windows Firewall blocks derived from high-confidence Suricata alerts.' -Impact 'A false positive could temporarily block an external source; managed rules expire and can be disabled immediately.')) { return }
    $state = Get-GuardedIpsState
    $state.Enabled = $true
    $cfg = Get-DefenseOpsConfig
    $state.BlockMinutes = [int]$cfg.BlockMinutes
    $state.MaxRules = 20
    Save-GuardedIpsState -State $state
    Register-GuardedIpsCleanupTask
    Invoke-GuardedIpsResponse
    Write-Console 'Guarded IPS response enabled.' Green
}

function Disable-GuardedIps {
    $state = Get-GuardedIpsState
    $state.Enabled = $false
    foreach ($entry in @($state.Rules)) { try { Remove-NetFirewallRule -Name ([string]$entry.RuleName) -ErrorAction SilentlyContinue } catch {} }
    $state.Rules = @()
    Save-GuardedIpsState -State $state
    try { Unregister-ScheduledTask -TaskName $script:GuardedIpsTaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Write-Console 'Guarded IPS disabled and assistant-managed firewall blocks removed.' Green
}

function Show-GuardedIpsStatus {
    [void](Remove-ExpiredGuardedIpsRules)
    $state = Get-GuardedIpsState
    Write-Section 'Guarded IPS status'
    Write-Console ("Enabled       : {0}" -f $state.Enabled)
    Write-Console ("Block TTL     : {0} minutes" -f $state.BlockMinutes)
    Write-Console ("Rule ceiling  : {0}" -f $state.MaxRules)
    Write-Console ("Active blocks : {0}" -f @($state.Rules).Count)
    Write-Console ("Last run      : {0}" -f $(if ($state.LastRun) { $state.LastRun } else { 'never' }))
    foreach ($rule in @($state.Rules)) { Write-Console ("  {0,-16} expires={1}  {2}" -f $rule.SourceIp,$rule.Expires,$rule.Signature) Gray }
}


function Get-DefenseOpsConfig {
    Initialize-IdsState
    $defaults = [ordered]@{
        SchemaVersion=1
        BusinessStart='08:00'
        BusinessEnd='18:00'
        BusinessDays=@('Monday','Tuesday','Wednesday','Thursday','Friday')
        DayAlertSeverity=1
        AfterHoursAlertSeverity=2
        DayWindowHours=1
        AfterHoursWindowHours=4
        BlockMinutes=30
        TelegramEnabled=$false
        TelegramChatId=''
        TrustedIps=@()
        LastAlertFingerprint=''
        LastAlertSentAt=$null
    }
    if (-not (Test-Path -LiteralPath $script:DefenseOpsConfigFile)) {
        [pscustomobject]$defaults | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:DefenseOpsConfigFile -Encoding UTF8
        return [pscustomobject]$defaults
    }
    try {
        $cfg = Get-Content -LiteralPath $script:DefenseOpsConfigFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach($k in $defaults.Keys) {
            if (-not $cfg.PSObject.Properties[$k]) {
                $cfg | Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k]
            }
        }
        return $cfg
    }
    catch {
        Write-Log ("Defense operations config unreadable; using defaults: {0}" -f $_.Exception.Message) WARN
        return [pscustomobject]$defaults
    }
}

function Save-DefenseOpsConfig {
    param([Parameter(Mandatory=$true)]$Config)
    Initialize-IdsState
    $Config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $script:DefenseOpsConfigFile -Encoding UTF8
}

function Test-DefenseIpTrusted {
    param([Parameter(Mandatory=$true)][string]$Address)
    $cfg=Get-DefenseOpsConfig
    return (@($cfg.TrustedIps) -contains $Address)
}

function Test-DefenseBusinessHours {
    param([datetime]$Now=(Get-Date))
    $cfg=Get-DefenseOpsConfig
    if (@($cfg.BusinessDays) -notcontains $Now.DayOfWeek.ToString()) { return $false }
    try {
        $start=[TimeSpan]::Parse([string]$cfg.BusinessStart)
        $end=[TimeSpan]::Parse([string]$cfg.BusinessEnd)
        $t=$Now.TimeOfDay
        if($start -le $end){ return ($t -ge $start -and $t -lt $end) }
        return ($t -ge $start -or $t -lt $end)
    } catch { return $true }
}

function Get-DefenseAwarenessProfile {
    $cfg=Get-DefenseOpsConfig
    $business=Test-DefenseBusinessHours
    if($business){
        return [pscustomobject]@{BusinessHours=$true;Severity=[int]$cfg.DayAlertSeverity;WindowHours=[int]$cfg.DayWindowHours;Label='business-hours'}
    }
    return [pscustomobject]@{BusinessHours=$false;Severity=[int]$cfg.AfterHoursAlertSeverity;WindowHours=[int]$cfg.AfterHoursWindowHours;Label='after-hours'}
}

function Protect-DefenseSecret {
    param([Parameter(Mandatory=$true)][string]$PlainText)
    $bytes=[Text.Encoding]::UTF8.GetBytes($PlainText)
    $protected=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
    return [Convert]::ToBase64String($protected)
}

function Unprotect-DefenseSecret {
    param([Parameter(Mandatory=$true)][string]$Encoded)
    try{
        $bytes=[Convert]::FromBase64String($Encoded)
        $plain=[Security.Cryptography.ProtectedData]::Unprotect($bytes,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
        return [Text.Encoding]::UTF8.GetString($plain)
    }catch{return $null}
}

function Set-DefenseTelegramHook {
    Initialize-IdsState
    $cfg=Get-DefenseOpsConfig
    $chat=(Read-Host ("Telegram chat/channel ID [{0}]" -f $(if($cfg.TelegramChatId){$cfg.TelegramChatId}else{'not configured'}))).Trim()
    if([string]::IsNullOrWhiteSpace($chat)){ $chat=[string]$cfg.TelegramChatId }
    $secure=Read-Host 'Telegram bot token (input hidden; leave blank to keep current)' -AsSecureString
    $token=''
    $ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try{ $token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
    if($token){
        (Protect-DefenseSecret -PlainText $token) | Set-Content -LiteralPath $script:TelegramTokenFile -Encoding ASCII
    }
    if(-not (Test-Path -LiteralPath $script:TelegramTokenFile)){
        Write-Console 'No Telegram bot token is stored; hook was not enabled.' Yellow
        return
    }
    $cfg.TelegramChatId=$chat
    $cfg.TelegramEnabled=$true
    Save-DefenseOpsConfig -Config $cfg
    Write-Console 'Telegram alert hook enabled. The token is protected with Windows DPAPI (LocalMachine).' Green
}

function Get-DefenseTelegramToken {
    if(-not(Test-Path -LiteralPath $script:TelegramTokenFile)){return $null}
    $encoded=(Get-Content -LiteralPath $script:TelegramTokenFile -Raw -ErrorAction SilentlyContinue).Trim()
    if(-not $encoded){return $null}
    return Unprotect-DefenseSecret -Encoded $encoded
}

function Send-DefenseTelegramMessage {
    param([Parameter(Mandatory=$true)][string]$Text,[switch]$Quiet)
    $cfg=Get-DefenseOpsConfig
    if(-not $cfg.TelegramEnabled){if(-not $Quiet){Write-Console 'Telegram notifications are disabled.' Yellow};return $false}
    if([string]::IsNullOrWhiteSpace([string]$cfg.TelegramChatId)){if(-not $Quiet){Write-Console 'Telegram chat ID is not configured.' Yellow};return $false}
    $token=Get-DefenseTelegramToken
    if(-not $token){if(-not $Quiet){Write-Console 'Telegram bot token could not be read.' Yellow};return $false}
    try{
        $uri='https://api.telegram.org/bot{0}/sendMessage' -f $token
        $body=@{chat_id=[string]$cfg.TelegramChatId;text=$Text;disable_web_page_preview='true'}
        [void](Invoke-RestMethod -Method Post -Uri $uri -Body $body -TimeoutSec 15 -ErrorAction Stop)
        return $true
    }catch{
        Write-Log ("Telegram notification failed: {0}" -f $_.Exception.Message) WARN
        if(-not $Quiet){Write-Console ("Telegram notification failed: {0}" -f $_.Exception.Message) Yellow}
        return $false
    }
}

function Get-DefenseAwarenessAlerts {
    param([int]$Hours=0,[int]$Severity=0,[int]$MaxEvents=8000)
    $profile=Get-DefenseAwarenessProfile
    if($Hours -le 0){$Hours=[int]$profile.WindowHours}
    if($Severity -le 0){$Severity=[int]$profile.Severity}
    $info=Get-WindowsSuricataInfo
    if(-not $info.EvePath){return @()}
    $cutoff=(Get-Date).ToUniversalTime().AddHours(-1*$Hours)
    $rows=New-Object 'System.Collections.Generic.List[object]'
    foreach($line in Get-Content -LiteralPath $info.EvePath -Tail $MaxEvents -ErrorAction SilentlyContinue){
        if([string]::IsNullOrWhiteSpace($line)){continue}
        try{$evt=$line|ConvertFrom-Json -ErrorAction Stop}catch{continue}
        if($evt.event_type -ne 'alert' -or -not $evt.alert){continue}
        $sev=99;try{$sev=[int]$evt.alert.severity}catch{}
        if($sev -gt $Severity){continue}
        $ts=$null;try{$ts=([datetime]$evt.timestamp).ToUniversalTime()}catch{}
        if($ts -and $ts -lt $cutoff){continue}
        $src=[string]$evt.src_ip
        if(-not $src){continue}
        $rows.Add([pscustomobject]@{Timestamp=[string]$evt.timestamp;SourceIp=$src;DestinationIp=[string]$evt.dest_ip;Severity=$sev;Signature=[string]$evt.alert.signature;Category=[string]$evt.alert.category;Action=[string]$evt.alert.action})
    }
    return @($rows|Sort-Object Timestamp -Descending)
}

function Invoke-DefenseAwarenessCheck {
    param([switch]$Notify)
    $profile=Get-DefenseAwarenessProfile
    $alerts=@(Get-DefenseAwarenessAlerts -Hours $profile.WindowHours -Severity $profile.Severity)
    Write-Section ("Defense awareness - {0}" -f $profile.Label)
    Write-Console ("Window       : {0}h" -f $profile.WindowHours)
    Write-Console ("Alert level  : severity <= {0}" -f $profile.Severity)
    Write-Console ("Matching     : {0}" -f $alerts.Count)
    $alerts|Select-Object -First 20|ForEach-Object{
        $trusted=if(Test-DefenseIpTrusted -Address $_.SourceIp){' TRUSTED'}else{''}
        Write-Console ("  sev={0} {1,-16} {2}{3}" -f $_.Severity,$_.SourceIp,$_.Signature,$trusted) Gray
    }
    if($Notify -and $alerts.Count -gt 0){
        $top=@($alerts|Group-Object SourceIp|Sort-Object Count -Descending|Select-Object -First 5)
        $fp=($top|ForEach-Object{"$($_.Name):$($_.Count)"}) -join '|'
        $cfg=Get-DefenseOpsConfig
        if($fp -ne [string]$cfg.LastAlertFingerprint){
            $lines=@(
                "Windows AD defense alert ($($profile.Label))",
                "Host: $env:COMPUTERNAME",
                "Window: $($profile.WindowHours)h | Matches: $($alerts.Count)",
                "Review manually in IDS > Suricata + Wazuh defense."
            )
            foreach($g in $top){$lines+=("Source {0}: {1} alert(s)" -f $g.Name,$g.Count)}
            if(Send-DefenseTelegramMessage -Text ($lines -join "`n") -Quiet){
                $cfg.LastAlertFingerprint=$fp;$cfg.LastAlertSentAt=(Get-Date).ToString('o');Save-DefenseOpsConfig -Config $cfg
                Write-Console 'Telegram alert sent.' Green
            }
        } else { Write-Console 'Alert fingerprint already notified; duplicate notification suppressed.' Gray }
    }
}

function Add-GuardedIpsManualBlock {
    param([string]$Address,[int]$Minutes=0)
    if(-not $Address){$Address=(Read-Host 'IPv4 address to block').Trim()}
    $ip=$null
    if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){Write-Console 'Invalid IPv4 address.' Yellow;return}
    if(Test-DefenseIpTrusted -Address $Address){Write-Console 'This address is in the trusted-IP list. Remove it from trusted IPs before blocking.' Yellow;return}
    $cfg=Get-DefenseOpsConfig
    if($Minutes -le 0){$Minutes=[int]$cfg.BlockMinutes}
    $state=Get-GuardedIpsState
    if(@($state.Rules|ForEach-Object{$_.SourceIp}) -contains $Address){Write-Console 'Address is already blocked by the assistant.' Yellow;return}
    $safeIp=$Address -replace '[^0-9A-Fa-f\.:]','_'
    $ruleName='{0}{1}-{2}' -f $script:GuardedIpsRulePrefix,$safeIp,([guid]::NewGuid().ToString('N').Substring(0,8))
    $expires=(Get-Date).AddMinutes($Minutes)
    New-NetFirewallRule -Name $ruleName -DisplayName ("Windows AD Manual IPS - {0}" -f $Address) -Description ("Operator temporary block; expires {0}" -f $expires.ToString('o')) -Direction Inbound -Action Block -RemoteAddress $Address -Profile Any -ErrorAction Stop|Out-Null
    $entry=[pscustomobject]@{RuleName=$ruleName;SourceIp=$Address;Created=(Get-Date).ToString('o');Expires=$expires.ToString('o');Signature='Manual operator block';AlertCount=0}
    $state.Rules=@($state.Rules)+@($entry);Save-GuardedIpsState -State $state
    Write-Log ("Operator temporarily blocked {0} for {1} minutes." -f $Address,$Minutes) CHANGE
    Write-Console ("Blocked {0} for {1} minutes." -f $Address,$Minutes) Green
}

function Remove-GuardedIpsBlock {
    param([string]$Address)
    [void](Remove-ExpiredGuardedIpsRules)
    $state=Get-GuardedIpsState
    if(-not $Address){$Address=(Read-Host 'IPv4 address to unblock').Trim()}
    $matches=@($state.Rules|Where-Object{[string]$_.SourceIp -eq $Address})
    if($matches.Count -eq 0){Write-Console 'No assistant-managed active block was found for that address.' Yellow;return}
    foreach($entry in $matches){try{Remove-NetFirewallRule -Name ([string]$entry.RuleName) -ErrorAction SilentlyContinue}catch{}}
    $state.Rules=@($state.Rules|Where-Object{[string]$_.SourceIp -ne $Address})
    Save-GuardedIpsState -State $state
    Write-Log ("Operator unblocked {0}." -f $Address) CHANGE
    Write-Console ("Unblocked {0}." -f $Address) Green
}

function Remove-AllGuardedIpsBlocks {
    $state=Get-GuardedIpsState
    foreach($entry in @($state.Rules)){try{Remove-NetFirewallRule -Name ([string]$entry.RuleName) -ErrorAction SilentlyContinue}catch{}}
    $state.Rules=@();Save-GuardedIpsState -State $state
    Write-Log 'Operator removed all assistant-managed IPS block rules.' CHANGE
    Write-Console 'All assistant-managed temporary blocks were removed.' Green
}

function Add-DefenseTrustedIp {
    param([string]$Address)
    if(-not $Address){$Address=(Read-Host 'IPv4 address to trust').Trim()}
    $ip=$null
    if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){Write-Console 'Invalid IPv4 address.' Yellow;return}
    $cfg=Get-DefenseOpsConfig
    $trusted=@($cfg.TrustedIps)
    if($trusted -notcontains $Address){$cfg.TrustedIps=@($trusted+$Address);Save-DefenseOpsConfig -Config $cfg}
    Remove-GuardedIpsBlock -Address $Address
    Write-Console ("Trusted IP added: {0}" -f $Address) Green
}

function Remove-DefenseTrustedIp {
    $cfg=Get-DefenseOpsConfig
    if(@($cfg.TrustedIps).Count -eq 0){Write-Console 'Trusted-IP list is empty.' Gray;return}
    @($cfg.TrustedIps)|ForEach-Object{Write-Console ("  {0}" -f $_) Gray}
    $address=(Read-Host 'IPv4 address to remove from trusted list').Trim()
    $cfg.TrustedIps=@($cfg.TrustedIps|Where-Object{$_ -ne $address});Save-DefenseOpsConfig -Config $cfg
    Write-Console ("Trusted IP removed: {0}" -f $address) Green
}

function Register-DefenseAwarenessTask {
    if (-not (Test-Command 'Register-ScheduledTask')) { Write-Console 'Scheduled Task cmdlets are unavailable.' Yellow; return }
    if (-not $PSCommandPath) { Write-Console 'The current script path is unavailable.' Yellow; return }
    $name='WindowsADControlPlane-DefenseAwareness'
    try{
        $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode IDSAwarenessCheck -NoColor -ExportPath "{1}"' -f $PSCommandPath,$ExportPath)
        $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)
        $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Force|Out-Null
        Write-Console 'Defense awareness notification task enabled (every 15 minutes).' Green
    }catch{Write-Console ("Could not register awareness task: {0}" -f $_.Exception.Message) Yellow}
}

function Set-DefenseAwarenessSchedule {
    $cfg=Get-DefenseOpsConfig
    Write-Section 'IDS / IPS awareness schedule'
    Write-Console 'Outside business hours the assistant expands the review window and can notify on lower-severity Suricata alerts.' Cyan
    Write-Console 'Automatic firewall blocking remains severity-1 only unless you manually block an address.' Yellow
    $start=(Read-Host ("Business start HH:mm [{0}]" -f $cfg.BusinessStart)).Trim();if(-not $start){$start=[string]$cfg.BusinessStart}
    $end=(Read-Host ("Business end HH:mm [{0}]" -f $cfg.BusinessEnd)).Trim();if(-not $end){$end=[string]$cfg.BusinessEnd}
    try{[void][TimeSpan]::Parse($start);[void][TimeSpan]::Parse($end)}catch{Write-Console 'Invalid time value.' Yellow;return}
    $dayWin=(Read-Host ("Business-hours review window (hours) [{0}]" -f $cfg.DayWindowHours)).Trim();if(-not $dayWin){$dayWin=[string]$cfg.DayWindowHours}
    $nightWin=(Read-Host ("After-hours review window (hours) [{0}]" -f $cfg.AfterHoursWindowHours)).Trim();if(-not $nightWin){$nightWin=[string]$cfg.AfterHoursWindowHours}
    $ttl=(Read-Host ("Temporary block duration (minutes) [{0}]" -f $cfg.BlockMinutes)).Trim();if(-not $ttl){$ttl=[string]$cfg.BlockMinutes}
    $cfg.BusinessStart=$start;$cfg.BusinessEnd=$end;$cfg.DayWindowHours=[math]::Max(1,[int]$dayWin);$cfg.AfterHoursWindowHours=[math]::Max(1,[int]$nightWin);$cfg.BlockMinutes=[math]::Max(1,[int]$ttl)
    Save-DefenseOpsConfig -Config $cfg
    $ips=Get-GuardedIpsState;$ips.BlockMinutes=[int]$cfg.BlockMinutes;Save-GuardedIpsState -State $ips
    Write-Console 'Awareness schedule updated.' Green
}

function Show-DefenseBlockManagement {
    while($true){
        [void](Remove-ExpiredGuardedIpsRules)
        $state=Get-GuardedIpsState;$cfg=Get-DefenseOpsConfig
        Write-Section 'Blocked / trusted IP management'
        Write-Console ("Active temporary blocks: {0}" -f @($state.Rules).Count)
        foreach($r in @($state.Rules)){Write-Console ("  {0,-16} expires={1}  {2}" -f $r.SourceIp,$r.Expires,$r.Signature) Gray}
        Write-Console ("Trusted IPs: {0}" -f $(if(@($cfg.TrustedIps).Count){(@($cfg.TrustedIps)-join ', ')}else{'none'})) Gray
        Write-Console ''
        Write-Console '  [1] Unblock one IP'
        Write-Console '  [2] Unblock all assistant-managed IPs'
        Write-Console '  [3] Add manual temporary block'
        Write-Console '  [4] Trust IP (also unblocks it)'
        Write-Console '  [5] Remove trusted IP'
        Write-Console '  [0] Back'
        switch((Read-Host 'Select operation').Trim().ToUpperInvariant()){
            '1'{Remove-GuardedIpsBlock}
            '2'{if(Read-BooleanChoice -Prompt 'Remove all assistant-managed block rules now?' -Default $false){Remove-AllGuardedIpsBlocks}}
            '3'{Add-GuardedIpsManualBlock}
            '4'{Add-DefenseTrustedIp}
            '5'{Remove-DefenseTrustedIp}
            '0'{return}
            default{Write-Console 'Invalid option.' Yellow}
        }
    }
}

function Show-DefenseOperationsGui {
    if(-not(Test-WindowsFormsAvailable)){Write-Console 'Windows Forms is unavailable; opening console management.' Yellow;Show-DefenseBlockManagement;return}
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    $form=New-Object System.Windows.Forms.Form
    $form.Text=(Get-UiText 'Windows AD Defense Center - Suricata + Wazuh')
    $form.Width=1180;$form.Height=760;$form.StartPosition='CenterScreen'
    $status=New-Object System.Windows.Forms.Label;$status.Dock='Top';$status.Height=55;$status.Padding=New-Object System.Windows.Forms.Padding(10)
    $tabs=New-Object System.Windows.Forms.TabControl;$tabs.Dock='Fill'
    $blockTab=New-Object System.Windows.Forms.TabPage;$blockTab.Text=(Get-UiText 'Blocked / trusted IPs')
    $grid=New-Object System.Windows.Forms.DataGridView;$grid.Dock='Fill';$grid.ReadOnly=$true;$grid.SelectionMode='FullRowSelect';$grid.AutoSizeColumnsMode='Fill';$grid.AllowUserToAddRows=$false
    $buttons=New-Object System.Windows.Forms.FlowLayoutPanel;$buttons.Dock='Bottom';$buttons.Height=48
    foreach($spec in @(
        @('Refresh','refresh'),@('Unblock selected','unblock'),@('Unblock all','unblockall'),@('Block IP','block'),@('Trust selected','trust'),@('Run IPS now','runips')
    )){
        $b=New-Object System.Windows.Forms.Button;$b.Text=(Get-UiText ([string]$spec[0]));$b.Tag=$spec[1];$b.AutoSize=$true;[void]$buttons.Controls.Add($b)
    }
    [void]$blockTab.Controls.Add($grid);[void]$blockTab.Controls.Add($buttons)
    $alertTab=New-Object System.Windows.Forms.TabPage;$alertTab.Text=(Get-UiText 'Awareness alerts')
    $alertGrid=New-Object System.Windows.Forms.DataGridView;$alertGrid.Dock='Fill';$alertGrid.ReadOnly=$true;$alertGrid.AutoSizeColumnsMode='Fill';$alertGrid.AllowUserToAddRows=$false
    [void]$alertTab.Controls.Add($alertGrid)
    $helpTab=New-Object System.Windows.Forms.TabPage;$helpTab.Text=(Get-UiText 'Operations')
    $help=New-Object System.Windows.Forms.TextBox;$help.Dock='Fill';$help.Multiline=$true;$help.ReadOnly=$true;$help.ScrollBars='Vertical'
    $help.Text="Use this window for fast response.`r`n`r`n- Unblock false positives immediately.`r`n- Trust known partner/public IPs to prevent future assistant auto-blocks.`r`n- Manual blocks use the configured TTL.`r`n- After-hours awareness expands the detection window and notification threshold.`r`n- Wazuh is the correlation/agent layer; Suricata remains the network sensor."
    [void]$helpTab.Controls.Add($help)
    [void]$tabs.TabPages.Add($blockTab);[void]$tabs.TabPages.Add($alertTab);[void]$tabs.TabPages.Add($helpTab)
    [void]$form.Controls.Add($tabs);[void]$form.Controls.Add($status)
    $refreshAction={
        [void](Remove-ExpiredGuardedIpsRules)
        $state=Get-GuardedIpsState;$cfg=Get-DefenseOpsConfig;$profile=Get-DefenseAwarenessProfile;$w=Get-WazuhWindowsInfo;$s=Get-WindowsSuricataInfo
        $status.Text=("Suricata={0} | Wazuh={1} | GuardedIPS={2} | {3}: {4}h / sev<={5}" -f $s.ServiceState,$w.ServiceState,$state.Enabled,$profile.Label,$profile.WindowHours,$profile.Severity)
        $grid.DataSource=$null;$grid.DataSource=@($state.Rules|Select-Object SourceIp,Created,Expires,Signature,AlertCount)
        $alertGrid.DataSource=$null;$alertGrid.DataSource=@(Get-DefenseAwarenessAlerts -Hours $profile.WindowHours -Severity $profile.Severity|Select-Object -First 200)
    }.GetNewClosure()
    foreach($ctrl in @($buttons.Controls)){
        $ctrl.Add_Click({
            $action=[string]$this.Tag
            try{
                switch($action){
                    'refresh'{}
                    'unblock'{if($grid.SelectedRows.Count -gt 0){Remove-GuardedIpsBlock -Address ([string]$grid.SelectedRows[0].Cells['SourceIp'].Value)}}
                    'unblockall'{if([System.Windows.Forms.MessageBox]::Show('Remove all assistant-managed blocks now?','Confirm','YesNo','Warning') -eq 'Yes'){Remove-AllGuardedIpsBlocks}}
                    'block'{
                        Add-Type -AssemblyName Microsoft.VisualBasic
                        $ip=[Microsoft.VisualBasic.Interaction]::InputBox('IPv4 address to block temporarily','Manual block','')
                        if($ip){Add-GuardedIpsManualBlock -Address $ip}
                    }
                    'trust'{if($grid.SelectedRows.Count -gt 0){Add-DefenseTrustedIp -Address ([string]$grid.SelectedRows[0].Cells['SourceIp'].Value)}}
                    'runips'{Invoke-GuardedIpsResponse -NonInteractive}
                }
                & $refreshAction
            }catch{[System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Defense operation','OK','Error')|Out-Null}
        }.GetNewClosure())
    }
    & $refreshAction
    [void]$form.ShowDialog();$form.Dispose()
}

function Show-WazuhDefenseMenu {
    while ($true) {
        Write-MenuHeader 'SURICATA + WAZUH DEFENSE' 'Telemetry, rapid unblock/trust actions, awareness scheduling and guarded response'
        Write-MenuItem '1' 'Unified status' 'Suricata sensor + Wazuh agent + EVE ingestion'
        Write-MenuItem '2' 'Configure Wazuh manager' 'Change the local agent manager address with backup/rollback' Warn
        Write-MenuItem '3' 'Enable EVE ingestion' 'Feed Suricata JSON events into the Wazuh agent' Good
        Write-MenuItem '4' 'Guarded IPS status' 'Temporary firewall response state and active blocks'
        Write-MenuItem '5' 'Enable guarded IPS' 'High-confidence public-source temporary blocks' Warn
        Write-MenuItem '6' 'Run guarded IPS now' 'Evaluate recent Suricata severity-1 alerts'
        Write-MenuItem '7' 'Disable guarded IPS' 'Remove assistant-managed response rules' Danger
        Write-MenuItem '8' 'Wazuh install guidance' 'Use the official Wazuh Windows agent package'
        Write-MenuItem '9' 'Defense GUI' 'GUI for alerts, blocks, rapid unblock and trusted IP actions' Good
        Write-MenuItem '10' 'Blocked / trusted IPs' 'Console management for false positives and temporary blocks'
        Write-MenuItem '11' 'Awareness schedule' 'Business hours, after-hours review window and block duration'
        Write-MenuItem '12' 'Telegram alert hook' 'Configure/test admin notifications without automatic chat-side changes'
        Write-MenuItem '13' 'Run awareness check' 'Review current window and optionally notify Telegram'
        Write-MenuNavigation
        Write-Rule
        switch ((Read-MenuChoice -Default '1').ToUpperInvariant()) {
            '1' { Show-WazuhIntegrationStatus; Pause-ControlPlane }
            '2' { Set-WazuhManagerAddress; Pause-ControlPlane }
            '3' { Enable-WazuhSuricataIngestion; Pause-ControlPlane }
            '4' { Show-GuardedIpsStatus; Pause-ControlPlane }
            '5' { Enable-GuardedIps; Pause-ControlPlane }
            '6' { Invoke-GuardedIpsResponse; Pause-ControlPlane }
            '7' { if (Read-BooleanChoice -Prompt 'Disable guarded IPS and remove all assistant-managed block rules?' -Default $false) { Disable-GuardedIps }; Pause-ControlPlane }
            '8' { Write-Section 'Wazuh Windows agent installation'; Write-Console 'Install the official Wazuh Windows agent package, then return here.' Cyan; Write-Console 'The assistant never downloads or executes third-party installers silently.' Gray; Pause-ControlPlane }
            '9' { Show-DefenseOperationsGui }
            '10' { Show-DefenseBlockManagement; Pause-ControlPlane }
            '11' { Set-DefenseAwarenessSchedule; Pause-ControlPlane }
            '12' {
                Write-Section 'Telegram alert hook'
                Write-Console 'The bot token is encrypted with Windows DPAPI and never written to logs.' Gray
                Write-Console 'Telegram notifications are advisory. Blocking/unblocking remains an explicit assistant action.' Cyan
                if(Read-BooleanChoice -Prompt 'Configure or replace the Telegram hook?' -Default $true){Set-DefenseTelegramHook}
                if(Read-BooleanChoice -Prompt 'Send a test notification now?' -Default $false){[void](Send-DefenseTelegramMessage -Text ("Windows AD Control Plane test alert from {0} at {1}" -f $env:COMPUTERNAME,(Get-Date)))}
                if(Read-BooleanChoice -Prompt 'Enable the 15-minute defense awareness notification task?' -Default $true){Register-DefenseAwarenessTask}
                Pause-ControlPlane
            }
            '13' { Invoke-DefenseAwarenessCheck -Notify; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-WindowsIdsMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }

        Write-MenuHeader 'NETWORK IDS / SURICATA' 'Optional passive detection, EVE analytics, AD protocol intelligence and native GUI'
        Write-MenuItem '1' 'IDS readiness' 'Suricata, Npcap, service, capture posture and EVE path'
        Write-MenuItem '2' 'Sensor health' 'Config test, EVE freshness and packet-drop telemetry'
        Write-MenuItem '3' 'Security summary' 'Alerts, DNS, Kerberos, SMB/NTLM and decision triggers'
        Write-MenuItem '4' 'Recent alerts' 'Console alert timeline'
        Write-MenuItem '5' 'AD protocol intelligence' 'Kerberos encryption, weak crypto, SMB dialects and NTLMSSP'
        Write-MenuItem '6' 'GUI dashboard' 'Native Windows Forms read-only IDS dashboard' Good
        Write-MenuItem '7' 'Configure EVE path' 'Use when auto-discovery cannot locate eve.json'
        Write-MenuItem '8' 'Update rules' 'Use detected suricata-update, validate config and restart service' Warn
        Write-MenuItem '9' 'Daily reports' 'Generate/view reports or register a SYSTEM scheduled task'
        Write-MenuItem '10' 'Installation guidance' 'Official Suricata installer + explicit Npcap driver installation'
        Write-MenuItem '11' 'Suricata + Wazuh defense' 'Unified telemetry, EVE correlation and guarded IPS response' Good
        Write-MenuNavigation
        Write-Rule

        try {
        switch (Read-MenuChoice -Default '1') {
            '1' { Show-WindowsIdsReadiness; Pause-ControlPlane }
            '2' { Show-WindowsIdsSensorHealth; Pause-ControlPlane }
            '3' {
                $hours = Read-IdsAnalysisHours
                if ($hours -gt 0) { Show-WindowsIdsSummary -Hours $hours }
                Pause-ControlPlane
            }
            '4' {
                $hours = Read-IdsAnalysisHours
                if ($hours -gt 0) { Show-WindowsIdsRecentAlerts -Hours $hours }
                Pause-ControlPlane
            }
            '5' {
                $hours = Read-IdsAnalysisHours
                if ($hours -gt 0) { Show-WindowsIdsAdIntelligence -Hours $hours }
                Pause-ControlPlane
            }
            '6' { Show-WindowsIdsDashboardGui }
            '7' { Set-WindowsSuricataEvePath; Pause-ControlPlane }
            '8' { Invoke-WindowsSuricataRuleUpdate; Pause-ControlPlane }
            '9' {
                Write-Console ''
                Write-Console '  [1] Generate 24h report now'
                Write-Console '  [2] View generated reports'
                Write-Console '  [3] Enable/refresh daily scheduled task'
                Write-Console '  [4] Disable daily scheduled task'
                Write-Console '  [0] Cancel'
                $sub = (Read-Host 'Select report operation [1]').Trim()
                if (-not $sub) { $sub = '1' }

                switch ($sub) {
                    '1' {
                        try {
                            $path = Export-WindowsIdsDailyReport -Hours 24
                            Write-Console ("Report: {0}" -f $path) Green
                        }
                        catch { Write-Console $_.Exception.Message Red }
                    }
                    '2' { Show-WindowsIdsReports }
                    '3' { Register-WindowsIdsDailyTask }
                    '4' {
                        if (Test-Command 'Unregister-ScheduledTask') {
                            Unregister-ScheduledTask -TaskName $script:IdsTaskName -Confirm:$false -ErrorAction SilentlyContinue
                            Write-Console 'Daily IDS scheduled task disabled.' Green
                        }
                    }
                }
                Pause-ControlPlane
            }
            '10' { Show-WindowsIdsInstallationGuidance; Pause-ControlPlane }
            '11' { Show-WazuhDefenseMenu }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ('Show-WindowsIdsMenu: operation failed: {0}' -f $message) Red
            Write-Log ('Recoverable menu error in Show-WindowsIdsMenu: {0}' -f $message) ERROR
            Pause-ControlPlane
        }
    }
}


# ===========================================================================
# Remote Operations Center
# ===========================================================================

function Write-RemoteOpsAudit {
    param(
        [Parameter(Mandatory=$true)][string]$Action,
        [Parameter(Mandatory=$true)][string]$Result,
        [string]$Detail = ''
    )

    $target = if ($script:RemoteTarget) {
        if ($script:RemoteTarget.DNSHostName) { $script:RemoteTarget.DNSHostName }
        else { $script:RemoteTarget.Name }
    }
    else {
        'none'
    }

    $operator = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $clean = ($Detail -replace "[`r`n`t]+", ' ').Trim()
    $line = "{0}`t{1}`t{2}`t{3}`t{4}:{5}" -f `
        (Get-Date -Format o), $operator, $target, $Action, $Result, $clean

    Add-Content -LiteralPath $script:RemoteOpsLog -Value $line -Encoding UTF8
}

function Test-RemoteTcpPort {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = 1500
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch {
        return $false
    }
    finally {
        $client.Close()
    }
}

function Select-RemoteOpsTarget {
    Assert-DomainController
    $identity = Select-AdComputerIdentity -Prompt 'Select remote target'
    if (-not $identity) { return $false }

    $script:RemoteTarget = Get-ADComputer `
        -Identity $identity `
        -Properties DNSHostName,IPv4Address,OperatingSystem,OperatingSystemVersion,Enabled,LastLogonDate `
        -ErrorAction Stop

    $script:RemoteSshUser = $null
    Write-Console ("Remote target: {0} / {1}" -f `
        $script:RemoteTarget.Name, $script:RemoteTarget.OperatingSystem) Green

    Write-RemoteOpsAudit -Action 'target-select' -Result 'OK' -Detail $script:RemoteTarget.OperatingSystem
    return $true
}

function Assert-RemoteOpsTarget {
    if ($script:RemoteTarget) { return $true }
    return (Select-RemoteOpsTarget)
}

function Get-RemoteOpsHost {
    if (-not $script:RemoteTarget) { return $null }
    if ($script:RemoteTarget.DNSHostName) { return [string]$script:RemoteTarget.DNSHostName }
    return [string]$script:RemoteTarget.Name
}

function Get-RemoteOpsTargetKind {
    if (-not $script:RemoteTarget) { return 'Unknown' }

    $os = [string]$script:RemoteTarget.OperatingSystem
    if ($os -match '(?i)windows') { return 'Windows' }
    if ($os -match '(?i)linux|ubuntu|debian|red hat|fedora|rocky|alma|centos') { return 'Linux' }

    $hostName = Get-RemoteOpsHost
    if ($hostName -and (Test-RemoteTcpPort -ComputerName $hostName -Port 5985)) { return 'Windows' }
    if ($hostName -and (Test-RemoteTcpPort -ComputerName $hostName -Port 445)) { return 'Windows' }
    if ($hostName -and (Test-RemoteTcpPort -ComputerName $hostName -Port 22)) { return 'Linux' }

    return 'Unknown'
}

function Set-RemoteOpsCredential {
    $script:RemoteOpsCredential = Get-Credential `
        -Message 'Optional alternate credential for Windows remote operations'
    if ($script:RemoteOpsCredential) {
        Write-Console ("Alternate credential held in memory only: {0}" -f `
            $script:RemoteOpsCredential.UserName) Green
    }
}

function Clear-RemoteOpsCredential {
    $script:RemoteOpsCredential = $null
    Write-Console 'Alternate remote credential cleared from memory.' Green
}

function Test-RemoteWinRm {
    param([Parameter(Mandatory=$true)][string]$ComputerName)

    try {
        $params = @{
            ComputerName = $ComputerName
            ErrorAction  = 'Stop'
        }
        if ($script:RemoteOpsCredential) {
            $params.Credential = $script:RemoteOpsCredential
            $params.Authentication = 'Negotiate'
        }

        Test-WSMan @params | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Invoke-RemoteWindowsPs {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    if (-not (Assert-RemoteOpsTarget)) { throw 'No remote target selected.' }
    $hostName = Get-RemoteOpsHost

    $params = @{
        ComputerName = $hostName
        ScriptBlock  = $ScriptBlock
        ErrorAction  = 'Stop'
    }

    if ($ArgumentList.Count -gt 0) {
        $params.ArgumentList = $ArgumentList
    }

    if ($script:RemoteOpsCredential) {
        $params.Credential = $script:RemoteOpsCredential
        $params.Authentication = 'Negotiate'
    }

    Invoke-Command @params
}

function Ensure-LocalOpenSshClient {
    $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
    if ($ssh) { return $ssh.Source }

    Write-Console 'OpenSSH Client is required to manage Linux endpoints from Windows.' Yellow
    if (-not (Confirm-Action `
        -Action 'Install the Microsoft OpenSSH Client optional capability on this management server' `
        -Reason 'Provide an in-box cross-platform SSH management transport.' `
        -Impact LOW)) {
        return $null
    }

    try {
        Add-WindowsCapability -Online -Name 'OpenSSH.Client~~~~0.0.1.0' -ErrorAction Stop | Out-Host
        $ssh = Get-Command ssh.exe -ErrorAction SilentlyContinue
        if ($ssh) {
            Write-Log 'Installed Microsoft OpenSSH Client capability for remote operations.' CHANGE
            return $ssh.Source
        }
    }
    catch {
        Write-Console ("OpenSSH Client installation failed: {0}" -f $_.Exception.Message) Red
    }

    return $null
}

function Get-RemoteSshUser {
    if ($script:RemoteSshUser) { return $script:RemoteSshUser }

    $default = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($default -match '\\') {
        $parts = $default -split '\\', 2
        if ($script:DomainInfo -and $script:DomainInfo.DNSRoot) {
            $default = '{0}@{1}' -f $parts[1], $script:DomainInfo.DNSRoot
        }
    }

    $script:RemoteSshUser = (Read-Host ("SSH login identity [{0}]" -f $default)).Trim()
    if (-not $script:RemoteSshUser) { $script:RemoteSshUser = $default }

    return $script:RemoteSshUser
}

function Invoke-RemoteSsh {
    param(
        [Parameter(Mandatory=$true)][string]$Command,
        [switch]$Interactive
    )

    if (-not (Assert-RemoteOpsTarget)) { throw 'No remote target selected.' }

    $ssh = Ensure-LocalOpenSshClient
    if (-not $ssh) { throw 'OpenSSH Client is unavailable.' }

    $hostName = Get-RemoteOpsHost
    $user = Get-RemoteSshUser

    $args = @(
        '-o','ConnectTimeout=6',
        '-o','ServerAliveInterval=10',
        '-o','StrictHostKeyChecking=accept-new'
    )
    if ($Interactive) { $args += '-t' }
    $args += @('-l', $user, $hostName, $Command)

    & $ssh @args
    if ($LASTEXITCODE -ne 0) {
        throw ("SSH command failed with exit code {0}." -f $LASTEXITCODE)
    }
}

function Get-RemoteSshOutput {
    param([Parameter(Mandatory=$true)][string]$Command)

    if (-not (Assert-RemoteOpsTarget)) { throw 'No remote target selected.' }
    $ssh = Ensure-LocalOpenSshClient
    if (-not $ssh) { throw 'OpenSSH Client is unavailable.' }

    $hostName = Get-RemoteOpsHost
    $user = Get-RemoteSshUser
    $args = @(
        '-o','ConnectTimeout=6',
        '-o','ServerAliveInterval=10',
        '-o','StrictHostKeyChecking=accept-new',
        '-l',$user,$hostName,$Command
    )

    $output = & $ssh @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ("SSH command failed with exit code {0}: {1}" -f `
            $LASTEXITCODE, ($output -join ' '))
    }
    return @($output)
}

function Show-RemoteOpsReadiness {
    if (-not (Assert-RemoteOpsTarget)) { return }

    $hostName = Get-RemoteOpsHost
    $kind = Get-RemoteOpsTargetKind
    $ports = [ordered]@{
        SSH      = Test-RemoteTcpPort -ComputerName $hostName -Port 22
        SMB      = Test-RemoteTcpPort -ComputerName $hostName -Port 445
        WinRM    = Test-RemoteTcpPort -ComputerName $hostName -Port 5985
        WinRMTLS = Test-RemoteTcpPort -ComputerName $hostName -Port 5986
    }

    Write-Section 'Remote endpoint readiness'
    [pscustomobject]@{
        Name            = $script:RemoteTarget.Name
        DNSHostName     = $script:RemoteTarget.DNSHostName
        IPv4Address     = $script:RemoteTarget.IPv4Address
        OperatingSystem = $script:RemoteTarget.OperatingSystem
        Enabled         = $script:RemoteTarget.Enabled
        LastLogonDate   = $script:RemoteTarget.LastLogonDate
        DetectedKind    = $kind
        SSH22           = $ports.SSH
        SMB445          = $ports.SMB
        WinRM5985       = $ports.WinRM
        WinRMTLS5986    = $ports.WinRMTLS
    } | Format-List

    if ($kind -eq 'Windows') {
        if (Test-RemoteWinRm -ComputerName $hostName) {
            Write-Badge -Text 'WINRM/KERBEROS READY' -Kind Good
        }
        elseif ($ports.SMB) {
            Write-Badge -Text 'RPC/SMB REACHABLE' -Kind Warn
            Write-Console '  WinRM is not currently usable; session/power commands may still work through native RPC tools.' Yellow
        }
        else {
            Write-Badge -Text 'NO WINDOWS CONTROL PATH' -Kind Bad
        }
    }
    elseif ($kind -eq 'Linux') {
        if ($ports.SSH) {
            Write-Badge -Text 'SSH READY' -Kind Good
        }
        else {
            Write-Badge -Text 'SSH CLOSED' -Kind Bad
        }
    }
    else {
        Write-Badge -Text 'OS/TRANSPORT UNKNOWN' -Kind Warn
    }

    Write-RemoteOpsAudit -Action 'readiness' -Result 'OK' `
        -Detail ("kind={0};ssh={1};smb={2};winrm={3}/{4}" -f `
            $kind,$ports.SSH,$ports.SMB,$ports.WinRM,$ports.WinRMTLS)
}

function Show-RemoteSessions {
    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind
    $hostName = Get-RemoteOpsHost

    Write-Section 'Remote user sessions'

    if ($kind -eq 'Windows') {
        $output = & quser.exe "/server:$hostName" 2>&1
        if ($LASTEXITCODE -eq 0) {
            $output | ForEach-Object { Write-Console ([string]$_) }
            Write-RemoteOpsAudit -Action 'sessions' -Result 'OK' -Detail 'quser'
            return
        }

        try {
            $output = Invoke-RemoteWindowsPs -ScriptBlock {
                & "$env:SystemRoot\System32\quser.exe" 2>&1
            }
            $output | ForEach-Object { Write-Console ([string]$_) }
            Write-RemoteOpsAudit -Action 'sessions' -Result 'OK' -Detail 'winrm'
            return
        }
        catch {
            throw ("Unable to enumerate Windows sessions: {0}" -f $_.Exception.Message)
        }
    }

    if ($kind -eq 'Linux') {
        Invoke-RemoteSsh `
            -Command 'loginctl list-sessions --no-legend 2>/dev/null || who' `
            -Interactive
        Write-RemoteOpsAudit -Action 'sessions' -Result 'OK' -Detail 'ssh'
        return
    }

    throw 'Unknown endpoint family.'
}

function Send-RemoteUserMessage {
    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind
    $hostName = Get-RemoteOpsHost
    $message = (Read-Host 'Message to interactive users').Trim()
    if (-not $message) { return }

    if ($kind -eq 'Windows') {
        $output = & msg.exe '*' "/server:$hostName" '/time:60' $message 2>&1
        if ($LASTEXITCODE -ne 0) {
            try {
                Invoke-RemoteWindowsPs -ScriptBlock {
                    param($Text)
                    & "$env:SystemRoot\System32\msg.exe" '*' '/time:60' $Text
                } -ArgumentList @($message) | Out-Host
            }
            catch {
                throw ("Windows user message failed: {0}" -f $_.Exception.Message)
            }
        }
        Write-RemoteOpsAudit -Action 'message' -Result 'OK' -Detail 'windows'
        return
    }

    if ($kind -eq 'Linux') {
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($message))
        $command = 'm=$(printf ''%s'' ''{0}'' | base64 -d); if [ "$(id -u)" -eq 0 ]; then printf ''%s\n'' "$m" | wall; else printf ''%s\n'' "$m" | sudo wall; fi' -f $b64
        Invoke-RemoteSsh -Command $command -Interactive
        Write-RemoteOpsAudit -Action 'message' -Result 'OK' -Detail 'linux'
        return
    }

    throw 'Unknown endpoint family.'
}

function Invoke-RemoteSessionLogoff {
    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind

    Show-RemoteSessions
    $sessionId = (Read-Host 'Session ID to terminate').Trim()
    if ($sessionId -notmatch '^[A-Za-z0-9_.-]+$') {
        Write-Console 'Invalid session ID.' Yellow
        return
    }

    if (-not (Confirm-Action `
        -Action ("Terminate session {0} on {1}" -f $sessionId, (Get-RemoteOpsHost)) `
        -Reason 'Logging off a user terminates applications in that session and can lose unsaved work.' `
        -Impact HIGH)) {
        return
    }

    if ($kind -eq 'Windows') {
        if ($sessionId -notmatch '^\d+$') {
            Write-Console 'Windows logoff requires a numeric session ID.' Yellow
            return
        }

        $output = & logoff.exe $sessionId "/server:$(Get-RemoteOpsHost)" 2>&1
        if ($LASTEXITCODE -ne 0) {
            Invoke-RemoteWindowsPs -ScriptBlock {
                param($Id)
                & "$env:SystemRoot\System32\logoff.exe" $Id
            } -ArgumentList @([int]$sessionId) | Out-Host
        }

        Write-RemoteOpsAudit -Action 'logoff' -Result 'OK' -Detail ("session={0}" -f $sessionId)
        return
    }

    if ($kind -eq 'Linux') {
        $command = 'if [ "$(id -u)" -eq 0 ]; then loginctl terminate-session ''{0}''; else sudo loginctl terminate-session ''{0}''; fi' -f $sessionId
        Invoke-RemoteSsh -Command $command -Interactive
        Write-RemoteOpsAudit -Action 'logoff' -Result 'OK' -Detail ("session={0}" -f $sessionId)
        return
    }

    throw 'Unknown endpoint family.'
}

function Show-RemoteDiagnostics {
    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind

    Write-Section 'Remote diagnostics'

    if ($kind -eq 'Windows') {
        Invoke-RemoteWindowsPs -ScriptBlock {
            $os = Get-CimInstance Win32_OperatingSystem
            $cs = Get-CimInstance Win32_ComputerSystem
            [pscustomobject]@{
                Computer     = $env:COMPUTERNAME
                Domain       = $cs.Domain
                OS           = $os.Caption
                Version      = $os.Version
                LastBoot     = $os.LastBootUpTime
                FreeMemoryMB = [math]::Round($os.FreePhysicalMemory / 1024, 0)
            }

            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object { $_.IPAddress -notlike '169.254.*' } |
                Select-Object InterfaceAlias,IPAddress,PrefixLength

            Get-Service WinRM,Dnscache,Netlogon -ErrorAction SilentlyContinue |
                Select-Object Name,Status,StartType
        } | Format-List

        Write-RemoteOpsAudit -Action 'diagnostics' -Result 'OK' -Detail 'windows-winrm'
        return
    }

    if ($kind -eq 'Linux') {
        Invoke-RemoteSsh -Command `
            "printf 'HOST\n'; hostnamectl 2>/dev/null || hostname; printf '\nUPTIME\n'; uptime; printf '\nFILESYSTEM\n'; df -h -x tmpfs -x devtmpfs; printf '\nMEMORY\n'; free -h 2>/dev/null || true; printf '\nFAILED UNITS\n'; systemctl --failed --no-pager 2>/dev/null || true; printf '\nNETWORK\n'; ip -brief address 2>/dev/null || true" `
            -Interactive

        Write-RemoteOpsAudit -Action 'diagnostics' -Result 'OK' -Detail 'linux-ssh'
        return
    }

    throw 'Unknown endpoint family.'
}

function Invoke-RemoteServiceControl {
    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind
    $service = (Read-Host 'Service/unit name').Trim()

    if ($service -notmatch '^[A-Za-z0-9@_.:-]+$') {
        Write-Console 'Invalid service/unit name.' Yellow
        return
    }

    if ($kind -eq 'Windows') {
        Invoke-RemoteWindowsPs -ScriptBlock {
            param($Name)
            Get-Service -Name $Name -ErrorAction Stop |
                Select-Object Name,DisplayName,Status,StartType
        } -ArgumentList @($service) | Format-Table -AutoSize

        if (Confirm-Action `
            -Action ("Restart remote service {0}" -f $service) `
            -Reason 'Restart a selected service on the endpoint.' `
            -Impact HIGH) {
            Invoke-RemoteWindowsPs -ScriptBlock {
                param($Name)
                Restart-Service -Name $Name -ErrorAction Stop
                Get-Service -Name $Name | Select-Object Name,Status
            } -ArgumentList @($service) | Format-Table -AutoSize

            Write-RemoteOpsAudit -Action 'service-restart' -Result 'OK' -Detail $service
        }
        return
    }

    if ($kind -eq 'Linux') {
        Invoke-RemoteSsh `
            -Command ("systemctl status --no-pager --full '{0}' 2>&1 || true" -f $service) `
            -Interactive

        if (Confirm-Action `
            -Action ("Restart remote unit {0}" -f $service) `
            -Reason 'Restart a selected systemd unit on the endpoint.' `
            -Impact HIGH) {
            $command = 'if [ "$(id -u)" -eq 0 ]; then systemctl restart ''{0}''; else sudo systemctl restart ''{0}''; fi; systemctl is-active ''{0}''' -f $service
            Invoke-RemoteSsh -Command $command -Interactive
            Write-RemoteOpsAudit -Action 'service-restart' -Result 'OK' -Detail $service
        }
        return
    }

    throw 'Unknown endpoint family.'
}

function Invoke-RemotePowerAction {
    param(
        [ValidateSet('Restart','Shutdown')]
        [string]$Action
    )

    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind
    $hostName = Get-RemoteOpsHost

    $delayText = (Read-Host 'Delay in seconds [120]').Trim()
    if (-not $delayText) { $delayText = '120' }
    [int]$delay = 120
    if (-not [int]::TryParse($delayText, [ref]$delay) -or $delay -lt 0) {
        $delay = 120
    }

    $reason = (Read-Host 'User-visible maintenance reason [Administrative maintenance]').Trim()
    if (-not $reason) { $reason = 'Administrative maintenance' }

    if (-not (Confirm-Action `
        -Action ("{0} {1} after {2}s" -f $Action, $hostName, $delay) `
        -Reason 'Remote power operations terminate interactive work when the timeout expires.' `
        -Impact HIGH)) {
        return
    }

    if ($kind -eq 'Windows') {
        $remote = "\\{0}" -f $hostName
        $args = if ($Action -eq 'Restart') {
            @('/r','/m',$remote,'/t',[string]$delay,'/c',$reason,'/d','p:0:0')
        }
        else {
            @('/s','/m',$remote,'/t',[string]$delay,'/c',$reason,'/d','p:0:0')
        }

        & shutdown.exe @args
        if ($LASTEXITCODE -ne 0) {
            throw ("Remote shutdown command failed with exit code {0}." -f $LASTEXITCODE)
        }

        Write-RemoteOpsAudit -Action ($Action.ToLowerInvariant()) -Result 'OK' -Detail 'windows-rpc'
        Write-Console ("{0} request submitted." -f $Action) Green
        return
    }

    if ($kind -eq 'Linux') {
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($reason))
        $minutes = [Math]::Max(1, [Math]::Ceiling($delay / 60.0))
        $flag = if ($Action -eq 'Restart') { '-r' } else { '-h' }
        $command = 'm=$(printf ''%s'' ''{0}'' | base64 -d); if [ "$(id -u)" -eq 0 ]; then shutdown {1} +{2} "$m"; else sudo shutdown {1} +{2} "$m"; fi' -f `
            $b64,$flag,[int]$minutes

        Invoke-RemoteSsh -Command $command -Interactive
        Write-RemoteOpsAudit -Action ($Action.ToLowerInvariant()) -Result 'OK' -Detail 'linux-ssh'
        return
    }

    throw 'Unknown endpoint family.'
}

function Cancel-RemotePowerAction {
    if (-not (Assert-RemoteOpsTarget)) { return }
    $kind = Get-RemoteOpsTargetKind
    $hostName = Get-RemoteOpsHost

    if ($kind -eq 'Windows') {
        & shutdown.exe '/a' '/m' ("\\{0}" -f $hostName)
        if ($LASTEXITCODE -ne 0) {
            throw ("Remote shutdown cancellation failed with exit code {0}." -f $LASTEXITCODE)
        }
        Write-RemoteOpsAudit -Action 'cancel-power' -Result 'OK' -Detail 'windows'
        return
    }

    if ($kind -eq 'Linux') {
        Invoke-RemoteSsh `
            -Command 'if [ "$(id -u)" -eq 0 ]; then shutdown -c; else sudo shutdown -c; fi' `
            -Interactive
        Write-RemoteOpsAudit -Action 'cancel-power' -Result 'OK' -Detail 'linux'
        return
    }

    throw 'Unknown endpoint family.'
}

function Export-RemoteOpsEvidence {
    if (-not (Assert-RemoteOpsTarget)) { return }

    $hostName = Get-RemoteOpsHost
    $kind = Get-RemoteOpsTargetKind
    $safe = ($hostName -replace '[^A-Za-z0-9_.-]', '_')
    $file = Join-Path $script:RemoteOpsEvidencePath `
        ("remote-{0}-{1}.txt" -f $safe, (Get-Date -Format 'yyyyMMdd-HHmmss'))

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('Remote Operations Evidence')
    $lines.Add(("Generated: {0}" -f (Get-Date -Format o)))
    $lines.Add(("Target: {0}" -f $hostName))
    $lines.Add(("OS hint: {0}" -f $script:RemoteTarget.OperatingSystem))
    $lines.Add(("Detected family: {0}" -f $kind))
    $lines.Add('')

    foreach ($port in @(22,445,5985,5986)) {
        $state = Test-RemoteTcpPort -ComputerName $hostName -Port $port
        $lines.Add(("Port {0}: {1}" -f $port, $(if ($state) { 'open' } else { 'closed/unreachable' })))
    }

    $lines.Add('')
    $lines.Add('Diagnostics')

    try {
        if ($kind -eq 'Windows') {
            $diag = Invoke-RemoteWindowsPs -ScriptBlock {
                $os = Get-CimInstance Win32_OperatingSystem
                [pscustomobject]@{
                    Computer=$env:COMPUTERNAME
                    OS=$os.Caption
                    Version=$os.Version
                    LastBoot=$os.LastBootUpTime
                }
                & "$env:SystemRoot\System32\quser.exe" 2>&1
                Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Select-Object InterfaceAlias,IPAddress,PrefixLength
            } | Out-String -Width 220

            $lines.Add($diag)
        }
        elseif ($kind -eq 'Linux') {
            $diag = Get-RemoteSshOutput -Command `
                "hostnamectl 2>/dev/null || hostname; uptime; loginctl list-sessions --no-legend 2>/dev/null || who; df -h -x tmpfs -x devtmpfs; free -h 2>/dev/null || true; systemctl --failed --no-pager 2>/dev/null || true"
            $lines.Add(($diag -join [Environment]::NewLine))
        }
    }
    catch {
        $lines.Add(("Diagnostics unavailable: {0}" -f $_.Exception.Message))
    }

    $lines | Set-Content -LiteralPath $file -Encoding UTF8
    Write-RemoteOpsAudit -Action 'evidence-export' -Result 'OK' -Detail $file
    Write-Console ("Evidence: {0}" -f $file) Green
}

function Show-RemoteOpsGuardrails {
    Write-Section 'Remote operations security model'
    Write-Console '  Windows -> Windows: prefer WinRM/PowerShell Remoting by hostname so domain Kerberos can be used.' Cyan
    Write-Console '  Windows -> Linux  : Microsoft OpenSSH Client + endpoint sshd + delegated sudo policy.' Cyan
    Write-Console ''
    Write-Console '  No password is persisted by this panel.' Green
    Write-Console '  Destructive session/service/power operations require HIGH-impact confirmation.' Green
    Write-Console '  Arbitrary remote script/shell deployment is intentionally not exposed.' Green
    Write-Console '  Remote actions are appended to remote-ops\operations.tsv.' Green
    Write-Console ''
    Write-Console '  Delegation recommendation:' Magenta
    Write-Console '    Windows: JEA endpoints / constrained role capabilities instead of broad local-admin rights.'
    Write-Console '    Linux  : restricted sudoers rules for approved commands instead of unrestricted sudo.'
    Write-Console '    Network: scope WinRM/SSH firewall access to trusted management networks.'
}

function Show-RemoteOpsMenu {
    Assert-DomainController

    while ($true) {
        if ($script:MainMenuRequested) { return }

        $targetText = if ($script:RemoteTarget) {
            '{0} · {1}' -f (Get-RemoteOpsHost), $script:RemoteTarget.OperatingSystem
        }
        else {
            'none selected'
        }

        Write-MenuHeader 'REMOTE OPERATIONS CENTER' ("Target: {0}" -f $targetText)
        Write-WorkspaceRow 'T' 'Target / readiness' Cyan 'S' 'Active sessions' DarkCyan
        Write-WorkspaceRow 'M' 'Message users' Green 'L' 'Log off session' Yellow
        Write-WorkspaceRow 'D' 'Diagnostics' Cyan 'V' 'Service control' Magenta
        Write-WorkspaceRow 'R' 'Restart endpoint' Yellow 'X' 'Shut down endpoint' Red
        Write-WorkspaceRow 'C' 'Cancel shutdown' Green 'E' 'Export evidence' Cyan
        Write-WorkspaceRow 'K' 'Alternate credential' Magenta 'J' 'Guardrails / JEA' DarkCyan
        Write-MenuNavigation
        Write-Rule

        try {
            switch ((Read-MenuChoice -Prompt 'Remote operation' -Default 'T').ToUpperInvariant()) {
                'T' {
                    if (Select-RemoteOpsTarget) { Show-RemoteOpsReadiness }
                    Pause-ControlPlane
                }
                'S' { Show-RemoteSessions; Pause-ControlPlane }
                'M' { Send-RemoteUserMessage; Pause-ControlPlane }
                'L' { Invoke-RemoteSessionLogoff; Pause-ControlPlane }
                'D' { Show-RemoteDiagnostics; Pause-ControlPlane }
                'V' { Invoke-RemoteServiceControl; Pause-ControlPlane }
                'R' { Invoke-RemotePowerAction -Action Restart; Pause-ControlPlane }
                'X' { Invoke-RemotePowerAction -Action Shutdown; Pause-ControlPlane }
                'C' { Cancel-RemotePowerAction; Pause-ControlPlane }
                'E' { Export-RemoteOpsEvidence; Pause-ControlPlane }
                'K' {
                    Write-Console ''
                    Write-Console '  [1] Set/replace alternate Windows credential'
                    Write-Console '  [2] Clear alternate credential'
                    Write-Console '  [0] Cancel'
                    $sub = (Read-Host 'Credential operation [1]').Trim()
                    if (-not $sub) { $sub = '1' }
                    if ($sub -eq '1') { Set-RemoteOpsCredential }
                    elseif ($sub -eq '2') { Clear-RemoteOpsCredential }
                    Pause-ControlPlane
                }
                'J' { Show-RemoteOpsGuardrails; Pause-ControlPlane }
                'H' { $script:MainMenuRequested = $true; return }
                '0' { return }
                default { Write-Console 'Invalid remote operation.' Yellow; Pause-ControlPlane }
            }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ("Remote operation failed: {0}" -f $message) Red
            Write-RemoteOpsAudit -Action 'operation' -Result 'FAIL' -Detail $message
            Write-Log ("Recoverable remote operation error: {0}" -f $message) ERROR
            Pause-ControlPlane
        }
    }
}

# ===========================================================================
# Compact workspace navigation
# ===========================================================================

function Show-DirectoryWorkspace {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'DIRECTORY WORKSPACE' 'Identity and machine lifecycle'
        Write-WorkspaceRow 'U' 'Users' Cyan 'G' 'Groups / access' Green
        Write-WorkspaceRow 'C' 'Computers / OUs' DarkCyan 'R' 'Remote operations' Magenta
        Write-MenuNavigation
        Write-Rule

        switch ((Read-MenuChoice -Default 'U').ToUpperInvariant()) {
            'U' { Show-UserMenu }
            'G' { Show-GroupMenu }
            'C' { Show-ComputerOuMenu }
            'R' { Show-RemoteOpsMenu }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid directory workspace.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-PolicyWorkspace {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'POLICY & NAME SERVICES' 'Group Policy and AD-integrated DNS'
        Write-WorkspaceRow 'P' 'Group Policy' Magenta 'N' 'AD DNS' Cyan
        Write-WorkspaceRow 'M' 'Domain migration' Yellow 'R' 'Remote operations' DarkCyan
        Write-MenuNavigation
        Write-Rule

        switch ((Read-MenuChoice -Default 'P').ToUpperInvariant()) {
            'P' { Show-GpoMenu }
            'N' { Show-DnsMenu }
            'M' { Show-DomainMigrationMenu }
            'R' { Show-RemoteOpsMenu }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid policy workspace.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-SecurityWorkspace {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'SECURITY WORKSPACE' 'Host, protocol and network detection'
        Write-WorkspaceRow 'S' 'Host hardening' Red 'P' 'Directory protocols' Magenta
        Write-WorkspaceRow 'I' 'Suricata IDS' DarkCyan 'R' 'Remote guardrails' Yellow
        Write-MenuNavigation
        Write-Rule

        switch ((Read-MenuChoice -Default 'S').ToUpperInvariant()) {
            'S' { Show-SecurityMenu }
            'P' { Show-DirectorySecurityMenu }
            'I' { Show-WindowsIdsMenu }
            'R' { Show-RemoteOpsGuardrails; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid security workspace.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-InsightsWorkspace {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'INSIGHTS & HEALTH' 'Health, findings and telemetry'
        Write-WorkspaceRow 'V' 'Validate DC' Green 'A' 'Host / AD audit' Cyan
        Write-WorkspaceRow 'F' 'Current findings' Yellow 'I' 'Suricata IDS' Magenta
        Write-MenuNavigation
        Write-Rule

        switch ((Read-MenuChoice -Default 'V').ToUpperInvariant()) {
            'V' { Invoke-DcValidation; Pause-ControlPlane }
            'A' {
                $script:Results.Clear()
                Invoke-HostAudit
                if ($script:IsDomainController) { Invoke-DcValidation }
                Pause-ControlPlane
            }
            'F' {
                $script:Results |
                    Select-Object Category,Control,Status,Current |
                    Format-Table -AutoSize
                Pause-ControlPlane
            }
            'I' { Show-WindowsIdsMenu }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid insights workspace.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-MaintenanceWorkspace {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'MAINTENANCE & LIFECYCLE' 'Recovery, servicing and domain lifecycle'
        Write-WorkspaceRow 'B' 'Backup / recovery' Green 'D' 'Dependencies' Cyan
        Write-WorkspaceRow 'M' 'Migration' Yellow 'X' 'Decommission / reset' Red
        Write-WorkspaceRow 'P' 'Provision forest' Magenta 'A' 'All modules' Gray
        Write-MenuNavigation
        Write-Rule

        switch ((Read-MenuChoice -Default 'B').ToUpperInvariant()) {
            'B' { Show-RecoveryMenu }
            'D' { Show-DependencyMenu }
            'M' { Show-DomainMigrationMenu }
            'X' { Show-DomainResetMenu }
            'P' { Invoke-NewForestProvisioning; Pause-ControlPlane }
            'A' { Show-AllModulesMenu }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid maintenance workspace.' Yellow; Pause-ControlPlane }
        }
    }
}

# ===========================================================================
# Interactive menus
# ===========================================================================

function Show-UserMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'USER DIRECTORY' 'Identity lifecycle, credentials, attributes and group membership'
        Write-MenuItem '1' 'List users' 'Inventory users, state and recent logon metadata'
        Write-MenuItem '2' 'Inspect user' 'Show detailed attributes for one identity'
        Write-MenuItem '3' 'Create user' 'Full user wizard + OU + password policy flags + groups' Good
        Write-MenuItem '4' 'Edit user' 'Identity fields, password behavior and account state'
        Write-MenuItem '5' 'Group memberships' 'List/add/remove groups with professional selectors' Good
        Write-MenuItem '6' 'Reset password' 'Administrative reset + change at next logon' Warn
        Write-MenuItem '7' 'Enable account' 'Restore authentication eligibility' Good
        Write-MenuItem '8' 'Disable account' 'Block authentication without deleting identity' Warn
        Write-MenuItem '9' 'Unlock account' 'Clear account lockout'
        Write-MenuItem '10' 'Delete user' 'Permanently remove directory object' Danger
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Show-AdUsers; Pause-ControlPlane }
            '2' { Show-AdUserDetail; Pause-ControlPlane }
            '3' { New-AdUserInteractive; Pause-ControlPlane }
            '4' { Edit-AdUserInteractive; Pause-ControlPlane }
            '5' { Manage-AdUserGroupsInteractive; Pause-ControlPlane }
            '6' { Reset-AdUserPassword; Pause-ControlPlane }
            '7' { Set-AdUserEnabledState -Enabled $true; Pause-ControlPlane }
            '8' { Set-AdUserEnabledState -Enabled $false; Pause-ControlPlane }
            '9' { Unlock-AdUserInteractive; Pause-ControlPlane }
            '10' { Remove-AdUserInteractive; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-GroupMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'GROUPS & ACCESS' 'Security groups, membership and privileged access review'
        Write-MenuItem '1' 'List groups' 'Inventory domain groups'
        Write-MenuItem '2' 'List members' 'Inspect direct membership of one group'
        Write-MenuItem '3' 'Create group' 'Create security/distribution group' Good
        Write-MenuItem '4' 'Add member' 'Select group and user/group/computer principal' Good
        Write-MenuItem '5' 'Remove member' 'Select group then one current member' Warn
        Write-MenuItem '6' 'Privileged groups' 'Review Domain/Enterprise/Schema/Admin operators'
        Write-MenuItem '7' 'Delete group' 'Delete non-core group object' Danger
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Show-AdGroups; Pause-ControlPlane }
            '2' { Show-AdGroupMembers; Pause-ControlPlane }
            '3' { New-AdGroupInteractive; Pause-ControlPlane }
            '4' { Add-AdGroupMemberInteractive; Pause-ControlPlane }
            '5' { Remove-AdGroupMemberInteractive; Pause-ControlPlane }
            '6' { Show-PrivilegedGroups; Pause-ControlPlane }
            '7' { Remove-AdGroupInteractive; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-ComputerOuMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'COMPUTERS & ORGANIZATIONAL UNITS' 'Machine accounts, OU structure and directory placement'
        Write-MenuItem '1' 'List computers' 'Inventory machine accounts and last-logon metadata'
        Write-MenuItem '2' 'Inspect computer' 'Select from indexed computer inventory and show attributes'
        Write-MenuItem '3' 'Enable computer' 'Restore machine authentication' Good
        Write-MenuItem '4' 'Disable computer' 'Disable stale/suspect machine account' Warn
        Write-MenuItem '5' 'Delete computer' 'Remove obsolete machine object' Danger
        Write-MenuItem '6' 'List OUs' 'Inventory organizational units and protection state'
        Write-MenuItem '7' 'Create OU' 'Create protected OU' Good
        Write-MenuItem '8' 'Move AD object' 'Move user/group/computer between OUs' Warn
        Write-MenuItem '9' 'Delete OU' 'Unprotect and delete empty OU' Danger
        Write-MenuItem 'R' 'Remote operations' 'Endpoint sessions, diagnostics and controlled actions' Good
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Show-AdComputers; Pause-ControlPlane }
            '2' { Show-AdComputerDetail; Pause-ControlPlane }
            '3' { Set-AdComputerEnabledState -Enabled $true; Pause-ControlPlane }
            '4' { Set-AdComputerEnabledState -Enabled $false; Pause-ControlPlane }
            '5' { Remove-AdComputerInteractive; Pause-ControlPlane }
            '6' { Show-AdOrganizationalUnits; Pause-ControlPlane }
            '7' { New-AdOrganizationalUnitInteractive; Pause-ControlPlane }
            '8' { Move-AdObjectInteractive; Pause-ControlPlane }
            '9' { Remove-AdOrganizationalUnitInteractive; Pause-ControlPlane }
            'R' { Show-RemoteOpsMenu }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-GpoMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'GROUP POLICY CONTROL' 'Selector-driven GPO lifecycle, common security templates, scope and delegation'
        Write-MenuItem '1' 'List GPOs + GUIDs' 'Indexed inventory; no manual GUID lookup required'
        Write-MenuItem '2' 'Inspect GPO' 'Select existing GPO by index or manual name/GUID'
        Write-MenuItem '3' 'Create empty GPO' 'Create a custom Group Policy Object' Good
        Write-MenuItem '4' 'Security GPO catalog' 'Deploy common curated security GPO templates' Good
        Write-MenuItem '5' 'Edit registry policy' 'Select GPO then set registry-based policy value' Warn
        Write-MenuItem '6' 'Link GPO' 'Select GPO and domain/OU target' Good
        Write-MenuItem '7' 'Remove link' 'Select GPO and domain/OU target' Warn
        Write-MenuItem '8' 'GPO permission' 'Select GPO and security principal' Warn
        Write-MenuItem '9' 'Backup GPO' 'Select and export one GPO'
        Write-MenuItem '10' 'HTML report' 'Select GPO and export human-readable report'
        Write-MenuItem '11' 'Delete GPO' 'Backup best-effort then permanently delete selected GPO' Danger
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Show-Gpos; Pause-ControlPlane }
            '2' { Show-GpoDetail; Pause-ControlPlane }
            '3' { New-GpoInteractive; Pause-ControlPlane }
            '4' { Invoke-SecurityGpoWizard; Pause-ControlPlane }
            '5' { Set-GpoRegistryValueInteractive; Pause-ControlPlane }
            '6' { Link-GpoInteractive; Pause-ControlPlane }
            '7' { Unlink-GpoInteractive; Pause-ControlPlane }
            '8' { Set-GpoPermissionInteractive; Pause-ControlPlane }
            '9' { Backup-GpoInteractive; Pause-ControlPlane }
            '10' { Export-GpoReportInteractive; Pause-ControlPlane }
            '11' { Remove-GpoInteractive; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-DnsMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'ACTIVE DIRECTORY DNS' 'Integrated zones and resource-record lifecycle'
        Write-MenuItem '1' 'List zones' 'Inventory DNS zones and integration state'
        Write-MenuItem '2' 'List records' 'Display records in one zone/node'
        Write-MenuItem '3' 'Create A record' 'Add IPv4 host record' Good
        Write-MenuItem '4' 'Delete record' 'Delete one unambiguous resource record' Danger
        Write-MenuItem '5' 'AD DNS health' 'Validate AD records plus external recursive resolution'
        Write-MenuItem '6' 'External resolution' 'Inspect forwarders/root-hint posture and Internet DNS health' Good
        Write-MenuItem '7' 'Repair forwarders' 'Replace forwarders only after direct validation and rollback protection' Warn
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Show-DnsZones; Pause-ControlPlane }
            '2' { Show-DnsRecords; Pause-ControlPlane }
            '3' { Add-DnsARecordInteractive; Pause-ControlPlane }
            '4' { Remove-DnsRecordInteractive; Pause-ControlPlane }
            '5' { $script:Results.Clear(); Test-DcDnsHealth; Pause-ControlPlane }
            '6' { $script:Results.Clear(); [void](Show-DnsExternalResolutionHealth); Pause-ControlPlane }
            '7' { Repair-DnsForwardersInteractive; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-DcHealthMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'DC HEALTH & REPLICATION' 'Service state, DCDiag, DNS, SYSVOL, replication and FSMO ownership'
        Write-MenuItem '1' 'Full validation' 'Run all Domain Controller health checks' Good
        Write-MenuItem '2' 'DCDiag' 'Run dcdiag /q and persist failures'
        Write-MenuItem '3' 'Replication' 'PowerShell replication failures + repadmin summary'
        Write-MenuItem '4' 'DNS health' 'Validate AD locator/Kerberos SRV records'
        Write-MenuItem '5' 'SYSVOL / NETLOGON' 'Verify required SMB shares'
        Write-MenuItem '6' 'FSMO roles' 'Display forest/domain FSMO holders'
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Invoke-DcValidation; Pause-ControlPlane }
            '2' { $script:Results.Clear(); Test-DcDiag; Pause-ControlPlane }
            '3' { $script:Results.Clear(); Test-ReplicationHealth; Pause-ControlPlane }
            '4' { $script:Results.Clear(); Test-DcDnsHealth; Pause-ControlPlane }
            '5' { $script:Results.Clear(); Test-SysvolNetlogonShares; Pause-ControlPlane }
            '6' { Show-FsmoRoles; Pause-ControlPlane }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-RecoveryMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'BACKUP & RECOVERY' 'Configuration evidence, GPO backup and Domain Controller system-state protection'
        Write-MenuItem '1' 'Configuration change-set' 'Capture firewall, registry, SMB, Defender, AD/GPO/DNS evidence'
        Write-MenuItem '2' 'DC system-state backup' 'Use wbadmin for AD DS/SYSVOL recovery-grade backup' Good
        Write-MenuItem '3' 'GPO backup' 'Back up one Group Policy Object'
        Write-MenuItem '4' 'Open run directory' 'Print current run/backup paths'
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { Set-StepPlan 1; Invoke-ConfigurationBackup; Complete-Progress; Pause-ControlPlane }
            '2' { Invoke-SystemStateBackup; Pause-ControlPlane }
            '3' { Backup-GpoInteractive; Pause-ControlPlane }
            '4' {
                Write-Console ("Run path    : {0}" -f $script:RunPath)
                Write-Console ("Backup path : {0}" -f $script:BackupPath)
                Pause-ControlPlane
            }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-SecurityMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'HOST SECURITY & HARDENING' 'Firewall, Defender, SMB, RDP, PowerShell logging and name-resolution controls'
        Write-MenuItem '1' 'Full host audit' 'Read-only selected security controls'
        Write-MenuItem '2' 'Interactive hardening' 'Propose supported remediations one by one' Good
        Write-MenuItem '3' 'Firewall only' 'Enable profiles and default inbound block' Warn
        Write-MenuItem '4' 'Defender only' 'Core protections + PUA where locally managed'
        Write-MenuItem '5' 'RDP NLA' 'Require Network Level Authentication'
        Write-MenuItem '6' 'SMB controls' 'Signing capability, guest logons, SMBv1 member-server handling'
        Write-MenuItem '7' 'LLMNR' 'Disable multicast name resolution' Warn
        Write-MenuItem '8' 'PowerShell logging' 'Script block + module logging'
        if ($script:IsDomainController) {
            Write-MenuItem '9' 'Directory protocol security' 'Kerberos AES/RC4, LDAP signing/channel binding and strict SMB' Good
        }
        Write-MenuNavigation
        Write-Rule

        switch (Read-MenuChoice -Default '1') {
            '1' { $script:Results.Clear(); Invoke-HostAudit; Pause-ControlPlane }
            '2' { Invoke-Hardening; Pause-ControlPlane }
            '3' { Remediate-Firewall; Pause-ControlPlane }
            '4' { Remediate-Defender; Pause-ControlPlane }
            '5' { Remediate-RdpNla; Pause-ControlPlane }
            '6' { Remediate-Smb; Pause-ControlPlane }
            '7' { Remediate-Llmnr; Pause-ControlPlane }
            '8' { Remediate-PowerShellLogging; Pause-ControlPlane }
            '9' {
                if ($script:IsDomainController) { Show-DirectorySecurityMenu }
                else { Write-Console 'Directory protocol security requires a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
    }
}

function Show-AdOperationsMenu {
    Assert-DomainController

    while ($true) {
        if ($script:MainMenuRequested) { return }

        Write-MenuHeader 'DAILY OPERATIONS' 'Stable letter shortcuts for routine administration'
        Write-WorkspaceRow 'U' 'Users' Cyan 'G' 'Groups / access' Green
        Write-WorkspaceRow 'C' 'Computers / OUs' DarkCyan 'P' 'Group Policy' Magenta
        Write-WorkspaceRow 'N' 'AD DNS' Cyan 'R' 'Remote operations' Magenta
        Write-WorkspaceRow 'V' 'Validate controller' Green 'B' 'Backup / recovery' Green
        Write-WorkspaceRow 'S' 'Security' Red 'M' 'Migration' Yellow
        Write-MenuNavigation
        Write-Rule

        try {
            switch ((Read-MenuChoice -Prompt 'Operation' -Default 'U').ToUpperInvariant()) {
                'U' { Show-UserMenu }
                'G' { Show-GroupMenu }
                'C' { Show-ComputerOuMenu }
                'P' { Show-GpoMenu }
                'N' { Show-DnsMenu }
                'R' { Show-RemoteOpsMenu }
                'V' { Invoke-DcValidation; Pause-ControlPlane }
                'B' { Show-RecoveryMenu }
                'S' { Show-SecurityMenu }
                'M' { Show-DomainMigrationMenu }

                '1' { Show-UserMenu }
                '2' { Show-GroupMenu }
                '3' { Show-ComputerOuMenu }
                '4' { Show-GpoMenu }
                '5' { Show-DnsMenu }
                '6' { Show-DcHealthMenu }
                '7' { Show-RecoveryMenu }
                '8' { Show-SecurityMenu }
                '9' { Show-DomainMigrationMenu }
                '10' { Show-DirectorySecurityMenu }
                '11' { Show-DependencyMenu }
                '12' { Show-DomainResetMenu }
                '13' { Show-WindowsIdsMenu }

                'H' { $script:MainMenuRequested = $true; return }
                '0' { return }
                default { Write-Console 'Invalid daily operation.' Yellow; Pause-ControlPlane }
            }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ("Daily operation failed: {0}" -f $message) Red
            Write-Log ("Recoverable menu error in Show-AdOperationsMenu: {0}" -f $message) ERROR
            Pause-ControlPlane
        }
    }
}

function Show-AllModulesMenu {
    while ($true) {
        if ($script:MainMenuRequested) { return }
        Write-MenuHeader 'ALL MODULES / CLASSIC MAP' 'Complete numbered map; compact workspaces remain the default'

        Write-MenuItem '1' 'Host security audit' 'Read-only server security inventory'
        Write-MenuItem '2' 'Interactive hardening' 'Apply selected host security changes' Good

        if ($script:IsDomainController) {
            Write-MenuItem '3' 'AD operations' 'Users, groups, computers, OUs, GPOs, DNS and health' Good
            Write-MenuItem '4' 'Validate Domain Controller' 'DCDiag, replication, DNS and SYSVOL'
            Write-MenuItem '5' 'Backup & recovery' 'Change-set, GPO and system-state backup'
        }
        else {
            Write-MenuItem '3' 'AD operations' 'Unavailable: this server is not a Domain Controller' Warn
            Write-MenuItem '4' 'Validate Domain Controller' 'Unavailable until server is promoted' Warn
            Write-MenuItem '5' 'Backup & recovery' 'Configuration change-set'
        }

        Write-MenuItem '6' 'Provision new AD forest' 'First-DC workflow; static IPv4 required' Warn
        Write-MenuItem '7' 'Current findings' 'Display latest audit/validation results'
        Write-MenuItem '8' 'Domain migration center' 'Assessment, inventory and client-migration tooling' Warn
        if ($script:IsDomainController) {
            Write-MenuItem '9' 'Directory protocol security' 'Kerberos AES/RC4, LDAP signing/channel binding and strict SMB' Good
        }
        Write-MenuItem '10' 'Dependencies & servicing' 'Official Windows features, modules and servicing status'
        Write-MenuItem '11' 'Domain decommission / reset' 'Supported DC demotion and post-reboot cleanup' Danger
        Write-MenuItem '12' 'Network IDS / Suricata' 'Optional EVE analytics and native Windows IDS dashboard' Good
        if ($script:IsDomainController) {
            Write-MenuItem '13' 'Remote operations' 'Endpoint sessions, diagnostics, messaging and controlled power actions' Good
        }
        Write-MenuItem '0' 'Back' 'Return to compact workspace navigation' Danger
        Write-MenuItem 'H' 'Main menu' 'Jump directly to compact workspace navigation' Warn
        Write-Rule

        try {
        switch (Read-MenuChoice -Prompt 'Select module' -Default '1') {
            '1' {
                $script:Results.Clear()
                Invoke-HostAudit
                if ($script:IsDomainController) {
                    Invoke-DcValidation
                }
                Pause-ControlPlane
            }
            '2' { Invoke-Hardening; Pause-ControlPlane }
            '3' {
                if ($script:IsDomainController) { Show-AdOperationsMenu }
                else { Write-Console 'AD operations require a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            '4' {
                if ($script:IsDomainController) { Invoke-DcValidation; Pause-ControlPlane }
                else { Write-Console 'This server is not a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            '5' {
                if ($script:IsDomainController) { Show-RecoveryMenu }
                else {
                    Set-StepPlan 1
                    Invoke-ConfigurationBackup
                    Complete-Progress
                    Pause-ControlPlane
                }
            }
            '6' { Invoke-NewForestProvisioning; Pause-ControlPlane }
            '7' {
                $script:Results |
                    Select-Object Category, Control, Status, Current |
                    Format-Table -AutoSize
                Pause-ControlPlane
            }
            '8' {
                if ($script:IsDomainController) { Show-DomainMigrationMenu }
                else { Write-Console 'Domain migration center requires a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            '9' {
                if ($script:IsDomainController) { Show-DirectorySecurityMenu }
                else { Write-Console 'Directory protocol security requires a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            '10' { Show-DependencyMenu }
            '11' { Show-DomainResetMenu }
            '12' { Show-WindowsIdsMenu }
            '13' {
                if ($script:IsDomainController) { Show-RemoteOpsMenu }
                else { Write-Console 'Remote domain operations require a Domain Controller.' Yellow; Pause-ControlPlane }
            }
            'H' { $script:MainMenuRequested = $true; return }
            '0' { return }
            default { Write-Console 'Invalid option.' Yellow; Pause-ControlPlane }
        }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ('Show-AllModulesMenu: operation failed: {0}' -f $message) Red
            Write-Log ('Recoverable menu error in Show-AllModulesMenu: {0}' -f $message) ERROR
            Pause-ControlPlane
        }
    }
}

function Show-MainMenu {
    while ($true) {
        $script:MainMenuRequested = $false

        Write-MenuHeader 'AD/DC CONTROL PLANE' 'Workspace navigation · stable letters for daily muscle memory'
        Write-WorkspaceRow 'O' 'Daily operations' Green 'D' 'Directory' Cyan
        Write-WorkspaceRow 'P' 'Policy / DNS' Magenta 'S' 'Security' Red
        Write-WorkspaceRow 'R' 'Remote operations' DarkCyan 'I' 'Insights / IDS' Yellow
        Write-WorkspaceRow 'M' 'Maintenance' Cyan 'A' 'All modules' Gray
        Write-MenuItem 'L' 'Language / Idioma' ("EN / ES [{0}]" -f $script:UiLanguage.ToUpperInvariant()) Normal
        Write-MenuItem '0' 'Exit' 'Close control plane' Danger
        Write-Rule

        try {
            switch ((Read-MenuChoice -Prompt 'Workspace' -Default 'O').ToUpperInvariant()) {
                'O' {
                    if ($script:IsDomainController) { Show-AdOperationsMenu }
                    else { Write-Console 'Daily AD operations require a Domain Controller.' Yellow; Pause-ControlPlane }
                }
                'D' {
                    if ($script:IsDomainController) { Show-DirectoryWorkspace }
                    else { Write-Console 'Directory workspace requires a Domain Controller.' Yellow; Pause-ControlPlane }
                }
                'P' {
                    if ($script:IsDomainController) { Show-PolicyWorkspace }
                    else { Write-Console 'Policy workspace requires a Domain Controller.' Yellow; Pause-ControlPlane }
                }
                'S' {
                    if ($script:IsDomainController) { Show-SecurityWorkspace }
                    else { Invoke-Hardening; Pause-ControlPlane }
                }
                'R' {
                    if ($script:IsDomainController) { Show-RemoteOpsMenu }
                    else { Write-Console 'Remote domain operations require a Domain Controller.' Yellow; Pause-ControlPlane }
                }
                'I' {
                    if ($script:IsDomainController) { Show-InsightsWorkspace }
                    else {
                        $script:Results.Clear()
                        Invoke-HostAudit
                        Pause-ControlPlane
                    }
                }
                'M' { Show-MaintenanceWorkspace }
                'A' { Show-AllModulesMenu }
                'L' { Switch-UiLanguage }
                '0' { return }
                default { Write-Console 'Invalid workspace.' Yellow; Pause-ControlPlane }
            }
        }
        catch {
            $message = $_.Exception.Message
            Write-Console ("Workspace operation failed: {0}" -f $message) Red
            Write-Log ("Recoverable menu error in Show-MainMenu: {0}" -f $message) ERROR
            Pause-ControlPlane
        }
    }
}

# ===========================================================================
# Report / summary
# ===========================================================================

function Write-Report {
    $counts = [ordered]@{
        PASS    = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
        WARN    = @($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count
        FAIL    = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
        ERROR   = @($script:Results | Where-Object { $_.Status -eq 'ERROR' }).Count
        INFO    = @($script:Results | Where-Object { $_.Status -eq 'INFO' }).Count
        SKIP    = @($script:Results | Where-Object { $_.Status -eq 'SKIP' }).Count
        MANAGED = @($script:Results | Where-Object { $_.Status -eq 'MANAGED' }).Count
    }

    $state = [pscustomobject]@{
        SchemaVersion = 2
        Assistant     = $script:ProductName
        Version       = $script:Version
        GeneratedAt   = Get-Date
        StartedAt     = $script:Started
        Mode          = $Mode
        Session       = $script:RemoteKind
        Server        = $script:ServerInfo
        Roles         = $script:RoleInfo
        IsDC          = $script:IsDomainController
        Domain        = $script:DomainInfo
        Forest        = $script:ForestInfo
        BaselineClaim = 'Selected baseline-oriented controls; not a CIS certification'
        Counts        = $counts
        Results       = @($script:Results)
        Changes       = @($script:Changes)
        Warnings      = @($script:Warnings)
        BackupPath    = $(if ($script:SnapshotCreated) { $script:BackupPath } else { $null })
    }

    $state |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $script:ReportFile -Encoding UTF8
}

function Show-Summary {
    Complete-Progress

    $pass = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $warn = @($script:Results | Where-Object { $_.Status -eq 'WARN' }).Count
    $fail = @($script:Results | Where-Object { $_.Status -in @('FAIL','ERROR') }).Count
    $applied = @($script:Changes | Where-Object { $_.Status -eq 'APPLIED' }).Count
    $skipped = @($script:Changes | Where-Object { $_.Status -eq 'SKIPPED' }).Count
    $failedChanges = @($script:Changes | Where-Object { $_.Status -eq 'FAILED' }).Count

    Write-Section 'Execution summary'

    Write-Console ('  PASS={0}  WARN={1}  FAIL/ERROR={2}' -f $pass, $warn, $fail)
    Write-Console ('  Changes: applied={0}; skipped={1}; failed={2}' -f $applied, $skipped, $failedChanges)
    Write-Console ''
    Write-Console ('  Log      : {0}' -f $script:LogFile)
    Write-Console ('  Report   : {0}' -f $script:ReportFile)
    Write-Console ('  Run path : {0}' -f $script:RunPath)

    if ($script:SnapshotCreated) {
        Write-Console ('  Backup   : {0}' -f $script:BackupPath)
    }

    Write-Console ''

    if ($fail -gt 0) {
        Write-Console '  STATUS: ATTENTION REQUIRED' Red
    }
    elseif ($warn -gt 0) {
        Write-Console '  STATUS: COMPLETE WITH WARNINGS' Yellow
    }
    else {
        Write-Console '  STATUS: OPERATION COMPLETE' Green
    }

    Write-Rule
}

# ===========================================================================
# Main
# ===========================================================================

try {
    Initialize-Runtime
    Initialize-Discovery
    Write-Banner

    Write-Log 'Starting Windows Server AD Control Plane.'
    Write-Log ("Export directory: {0}" -f $ExportPath)

    switch ($Mode) {
        'Audit' {
            $script:Results.Clear()
            Invoke-HostAudit

            if ($script:IsDomainController) {
                Invoke-DcValidation
            }
        }

        'Validate' {
            Invoke-DcValidation
        }

        'Harden' {
            $script:Results.Clear()
            Invoke-HostAudit
            Invoke-Hardening
        }

        'Backup' {
            Set-StepPlan 1
            Invoke-ConfigurationBackup
            Complete-Progress
        }

        'ADAdmin' {
            Show-AdOperationsMenu
        }

        'Provision' {
            Invoke-NewForestProvisioning
        }

        'Migration' {
            Show-DomainMigrationMenu
        }

        'DirectorySecurity' {
            if ($script:IsDomainController) {
                Show-DirectorySecurityMenu
            }
            else {
                throw 'DirectorySecurity mode requires a Domain Controller.'
            }
        }

        'Dependencies' {
            Show-DependencyMenu
        }

        'Reset' {
            Show-DomainResetMenu
        }

        'IDS' {
            Show-WindowsIdsMenu
        }

        'RemoteOps' {
            if ($script:IsDomainController) {
                Show-RemoteOpsMenu
            }
            else {
                throw 'RemoteOps mode requires a Domain Controller.'
            }
        }

        'IDSReport' {
            try {
                $path = Export-WindowsIdsDailyReport -Hours 24
                Write-Log ("Scheduled IDS report completed: {0}" -f $path) OK
            }
            catch {
                Write-Log ("Scheduled IDS report failed: {0}" -f $_.Exception.Message) ERROR
                throw
            }
        }

        'IDSResponseCleanup' {
            try {
                [void](Remove-ExpiredGuardedIpsRules)
                Invoke-GuardedIpsResponse -NonInteractive
                Write-Log 'Scheduled guarded IPS cleanup/response cycle completed.' OK
            }
            catch {
                Write-Log ("Guarded IPS scheduled cycle failed: {0}" -f $_.Exception.Message) ERROR
                throw
            }
        }

        'IDSAwarenessCheck' {
            try {
                Invoke-DefenseAwarenessCheck -Notify
                Write-Log 'Scheduled defense awareness cycle completed.' OK
            }
            catch {
                Write-Log ("Defense awareness scheduled cycle failed: {0}" -f $_.Exception.Message) ERROR
                throw
            }
        }

        default {
            $script:Results.Clear()
            Invoke-HostAudit

            if ($script:IsDomainController) {
                Invoke-DcValidation
            }

            Show-MainMenu
        }
    }

    if ($script:MainMenuRequested) {
        $script:MainMenuRequested = $false
        Show-MainMenu
    }

    if (-not $script:ResetCompleted -and $Mode -notin @('IDSReport','IDSResponseCleanup','IDSAwarenessCheck')) {
        Write-Report
        Show-Summary
    }
}
catch {
    if ($script:LogFile) {
        Write-Log ("FATAL: {0}" -f $_.Exception.Message) ERROR
    }
    else {
        Write-Error $_.Exception.Message
    }

    throw
}
finally {
    Complete-Progress

    if ($script:LogFile) {
        Write-Log 'Windows Server AD Control Plane finished.'
    }
}
