#requires -Version 5.1
<#
.SYNOPSIS
    Windows AD Client Assistant - v1.5.3-runtime-sanitization

.DESCRIPTION
    Reversible, transaction-aware assistant for joining Windows clients and
    member servers to classic Active Directory.

    Core flow:
      detect -> preflight -> snapshot -> DNS -> discover -> join -> validate
      recover interrupted transactions without guessing membership state
      leave -> reboot -> restore pre-join DNS/hostname

    The assistant never stores domain passwords and does not add third-party
    package managers or repositories.

.EXAMPLE
    .\windows-ad-client-assistant.ps1 -Mode Preflight
    Check local launch prerequisites without elevation or configuration changes.

.NOTES
    Run from Windows PowerShell 5.1+ as Administrator.
    Test domain lifecycle changes in a lab before broad deployment.
#>

[CmdletBinding()]
param(
    [ValidateSet('Preflight','Interactive','Audit','Join','Status','Leave','Switch','Connectivity','Troubleshoot','Diagnostics','RemoteSetup','Security','SecurityCleanup','SecurityAwareness','Restore','Snapshots','Recover')]
    [string]$Mode = 'Interactive',

    [ValidateSet('en','es')]
    [string]$Language = 'en',

    [string]$StateRoot = "$env:ProgramData\ADClientAssistant",

    [string]$ExternalDnsProbe = 'www.microsoft.com',

    [ValidateRange(5,300)]
    [int]$NetworkOperationTimeoutSeconds = 60,

    [ValidateRange(1000,60000)]
    [int]$TcpProbeTimeoutMs = 8000,

    # AD clients should normally use only AD DNS. By default, every configured
    # AD DNS server must also resolve a name outside the AD zone before the
    # client resolver is replaced. This switch is an explicit exception for
    # intentionally isolated environments.
    [switch]$AllowAdDnsWithoutExternalResolution,

    [switch]$NoColor
)

# Preflight must run before path construction, logging, discovery or elevation.
# A standalone download needs no helper modules for this check.
function Invoke-LaunchPreflight {
    $failed = $false
    Write-Output 'Preflight: Windows domain client'
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
    foreach ($module in @('Microsoft.PowerShell.Management')) {
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

# Engine handoff. This assistant relies on Windows PowerShell 5.1-only cmdlets
# (Add-Computer, Remove-Computer, Test-ComputerSecureChannel) and on 64-bit registry/module views. When launched from
# PowerShell 7 (pwsh) or a 32-bit host, relaunch the same file with the native
# 64-bit Windows PowerShell and the original arguments. Set
# ADASSISTANT_NO_ENGINE_HANDOFF=1 to disable.
function Get-NativeWindowsPowerShellPath {
    $root = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($root)) { $root = 'C:\Windows' }
    # A 32-bit process on 64-bit Windows must use Sysnative to reach 64-bit System32.
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        $candidate = Join-Path $root 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $candidate = Join-Path $root 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $candidate) { return $candidate }
    return $null
}

function ConvertTo-HandoffArgument {
    param([string]$Value)
    if ($Value -notmatch '[\s"]' -and $Value.Length -gt 0) { return $Value }
    # CommandLineToArgvW quoting: double backslashes that precede a quote.
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

$script:NeedsEngineHandoff = (
    $env:ADASSISTANT_NO_ENGINE_HANDOFF -ne '1' -and
    -not [string]::IsNullOrWhiteSpace($PSCommandPath) -and (
        $PSVersionTable.PSEdition -eq 'Core' -or
        ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess)
    )
)
if ($script:NeedsEngineHandoff) {
    $nativeShell = Get-NativeWindowsPowerShellPath
    if ($nativeShell) {
        $handoffArgs = New-Object System.Collections.Generic.List[string]
        foreach ($item in @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)) { $handoffArgs.Add($item) }
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
                if ($entry.Value.IsPresent) { $handoffArgs.Add('-' + $entry.Key) }
            }
            else {
                $handoffArgs.Add('-' + $entry.Key)
                $handoffArgs.Add([string]$entry.Value)
            }
        }
        $reason = if ($PSVersionTable.PSEdition -eq 'Core') { 'PowerShell {0}' -f $PSVersionTable.PSVersion } else { '32-bit host' }
        Write-Host ("[INFO] {0} detected; relaunching with 64-bit Windows PowerShell 5.1." -f $reason) -ForegroundColor Cyan
        $argLine = (@($handoffArgs) | ForEach-Object { ConvertTo-HandoffArgument $_ }) -join ' '
        $process = Start-Process -FilePath $nativeShell -ArgumentList $argLine -NoNewWindow -Wait -PassThru
        exit $process.ExitCode
    }
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Write-Warning 'Windows PowerShell 5.1 was not found; some cmdlets used by this assistant are unavailable in PowerShell 7.'
    }
}
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Administrator privileges are required. Preflight is the only non-elevated mode.'
}

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Runtime state
# ---------------------------------------------------------------------------

$script:ProductName = 'Windows AD Client Assistant'
$script:Version = '1.5.3-runtime-sanitization'
$script:StartedAt = Get-Date
$script:SnapshotRoot = Join-Path $StateRoot 'snapshots'
$script:CurrentState = Join-Path $StateRoot 'current.json'
$script:LogRoot = Join-Path $StateRoot 'logs'
$script:ReportRoot = Join-Path $StateRoot 'reports'
$script:RunId = '{0}-{1}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'), $PID
$script:LogFile = Join-Path $script:LogRoot ("client-assistant-{0}.log" -f $script:RunId)
$script:ReportFile = Join-Path $script:ReportRoot ("client-assistant-{0}.json" -f $script:RunId)
$script:NetSetupLog = Join-Path $env:SystemRoot 'debug\NetSetup.log'
$script:UseColor = (-not $NoColor) -and (-not [Console]::IsOutputRedirected)
$script:Events = New-Object 'System.Collections.Generic.List[object]'
$script:LockStream = $null
$script:RunOutcome = 'COMPLETE'
$script:UiLanguage = $Language.ToLowerInvariant()

# ---------------------------------------------------------------------------
# UI / logging / persistence
# ---------------------------------------------------------------------------

function Initialize-Runtime {
    foreach ($path in @($StateRoot,$script:SnapshotRoot,$script:LogRoot,$script:ReportRoot)) {
        New-Item -ItemType Directory -Force -Path $path | Out-Null
    }

    New-Item -ItemType File -Force -Path $script:LogFile | Out-Null

    $lockPath = Join-Path $StateRoot 'assistant.lock'
    try {
        $script:LockStream = [System.IO.File]::Open(
            $lockPath,
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None
        )
    }
    catch {
        throw 'Another Windows AD Client Assistant process appears to be running.'
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet('INFO','OK','WARN','ERROR')]
        [string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format o), $Level, $Message
    Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
}

function Add-RunEvent {
    param(
        [Parameter(Mandatory=$true)][string]$Type,
        [Parameter(Mandatory=$true)][string]$Message
    )

    $script:Events.Add([pscustomobject]@{
        Time    = (Get-Date).ToString('o')
        Type    = $Type
        Message = $Message
    }) | Out-Null
}

function Write-Ui {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text,
        [ValidateSet('Default','Cyan','Green','Yellow','Red','Gray','White','Magenta')]
        [string]$Color = 'Default',
        [switch]$NoNewline
    )

    $params = @{}
    if ($NoNewline) { $params.NoNewline = $true }

    if (-not $script:UseColor -or $Color -eq 'Default') {
        Write-Host $Text @params
        return
    }

    Write-Host $Text -ForegroundColor $Color @params
}

function Write-Info {
    param([string]$Text)
    Write-Ui '[INFO] ' Cyan -NoNewline
    Write-Ui $Text
    Write-Log $Text INFO
    Add-RunEvent INFO $Text
}

function Write-Ok {
    param([string]$Text)
    Write-Ui '[ OK ] ' Green -NoNewline
    Write-Ui $Text
    Write-Log $Text OK
    Add-RunEvent OK $Text
}

function Write-Warn {
    param([string]$Text)
    Write-Ui '[WARN] ' Yellow -NoNewline
    Write-Ui $Text
    Write-Log $Text WARN
    Add-RunEvent WARN $Text
}

function Write-ErrorUi {
    param([string]$Text)
    Write-Ui '[ERROR] ' Red -NoNewline
    Write-Ui $Text
    Write-Log $Text ERROR
    Add-RunEvent ERROR $Text
}

$script:UiSpanish = @{
    'Press Enter to continue' = 'Pulsa Enter para continuar'
    'Select operation' = 'Selecciona una operación'
    'Readiness audit' = 'Auditoría de preparación'
    'Guided domain join' = 'Unión guiada al dominio'
    'Domain client status' = 'Estado del cliente de dominio'
    'Leave domain cleanly' = 'Salir limpiamente del dominio'
    'Switch to another domain' = 'Cambiar a otro dominio'
    'AD connectivity test' = 'Prueba de conectividad AD'
    'Troubleshoot / repair' = 'Diagnóstico / reparación'
    'Export diagnostic bundle' = 'Exportar paquete de diagnóstico'
    'Restore pre-join state' = 'Restaurar estado previo a la unión'
    'List recovery snapshots' = 'Listar snapshots de recuperación'
    'Recover interrupted lifecycle' = 'Recuperar ciclo interrumpido'
    'Language / Idioma' = 'Idioma / Language'
    'Exit' = 'Salir'
    'AD DNS domain (for example corp.example.com)' = 'Dominio DNS de AD (por ejemplo corp.example.com)'
    'AD DNS server IPv4 addresses (comma separated)' = 'Direcciones IPv4 de los DNS de AD (separadas por comas)'
    'Target AD DNS domain (for example corp.example.com)' = 'Dominio DNS de AD destino (por ejemplo corp.example.com)'
    'Target AD DNS server IPv4 addresses (comma separated)' = 'Direcciones IPv4 de los DNS AD destino (separadas por comas)'
    'Join account' = 'Cuenta autorizada para unir el equipo'
    'Source-domain unjoin account' = 'Cuenta autorizada para salir del dominio origen'
    'Target-domain join account' = 'Cuenta autorizada para unir al dominio destino'
    'Computer OU DN (optional)' = 'DN de la OU del equipo (opcional)'
    'Computer name' = 'Nombre del equipo'
    'Workgroup after leaving the domain' = 'Grupo de trabajo tras abandonar el dominio'
    'Restart now?' = '¿Reiniciar ahora?'
    'Suricata + Wazuh security / guarded IPS' = 'Seguridad Suricata + Wazuh / IPS controlado'
    'SURICATA + WAZUH SECURITY' = 'SEGURIDAD SURICATA + WAZUH'
    'Validate Suricata configuration' = 'Validar configuración de Suricata'
    'Configure Wazuh manager' = 'Configurar manager Wazuh'
    'Enable Suricata EVE ingestion in Wazuh' = 'Activar ingestión EVE de Suricata en Wazuh'
    'IDS / IPS response center' = 'Centro de respuesta IDS / IPS'
    'Recent Wazuh agent log' = 'Registro reciente del agente Wazuh'
    'Open graphical Defense Center' = 'Abrir Centro de Defensa gráfico'
    'AD Client Defense Center - Suricata + Wazuh' = 'Centro de Defensa del cliente AD - Suricata + Wazuh'
    'Blocks' = 'Bloqueos'
    'Alerts' = 'Alertas'
    'Refresh' = 'Actualizar'
    'Unblock selected' = 'Desbloquear seleccionado'
    'Unblock all' = 'Desbloquear todo'
    'Block IP' = 'Bloquear IP'
    'Trust selected' = 'Confiar en seleccionado'
    'Run IPS' = 'Ejecutar IPS'
    'Unblock' = 'Desbloquear'
    'Trust IP' = 'Confiar en IP'
    'Apply response' = 'Aplicar respuesta'
    'Close' = 'Cerrar'

}

function Get-UiText {
    param([Parameter(Mandatory=$true)][string]$Text)
    if ($script:UiLanguage -eq 'es' -and $script:UiSpanish.ContainsKey($Text)) {
        return [string]$script:UiSpanish[$Text]
    }
    return $Text
}

function Switch-UiLanguage {
    $script:UiLanguage = if ($script:UiLanguage -eq 'en') { 'es' } else { 'en' }
}

function Pause-Ui {
    if (-not [Console]::IsInputRedirected) {
        [void](Read-Host (Get-UiText 'Press Enter to continue'))
    }
}

function Read-Value {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [string]$Default = ''
    )

    if ($Default) {
        $value = Read-Host ("{0} [{1}]" -f (Get-UiText $Prompt), $Default)
        if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
        return $value.Trim()
    }

    return (Read-Host (Get-UiText $Prompt)).Trim()
}

function Confirm-Choice {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [ValidateSet('Y','N')][string]$Default = 'N'
    )

    $shownDefault = $Default
    if ($script:UiLanguage -eq 'es' -and $Default -eq 'Y') { $shownDefault = 'S' }
    $answer = Read-Host ("{0} [{1}]" -f (Get-UiText $Prompt), $shownDefault)
    if ([string]::IsNullOrWhiteSpace($answer)) { $answer = $Default }
    return ($answer -match '^(?i:y|yes|s|si|sí)$')
}

function Confirm-Literal {
    param(
        [Parameter(Mandatory=$true)][string]$Prompt,
        [Parameter(Mandatory=$true)][string]$Literal
    )

    Write-Ui (Get-UiText $Prompt) Yellow
    $literalPrompt = if ($script:UiLanguage -eq 'es') { "Escribe {0} para continuar" -f $Literal } else { "Type {0} to continue" -f $Literal }
    $answer = Read-Host $literalPrompt
    return ($answer -ceq $Literal)
}

function Write-JsonAtomic {
    param(
        [Parameter(Mandatory=$true)]$Object,
        [Parameter(Mandatory=$true)][string]$Path,
        [int]$Depth = 10
    )

    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
    }

    $tmp = '{0}.tmp.{1}' -f $Path,$PID
    try {
        $Object | ConvertTo-Json -Depth $Depth | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-CurrentState {
    if (-not (Test-Path -LiteralPath $script:CurrentState)) { return $null }
    try {
        return Get-Content -LiteralPath $script:CurrentState -Raw -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warn ("Current state file is unreadable: {0}" -f $_.Exception.Message)
        return $null
    }
}

function Set-CurrentStateValues {
    param([Parameter(Mandatory=$true)][hashtable]$Values)

    $state = Get-CurrentState
    if (-not $state) { return $false }

    foreach ($key in $Values.Keys) {
        if ($state.PSObject.Properties[$key]) {
            $state.$key = $Values[$key]
        }
        else {
            $state | Add-Member -NotePropertyName $key -NotePropertyValue $Values[$key]
        }
    }

    if ($state.PSObject.Properties['UpdatedAt']) {
        $state.UpdatedAt = (Get-Date).ToString('o')
    }
    else {
        $state | Add-Member -NotePropertyName UpdatedAt -NotePropertyValue (Get-Date).ToString('o')
    }

    Write-JsonAtomic -Object $state -Path $script:CurrentState
    return $true
}

function Remove-CurrentState {
    Remove-Item -LiteralPath $script:CurrentState -Force -ErrorAction SilentlyContinue
}

function Get-BootMarker {
    try {
        return (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToString('o')
    }
    catch {
        return 'unknown'
    }
}

function Get-LifecycleLabel {
    $state = Get-CurrentState
    if (-not $state) { return 'none' }
    if ($state.PSObject.Properties['Phase']) { return [string]$state.Phase }
    return 'legacy'
}

function Write-Header {
    try { Clear-Host } catch {}

    Write-Ui ('  {0}' -f $script:ProductName) Cyan
    Write-Ui ('  v{0}' -f $script:Version) Gray
    Write-Ui ('-' * 88) Gray

    $identity = 'unavailable'
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $identity = if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup }
    }
    catch {}

    $remote = if (Test-RemoteSession) { 'remote' } else { 'local' }
    Write-Ui ('  Computer={0}  Identity={1}  Session={2}' -f $env:COMPUTERNAME,$identity,$remote) White
    Write-Ui ('  Lifecycle={0}  Log={1}' -f (Get-LifecycleLabel),$script:LogFile) Gray
    Write-Ui ('-' * 88) Gray
    Write-Ui ''
}

function Write-RunReport {
    try {
        $cs = $null
        try { $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch {}

        $state = Get-CurrentState
        $report = [ordered]@{
            SchemaVersion = 1
            Assistant     = $script:ProductName
            Version       = $script:Version
            Mode          = $Mode
            StartedAt     = $script:StartedAt.ToString('o')
            CompletedAt   = (Get-Date).ToString('o')
            Outcome       = $script:RunOutcome
            Computer      = $env:COMPUTERNAME
            PartOfDomain  = $(if ($cs) { [bool]$cs.PartOfDomain } else { $null })
            Domain        = $(if ($cs) { [string]$cs.Domain } else { $null })
            CurrentState  = $state
            LogFile       = $script:LogFile
            Events        = @($script:Events)
        }
        Write-JsonAtomic -Object $report -Path $script:ReportFile -Depth 12
    }
    catch {
        try { Write-Log ("Could not write run report: {0}" -f $_.Exception.Message) WARN } catch {}
    }
}

# ---------------------------------------------------------------------------
# Host / network discovery
# ---------------------------------------------------------------------------

function Test-RemoteSession {
    $sender = Get-Variable -Name PSSenderInfo -ErrorAction SilentlyContinue
    return ($env:SESSIONNAME -match '^(?i)RDP-' -or [bool]$sender)
}

function Get-ProductInfo {
    $cv = Get-ItemProperty `
        -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' `
        -ErrorAction Stop

    return [pscustomobject]@{
        ProductName = [string]$cv.ProductName
        EditionID   = [string]$cv.EditionID
    }
}

function Test-DomainJoinEdition {
    $info = Get-ProductInfo
    if ($info.ProductName -match '(?i)\bHome\b' -or $info.EditionID -match '(?i)^Core') {
        Write-ErrorUi ("Windows edition does not support classic AD domain join: {0} / {1}" -f `
            $info.ProductName,$info.EditionID)
        return $false
    }
    return $true
}

function Test-DnsDomainName {
    param([Parameter(Mandatory=$true)][string]$Name)

    if ($Name.Length -lt 3 -or $Name.Length -gt 253) { return $false }
    if ($Name -notmatch '\.' -or $Name.StartsWith('.') -or $Name.EndsWith('.') -or $Name.Contains('..')) {
        return $false
    }

    foreach ($label in $Name.Split('.')) {
        if ($label.Length -lt 1 -or $label.Length -gt 63) { return $false }
        if ($label -notmatch '^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$' -and $label.Length -gt 1) {
            return $false
        }
        if ($label.Length -eq 1 -and $label -notmatch '^[A-Za-z0-9]$') { return $false }
    }
    return $true
}

function Test-ComputerNameValue {
    param([Parameter(Mandatory=$true)][string]$Name)
    if ($Name.Length -lt 1 -or $Name.Length -gt 15) { return $false }
    return ($Name -match '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?$' -or $Name -match '^[A-Za-z0-9]$')
}

function Test-IPv4AddressList {
    param([Parameter(Mandatory=$true)][string[]]$Addresses)

    if ($Addresses.Count -eq 0) { return $false }
    foreach ($address in $Addresses) {
        if ($address -notmatch '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $false }
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsed)) { return $false }
        if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }
    }
    return $true
}

function Parse-DnsInput {
    param([Parameter(Mandatory=$true)][string]$Text)
    return @(
        $Text -split '[,;\s]+' |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.Trim() }
    )
}

function Test-TcpPort {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName,
        [Parameter(Mandatory=$true)][int]$Port,
        [int]$TimeoutMs = $TcpProbeTimeoutMs
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName,$Port,$null,$null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs,$false)) { return $false }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function Get-RecommendedInterfaceIndex {
    param([Parameter(Mandatory=$true)][string]$RemoteIPAddress)
    try {
        $route = Find-NetRoute -RemoteIPAddress $RemoteIPAddress -ErrorAction Stop |
            Select-Object -First 1
        if ($route -and $route.InterfaceIndex) { return [uint32]$route.InterfaceIndex }
    }
    catch {}
    return $null
}

function Get-NetworkCandidates {
    $configs = @(Get-NetIPConfiguration -ErrorAction Stop |
        Where-Object {
            $_.NetAdapter -and
            $_.NetAdapter.Status -eq 'Up' -and
            $_.IPv4Address
        })

    return @($configs | Sort-Object `
        @{ Expression = { if ($_.IPv4DefaultGateway) { 0 } else { 1 } } }, `
        InterfaceAlias)
}

function Select-NetworkInterface {
    param([string]$RemoteIPAddress = '')

    $items = @(Get-NetworkCandidates)
    if ($items.Count -eq 0) { throw 'No active IPv4 network interface was detected.' }

    $recommended = $null
    if ($RemoteIPAddress) { $recommended = Get-RecommendedInterfaceIndex -RemoteIPAddress $RemoteIPAddress }

    if ($items.Count -eq 1) {
        Write-Ok ("Single active IPv4 interface selected automatically: {0}" -f $items[0].InterfaceAlias)
        return $items[0]
    }

    Write-Ui ''
    Write-Ui 'NETWORK INTERFACES' Cyan
    $defaultChoice = 1
    for ($i = 0; $i -lt $items.Count; $i++) {
        $cfg = $items[$i]
        $ips = @($cfg.IPv4Address | ForEach-Object { $_.IPAddress }) -join ','
        $gw = if ($cfg.IPv4DefaultGateway) {
            @($cfg.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ','
        }
        else { '-' }
        $metric = try {
            (Get-NetIPInterface -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop).InterfaceMetric
        }
        catch { '-' }
        $mark = ''
        if ($recommended -and [uint32]$cfg.InterfaceIndex -eq [uint32]$recommended) {
            $mark = ' <- route to AD DNS'
            $defaultChoice = $i + 1
        }
        Write-Ui ("  [{0}] {1,-24} IPv4={2,-18} GW={3,-16} metric={4}{5}" -f `
            ($i + 1),$cfg.InterfaceAlias,$ips,$gw,$metric,$mark)
    }
    Write-Ui '  [M] Enter interface index manually'

    $choice = Read-Value -Prompt 'Select interface' -Default ([string]$defaultChoice)
    if ($choice -match '^(?i)m$') {
        $idxRaw = Read-Value -Prompt 'InterfaceIndex' -Default ''
        [uint32]$idx = 0
        if (-not [uint32]::TryParse($idxRaw,[ref]$idx)) { throw 'Invalid InterfaceIndex.' }
        return Get-NetIPConfiguration -InterfaceIndex $idx -ErrorAction Stop
    }

    [int]$number = 0
    if (-not [int]::TryParse($choice,[ref]$number) -or $number -lt 1 -or $number -gt $items.Count) {
        throw 'Invalid interface selection.'
    }

    $selected = $items[$number - 1]
    if ($recommended -and [uint32]$selected.InterfaceIndex -ne [uint32]$recommended) {
        Write-Warn ("Selected interface {0} differs from the current route to AD DNS (ifIndex {1})." -f `
            $selected.InterfaceAlias,$recommended)
        if (-not (Confirm-Choice -Prompt 'Continue without changing the Windows route table?' -Default N)) {
            throw 'Interface selection cancelled because routing does not match.'
        }
    }
    return $selected
}

function Get-InterfaceDnsState {
    param([Parameter(Mandatory=$true)][uint32]$InterfaceIndex)

    $adapter = Get-NetAdapter -InterfaceIndex $InterfaceIndex -ErrorAction Stop
    $dns4 = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop
    $dns6 = Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue

    $guidText = [string]$adapter.InterfaceGuid
    if (-not $guidText.StartsWith('{')) { $guidText = '{' + $guidText.Trim('{}') + '}' }

    $regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0}' -f $guidText
    $nameServer = ''
    $dhcpNameServer = ''
    try {
        $props = Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop
        $nameServer = [string]$props.NameServer
        $dhcpNameServer = [string]$props.DhcpNameServer
    }
    catch {}

    return [pscustomobject]@{
        InterfaceIndex      = $InterfaceIndex
        InterfaceAlias      = [string]$adapter.Name
        InterfaceGuid       = $guidText
        ServerAddresses     = @($dns4.ServerAddresses)
        IPv6ServerAddresses = @($dns6.ServerAddresses)
        DnsWasStatic        = -not [string]::IsNullOrWhiteSpace($nameServer)
        StaticNameServer    = $nameServer
        DhcpNameServer      = $dhcpNameServer
    }
}

# ---------------------------------------------------------------------------
# NetSetup evidence
# ---------------------------------------------------------------------------

function Get-NetSetupLineCount {
    if (-not (Test-Path -LiteralPath $script:NetSetupLog)) { return 0 }
    try { return @(Get-Content -LiteralPath $script:NetSetupLog -ErrorAction Stop).Count }
    catch { return 0 }
}

function Get-NetSetupAttemptLines {
    param([int]$StartLine = 0)

    if (-not (Test-Path -LiteralPath $script:NetSetupLog)) { return @() }
    try {
        $all = @(Get-Content -LiteralPath $script:NetSetupLog -ErrorAction Stop)
        if ($StartLine -gt 0 -and $StartLine -lt $all.Count) {
            return @($all | Select-Object -Skip $StartLine | Select-Object -Last 500)
        }
        return @($all | Select-Object -Last 500)
    }
    catch { return @() }
}

function Get-JoinCommitEvidence {
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        [int]$NetSetupStartLine = 0
    )

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain -and $cs.Domain -ieq $Domain) {
            return [pscustomobject]@{Outcome='Accepted';Reason='Windows reports target-domain membership'}
        }
    }
    catch {}

    $lines = @(Get-NetSetupAttemptLines -StartLine $NetSetupStartLine)
    $text = $lines -join "`n"

    if ($text -match '(?i)Netp(?:Do)?JoinDomain[^\r\n]*status:\s*0x0\b' -or
        $text -match '(?i)machine is now joined to the domain') {
        return [pscustomobject]@{Outcome='Accepted';Reason='NetSetup.log contains a successful join result'}
    }

    if ($text -match '(?i)Netp(?:Do)?JoinDomain[^\r\n]*status:\s*0x(?!0\b)[0-9a-f]+' -or
        $text -match '(?i)NERR_AccountReuseBlockedByPolicy|ERROR_NO_SUCH_DOMAIN|ERROR_LOGON_FAILURE') {
        return [pscustomobject]@{Outcome='Failed';Reason='NetSetup.log contains an explicit join failure'}
    }

    return [pscustomobject]@{Outcome='Ambiguous';Reason='No conclusive membership result was found'}
}

function Write-NetSetupDiagnosis {
    param(
        [string]$SnapshotPath = '',
        [int]$StartLine = 0
    )

    $tail = @(Get-NetSetupAttemptLines -StartLine $StartLine)
    if ($tail.Count -eq 0) {
        Write-Warn 'NetSetup.log is unavailable; no Windows domain-join diagnostics could be extracted.'
        return
    }

    if ($SnapshotPath) {
        try { $tail | Set-Content -LiteralPath (Join-Path $SnapshotPath 'NetSetup-tail.txt') -Encoding UTF8 } catch {}
    }

    $joined = $tail -join "`n"
    if ($joined -match '(?i)0x0*AAC|NERR_AccountReuseBlockedByPolicy|account reuse.*blocked') {
        Write-ErrorUi 'Windows blocked reuse of an existing AD computer account (0xAAC).'
        Write-Warn 'Use a delegated account/owner allowed by NetJoin hardening, or inspect the stale computer object.'
        Write-Warn 'This assistant will not apply legacy registry bypasses for account-reuse hardening.'
    }
    elseif ($joined -match '(?i)0x0*54B|ERROR_NO_SUCH_DOMAIN|domain.*could not be contacted') {
        Write-Warn 'NetSetup indicates DC/domain discovery failure. Re-check AD DNS, routing and required ports.'
    }
    elseif ($joined -match '(?i)0x0*52E|ERROR_LOGON_FAILURE') {
        Write-Warn 'NetSetup indicates credential/logon failure. Verify the join identity and Kerberos time.'
    }
    elseif ($joined -match '(?i)0x0*5\b|ERROR_ACCESS_DENIED') {
        Write-Warn 'NetSetup indicates access denied. Verify delegated computer-join permissions and OU ACLs.'
    }
    else {
        Write-Warn 'NetSetup.log evidence from the attempt was captured for troubleshooting.'
    }
}

# ---------------------------------------------------------------------------
# Snapshots / transaction state
# ---------------------------------------------------------------------------

function New-PreJoinSnapshot {
    param(
        [Parameter(Mandatory=$true)]$Interface,
        [Parameter(Mandatory=$true)][string]$TargetDomain
    )

    $snapshotPath = Join-Path $script:SnapshotRoot $script:RunId
    New-Item -ItemType Directory -Force -Path $snapshotPath | Out-Null

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $dnsState = Get-InterfaceDnsState -InterfaceIndex ([uint32]$Interface.InterfaceIndex)
    $product = Get-ProductInfo
    $netSetupStartLine = Get-NetSetupLineCount

    $snapshot = [ordered]@{
        SnapshotVersion   = 3
        CreatedAt         = (Get-Date).ToString('o')
        SnapshotPath      = $snapshotPath
        TargetDomain      = $TargetDomain
        ComputerName      = [string]$env:COMPUTERNAME
        BootMarker        = Get-BootMarker
        PartOfDomain      = [bool]$cs.PartOfDomain
        Domain            = [string]$cs.Domain
        Workgroup         = [string]$cs.Workgroup
        ProductName       = $product.ProductName
        EditionID         = $product.EditionID
        NetSetupStartLine = $netSetupStartLine
        Interface         = $dnsState
    }

    Write-JsonAtomic -Object $snapshot -Path (Join-Path $snapshotPath 'snapshot.json')
    @(Get-NetSetupAttemptLines -StartLine 0 | Select-Object -Last 250) |
        Set-Content -LiteralPath (Join-Path $snapshotPath 'NetSetup-before.txt') -Encoding UTF8

    Write-Ok ("Pre-join snapshot created: {0}" -f $snapshotPath)
    return [pscustomobject]$snapshot
}

function Get-Snapshot {
    param([Parameter(Mandatory=$true)][string]$SnapshotPath)

    $file = Join-Path $SnapshotPath 'snapshot.json'
    if (-not (Test-Path -LiteralPath $file)) { throw "Snapshot metadata not found: $file" }
    return Get-Content -LiteralPath $file -Raw -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
}

function New-JoinState {
    param(
        [Parameter(Mandatory=$true)]$Snapshot,
        [Parameter(Mandatory=$true)][string]$Domain,
        [Parameter(Mandatory=$true)][string[]]$DnsServers,
        [Parameter(Mandatory=$true)][string]$RequestedComputerName,
        [ValidateSet('Join','Switch')][string]$Operation = 'Join',
        [string]$SourceDomain = ''
    )

    $state = [ordered]@{
        StateVersion          = 4
        Operation             = $Operation
        SourceDomain          = $SourceDomain
        Phase                 = 'SNAPSHOT_CREATED'
        PhaseBootMarker       = Get-BootMarker
        TransactionStartedAt  = (Get-Date).ToString('o')
        UpdatedAt             = (Get-Date).ToString('o')
        Domain                = $Domain
        DnsServers            = @($DnsServers)
        RequestedComputerName = $RequestedComputerName
        SnapshotPath          = [string]$Snapshot.SnapshotPath
        NetSetupStartLine     = [int]$Snapshot.NetSetupStartLine
        JoinAttempted         = $false
        MembershipCommitted   = $false
    }

    Write-JsonAtomic -Object $state -Path $script:CurrentState
}

function Show-Snapshots {
    Write-Header
    Write-Ui 'RECOVERY SNAPSHOTS' Cyan
    Write-Ui ''

    $dirs = @(Get-ChildItem -LiteralPath $script:SnapshotRoot -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending)
    if ($dirs.Count -eq 0) {
        Write-Info 'No snapshots found.'
        return
    }

    $current = Get-CurrentState
    Write-Ui ('  {0,-22} {1,-28} {2,-16} {3,-22} {4}' -f 'CREATED','TARGET DOMAIN','COMPUTER','INTERFACE','STATE') Gray
    foreach ($dir in $dirs) {
        try {
            $snap = Get-Snapshot -SnapshotPath $dir.FullName
            $stateText = ''
            if ($current -and [string]$current.SnapshotPath -eq $dir.FullName) {
                $stateText = [string]$current.Phase
            }
            Write-Ui ('  {0,-22} {1,-28} {2,-16} {3,-22} {4}' -f `
                ([string]$snap.CreatedAt).Substring(0,[Math]::Min(19,([string]$snap.CreatedAt).Length)),
                [string]$snap.TargetDomain,
                [string]$snap.ComputerName,
                [string]$snap.Interface.InterfaceAlias,
                $stateText)
            Write-Ui ('    {0}' -f $dir.FullName) Gray
        }
        catch {
            Write-Warn ("Unreadable snapshot: {0}" -f $dir.FullName)
        }
    }
}

# ---------------------------------------------------------------------------
# DNS / discovery / readiness
# ---------------------------------------------------------------------------

function Test-AdDnsServers {
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        [Parameter(Mandatory=$true)][string[]]$DnsServers
    )

    $srvName = '_ldap._tcp.dc._msdcs.{0}' -f $Domain
    $adOk = $true
    $forwardingOk = $true
    $dcNames = New-Object 'System.Collections.Generic.List[string]'

    foreach ($server in $DnsServers) {
        try {
            $answers = @(Resolve-DnsName -Name $srvName -Type SRV -Server $server -DnsOnly -ErrorAction Stop |
                Where-Object { $_.Type -eq 'SRV' -and $_.NameTarget })
            if ($answers.Count -eq 0) { throw 'No SRV answer.' }
            Write-Ok ("AD DNS preflight passed through {0}." -f $server)
            foreach ($answer in $answers) {
                $dc = ([string]$answer.NameTarget).TrimEnd('.')
                if ($dc -and -not $dcNames.Contains($dc)) { $dcNames.Add($dc) | Out-Null }
            }
        }
        catch {
            Write-ErrorUi ("AD DNS {0} does not return DC locator SRV records: {1}" -f $server,$_.Exception.Message)
            $adOk = $false
            continue
        }

        try {
            $external = @(Resolve-DnsName -Name $ExternalDnsProbe -Type A -Server $server -DnsOnly -ErrorAction Stop |
                Where-Object { $_.IPAddress })
            if ($external.Count -eq 0) { throw 'No external A answer.' }
            Write-Ok ("AD DNS {0} resolves names outside the AD zone." -f $server)
        }
        catch {
            Write-Warn ("AD DNS {0} cannot resolve the external probe {1}." -f $server,$ExternalDnsProbe)
            $forwardingOk = $false
        }
    }

    return [pscustomobject]@{
        AdDiscoveryOk = $adOk
        ForwardingOk  = $forwardingOk
        DomainControllers = @($dcNames)
    }
}

function Wait-SystemAdDiscovery {
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        [int]$Attempts = 0
    )

    if ($Attempts -le 0) {
        $Attempts = [Math]::Max(8,[Math]::Ceiling($NetworkOperationTimeoutSeconds / 2))
    }

    $srvName = '_ldap._tcp.dc._msdcs.{0}' -f $Domain
    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            $answers = @(Resolve-DnsName -Name $srvName -Type SRV -DnsOnly -ErrorAction Stop |
                Where-Object { $_.Type -eq 'SRV' -and $_.NameTarget })
            if ($answers.Count -gt 0) { return $true }
        }
        catch {}
        Start-Sleep -Seconds 2
    }
    return $false
}

function Test-AdNetworkReadiness {
    param([Parameter(Mandatory=$true)][string]$DomainController)

    Write-Ui ''
    Write-Ui ("AD NETWORK READINESS - {0}" -f $DomainController) Cyan

    $required = @(
        @{Name='DNS';Port=53},
        @{Name='Kerberos';Port=88},
        @{Name='RPC';Port=135},
        @{Name='LDAP';Port=389},
        @{Name='SMB';Port=445}
    )
    $optional = @(
        @{Name='Kerberos password';Port=464},
        @{Name='Global Catalog';Port=3268}
    )

    $all = $true
    foreach ($check in $required) {
        if (Test-TcpPort -ComputerName $DomainController -Port $check.Port) {
            Write-Ok ("{0}/TCP {1} reachable." -f $check.Name,$check.Port)
        }
        else {
            Write-ErrorUi ("{0}/TCP {1} is not reachable." -f $check.Name,$check.Port)
            $all = $false
        }
    }

    foreach ($check in $optional) {
        if (Test-TcpPort -ComputerName $DomainController -Port $check.Port) {
            Write-Ok ("{0}/TCP {1} reachable." -f $check.Name,$check.Port)
        }
        else {
            Write-Warn ("{0}/TCP {1} is not reachable from this path." -f $check.Name,$check.Port)
        }
    }

    Write-Info 'Dynamic RPC ports are validated by the actual Windows domain-join operation.'
    return $all
}

function Test-TimeState {
    if (-not (Get-Command w32tm.exe -ErrorAction SilentlyContinue)) { return $true }

    $status = & w32tm.exe /query /status 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok 'Windows Time status is available.'
        return $true
    }

    Write-Warn 'Windows Time is not currently reporting synchronized status.'
    Write-Warn 'Kerberos is sensitive to clock skew; verify time if authentication fails.'
    return $false
}

function Test-TimeAgainstDomainController {
    param([Parameter(Mandatory=$true)][string]$ComputerName)

    if (-not (Get-Command w32tm.exe -ErrorAction SilentlyContinue)) { return $true }
    $output = & w32tm.exe /stripchart "/computer:$ComputerName" /samples:3 /dataonly 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Ok ("Time samples from domain controller {0} succeeded." -f $ComputerName)
        return $true
    }

    Write-Warn ("Could not sample domain-controller time from {0}." -f $ComputerName)
    $output | Select-Object -Last 5 | ForEach-Object { Write-Ui ([string]$_) Gray }
    return $false
}

function Set-DomainDns {
    param(
        [Parameter(Mandatory=$true)][uint32]$InterfaceIndex,
        [Parameter(Mandatory=$true)][string[]]$DnsServers
    )

    if (Test-RemoteSession) {
        Write-Warn 'Remote/RDP session detected. DNS changes normally preserve an existing IP session,'
        Write-Warn 'but incorrect DNS can prevent reconnecting by hostname.'
    }

    Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses $DnsServers -ErrorAction Stop
    Clear-DnsClientCache -ErrorAction SilentlyContinue
    Write-Ok ("AD DNS configured: {0}" -f ($DnsServers -join ', '))

    $v6 = @(Get-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
    if ($v6.Count -gt 0) {
        Write-Warn ("IPv6 DNS servers are also present on this interface: {0}" -f ($v6 -join ', '))
        Write-Warn 'Ensure they can resolve the AD zone or correct them through the network policy that owns IPv6.'
    }
}

function Restore-DnsFromSnapshot {
    param([Parameter(Mandatory=$true)]$Snapshot)

    $iface = $Snapshot.Interface
    $adapter = $null

    if ($iface.InterfaceGuid) {
        $targetGuid = ([string]$iface.InterfaceGuid).Trim('{}')
        $adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { ([string]$_.InterfaceGuid).Trim('{}') -ieq $targetGuid } |
            Select-Object -First 1
    }
    if (-not $adapter -and $iface.InterfaceIndex) {
        $adapter = Get-NetAdapter -InterfaceIndex ([uint32]$iface.InterfaceIndex) -ErrorAction SilentlyContinue
    }
    if (-not $adapter -and $iface.InterfaceAlias) {
        $adapter = Get-NetAdapter -Name ([string]$iface.InterfaceAlias) -ErrorAction SilentlyContinue
    }
    if (-not $adapter) { throw 'Original network adapter could not be matched by GUID, index or alias.' }

    $index = [uint32]$adapter.ifIndex
    Write-Info ("Restoring DNS on {0} (ifIndex {1})." -f $adapter.Name,$index)

    if ([bool]$iface.DnsWasStatic) {
        $old = @($iface.ServerAddresses)
        if ($old.Count -gt 0) {
            Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $old -ErrorAction Stop
            Write-Ok ("Previous static IPv4 DNS restored: {0}" -f ($old -join ', '))
        }
        else {
            Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop
            Write-Ok 'Previous DNS state reset to interface defaults.'
        }
    }
    else {
        Set-DnsClientServerAddress -InterfaceIndex $index -ResetServerAddresses -ErrorAction Stop
        Write-Ok 'DNS returned to DHCP/default behavior.'
    }

    Clear-DnsClientCache -ErrorAction SilentlyContinue
}

function Restore-ComputerNameFromSnapshot {
    param([Parameter(Mandatory=$true)]$Snapshot)

    $oldName = [string]$Snapshot.ComputerName
    if ([string]::IsNullOrWhiteSpace($oldName)) { return $true }
    if ($env:COMPUTERNAME -ieq $oldName) { return $true }

    try {
        Rename-Computer -NewName $oldName -Force -ErrorAction Stop
        Write-Ok ("Computer name restoration scheduled: {0}" -f $oldName)
        return $true
    }
    catch {
        Write-Warn ("Computer name could not be restored yet: {0}" -f $_.Exception.Message)
        return $false
    }
}

# ---------------------------------------------------------------------------
# Join validation and lifecycle observation
# ---------------------------------------------------------------------------

function Test-PostJoinAcceptance {
    param([Parameter(Mandatory=$true)][string]$Domain)

    $fail = $false
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop

    if ($cs.PartOfDomain -and $cs.Domain -ieq $Domain) {
        Write-Ok 'Windows reports the expected domain membership.'
    }
    else {
        Write-ErrorUi ("Windows domain membership is not {0}." -f $Domain)
        $fail = $true
    }

    try {
        if (Test-ComputerSecureChannel -ErrorAction Stop) {
            Write-Ok 'Computer secure channel is healthy.'
        }
        else {
            Write-ErrorUi 'Computer secure channel test returned False.'
            $fail = $true
        }
    }
    catch {
        Write-ErrorUi ("Secure channel validation failed: {0}" -f $_.Exception.Message)
        $fail = $true
    }

    if (Get-Command nltest.exe -ErrorAction SilentlyContinue) {
        & nltest.exe "/dsgetdc:$Domain" 2>&1 | ForEach-Object { Write-Ui ([string]$_) Gray }
        if ($LASTEXITCODE -ne 0) { $fail = $true }
        & nltest.exe "/sc_verify:$Domain" 2>&1 | ForEach-Object { Write-Ui ([string]$_) Gray }
        if ($LASTEXITCODE -ne 0) { $fail = $true }
    }

    if (Wait-SystemAdDiscovery -Domain $Domain -Attempts 2) {
        Write-Ok 'System resolver can discover AD DC locator records.'
    }
    else {
        Write-ErrorUi 'System resolver cannot discover AD DC locator records.'
        $fail = $true
    }

    [void](Test-TimeState)
    return (-not $fail)
}

function Sync-LifecycleState {
    # This function only reconciles lifecycle metadata and performs acceptance
    # checks. It does not restore DNS, rename the host, unjoin, or change AD.
    $state = Get-CurrentState
    if (-not $state -or -not $state.PSObject.Properties['Phase']) { return }

    $phase = [string]$state.Phase
    $currentBoot = Get-BootMarker
    $phaseBoot = if ($state.PSObject.Properties['PhaseBootMarker']) { [string]$state.PhaseBootMarker } else { '' }

    if ($phase -in @('JOIN_SUBMITTED','JOIN_AMBIGUOUS')) {
        $startLine = if ($state.PSObject.Properties['NetSetupStartLine']) { [int]$state.NetSetupStartLine } else { 0 }
        $evidence = Get-JoinCommitEvidence -Domain ([string]$state.Domain) -NetSetupStartLine $startLine
        if ($evidence.Outcome -eq 'Accepted') {
            [void](Set-CurrentStateValues -Values @{
                Phase='JOIN_PENDING_REBOOT'
                PhaseBootMarker=$currentBoot
                MembershipCommitted=$true
            })
            Write-Warn 'A previously interrupted join now has acceptance evidence. Keep AD DNS and reboot before final validation.'
            return
        }
    }

    if ($phase -eq 'JOINED_DEGRADED') {
        Write-Info 'Re-checking previously degraded domain membership.'
        if (Test-PostJoinAcceptance -Domain ([string]$state.Domain)) {
            [void](Set-CurrentStateValues -Values @{Phase='JOINED';PhaseBootMarker=$currentBoot;MembershipCommitted=$true})
            Write-Ok 'The repaired client now passes domain acceptance checks.'
        }
        return
    }

    if ($phase -eq 'JOIN_PENDING_REBOOT' -and $phaseBoot -and $phaseBoot -ne $currentBoot) {
        Write-Info 'Post-reboot join transition detected; running final acceptance checks.'
        if (Test-PostJoinAcceptance -Domain ([string]$state.Domain)) {
            [void](Set-CurrentStateValues -Values @{Phase='JOINED';PhaseBootMarker=$currentBoot;MembershipCommitted=$true})
            Write-Ok 'Post-reboot domain acceptance passed.'
        }
        else {
            [void](Set-CurrentStateValues -Values @{Phase='JOINED_DEGRADED';PhaseBootMarker=$currentBoot;MembershipCommitted=$true})
            Write-Warn 'Domain membership exists but one or more post-reboot checks are degraded.'
        }
        return
    }

    if ($phase -eq 'LEAVE_PENDING_REBOOT' -and $phaseBoot -and $phaseBoot -ne $currentBoot) {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if (-not $cs.PartOfDomain) {
            [void](Set-CurrentStateValues -Values @{Phase='RESTORE_READY';PhaseBootMarker=$currentBoot})
            Write-Info 'Domain leave completed after reboot. Pre-join local state is ready to restore.'
        }
        else {
            Write-Warn ("The leave reboot occurred, but Windows still reports domain membership: {0}." -f $cs.Domain)
        }
        return
    }

    if ($phase -eq 'RESTORE_PENDING_REBOOT' -and $phaseBoot -and $phaseBoot -ne $currentBoot) {
        try {
            $snap = Get-Snapshot -SnapshotPath ([string]$state.SnapshotPath)
            $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
            if (-not $cs.PartOfDomain -and $env:COMPUTERNAME -ieq [string]$snap.ComputerName) {
                Remove-CurrentState
                Write-Ok 'Pre-join hostname restoration completed after reboot.'
            }
            else {
                Write-Warn 'Post-restore reboot occurred, but the original local identity is not fully materialized.'
            }
        }
        catch {
            Write-Warn ("Could not finalize restore lifecycle: {0}" -f $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------------------
# Audit / status
# ---------------------------------------------------------------------------

function Get-RemoteManagementReadiness {
    $result = [ordered]@{
        OpenSshInstalled = $false
        SshdService      = $false
        SshdRunning      = $false
        SshdAutomatic    = $false
        FirewallRule     = $false
        Tcp22Listening   = $false
        WinRMRunning     = $false
    }

    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($cap -and $cap.State -eq 'Installed') { $result.OpenSshInstalled = $true }
    }
    catch {}

    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if ($svc) {
        $result.SshdService = $true
        $result.SshdRunning = ($svc.Status -eq 'Running')
        try {
            $svcCim = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
            $result.SshdAutomatic = ($svcCim.StartMode -eq 'Auto')
        }
        catch {}
    }

    try {
        $rules = @(Get-NetFirewallRule -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -eq 'AD Client Assistant - OpenSSH' -or $_.Name -eq 'OpenSSH-Server-In-TCP' })
        $result.FirewallRule = ($rules.Count -gt 0 -and @($rules | Where-Object Enabled -eq 'True').Count -gt 0)
    }
    catch {}

    try {
        $result.Tcp22Listening = @(
            Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue
        ).Count -gt 0
    }
    catch {}

    $winrm = Get-Service -Name WinRM -ErrorAction SilentlyContinue
    if ($winrm) { $result.WinRMRunning = ($winrm.Status -eq 'Running') }

    return [pscustomobject]$result
}

function Show-RemoteManagementReadiness {
    Write-Ui ''
    Write-Ui 'REMOTE MANAGEMENT READINESS' Cyan
    $r = Get-RemoteManagementReadiness

    if ($r.OpenSshInstalled) { Write-Ok 'OpenSSH Server capability is installed.' }
    else { Write-Warn 'OpenSSH Server capability is not installed.' }

    if ($r.SshdRunning) { Write-Ok 'sshd service is running.' }
    elseif ($r.SshdService) { Write-Warn 'sshd service exists but is not running.' }
    else { Write-Warn 'sshd service is not installed.' }

    if ($r.SshdAutomatic) { Write-Ok 'sshd startup type is Automatic.' }
    elseif ($r.SshdService) { Write-Warn 'sshd startup type is not Automatic.' }

    if ($r.Tcp22Listening) { Write-Ok 'TCP/22 is listening locally.' }
    else { Write-Warn 'TCP/22 is not listening locally.' }

    if ($r.FirewallRule) { Write-Ok 'An enabled inbound OpenSSH firewall rule exists.' }
    else { Write-Warn 'No enabled inbound OpenSSH firewall rule was detected.' }

    if ($r.WinRMRunning) { Write-Info 'WinRM is also running; Windows-native administration is available where policy permits.' }
    else { Write-Info 'WinRM is not required by the Debian remote-operations console; OpenSSH is its primary full-control transport.' }

    return $r
}

function Enable-RemoteManagementReadiness {
    [CmdletBinding()]
    param([switch]$NonInteractive)

    if (-not $NonInteractive) {
        if (-not (Confirm-Choice -Prompt 'Enable remote administration readiness (OpenSSH Server) on this domain client?' -Default Y)) {
            Write-Info 'Remote administration setup skipped.'
            return $false
        }
    }

    Write-Ui ''
    Write-Ui 'REMOTE MANAGEMENT SETUP' Cyan

    $cap = $null
    try {
        $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop |
            Select-Object -First 1
    }
    catch {
        Write-Warn ("Unable to query OpenSSH capability: {0}" -f $_.Exception.Message)
    }

    if (-not $cap -or $cap.State -ne 'Installed') {
        Write-Info 'Installing Windows OpenSSH Server capability. This may take time on WSUS/FOD-backed systems.'
        try {
            Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' -ErrorAction Stop | Out-Null
            Write-Ok 'OpenSSH Server capability installed.'
        }
        catch {
            Write-ErrorUi ("OpenSSH Server installation failed: {0}" -f $_.Exception.Message)
            Write-Warn 'Domain membership is unaffected. Install the Windows OpenSSH Server capability manually and rerun Remote Setup.'
            return $false
        }
    }

    try {
        Set-Service -Name sshd -StartupType Automatic -ErrorAction Stop
        Start-Service -Name sshd -ErrorAction Stop
        Write-Ok 'sshd enabled and started.'
    }
    catch {
        Write-ErrorUi ("Unable to start/configure sshd: {0}" -f $_.Exception.Message)
        return $false
    }

    try {
        $existing = Get-NetFirewallRule -DisplayName 'AD Client Assistant - OpenSSH' -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-NetFirewallRule `
                -DisplayName 'AD Client Assistant - OpenSSH' `
                -Direction Inbound `
                -Action Allow `
                -Protocol TCP `
                -LocalPort 22 `
                -Profile Domain,Private `
                -ErrorAction Stop | Out-Null
        }
        else {
            $existing | Enable-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null
        }
        Write-Ok 'OpenSSH inbound firewall rule enabled for Domain/Private profiles.'
    }
    catch {
        Write-Warn ("Could not configure the OpenSSH firewall rule: {0}" -f $_.Exception.Message)
    }

    [void](Show-RemoteManagementReadiness)
    Write-Info 'No local/domain account was granted additional administrator rights by this setup.'
    return $true
}

function Invoke-ReadinessAudit {
    Write-Header
    Write-Ui 'CLIENT READINESS' Cyan
    Write-Ui ''

    $product = Get-ProductInfo
    Write-Ui ("Windows       : {0}" -f $product.ProductName)
    Write-Ui ("Edition ID    : {0}" -f $product.EditionID)
    Write-Ui ("Remote session: {0}" -f (Test-RemoteSession))

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Write-Ui ("PartOfDomain  : {0}" -f $cs.PartOfDomain)
    Write-Ui ("Domain/Group  : {0}" -f $(if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup }))
    [void](Test-DomainJoinEdition)

    $interfaces = @(Get-NetworkCandidates)
    Write-Ui ''
    Write-Ui 'Active IPv4 interfaces:' Cyan
    foreach ($cfg in $interfaces) {
        $dns4 = @(Get-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses
        $dns6 = @(Get-DnsClientServerAddress -InterfaceIndex $cfg.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses
        Write-Ui ("  {0} / ifIndex {1} / IPv4 DNS {2}" -f $cfg.InterfaceAlias,$cfg.InterfaceIndex,($dns4 -join ', '))
        if ($dns6.Count -gt 0) { Write-Ui ("      IPv6 DNS: {0}" -f ($dns6 -join ', ')) Gray }
    }

    [void](Test-TimeState)
    [void](Show-RemoteManagementReadiness)

    $state = Get-CurrentState
    if ($state) {
        Write-Warn ("Assistant-managed lifecycle exists: {0} / {1}." -f $state.Domain,$state.Phase)
        if ([string]$state.Phase -in @('SNAPSHOT_CREATED','DNS_APPLIED','JOIN_SUBMITTED','JOIN_AMBIGUOUS','RESTORE_READY')) {
            Write-Warn 'Review -Mode Recover before starting another domain lifecycle operation.'
        }
    }
    else {
        Write-Info 'No assistant-managed lifecycle state exists.'
    }
}

function Invoke-Status {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'DOMAIN CLIENT STATUS' Cyan
    Write-Ui ''

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    Write-Ui ("Computer      : {0}" -f $env:COMPUTERNAME)
    Write-Ui ("PartOfDomain  : {0}" -f $cs.PartOfDomain)
    Write-Ui ("Domain/Group  : {0}" -f $(if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup }))

    if ($cs.PartOfDomain) {
        try {
            if (Test-ComputerSecureChannel -ErrorAction Stop) { Write-Ok 'Computer secure channel is healthy.' }
            else { Write-Warn 'Computer secure channel test returned False.' }
        }
        catch { Write-Warn ("Secure channel test failed: {0}" -f $_.Exception.Message) }

        if (Get-Command nltest.exe -ErrorAction SilentlyContinue) {
            & nltest.exe "/dsgetdc:$($cs.Domain)" 2>&1 | ForEach-Object { Write-Ui ([string]$_) Gray }
        }
    }

    $state = Get-CurrentState
    if ($state) {
        Write-Ui ''
        Write-Ui 'Assistant lifecycle:' Cyan
        Write-Ui ("  Phase    : {0}" -f $state.Phase)
        Write-Ui ("  Domain   : {0}" -f $state.Domain)
        Write-Ui ("  DNS      : {0}" -f (@($state.DnsServers) -join ', '))
        Write-Ui ("  Snapshot : {0}" -f $state.SnapshotPath)
        if ([string]$state.Phase -eq 'RESTORE_READY') {
            Write-Warn 'Domain leave is complete. Run -Mode Restore (or Recover) to restore pre-join DNS/hostname.'
        }
        elseif ([string]$state.Phase -eq 'JOIN_PENDING_REBOOT') {
            Write-Warn 'Final domain acceptance is pending a reboot.'
        }
        elseif ([string]$state.Phase -eq 'JOIN_AMBIGUOUS') {
            Write-Warn 'Join commit state is ambiguous. Run -Mode Recover before changing DNS.'
        }
    }

    [void](Test-TimeState)
}

# ---------------------------------------------------------------------------
# IT administrator diagnostics / domain transition
# ---------------------------------------------------------------------------

function Test-DomainDnsThroughServers {
    param(
        [Parameter(Mandatory=$true)][string]$Domain,
        [Parameter(Mandatory=$true)][string[]]$DnsServers
    )

    $srv = '_ldap._tcp.dc._msdcs.{0}' -f $Domain
    $ok = $true
    foreach ($server in $DnsServers) {
        try {
            $answers = @(Resolve-DnsName -Name $srv -Type SRV -Server $server -DnsOnly -ErrorAction Stop |
                Where-Object { $_.Type -eq 'SRV' -and $_.NameTarget })
            if ($answers.Count -eq 0) { throw 'No DC locator SRV records returned.' }
            Write-Ok ("DNS {0} resolves {1}." -f $server,$Domain)
        }
        catch {
            Write-ErrorUi ("DNS {0} cannot resolve {1}: {2}" -f $server,$Domain,$_.Exception.Message)
            $ok = $false
        }
    }
    return $ok
}

function Invoke-ConnectivityTest {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'AD CONNECTIVITY TEST' Cyan
    Write-Ui ''

    $state = Get-CurrentState
    $defaultDomain = if ($state -and $state.Domain) { [string]$state.Domain } else {
        try { $c = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; if ($c.PartOfDomain) { [string]$c.Domain } else { '' } } catch { '' }
    }
    $defaultDns = if ($state -and $state.DnsServers) { (@($state.DnsServers) -join ',') } else { '' }

    $domain = (Read-Value -Prompt 'AD DNS domain (for example corp.example.com)' -Default $defaultDomain).ToLowerInvariant()
    if (-not (Test-DnsDomainName -Name $domain)) { Write-ErrorUi 'A valid AD DNS domain is required.'; return }
    $dnsServers = @(Parse-DnsInput -Text (Read-Value -Prompt 'AD DNS server IPv4 addresses (comma separated)' -Default $defaultDns))
    if (-not (Test-IPv4AddressList -Addresses $dnsServers)) { Write-ErrorUi 'At least one valid IPv4 AD DNS server is required.'; return }

    $dns = Test-AdDnsServers -Domain $domain -DnsServers $dnsServers
    $iface = Select-NetworkInterface -RemoteIPAddress $dnsServers[0]
    $dcName = @($dns.DomainControllers | Select-Object -First 1)
    $portsOk = $false
    if ($dcName.Count -gt 0) { $portsOk = Test-AdNetworkReadiness -DomainController ([string]$dcName[0]) }
    $timeOk = Test-TimeState

    Write-Ui ''
    Write-Ui 'SYSTEM RESOLVER' Cyan
    if (Wait-SystemAdDiscovery -Domain $domain -Attempts 2) { Write-Ok 'System resolver can discover Active Directory.' }
    else { Write-Warn 'System resolver cannot currently discover the domain.' }

    Write-Ui ''
    Write-Ui 'MEMBERSHIP / SECURE CHANNEL' Cyan
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            Write-Ok ("Current domain membership: {0}" -f $cs.Domain)
            try {
                if (Test-ComputerSecureChannel -ErrorAction Stop) { Write-Ok 'Windows secure channel is healthy.' }
                else { Write-Warn 'Windows secure channel test returned false.' }
            } catch { Write-Warn ("Secure-channel test could not complete: {0}" -f $_.Exception.Message) }
        } else { Write-Info 'Computer is not currently domain joined.' }
    } catch {}

    Write-Ui ''
    if ($dns.AdDiscoveryOk -and $portsOk -and $timeOk) { Write-Ok 'READY: AD DNS, required ports and local time checks passed.' }
    else { Write-ErrorUi 'BLOCKED/DEGRADED: one or more readiness checks failed.' }
}

function Invoke-Troubleshoot {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'AD TROUBLESHOOTER' Cyan
    Write-Ui ''

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    Write-Ui ("Computer : {0}" -f $env:COMPUTERNAME)
    if ($cs) { Write-Ui ("Identity : {0}" -f $(if ($cs.PartOfDomain) { $cs.Domain } else { $cs.Workgroup })) }
    Write-Ui ("Lifecycle: {0}" -f (Get-LifecycleLabel))

    Write-Ui ''
    Write-Ui 'NETWORK' Cyan
    Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
        $dns = @($_.DNSServer.ServerAddresses) -join ','
        Write-Ui ("  {0} ifIndex={1} IPv4={2} DNS={3}" -f $_.InterfaceAlias,$_.InterfaceIndex,(@($_.IPv4Address.IPAddress) -join ','),$dns)
    }

    Write-Ui ''
    Write-Ui 'SECURE CHANNEL' Cyan
    if ($cs -and $cs.PartOfDomain) {
        $secure = $false
        try { $secure = Test-ComputerSecureChannel -ErrorAction Stop } catch { Write-Warn $_.Exception.Message }
        if ($secure) { Write-Ok 'Secure channel is healthy.' }
        else {
            Write-ErrorUi 'Secure channel is unhealthy or could not be validated.'
            if (Confirm-Choice -Prompt 'Attempt secure-channel repair with explicit domain credentials?' -Default N) {
                $user = Read-Value -Prompt 'Join account' -Default ("Administrator@{0}" -f $cs.Domain)
                $cred = Get-Credential -UserName $user -Message ("Credentials authorized to repair secure channel for {0}" -f $cs.Domain)
                if ($cred) {
                    try {
                        if (Test-ComputerSecureChannel -Repair -Credential $cred -ErrorAction Stop) { Write-Ok 'Secure channel repaired.' }
                        else { Write-ErrorUi 'Windows did not confirm secure-channel repair.' }
                    } catch { Write-ErrorUi ("Secure-channel repair failed: {0}" -f $_.Exception.Message) }
                }
            }
        }
    } else { Write-Info 'Secure-channel test is not applicable while off-domain.' }

    Write-Ui ''
    Write-Ui 'NETSETUP DIAGNOSTICS' Cyan
    $state = Get-CurrentState
    $start = if ($state -and $state.PSObject.Properties['NetSetupStartLine']) { [int]$state.NetSetupStartLine } else { 0 }
    Write-NetSetupDiagnosis -SnapshotPath $(if ($state) { [string]$state.SnapshotPath } else { '' }) -StartLine $start

    if (Confirm-Choice -Prompt 'Flush DNS client cache and restart Netlogon now?' -Default N) {
        try { Clear-DnsClientCache -ErrorAction Stop; Write-Ok 'DNS client cache cleared.' } catch { Write-Warn $_.Exception.Message }
        if (Get-Service Netlogon -ErrorAction SilentlyContinue) {
            try { Restart-Service Netlogon -Force -ErrorAction Stop; Write-Ok 'Netlogon restarted.' } catch { Write-Warn $_.Exception.Message }
        }
    }
}

function Export-DiagnosticBundle {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'EXPORT DIAGNOSTIC BUNDLE' Cyan
    Write-Ui ''

    $root = Join-Path $script:ReportRoot ("diagnostic-{0}" -f $script:RunId)
    $zip = "{0}.zip" -f $root
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    try {
        Get-ComputerInfo -ErrorAction SilentlyContinue | Out-File (Join-Path $root 'computer-info.txt') -Width 240 -Encoding utf8
        Get-NetIPConfiguration -Detailed -ErrorAction SilentlyContinue | Out-File (Join-Path $root 'network.txt') -Width 240 -Encoding utf8
        Get-NetRoute -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Format-Table -AutoSize | Out-String -Width 240 | Set-Content (Join-Path $root 'routes.txt') -Encoding utf8
        Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Format-List * | Out-String -Width 240 | Set-Content (Join-Path $root 'dns.txt') -Encoding utf8
        $state = Get-CurrentState
        if ($state) { $state | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $root 'lifecycle.json') -Encoding utf8 }
        @(Get-NetSetupAttemptLines -StartLine 0 | Select-Object -Last 500) | Set-Content (Join-Path $root 'NetSetup-tail.txt') -Encoding utf8
        try { Test-ComputerSecureChannel -Verbose 4>&1 | Out-File (Join-Path $root 'secure-channel.txt') -Encoding utf8 } catch { $_ | Out-File (Join-Path $root 'secure-channel.txt') -Encoding utf8 }
        Compress-Archive -Path (Join-Path $root '*') -DestinationPath $zip -Force
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok ("Diagnostic bundle created: {0}" -f $zip)
        Write-Warn 'Review the archive before sharing; it contains host/network/domain metadata. Credentials are not collected.'
    }
    catch { Write-ErrorUi ("Diagnostic bundle export failed: {0}" -f $_.Exception.Message) }
}

function Invoke-DomainSwitch {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'GUIDED DOMAIN SWITCH' Cyan
    Write-Ui ''

    if (-not (Test-DomainJoinEdition)) { return }
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if (-not $cs.PartOfDomain) { Write-Info 'Computer is not domain joined; starting normal guided join.'; Invoke-GuidedJoin; return }

    $existing = Get-CurrentState
    if ($existing -and [string]$existing.Phase -notin @('JOINED','JOINED_DEGRADED')) {
        Write-ErrorUi ("Unfinished lifecycle exists: {0}. Recover it before switching domains." -f $existing.Phase); return
    }

    $sourceDomain = [string]$cs.Domain
    $targetDomain = (Read-Value -Prompt 'Target AD DNS domain (for example corp.example.com)' -Default '').ToLowerInvariant()
    if (-not (Test-DnsDomainName -Name $targetDomain) -or $targetDomain -ieq $sourceDomain) { Write-ErrorUi 'A different valid target domain is required.'; return }
    $dnsServers = @(Parse-DnsInput -Text (Read-Value -Prompt 'Target AD DNS server IPv4 addresses (comma separated)' -Default ''))
    if (-not (Test-IPv4AddressList -Addresses $dnsServers)) { Write-ErrorUi 'At least one valid target AD DNS IPv4 address is required.'; return }

    $targetPreflight = Test-AdDnsServers -Domain $targetDomain -DnsServers $dnsServers
    if (-not $targetPreflight.AdDiscoveryOk) { Write-ErrorUi 'Target AD DNS discovery failed. Nothing was changed.'; return }
    if (-not $targetPreflight.ForwardingOk -and -not $AllowAdDnsWithoutExternalResolution) { Write-ErrorUi 'Target AD DNS external forwarding check failed.'; return }
    if (-not (Test-DomainDnsThroughServers -Domain $sourceDomain -DnsServers $dnsServers)) {
        Write-ErrorUi 'Target DNS cannot resolve the source domain. Configure conditional forwarding/coexistence before an automated switch.'; return
    }

    $iface = Select-NetworkInterface -RemoteIPAddress $dnsServers[0]
    $targetDc = @($targetPreflight.DomainControllers | Select-Object -First 1)
    if ($targetDc.Count -eq 0) { Write-ErrorUi 'No target DC FQDN was discovered.'; return }
    $targetDcName = ([string]$targetDc[0]).TrimEnd('.')
    if (-not (Test-AdNetworkReadiness -DomainController $targetDcName)) { Write-ErrorUi 'Target-domain required ports are not reachable.'; return }
    [void](Test-TimeState); [void](Test-TimeAgainstDomainController -ComputerName $targetDcName)

    $sourceUser = Read-Value -Prompt 'Source-domain unjoin account' -Default ("Administrator@{0}" -f $sourceDomain)
    $targetUser = Read-Value -Prompt 'Target-domain join account' -Default ("Administrator@{0}" -f $targetDomain)
    $ouPath = Read-Value -Prompt 'Computer OU DN (optional)' -Default ''
    $requestedName = Read-Value -Prompt 'Computer name' -Default $env:COMPUTERNAME
    if (-not (Test-ComputerNameValue -Name $requestedName)) { Write-ErrorUi 'Invalid computer name.'; return }

    Write-Ui ''
    Write-Ui ("  Source domain : {0}" -f $sourceDomain)
    Write-Ui ("  Target domain : {0}" -f $targetDomain)
    Write-Ui ("  Target DC     : {0}" -f $targetDcName)
    Write-Ui ("  Target DNS    : {0}" -f ($dnsServers -join ', '))
    Write-Ui ("  Computer      : {0}" -f $requestedName)
    Write-Ui '  Transition    : direct domain-to-domain, one reboot, no stored passwords' Gray
    if (-not (Confirm-Literal -Prompt 'The computer will move directly to the target domain after all preflight checks passed.' -Literal 'SWITCH')) { return }

    $sourceCredential = Get-Credential -UserName $sourceUser -Message ("Credentials authorized to unjoin from {0}" -f $sourceDomain)
    if (-not $sourceCredential) { return }
    $targetCredential = Get-Credential -UserName $targetUser -Message ("Credentials authorized to join {0}" -f $targetDomain)
    if (-not $targetCredential) { return }

    $snapshot = New-PreJoinSnapshot -Interface $iface -TargetDomain $targetDomain
    New-JoinState -Snapshot $snapshot -Domain $targetDomain -DnsServers $dnsServers -RequestedComputerName $requestedName -Operation Switch -SourceDomain $sourceDomain

    try {
        Set-DomainDns -InterfaceIndex ([uint32]$iface.InterfaceIndex) -DnsServers $dnsServers
        [void](Set-CurrentStateValues -Values @{Phase='DNS_APPLIED';PhaseBootMarker=(Get-BootMarker)})
        if (-not (Wait-SystemAdDiscovery -Domain $targetDomain)) { throw 'System resolver cannot discover target AD after applying target DNS.' }
        if (-not (Wait-SystemAdDiscovery -Domain $sourceDomain)) { throw 'Target DNS stopped resolving source AD after resolver transition.' }

        [void](Set-CurrentStateValues -Values @{Phase='JOIN_SUBMITTED';PhaseBootMarker=(Get-BootMarker);JoinAttempted=$true})
        $params = @{
            DomainName=$targetDomain; Server=$targetDcName; Credential=$targetCredential;
            UnjoinDomainCredential=$sourceCredential; PassThru=$true; Force=$true; ErrorAction='Stop'
        }
        if ($ouPath) { $params.OUPath = $ouPath }
        if ($requestedName -ine $env:COMPUTERNAME) { $params.NewName = $requestedName }
        $result = Add-Computer @params
        if ($result -and $result.PSObject.Properties['HasSucceeded'] -and -not $result.HasSucceeded) { throw 'Add-Computer returned HasSucceeded=False.' }
        [void](Set-CurrentStateValues -Values @{Phase='JOIN_PENDING_REBOOT';PhaseBootMarker=(Get-BootMarker);MembershipCommitted=$true})
        Write-Ok 'Windows accepted the direct domain-to-domain transition.'
        [void](Enable-RemoteManagementReadiness)
        Write-Warn 'Target AD DNS is retained until reboot and secure-channel validation.'
        if (Confirm-Choice -Prompt 'Restart now?' -Default N) { $script:RunOutcome='REBOOT_REQUESTED'; Write-RunReport; Restart-Computer -Force }
    }
    catch {
        Write-ErrorUi ("Domain switch stopped: {0}" -f $_.Exception.Message)
        $state = Get-CurrentState
        $phase = if ($state) { [string]$state.Phase } else { '' }
        if ($phase -in @('SNAPSHOT_CREATED','DNS_APPLIED')) {
            try { Restore-DnsFromSnapshot -Snapshot $snapshot; Remove-CurrentState; Write-Ok 'Pre-switch DNS restored; membership transition was not submitted.' } catch { Write-ErrorUi $_.Exception.Message }
        }
        else {
            Write-NetSetupDiagnosis -SnapshotPath ([string]$snapshot.SnapshotPath) -StartLine ([int]$snapshot.NetSetupStartLine)
            $evidence = Get-JoinCommitEvidence -Domain $targetDomain -NetSetupStartLine ([int]$snapshot.NetSetupStartLine)
            if ($evidence.Outcome -eq 'Accepted') {
                [void](Set-CurrentStateValues -Values @{Phase='JOIN_PENDING_REBOOT';PhaseBootMarker=(Get-BootMarker);MembershipCommitted=$true})
                Write-Warn 'Target-domain acceptance evidence exists. Keep target DNS and reboot.'
            } elseif ($evidence.Outcome -eq 'Failed') {
                Write-ErrorUi 'Windows reported an explicit transition failure. Membership may still require operator verification before DNS rollback.'
                Write-Warn 'Run Recover/Status and inspect NetSetup evidence before another membership operation.'
            } else {
                [void](Set-CurrentStateValues -Values @{Phase='JOIN_AMBIGUOUS';PhaseBootMarker=(Get-BootMarker)})
                Write-ErrorUi 'Domain-switch membership state is ambiguous. Automatic rollback is blocked intentionally.'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Guided join
# ---------------------------------------------------------------------------

function Invoke-GuidedJoin {
    Write-Header
    Write-Ui 'GUIDED DOMAIN JOIN' Cyan
    Write-Ui ''

    if (-not (Test-DomainJoinEdition)) { return }

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs.PartOfDomain) {
        Write-Warn ("This computer is already joined to: {0}" -f $cs.Domain)
        return
    }

    $existingState = Get-CurrentState
    if ($existingState) {
        Write-ErrorUi ("Assistant lifecycle already exists: {0}." -f $existingState.Phase)
        Write-Warn 'Run -Mode Recover, Restore, or Status before starting another join.'
        return
    }

    $domain = (Read-Value -Prompt 'AD DNS domain (for example corp.example.com)' -Default '').ToLowerInvariant()
    if (-not (Test-DnsDomainName -Name $domain)) {
        Write-ErrorUi 'A valid DNS domain is required.'
        return
    }

    $dnsText = Read-Value -Prompt 'AD DNS server IPv4 addresses (comma separated)' -Default ''
    $dnsServers = @(Parse-DnsInput -Text $dnsText)
    if (-not (Test-IPv4AddressList -Addresses $dnsServers)) {
        Write-ErrorUi 'At least one valid IPv4 AD DNS server address is required.'
        return
    }

    Write-Ui ''
    Write-Ui 'DIRECT DNS PREFLIGHT' Cyan
    $dnsPreflight = Test-AdDnsServers -Domain $domain -DnsServers $dnsServers
    if (-not $dnsPreflight.AdDiscoveryOk) {
        Write-ErrorUi 'At least one configured DNS server cannot locate the target Active Directory domain.'
        Write-ErrorUi 'No local DNS change has been made.'
        return
    }

    if (-not $dnsPreflight.ForwardingOk -and -not $AllowAdDnsWithoutExternalResolution) {
        Write-ErrorUi 'One or more AD DNS servers cannot resolve the configured external probe.'
        Write-Warn 'Do not add public DNS as a client fallback; repair forwarding on the AD DNS service instead.'
        Write-Warn 'For an intentionally isolated network, rerun with -AllowAdDnsWithoutExternalResolution.'
        return
    }
    elseif (-not $dnsPreflight.ForwardingOk) {
        Write-Warn 'Continuing without external DNS resolution because the explicit override switch was supplied.'
    }

    $iface = Select-NetworkInterface -RemoteIPAddress $dnsServers[0]
    $joinUser = Read-Value -Prompt 'Join account' -Default ("Administrator@{0}" -f $domain)
    $ouPath = Read-Value -Prompt 'Computer OU DN (optional)' -Default ''
    if ($ouPath -and $ouPath -notmatch '^(?i:OU|CN)=') {
        Write-Warn 'OU path does not look like a distinguished name beginning with OU= or CN=.'
        if (-not (Confirm-Choice -Prompt 'Use this OU value anyway?' -Default N)) { return }
    }

    $requestedName = Read-Value -Prompt 'Computer name' -Default $env:COMPUTERNAME
    if (-not (Test-ComputerNameValue -Name $requestedName)) {
        Write-ErrorUi 'Computer name must be 1-15 characters using letters, digits or hyphen.'
        return
    }

    Write-Ui ''
    Write-Ui 'PLAN' Cyan
    Write-Ui ("  Domain       : {0}" -f $domain)
    Write-Ui ("  Interface    : {0} / ifIndex {1}" -f $iface.InterfaceAlias,$iface.InterfaceIndex)
    Write-Ui ("  DNS          : {0}" -f ($dnsServers -join ', '))
    Write-Ui ("  Computer     : {0}" -f $requestedName)
    Write-Ui ("  Join account : {0}" -f $joinUser)
    Write-Ui ("  OU           : {0}" -f $(if ($ouPath) { $ouPath } else { '(default container)' }))
    Write-Ui '  Rollback     : automatic only before membership commit; commit-aware after Add-Computer starts' Gray

    if (-not (Confirm-Choice -Prompt 'Create a recovery snapshot and continue?' -Default Y)) { return }

    $snapshot = New-PreJoinSnapshot -Interface $iface -TargetDomain $domain
    New-JoinState -Snapshot $snapshot -Domain $domain -DnsServers $dnsServers -RequestedComputerName $requestedName

    try {
        Set-DomainDns -InterfaceIndex ([uint32]$iface.InterfaceIndex) -DnsServers $dnsServers
        [void](Set-CurrentStateValues -Values @{Phase='DNS_APPLIED';PhaseBootMarker=(Get-BootMarker)})

        if (-not (Wait-SystemAdDiscovery -Domain $domain)) {
            throw 'System resolver cannot discover the target AD domain after applying AD DNS.'
        }
        Write-Ok 'System resolver can discover Active Directory.'

        $dc = @($dnsPreflight.DomainControllers | Select-Object -First 1)
        if ($dc.Count -eq 0 -or [string]::IsNullOrWhiteSpace([string]$dc[0])) {
            throw 'No domain controller hostname was returned by DNS preflight.'
        }
        $dcName = [string]$dc[0]

        if (-not (Test-AdNetworkReadiness -DomainController $dcName)) {
            throw 'Required AD ports are not reachable from the selected network path.'
        }
        [void](Test-TimeState)
        [void](Test-TimeAgainstDomainController -ComputerName $dcName)

        Write-Ui ''
        Write-Info 'Domain credentials are requested by Windows and are held in memory only.'
        $credential = Get-Credential -UserName $joinUser -Message ("Credentials authorized to join {0}" -f $domain)
        if (-not $credential) { throw 'Credential prompt was cancelled.' }

        $params = @{
            DomainName  = $domain
            Credential  = $credential
            PassThru    = $true
            Force       = $true
            ErrorAction = 'Stop'
        }
        if ($ouPath) { $params.OUPath = $ouPath }
        if ($requestedName -ine $env:COMPUTERNAME) { $params.NewName = $requestedName }

        [void](Set-CurrentStateValues -Values @{
            Phase='JOIN_SUBMITTED'
            PhaseBootMarker=(Get-BootMarker)
            JoinAttempted=$true
        })

        Write-Info 'Submitting the domain join to Windows.'
        $result = Add-Computer @params
        if ($result -and $result.PSObject.Properties['HasSucceeded'] -and -not $result.HasSucceeded) {
            throw 'Add-Computer returned HasSucceeded=False.'
        }

        [void](Set-CurrentStateValues -Values @{
            Phase='JOIN_PENDING_REBOOT'
            PhaseBootMarker=(Get-BootMarker)
            MembershipCommitted=$true
        })

        Write-Ok 'Windows accepted the domain join operation.'
        Write-Warn 'AD DNS is intentionally retained until reboot and final secure-channel validation.'
        Write-Info ("Recovery snapshot: {0}" -f $snapshot.SnapshotPath)

        [void](Enable-RemoteManagementReadiness)
        Initialize-EndpointSecurityAfterJoin

        if (Confirm-Choice -Prompt 'Restart now?' -Default N) {
            $script:RunOutcome = 'REBOOT_REQUESTED'
            Write-RunReport
            Restart-Computer -Force
        }
    }
    catch {
        Write-ErrorUi ("Domain join workflow stopped: {0}" -f $_.Exception.Message)

        $state = Get-CurrentState
        $phase = if ($state -and $state.PSObject.Properties['Phase']) { [string]$state.Phase } else { '' }
        $startLine = if ($state -and $state.PSObject.Properties['NetSetupStartLine']) { [int]$state.NetSetupStartLine } else { [int]$snapshot.NetSetupStartLine }

        if ($phase -in @('SNAPSHOT_CREATED','DNS_APPLIED')) {
            Write-Warn 'AD membership was not submitted; restoring the local pre-join state.'
            try {
                Restore-DnsFromSnapshot -Snapshot $snapshot
                Remove-CurrentState
                Write-Ok 'Pre-join DNS state restored.'
            }
            catch {
                Write-ErrorUi ("Automatic rollback failed: {0}" -f $_.Exception.Message)
                Write-Warn ("Snapshot remains available at: {0}" -f $snapshot.SnapshotPath)
            }
        }
        else {
            Write-NetSetupDiagnosis -SnapshotPath ([string]$snapshot.SnapshotPath) -StartLine $startLine
            $evidence = Get-JoinCommitEvidence -Domain $domain -NetSetupStartLine $startLine

            if ($evidence.Outcome -eq 'Accepted') {
                [void](Set-CurrentStateValues -Values @{
                    Phase='JOIN_PENDING_REBOOT'
                    PhaseBootMarker=(Get-BootMarker)
                    MembershipCommitted=$true
                })
                Write-Warn ("Join acceptance evidence exists: {0}." -f $evidence.Reason)
                Write-Warn 'AD DNS has been retained. Reboot, then run -Mode Status.'
            }
            elseif ($evidence.Outcome -eq 'Failed') {
                Write-Warn ("Join failure is explicit: {0}. Restoring local DNS." -f $evidence.Reason)
                try {
                    Restore-DnsFromSnapshot -Snapshot $snapshot
                    Remove-CurrentState
                    Write-Ok 'Pre-join DNS state restored after explicit join failure.'
                }
                catch {
                    Write-ErrorUi ("DNS rollback failed: {0}" -f $_.Exception.Message)
                }
            }
            else {
                [void](Set-CurrentStateValues -Values @{Phase='JOIN_AMBIGUOUS';PhaseBootMarker=(Get-BootMarker)})
                Write-ErrorUi 'Join commit state is ambiguous. The assistant will not guess and will not restore DNS automatically.'
                Write-Warn 'Keep AD DNS in place, inspect NetSetup evidence, and run -Mode Recover.'
            }
        }

        Write-Warn 'No domain password was persisted.'
    }
}

# ---------------------------------------------------------------------------
# Leave / restore / recovery
# ---------------------------------------------------------------------------

function Invoke-LeaveDomain {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'LEAVE DOMAIN CLEANLY' Cyan
    Write-Ui ''

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if (-not $cs.PartOfDomain) {
        Write-Info 'This computer is not currently joined to a domain.'
        return
    }

    $state = Get-CurrentState
    if ($state -and [string]$state.Phase -eq 'JOIN_PENDING_REBOOT' -and
        [string]$state.PhaseBootMarker -eq (Get-BootMarker)) {
        Write-ErrorUi 'The join is still pending its first reboot. Complete that transition before attempting a leave.'
        return
    }

    $snapshot = $null
    if ($state -and $state.SnapshotPath) {
        try { $snapshot = Get-Snapshot -SnapshotPath ([string]$state.SnapshotPath) }
        catch { Write-Warn ("Recorded snapshot could not be loaded: {0}" -f $_.Exception.Message) }
    }

    $defaultWorkgroup = if ($snapshot -and $snapshot.Workgroup) { [string]$snapshot.Workgroup } else { 'WORKGROUP' }
    $unjoinUser = Read-Value -Prompt 'Account authorized to remove this computer from AD' `
        -Default ("Administrator@{0}" -f $cs.Domain)
    $workgroup = Read-Value -Prompt 'Workgroup after leaving the domain' -Default $defaultWorkgroup
    if ($workgroup.Length -lt 1 -or $workgroup.Length -gt 15 -or $workgroup -notmatch '^[A-Za-z0-9][A-Za-z0-9-]*$') {
        Write-ErrorUi 'Workgroup must be 1-15 characters using letters, digits or hyphen.'
        return
    }

    if (-not (Confirm-Literal -Prompt ("This computer will leave domain {0}." -f $cs.Domain) -Literal 'LEAVE')) { return }

    $credential = Get-Credential -UserName $unjoinUser -Message ("Credentials authorized to unjoin from {0}" -f $cs.Domain)
    if (-not $credential) { Write-Warn 'Credential prompt cancelled.'; return }

    try {
        $result = Remove-Computer -UnjoinDomainCredential $credential -WorkgroupName $workgroup `
            -PassThru -Force -ErrorAction Stop
        if ($result -and $result.PSObject.Properties['HasSucceeded'] -and -not $result.HasSucceeded) {
            throw 'Remove-Computer returned HasSucceeded=False.'
        }

        Write-Ok 'Windows accepted the domain leave operation.'

        if ($state) {
            [void](Set-CurrentStateValues -Values @{
                Phase='LEAVE_PENDING_REBOOT'
                PhaseBootMarker=(Get-BootMarker)
            })
            Write-Warn 'AD DNS is intentionally retained until the leave reboot completes.'
            if ($snapshot) {
                Write-Info 'After reboot, run -Mode Restore or -Mode Recover to restore the original local state.'
            }
            else {
                Write-Warn 'The recorded pre-join snapshot is unavailable; automatic DNS/hostname restoration may not be possible.'
            }
        }
        else {
            Write-Warn 'No assistant pre-join lifecycle exists; automatic DNS/hostname restoration is unavailable.'
            Write-Warn 'The assistant will not invent a pre-domain resolver configuration.'
        }

        Write-Warn 'A reboot is required to complete the domain leave.'
        if (Confirm-Choice -Prompt 'Restart now?' -Default N) {
            $script:RunOutcome = 'REBOOT_REQUESTED'
            Write-RunReport
            Restart-Computer -Force
        }
    }
    catch {
        Write-ErrorUi ("Domain leave failed: {0}" -f $_.Exception.Message)
        Write-NetSetupDiagnosis
        Write-Warn 'No forced registry/domain-membership manipulation was attempted.'
    }
}

function Invoke-RestorePreJoin {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'RESTORE PRE-JOIN STATE' Cyan
    Write-Ui ''

    $state = Get-CurrentState
    if (-not $state) {
        Write-ErrorUi 'No assistant-managed current state exists.'
        return
    }

    $phase = [string]$state.Phase
    $currentBoot = Get-BootMarker
    $phaseBoot = if ($state.PSObject.Properties['PhaseBootMarker']) { [string]$state.PhaseBootMarker } else { '' }

    if ($phase -eq 'JOIN_PENDING_REBOOT' -and $phaseBoot -eq $currentBoot) {
        Write-ErrorUi 'The domain join is still pending its first reboot.'
        Write-Warn 'Restoring DNS/hostname now could break the pending Windows domain transition.'
        return
    }
    if ($phase -eq 'LEAVE_PENDING_REBOOT' -and $phaseBoot -eq $currentBoot) {
        Write-ErrorUi 'The domain leave is still pending reboot.'
        Write-Warn 'AD DNS is intentionally retained until Windows materializes the leave operation.'
        return
    }
    if ($phase -eq 'RESTORE_PENDING_REBOOT' -and $phaseBoot -eq $currentBoot) {
        Write-ErrorUi 'Hostname restoration is already pending reboot.'
        return
    }

    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    if ($cs.PartOfDomain) {
        Write-ErrorUi ("This computer is still joined to {0}." -f $cs.Domain)
        Write-Warn 'Use Leave domain cleanly first. The assistant will not fake an unjoin through registry changes.'
        return
    }

    try { $snapshot = Get-Snapshot -SnapshotPath ([string]$state.SnapshotPath) }
    catch { Write-ErrorUi $_.Exception.Message; return }

    try {
        Restore-DnsFromSnapshot -Snapshot $snapshot
        $needsRename = ($env:COMPUTERNAME -ine [string]$snapshot.ComputerName)
        $nameRestored = Restore-ComputerNameFromSnapshot -Snapshot $snapshot

        if ($needsRename -and $nameRestored) {
            [void](Set-CurrentStateValues -Values @{
                Phase='RESTORE_PENDING_REBOOT'
                PhaseBootMarker=(Get-BootMarker)
            })
            Write-Warn 'DNS is restored and the original hostname is scheduled; reboot once more to finish.'
            if (Confirm-Choice -Prompt 'Restart now?' -Default N) {
                $script:RunOutcome = 'REBOOT_REQUESTED'
                Write-RunReport
                Restart-Computer -Force
            }
        }
        elseif ($nameRestored) {
            Remove-CurrentState
            Write-Ok 'Pre-join state restored. Snapshot retained for evidence.'
        }
    }
    catch {
        Write-ErrorUi ("Restore failed: {0}" -f $_.Exception.Message)
    }
}

function Invoke-Recovery {
    Sync-LifecycleState
    Write-Header
    Write-Ui 'LIFECYCLE RECOVERY' Cyan
    Write-Ui ''

    $state = Get-CurrentState
    if (-not $state) {
        Write-Info 'No interrupted or pending assistant lifecycle exists.'
        return
    }

    $phase = [string]$state.Phase
    Write-Ui ("Phase    : {0}" -f $phase)
    Write-Ui ("Domain   : {0}" -f $state.Domain)
    Write-Ui ("Snapshot : {0}" -f $state.SnapshotPath)
    Write-Ui ''

    $snapshot = $null
    try { $snapshot = Get-Snapshot -SnapshotPath ([string]$state.SnapshotPath) }
    catch { Write-ErrorUi ("Snapshot cannot be loaded: {0}" -f $_.Exception.Message) }

    switch ($phase) {
        'SNAPSHOT_CREATED' {
            Write-Info 'The transaction stopped before DNS or membership changes were applied.'
            if (Confirm-Choice -Prompt 'Clear the stale transaction state and keep the snapshot as evidence?' -Default Y) {
                Remove-CurrentState
                Write-Ok 'Stale transaction state cleared.'
            }
        }

        'DNS_APPLIED' {
            if (-not $snapshot) { return }
            Write-Warn 'AD DNS was applied, but Add-Computer was not submitted.'
            if (Confirm-Choice -Prompt 'Restore the pre-join DNS state now?' -Default Y) {
                Restore-DnsFromSnapshot -Snapshot $snapshot
                Remove-CurrentState
                Write-Ok 'Interrupted pre-membership transaction rolled back safely.'
            }
        }

        { $_ -in @('JOIN_SUBMITTED','JOIN_AMBIGUOUS') } {
            $startLine = if ($state.PSObject.Properties['NetSetupStartLine']) { [int]$state.NetSetupStartLine } else { 0 }
            $evidence = Get-JoinCommitEvidence -Domain ([string]$state.Domain) -NetSetupStartLine $startLine
            Write-Info ("Join evidence: {0} - {1}" -f $evidence.Outcome,$evidence.Reason)
            Write-NetSetupDiagnosis -SnapshotPath ([string]$state.SnapshotPath) -StartLine $startLine

            if ($evidence.Outcome -eq 'Accepted') {
                [void](Set-CurrentStateValues -Values @{
                    Phase='JOIN_PENDING_REBOOT'
                    PhaseBootMarker=(Get-BootMarker)
                    MembershipCommitted=$true
                })
                Write-Warn 'Membership acceptance is evidenced. Keep AD DNS and reboot before final validation.'
            }
            elseif ($evidence.Outcome -eq 'Failed') {
                if (-not $snapshot) { return }
                if (Confirm-Choice -Prompt 'Explicit join failure detected. Restore pre-join DNS?' -Default Y) {
                    Restore-DnsFromSnapshot -Snapshot $snapshot
                    Remove-CurrentState
                    Write-Ok 'Failed join transaction rolled back.'
                }
            }
            else {
                Write-ErrorUi 'Membership state is still ambiguous. Automatic rollback is intentionally blocked.'
                Write-Warn 'If an administrator has independently verified that AD membership was NOT committed,'
                Write-Warn 'the local DNS state can be restored with an explicit high-impact acknowledgement.'
                if ($snapshot -and (Confirm-Literal `
                    -Prompt 'Restoring DNS during an ambiguous join can break a partially committed membership.' `
                    -Literal 'ROLLBACK-LOCAL')) {
                    Restore-DnsFromSnapshot -Snapshot $snapshot
                    Remove-CurrentState
                    Write-Ok 'Local pre-join DNS restored by explicit operator decision.'
                }
            }
        }

        'JOIN_PENDING_REBOOT' {
            if ([string]$state.PhaseBootMarker -eq (Get-BootMarker)) {
                Write-Warn 'Domain join is accepted and waiting for its first reboot. Keep AD DNS unchanged.'
            }
            else {
                Sync-LifecycleState
                Invoke-Status
            }
        }

        'JOINED' {
            Write-Ok 'Managed domain membership is healthy; no recovery action is pending.'
        }

        'JOINED_DEGRADED' {
            Write-Warn 'Managed membership is degraded. Re-running acceptance checks.'
            if (Test-PostJoinAcceptance -Domain ([string]$state.Domain)) {
                [void](Set-CurrentStateValues -Values @{Phase='JOINED';PhaseBootMarker=(Get-BootMarker)})
                Write-Ok 'The client now passes domain acceptance checks.'
            }
        }

        'LEAVE_PENDING_REBOOT' {
            if ([string]$state.PhaseBootMarker -eq (Get-BootMarker)) {
                Write-Warn 'Domain leave is accepted and waiting for reboot. Keep AD DNS unchanged.'
            }
            else {
                Sync-LifecycleState
                $newState = Get-CurrentState
                if ($newState -and [string]$newState.Phase -eq 'RESTORE_READY') {
                    Invoke-RestorePreJoin
                }
            }
        }

        'RESTORE_READY' {
            Invoke-RestorePreJoin
        }

        'RESTORE_PENDING_REBOOT' {
            if ([string]$state.PhaseBootMarker -eq (Get-BootMarker)) {
                Write-Warn 'Original hostname restoration is waiting for reboot.'
            }
            else {
                Sync-LifecycleState
                if (-not (Get-CurrentState)) { Write-Ok 'Restore lifecycle is complete.' }
            }
        }

        default {
            Write-Warn ("Unknown lifecycle phase: {0}. No automatic recovery was attempted." -f $phase)
        }
    }
}

# ---------------------------------------------------------------------------
# Suricata + Wazuh endpoint defense
# ---------------------------------------------------------------------------

function Get-ClientSecurityPaths {
    $root = Join-Path $StateRoot 'security'
    $backup = Join-Path $root 'backups'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path $backup -Force | Out-Null
    return [pscustomobject]@{
        Root=$root
        Backup=$backup
        IpsState=(Join-Path $root 'guarded-ips.json')
        IpsTask='ADClientAssistant-GuardedIpsCleanup'
        IpsPrefix='ADClientAssistant-IPS-'
    }
}

function Get-ClientSuricataInfo {
    $service = $null
    try {
        $service = Get-CimInstance Win32_Service -ErrorAction Stop |
            Where-Object { $_.Name -match '(?i)suricata' -or $_.DisplayName -match '(?i)suricata' } |
            Select-Object -First 1
    }
    catch {}
    $servicePath = if ($service) { [string]$service.PathName } else { '' }
    $exe = $null
    if ($servicePath -match '^\s*"([^"]*suricata\.exe)"') { $exe=$Matches[1] }
    elseif ($servicePath -match '([A-Za-z]:\\[^\r\n"]*?suricata\.exe)') { $exe=$Matches[1] }
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
        $exe = @("$env:ProgramFiles\Suricata\suricata.exe","${env:ProgramFiles(x86)}\Suricata\suricata.exe",'C:\Suricata\suricata.exe') |
            Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    }
    $config = @("$env:ProgramFiles\Suricata\suricata.yaml","$env:ProgramFiles\Suricata\etc\suricata\suricata.yaml","$env:ProgramData\Suricata\suricata.yaml",'C:\Suricata\suricata.yaml') |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    $eve = @("$env:ProgramFiles\Suricata\log\eve.json","$env:ProgramFiles\Suricata\logs\eve.json","$env:ProgramData\Suricata\log\eve.json","$env:ProgramData\Suricata\logs\eve.json",'C:\Suricata\log\eve.json','C:\Suricata\logs\eve.json') |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if (-not $eve -and $config) {
        try {
            $logDir = $null
            foreach ($line in Get-Content -LiteralPath $config -ErrorAction Stop) {
                if ($line -match '^\s*default-log-dir:\s*["'']?([^"''#]+)') { $logDir=$Matches[1].Trim(); break }
            }
            if ($logDir) {
                $candidate=Join-Path $logDir 'eve.json'
                if (Test-Path -LiteralPath $candidate) { $eve=$candidate }
            }
        }
        catch {}
    }
    $npcap = Get-Service -Name npcap,npf -ErrorAction SilentlyContinue | Select-Object -First 1
    [pscustomobject]@{
        Installed=[bool]($exe -and (Test-Path -LiteralPath $exe))
        Executable=$exe
        Config=$config
        EvePath=$eve
        ServiceName=$(if($service){[string]$service.Name}else{$null})
        ServiceState=$(if($service){[string]$service.State}else{'Not installed'})
        NpcapInstalled=[bool]$npcap
    }
}

function Get-ClientWazuhInfo {
    $service=$null
    foreach($name in @('WazuhSvc','wazuh','ossec-agent')){
        try{$service=Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $name) -ErrorAction Stop;if($service){break}}catch{}
    }
    if(-not $service){
        try{$service=Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object{$_.Name -match '(?i)wazuh|ossec' -or $_.DisplayName -match '(?i)wazuh|ossec'} | Select-Object -First 1}catch{}
    }
    $roots=@("${env:ProgramFiles(x86)}\ossec-agent","$env:ProgramFiles\Wazuh Agent","$env:ProgramFiles\ossec-agent",'C:\Program Files (x86)\ossec-agent')|Where-Object{$_}
    $root=$roots|Where-Object{Test-Path -LiteralPath $_}|Select-Object -First 1
    $config=$null;$log=$null;$manager=$null;$eveConfigured=$false
    if($root){
        foreach($candidate in @((Join-Path $root 'ossec.conf'),(Join-Path $root 'etc\ossec.conf'))){if(Test-Path -LiteralPath $candidate){$config=$candidate;break}}
        foreach($candidate in @((Join-Path $root 'ossec.log'),(Join-Path $root 'logs\ossec.log'))){if(Test-Path -LiteralPath $candidate){$log=$candidate;break}}
    }
    if($config){
        try{
            $raw=Get-Content -LiteralPath $config -Raw -ErrorAction Stop
            if($raw -match '(?is)<client>.*?<server>.*?<address>\s*([^<]+)\s*</address>'){$manager=$Matches[1].Trim()}
            $suricata=Get-ClientSuricataInfo
            if($suricata.EvePath -and $raw -match [regex]::Escape([string]$suricata.EvePath)){$eveConfigured=$true}
        }catch{}
    }
    [pscustomobject]@{
        Installed=[bool]($service -or $root)
        ServiceName=$(if($service){[string]$service.Name}else{$null})
        ServiceState=$(if($service){[string]$service.State}else{'Not installed'})
        Config=$config
        Log=$log
        Manager=$manager
        EveConfigured=$eveConfigured
    }
}

# Third-party configuration files (Wazuh ossec.conf, Suricata YAML) are usually
# UTF-8 without BOM. Windows PowerShell 5.1 `Set-Content -Encoding UTF8` always
# prepends a BOM and `Get-Content` without -Encoding reads ANSI; both differ from
# PowerShell 7. These helpers keep the file's original BOM state on both engines.
function Read-ConfigText {
    param([Parameter(Mandatory)][string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $hasBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
    $offset = if ($hasBom) { 3 } else { 0 }
    [pscustomobject]@{
        Text   = [System.Text.UTF8Encoding]::new($false).GetString($bytes, $offset, $bytes.Length - $offset)
        HasBom = $hasBom
    }
}

function Write-ConfigText {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][AllowEmptyString()][string]$Text, [bool]$HasBom = $false)
    [System.IO.File]::WriteAllText($Path, $Text, [System.Text.UTF8Encoding]::new($HasBom))
}

function Backup-ClientSecurityConfig {
    param([Parameter(Mandatory=$true)][string]$Path)
    if(-not(Test-Path -LiteralPath $Path)){return $null}
    $paths=Get-ClientSecurityPaths
    $dest=Join-Path $paths.Backup ('{0}.{1}.bak' -f ([IO.Path]::GetFileName($Path)),(Get-Date -Format 'yyyyMMdd-HHmmss'))
    Copy-Item -LiteralPath $Path -Destination $dest -Force
    Write-Log ("Security config backup: {0}" -f $dest) INFO
    return $dest
}

function Set-ClientWazuhManager {
    $w=Get-ClientWazuhInfo
    if(-not $w.Config){Write-Warn 'Wazuh agent configuration was not detected.';return}
    $manager=Read-Value -Prompt 'Wazuh manager FQDN or IP' -Default $(if($w.Manager){$w.Manager}else{''})
    if([string]::IsNullOrWhiteSpace($manager)){return}
    if($manager -notmatch '^[A-Za-z0-9._:-]+$'){Write-ErrorUi 'Unsupported manager value.';return}
    if(-not(Confirm-Choice -Prompt ("Apply Wazuh manager {0}?" -f $manager) -Default N)){return}
    $backup=Backup-ClientSecurityConfig -Path $w.Config
    try{
        $configFile=Read-ConfigText -Path $w.Config;$raw=$configFile.Text
        if($raw -match '(?is)(<client>.*?<server>.*?<address>)(.*?)(</address>)'){
            $updated=[regex]::Replace($raw,'(?is)(<client>.*?<server>.*?<address>)(.*?)(</address>)',('$1'+$manager+'$3'),1)
        }else{
            $block="<ossec_config>`r`n  <client>`r`n    <server>`r`n      <address>$manager</address>`r`n    </server>`r`n  </client>`r`n</ossec_config>`r`n"
            $updated=$raw.TrimEnd()+"`r`n"+$block
        }
        Write-ConfigText -Path $w.Config -Text $updated -HasBom $configFile.HasBom
        if($w.ServiceName){
            Restart-Service -Name $w.ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $svc=Get-Service -Name $w.ServiceName -ErrorAction Stop
            if($svc.Status -ne 'Running'){throw 'Wazuh service did not return to Running state.'}
        }
        Write-Ok 'Wazuh manager configuration updated and service is healthy.'
    }catch{
        Write-ErrorUi ("Wazuh manager update failed: {0}" -f $_.Exception.Message)
        if($backup -and(Test-Path -LiteralPath $backup)){Copy-Item -LiteralPath $backup -Destination $w.Config -Force;if($w.ServiceName){try{Restart-Service -Name $w.ServiceName -Force -ErrorAction SilentlyContinue}catch{}};Write-Warn 'Original Wazuh configuration restored.'}
    }
}

function Enable-ClientWazuhSuricataIngestion {
    param([switch]$NonInteractive)
    $w=Get-ClientWazuhInfo;$suricata=Get-ClientSuricataInfo
    if(-not $w.Config){if(-not $NonInteractive){Write-Warn 'Wazuh agent is not installed/configured.'};return $false}
    if(-not $suricata.EvePath){if(-not $NonInteractive){Write-Warn 'Suricata EVE JSON was not detected.'};return $false}
    $configFile=Read-ConfigText -Path $w.Config;$raw=$configFile.Text
    if($raw -match [regex]::Escape([string]$suricata.EvePath)){if(-not $NonInteractive){Write-Ok 'Wazuh already ingests Suricata EVE JSON.'};return $true}
    if(-not $NonInteractive -and -not(Confirm-Choice -Prompt 'Add Suricata EVE JSON to Wazuh telemetry?' -Default Y)){return $false}
    $backup=Backup-ClientSecurityConfig -Path $w.Config
    try{
        $block="  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$($suricata.EvePath)</location>`r`n  </localfile>`r`n"
        if($raw -notmatch '(?i)</ossec_config>\s*$'){throw 'Wazuh ossec.conf closing element was not found.'}
        $updated=[regex]::Replace($raw,'(?i)</ossec_config>\s*$',($block+'</ossec_config>'+"`r`n"),1)
        Write-ConfigText -Path $w.Config -Text $updated -HasBom $configFile.HasBom
        if($w.ServiceName){
            Restart-Service -Name $w.ServiceName -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            $svc=Get-Service -Name $w.ServiceName -ErrorAction Stop
            if($svc.Status -ne 'Running'){throw 'Wazuh service did not return to Running state.'}
        }
        if(-not $NonInteractive){Write-Ok 'Wazuh now ingests Suricata EVE JSON.'}
        return $true
    }catch{
        if($backup -and(Test-Path -LiteralPath $backup)){Copy-Item -LiteralPath $backup -Destination $w.Config -Force}
        if(-not $NonInteractive){Write-ErrorUi ("Wazuh/Suricata integration failed: {0}" -f $_.Exception.Message)}
        return $false
    }
}

function Test-ClientSuricataConfiguration {
    $s=Get-ClientSuricataInfo
    if(-not $s.Executable -or -not $s.Config){Write-Warn 'Suricata executable/configuration was not detected.';return $false}
    Write-Info ("Validating Suricata configuration: {0}" -f $s.Config)
    $out=& $s.Executable -T -c $s.Config 2>&1
    $rc=$LASTEXITCODE
    $out|Select-Object -Last 30|ForEach-Object{Write-Ui ("  {0}" -f $_) Gray}
    if($rc -eq 0){Write-Ok 'Suricata configuration is valid.';return $true}
    Write-ErrorUi ("Suricata configuration test failed (exit {0})." -f $rc);return $false
}

function Get-ClientGuardedIpsState {
    $p=Get-ClientSecurityPaths
    if(-not(Test-Path -LiteralPath $p.IpsState)){return [pscustomobject]@{Enabled=$false;BlockMinutes=30;MaxRules=20;LastRun=$null;Rules=@()}}
    try{return Get-Content -LiteralPath $p.IpsState -Raw|ConvertFrom-Json}catch{return [pscustomobject]@{Enabled=$false;BlockMinutes=30;MaxRules=20;LastRun=$null;Rules=@()}}
}

function Save-ClientGuardedIpsState { param($State);$p=Get-ClientSecurityPaths;$State|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $p.IpsState -Encoding UTF8 }

function Test-ClientPublicIpCandidate {
    param([string]$Address)
    if(Test-ClientDefenseTrustedIp -Address $Address){return $false}
    $ip=$null;if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip)){return $false};if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
    $b=$ip.GetAddressBytes();if($b[0]-eq 10 -or $b[0]-eq 127){return $false};if($b[0]-eq 169 -and $b[1]-eq 254){return $false};if($b[0]-eq 172 -and $b[1]-ge 16 -and $b[1]-le 31){return $false};if($b[0]-eq 192 -and $b[1]-eq 168){return $false};if($b[0]-eq 0 -or $b[0]-ge 224){return $false}
    try{if(@(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue|Select-Object -ExpandProperty IPAddress)-contains $Address){return $false}}catch{}
    return $true
}

function Get-ClientGuardedIpsCandidates {
    param([int]$Hours=1,[int]$MaxEvents=5000)
    $s=Get-ClientSuricataInfo;if(-not $s.EvePath){return @()};$cutoff=(Get-Date).ToUniversalTime().AddHours(-1*$Hours);$events=New-Object 'System.Collections.Generic.List[object]'
    foreach($line in Get-Content -LiteralPath $s.EvePath -Tail $MaxEvents -ErrorAction SilentlyContinue){
        if([string]::IsNullOrWhiteSpace($line)){continue};try{$evt=$line|ConvertFrom-Json -ErrorAction Stop}catch{continue};if($evt.event_type -ne 'alert' -or -not $evt.alert){continue}
        $sev=99;try{$sev=[int]$evt.alert.severity}catch{};if($sev -gt 1){continue};$ts=$null;try{$ts=([datetime]$evt.timestamp).ToUniversalTime()}catch{};if($ts -and $ts -lt $cutoff){continue}
        $src=[string]$evt.src_ip;if(-not(Test-ClientPublicIpCandidate -Address $src)){continue};$events.Add([pscustomobject]@{SourceIp=$src;Signature=[string]$evt.alert.signature;Severity=$sev})
    }
    return @($events|Group-Object SourceIp|Sort-Object Count -Descending|ForEach-Object{$sample=$_.Group|Select-Object -First 1;[pscustomobject]@{SourceIp=$_.Name;Count=$_.Count;Signature=$sample.Signature;Severity=$sample.Severity}})
}

function Remove-ExpiredClientGuardedIpsRules {
    $state=Get-ClientGuardedIpsState;$now=Get-Date;$keep=New-Object 'System.Collections.Generic.List[object]'
    foreach($entry in @($state.Rules)){$expires=$null;try{$expires=[datetime]$entry.Expires}catch{};if(-not $expires -or $expires -le $now){try{Remove-NetFirewallRule -Name ([string]$entry.RuleName) -ErrorAction SilentlyContinue}catch{}}else{$keep.Add($entry)}}
    $state.Rules=@($keep);$state.LastRun=(Get-Date).ToString('o');Save-ClientGuardedIpsState $state;return $keep.Count
}

function Register-ClientGuardedIpsTask {
    $p=Get-ClientSecurityPaths;if(-not(Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)){return};if(-not $PSCommandPath){return}
    try{$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode SecurityCleanup -NoColor -StateRoot "{1}"' -f $PSCommandPath,$StateRoot);$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650);$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;Register-ScheduledTask -TaskName $p.IpsTask -Action $action -Trigger $trigger -Principal $principal -Force|Out-Null}catch{Write-Warn ("Could not register guarded IPS cleanup task: {0}" -f $_.Exception.Message)}
}

function Invoke-ClientGuardedIpsResponse {
    param([switch]$NonInteractive)
    [void](Remove-ExpiredClientGuardedIpsRules);$state=Get-ClientGuardedIpsState;if(-not $state.Enabled){if(-not $NonInteractive){Write-Warn 'Guarded IPS is disabled.'};return}
    $candidates=@(Get-ClientGuardedIpsCandidates -Hours 1);if($candidates.Count -eq 0){if(-not $NonInteractive){Write-Ok 'No high-confidence public-source candidates were found.'};return}
    $active=@($state.Rules|ForEach-Object{[string]$_.SourceIp});$remaining=[math]::Max(0,[int]$state.MaxRules-@($state.Rules).Count);$new=New-Object 'System.Collections.Generic.List[object]';$paths=Get-ClientSecurityPaths
    foreach($candidate in $candidates){if($remaining -le 0){break};if($active -contains [string]$candidate.SourceIp){continue};$safe=([string]$candidate.SourceIp)-replace '[^0-9A-Fa-f\.:]','_';$name='{0}{1}-{2}' -f $paths.IpsPrefix,$safe,([guid]::NewGuid().ToString('N').Substring(0,8));$expires=(Get-Date).AddMinutes([int]$state.BlockMinutes)
        try{New-NetFirewallRule -Name $name -DisplayName ("AD Client Guarded IPS - {0}" -f $candidate.SourceIp) -Description ("Temporary Suricata severity-1 response; expires {0}; {1}" -f $expires.ToString('o'),$candidate.Signature) -Direction Inbound -Action Block -RemoteAddress ([string]$candidate.SourceIp) -Profile Any -ErrorAction Stop|Out-Null;$new.Add([pscustomobject]@{RuleName=$name;SourceIp=[string]$candidate.SourceIp;Created=(Get-Date).ToString('o');Expires=$expires.ToString('o');Signature=[string]$candidate.Signature;AlertCount=[int]$candidate.Count});$remaining--;Write-Log ("Guarded IPS blocked {0} temporarily." -f $candidate.SourceIp) WARN}catch{Write-Log ("Guarded IPS block failed for {0}: {1}" -f $candidate.SourceIp,$_.Exception.Message) WARN}}
    $state.Rules=@($state.Rules)+@($new);$state.LastRun=(Get-Date).ToString('o');Save-ClientGuardedIpsState $state;if(-not $NonInteractive){Write-Ok ("Created {0} temporary firewall block rule(s)." -f $new.Count)}
}

function Enable-ClientGuardedIps {
    $s=Get-ClientSuricataInfo;if(-not $s.EvePath){Write-Warn 'Suricata EVE JSON is required before guarded IPS can be enabled.';return}
    Write-Ui '';Write-Ui 'GUARDED IPS SAFETY PROFILE' Cyan;Write-Info 'Only severity-1 Suricata alerts from public IPv4 sources are eligible.';Write-Info 'Private/local/domain addresses are never automatically blocked. Rules expire after 30 minutes.';Write-Info 'The assistant does not enable inline Suricata/WinDivert automatically.'
    $preview=@(Get-ClientGuardedIpsCandidates -Hours 1);Write-Info ("Current eligible candidates: {0}" -f $preview.Count);$preview|Select-Object -First 10|ForEach-Object{Write-Ui ("  {0,-16} alerts={1,-3} {2}" -f $_.SourceIp,$_.Count,$_.Signature) Gray}
    if(-not(Confirm-Literal -Prompt 'Enable temporary firewall responses from high-confidence Suricata alerts.' -Literal 'APPLY')){Write-Info 'Guarded IPS activation cancelled.';return}
    $state=Get-ClientGuardedIpsState;$cfg=Get-ClientDefenseConfig;$state.Enabled=$true;$state.BlockMinutes=[int]$cfg.BlockMinutes;$state.MaxRules=20;Save-ClientGuardedIpsState $state;Register-ClientGuardedIpsTask;Invoke-ClientGuardedIpsResponse;Write-Ok 'Guarded IPS enabled.'
}

function Disable-ClientGuardedIps {
    $state=Get-ClientGuardedIpsState;$paths=Get-ClientSecurityPaths;$state.Enabled=$false;foreach($entry in @($state.Rules)){try{Remove-NetFirewallRule -Name ([string]$entry.RuleName) -ErrorAction SilentlyContinue}catch{}};$state.Rules=@();Save-ClientGuardedIpsState $state;try{Unregister-ScheduledTask -TaskName $paths.IpsTask -Confirm:$false -ErrorAction SilentlyContinue}catch{};Write-Ok 'Guarded IPS disabled and managed block rules removed.'
}


function Get-ClientDefenseConfig {
    $p=Get-ClientSecurityPaths
    $path=Join-Path $p.Root 'defense-ops.json'
    $defaults=[ordered]@{BusinessStart='08:00';BusinessEnd='18:00';BusinessDays=@('Monday','Tuesday','Wednesday','Thursday','Friday');DayAlertSeverity=1;AfterHoursAlertSeverity=2;DayWindowHours=1;AfterHoursWindowHours=4;BlockMinutes=30;TrustedIps=@();TelegramEnabled=$false;TelegramChatId='';LastAlertFingerprint=''}
    if(-not(Test-Path -LiteralPath $path)){[pscustomobject]$defaults|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $path -Encoding UTF8;return [pscustomobject]$defaults}
    try{$cfg=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json;foreach($k in $defaults.Keys){if(-not $cfg.PSObject.Properties[$k]){$cfg|Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k]}};return $cfg}catch{return [pscustomobject]$defaults}
}
function Save-ClientDefenseConfig {param($Config);$p=Get-ClientSecurityPaths;$Config|ConvertTo-Json -Depth 8|Set-Content -LiteralPath (Join-Path $p.Root 'defense-ops.json') -Encoding UTF8}
function Test-ClientDefenseTrustedIp {param([string]$Address);$cfg=Get-ClientDefenseConfig;return(@($cfg.TrustedIps)-contains $Address)}
function Test-ClientBusinessHours {
    $cfg=Get-ClientDefenseConfig;$now=Get-Date;if(@($cfg.BusinessDays)-notcontains $now.DayOfWeek.ToString()){return $false}
    try{$s=[TimeSpan]::Parse([string]$cfg.BusinessStart);$e=[TimeSpan]::Parse([string]$cfg.BusinessEnd);$t=$now.TimeOfDay;if($s -le $e){return($t -ge $s -and $t -lt $e)};return($t -ge $s -or $t -lt $e)}catch{return $true}
}
function Get-ClientAwarenessProfile {$cfg=Get-ClientDefenseConfig;if(Test-ClientBusinessHours){return[pscustomobject]@{Label='business-hours';Severity=[int]$cfg.DayAlertSeverity;WindowHours=[int]$cfg.DayWindowHours}};return[pscustomobject]@{Label='after-hours';Severity=[int]$cfg.AfterHoursAlertSeverity;WindowHours=[int]$cfg.AfterHoursWindowHours}}
function Protect-ClientSecret {param([string]$Text);$bytes=[Text.Encoding]::UTF8.GetBytes($Text);$p=[Security.Cryptography.ProtectedData]::Protect($bytes,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine);[Convert]::ToBase64String($p)}
function Unprotect-ClientSecret {param([string]$Text);try{$b=[Convert]::FromBase64String($Text);$p=[Security.Cryptography.ProtectedData]::Unprotect($b,$null,[Security.Cryptography.DataProtectionScope]::LocalMachine);[Text.Encoding]::UTF8.GetString($p)}catch{$null}}
function Set-ClientTelegramHook {
    $p=Get-ClientSecurityPaths;$cfg=Get-ClientDefenseConfig;$tokenPath=Join-Path $p.Root 'telegram-token.dpapi'
    $chat=Read-Value -Prompt 'Telegram chat/channel ID' -Default $(if($cfg.TelegramChatId){[string]$cfg.TelegramChatId}else{''})
    $sec=Read-Host 'Telegram bot token (hidden; Enter keeps current)' -AsSecureString;$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
    try{$token=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)}finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}
    if($token){(Protect-ClientSecret $token)|Set-Content -LiteralPath $tokenPath -Encoding ASCII}
    if(-not(Test-Path -LiteralPath $tokenPath)){Write-Warn 'No Telegram token is stored.';return}
    $cfg.TelegramChatId=$chat;$cfg.TelegramEnabled=$true;Save-ClientDefenseConfig $cfg;Write-Ok 'Telegram hook configured with a DPAPI-protected token.'
}
function Send-ClientTelegramMessage {
    param([string]$Text,[switch]$Quiet)
    $p=Get-ClientSecurityPaths;$cfg=Get-ClientDefenseConfig;$tokenPath=Join-Path $p.Root 'telegram-token.dpapi'
    if(-not $cfg.TelegramEnabled -or -not (Test-Path -LiteralPath $tokenPath)){if(-not $Quiet){Write-Warn 'Telegram hook is disabled.'};return $false}
    $token=Unprotect-ClientSecret ((Get-Content -LiteralPath $tokenPath -Raw).Trim());if(-not $token){if(-not $Quiet){Write-Warn 'Telegram token could not be decrypted.'};return $false}
    try{[void](Invoke-RestMethod -Method Post -Uri ('https://api.telegram.org/bot{0}/sendMessage'-f $token) -Body @{chat_id=[string]$cfg.TelegramChatId;text=$Text;disable_web_page_preview='true'} -TimeoutSec 15 -ErrorAction Stop);return $true}catch{Write-Log ("Telegram notification failed: {0}"-f$_.Exception.Message) WARN;if(-not $Quiet){Write-Warn $_.Exception.Message};return $false}
}
function Get-ClientAwarenessAlerts {
    param([int]$Hours=0,[int]$Severity=0)
    $profile=Get-ClientAwarenessProfile;if($Hours -le 0){$Hours=$profile.WindowHours};if($Severity -le 0){$Severity=$profile.Severity};$s=Get-ClientSuricataInfo;if(-not $s.EvePath){return @()}
    $cut=(Get-Date).ToUniversalTime().AddHours(-1*$Hours);$r=New-Object 'System.Collections.Generic.List[object]'
    foreach($line in Get-Content -LiteralPath $s.EvePath -Tail 8000 -ErrorAction SilentlyContinue){if([string]::IsNullOrWhiteSpace($line)){continue};try{$e=$line|ConvertFrom-Json -ErrorAction Stop}catch{continue};if($e.event_type -ne 'alert' -or -not $e.alert){continue};$sev=99;try{$sev=[int]$e.alert.severity}catch{};if($sev -gt $Severity){continue};$ts=$null;try{$ts=([datetime]$e.timestamp).ToUniversalTime()}catch{};if($ts -and $ts -lt $cut){continue};$r.Add([pscustomobject]@{Timestamp=[string]$e.timestamp;SourceIp=[string]$e.src_ip;DestinationIp=[string]$e.dest_ip;Severity=$sev;Signature=[string]$e.alert.signature;Action=[string]$e.alert.action})}
    return @($r|Sort-Object Timestamp -Descending)
}
function Add-ClientManualBlock {
    param([string]$Address)
    if(-not $Address){$Address=Read-Value -Prompt 'IPv4 address to block'}
    $ip=$null;if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip)-or$ip.AddressFamily-ne[Net.Sockets.AddressFamily]::InterNetwork){Write-Warn 'Invalid IPv4 address.';return};if(Test-ClientDefenseTrustedIp $Address){Write-Warn 'Address is trusted; remove it from trusted IPs first.';return}
    $cfg=Get-ClientDefenseConfig;$state=Get-ClientGuardedIpsState;$paths=Get-ClientSecurityPaths;if(@($state.Rules|ForEach-Object{$_.SourceIp})-contains$Address){Write-Warn 'Already blocked.';return}
    $name='{0}{1}-{2}'-f $paths.IpsPrefix,($Address -replace '[^0-9.]','_'),([guid]::NewGuid().ToString('N').Substring(0,8));$exp=(Get-Date).AddMinutes([int]$cfg.BlockMinutes)
    New-NetFirewallRule -Name $name -DisplayName ("AD Client Manual IPS - {0}" -f $Address) -Direction Inbound -Action Block -RemoteAddress $Address -Profile Any -Description ("Operator temporary block; expires {0}"-f$exp.ToString('o'))|Out-Null
    $state.Rules=@($state.Rules)+@([pscustomobject]@{RuleName=$name;SourceIp=$Address;Created=(Get-Date).ToString('o');Expires=$exp.ToString('o');Signature='Manual operator block';AlertCount=0});Save-ClientGuardedIpsState $state;Write-Ok ("Blocked {0} temporarily." -f $Address)
}
function Remove-ClientBlock {
    param([string]$Address)
    $state=Get-ClientGuardedIpsState;if(-not $Address){$Address=Read-Value -Prompt 'IPv4 address to unblock'};$matches=@($state.Rules|Where-Object{$_.SourceIp -eq $Address});if($matches.Count -eq 0){Write-Warn 'No active assistant-managed block found.';return};foreach($r in $matches){Remove-NetFirewallRule -Name ([string]$r.RuleName) -ErrorAction SilentlyContinue};$state.Rules=@($state.Rules|Where-Object{$_.SourceIp -ne $Address});Save-ClientGuardedIpsState $state;Write-Ok ("Unblocked {0}." -f $Address)
}
function Remove-AllClientBlocks {$state=Get-ClientGuardedIpsState;foreach($r in @($state.Rules)){Remove-NetFirewallRule -Name ([string]$r.RuleName) -ErrorAction SilentlyContinue};$state.Rules=@();Save-ClientGuardedIpsState $state;Write-Ok 'All assistant-managed blocks removed.'}
function Add-ClientTrustedIp {
    param([string]$Address)
    if(-not $Address){$Address=Read-Value -Prompt 'IPv4 address to trust'};$ip=$null;if(-not [Net.IPAddress]::TryParse($Address,[ref]$ip)){Write-Warn 'Invalid IP.';return};$cfg=Get-ClientDefenseConfig;if(@($cfg.TrustedIps) -notcontains $Address){$cfg.TrustedIps=@($cfg.TrustedIps)+$Address;Save-ClientDefenseConfig $cfg};Remove-ClientBlock -Address $Address;Write-Ok ("Trusted IP: {0}" -f $Address)
}
function Register-ClientAwarenessTask {
    $p=Get-ClientSecurityPaths
    if(-not(Get-Command Register-ScheduledTask -ErrorAction SilentlyContinue)){Write-Warn 'Scheduled Task cmdlets unavailable.';return}
    if(-not $PSCommandPath){Write-Warn 'Current script path unavailable.';return}
    try{
        $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File "{0}" -Mode SecurityAwareness -NoColor -StateRoot "{1}"' -f $PSCommandPath,$StateRoot)
        $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 3650)
        $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName 'ADClientAssistant-DefenseAwareness' -Action $action -Trigger $trigger -Principal $principal -Force|Out-Null
        Write-Ok 'Defense awareness notification task enabled (every 15 minutes).'
    }catch{Write-Warn ("Could not register awareness task: {0}" -f $_.Exception.Message)}
}

function Set-ClientAwarenessSchedule {
    $cfg=Get-ClientDefenseConfig;Write-Ui 'AWARENESS SCHEDULE' Cyan
    $s=Read-Value -Prompt 'Business start HH:mm' -Default ([string]$cfg.BusinessStart);$e=Read-Value -Prompt 'Business end HH:mm' -Default ([string]$cfg.BusinessEnd);try{[void][TimeSpan]::Parse($s);[void][TimeSpan]::Parse($e)}catch{Write-Warn 'Invalid time.';return}
    $d=[int](Read-Value -Prompt 'Business-hours review window (hours)' -Default ([string]$cfg.DayWindowHours));$n=[int](Read-Value -Prompt 'After-hours review window (hours)' -Default ([string]$cfg.AfterHoursWindowHours));$ttl=[int](Read-Value -Prompt 'Temporary block duration (minutes)' -Default ([string]$cfg.BlockMinutes))
    $cfg.BusinessStart=$s;$cfg.BusinessEnd=$e;$cfg.DayWindowHours=[math]::Max(1,$d);$cfg.AfterHoursWindowHours=[math]::Max(1,$n);$cfg.BlockMinutes=[math]::Max(1,$ttl);Save-ClientDefenseConfig $cfg;$ips=Get-ClientGuardedIpsState;$ips.BlockMinutes=$cfg.BlockMinutes;Save-ClientGuardedIpsState $ips;Write-Ok 'Awareness schedule updated.'
}
function Invoke-ClientAwarenessCheck {
    param([switch]$Notify)
    $p=Get-ClientAwarenessProfile;$a=@(Get-ClientAwarenessAlerts -Hours $p.WindowHours -Severity $p.Severity);Write-Info ("{0}: {1} matching alert(s) in {2}h (severity <= {3})." -f $p.Label,$a.Count,$p.WindowHours,$p.Severity);$a|Select-Object -First 20|ForEach-Object{Write-Ui ("  sev={0} {1,-16} {2}" -f $_.Severity,$_.SourceIp,$_.Signature) Gray}
    if($Notify -and $a.Count -gt 0){$cfg=Get-ClientDefenseConfig;$groups=@($a|Group-Object SourceIp|Sort-Object Count -Descending|Select-Object -First 5);$fp=($groups|ForEach-Object{"$($_.Name):$($_.Count)"})-join'|';if($fp -ne [string]$cfg.LastAlertFingerprint){$msg=@("Windows AD client security alert ($($p.Label))","Host: $env:COMPUTERNAME","Matches: $($a.Count)","Review manually in Security Center.")+@($groups|ForEach-Object{"Source $($_.Name): $($_.Count) alert(s)"});if(Send-ClientTelegramMessage -Text ($msg -join "`n") -Quiet){$cfg.LastAlertFingerprint=$fp;Save-ClientDefenseConfig $cfg;Write-Ok 'Telegram alert sent.'}}}
}
function Show-ClientDefenseGui {
    try{Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop;Add-Type -AssemblyName System.Drawing -ErrorAction Stop}catch{Write-Warn 'Windows Forms unavailable.';return}
    $form=New-Object Windows.Forms.Form;$form.Text=(Get-UiText 'AD Client Defense Center - Suricata + Wazuh');$form.Width=1060;$form.Height=700;$form.StartPosition='CenterScreen'
    $status=New-Object Windows.Forms.Label;$status.Dock='Top';$status.Height=48;$status.Padding=New-Object Windows.Forms.Padding(8)
    $tabs=New-Object Windows.Forms.TabControl;$tabs.Dock='Fill'
    $t1=New-Object Windows.Forms.TabPage;$t1.Text=(Get-UiText 'Blocks');$grid=New-Object Windows.Forms.DataGridView;$grid.Dock='Fill';$grid.ReadOnly=$true;$grid.SelectionMode='FullRowSelect';$grid.AutoSizeColumnsMode='Fill';$grid.AllowUserToAddRows=$false
    $bar=New-Object Windows.Forms.FlowLayoutPanel;$bar.Dock='Bottom';$bar.Height=46
    foreach($spec in @(@('Refresh','r'),@('Unblock selected','u'),@('Unblock all','ua'),@('Block IP','b'),@('Trust selected','t'),@('Run IPS','i'))){$btn=New-Object Windows.Forms.Button;$btn.Text=(Get-UiText ([string]$spec[0]));$btn.Tag=$spec[1];$btn.AutoSize=$true;[void]$bar.Controls.Add($btn)}
    [void]$t1.Controls.Add($grid);[void]$t1.Controls.Add($bar)
    $t2=New-Object Windows.Forms.TabPage;$t2.Text=(Get-UiText 'Alerts');$ag=New-Object Windows.Forms.DataGridView;$ag.Dock='Fill';$ag.ReadOnly=$true;$ag.AutoSizeColumnsMode='Fill';$ag.AllowUserToAddRows=$false;[void]$t2.Controls.Add($ag)
    [void]$tabs.TabPages.Add($t1);[void]$tabs.TabPages.Add($t2);[void]$form.Controls.Add($tabs);[void]$form.Controls.Add($status)
    $refresh={$state=Get-ClientGuardedIpsState;$p=Get-ClientAwarenessProfile;$s=Get-ClientSuricataInfo;$w=Get-ClientWazuhInfo;$status.Text=("Suricata={0} | Wazuh={1} | IPS={2} | {3}: {4}h/sev<={5}"-f$s.ServiceState,$w.ServiceState,$state.Enabled,$p.Label,$p.WindowHours,$p.Severity);$grid.DataSource=$null;$grid.DataSource=@($state.Rules|Select-Object SourceIp,Created,Expires,Signature);$ag.DataSource=$null;$ag.DataSource=@(Get-ClientAwarenessAlerts -Hours $p.WindowHours -Severity $p.Severity|Select-Object -First 150)}.GetNewClosure()
    foreach($btn in @($bar.Controls)){$btn.Add_Click({try{switch([string]$this.Tag){'u'{if($grid.SelectedRows.Count -gt 0){Remove-ClientBlock -Address ([string]$grid.SelectedRows[0].Cells['SourceIp'].Value)}}'ua'{Remove-AllClientBlocks}'b'{Add-Type -AssemblyName Microsoft.VisualBasic;$ip=[Microsoft.VisualBasic.Interaction]::InputBox('IPv4 address','Temporary block','');if($ip){Add-ClientManualBlock -Address $ip}}'t'{if($grid.SelectedRows.Count -gt 0){Add-ClientTrustedIp -Address ([string]$grid.SelectedRows[0].Cells['SourceIp'].Value)}}'i'{Invoke-ClientGuardedIpsResponse -NonInteractive}};&$refresh}catch{[Windows.Forms.MessageBox]::Show($_.Exception.Message)|Out-Null}}.GetNewClosure())}
    &$refresh;[void]$form.ShowDialog();$form.Dispose()
}

function Show-ClientSecurityStatus {
    Write-Header;Write-Ui (Get-UiText 'SURICATA + WAZUH SECURITY') Cyan;Write-Ui '';$s=Get-ClientSuricataInfo;$w=Get-ClientWazuhInfo;[void](Remove-ExpiredClientGuardedIpsRules);$ips=Get-ClientGuardedIpsState
    Write-Ui ("Suricata installed : {0}" -f $s.Installed);Write-Ui ("Suricata service   : {0}" -f $s.ServiceState);Write-Ui ("Suricata EVE       : {0}" -f $(if($s.EvePath){$s.EvePath}else{'not detected'}));Write-Ui ("Npcap              : {0}" -f $s.NpcapInstalled)
    Write-Ui ("Wazuh installed    : {0}" -f $w.Installed);Write-Ui ("Wazuh service      : {0}" -f $w.ServiceState);Write-Ui ("Wazuh manager      : {0}" -f $(if($w.Manager){$w.Manager}else{'not detected'}));Write-Ui ("EVE -> Wazuh       : {0}" -f $w.EveConfigured)
    Write-Ui ("Guarded IPS        : {0}" -f $(if($ips.Enabled){'enabled'}else{'disabled'}));Write-Ui ("Active temp blocks : {0}" -f @($ips.Rules).Count)
    Write-Info 'Recommended posture is passive Suricata IDS + Wazuh correlation. Guarded IPS is optional and conservative.'
}

function Show-ClientSecurityMenu {
    while($true){
        Show-ClientSecurityStatus
        Write-Ui ''
        Write-Ui ("  [1] {0}" -f (Get-UiText 'Validate Suricata configuration'))
        Write-Ui ("  [2] {0}" -f (Get-UiText 'Configure Wazuh manager'))
        Write-Ui ("  [3] {0}" -f (Get-UiText 'Enable Suricata EVE ingestion in Wazuh'))
        Write-Ui '  [4] Enable guarded IPS' Yellow
        Write-Ui '  [5] Run guarded IPS now'
        Write-Ui '  [6] Disable guarded IPS' Yellow
        Write-Ui ("  [7] {0}" -f (Get-UiText 'Recent Wazuh agent log'))
        Write-Ui '  [8] Defense GUI (alerts / blocked IPs / quick unblock)' Cyan
        Write-Ui '  [9] Unblock / trust / manual block'
        Write-Ui '  [10] Awareness schedule'
        Write-Ui '  [11] Telegram alert hook'
        Write-Ui '  [12] Run awareness check + notify'
        Write-Ui '  [0] Back';Write-Ui ''
        $choice=Read-Value -Prompt 'Select operation' -Default '1'
        switch($choice.ToUpperInvariant()){
            '1'{[void](Test-ClientSuricataConfiguration);Pause-Ui}
            '2'{Set-ClientWazuhManager;Pause-Ui}
            '3'{[void](Enable-ClientWazuhSuricataIngestion);Pause-Ui}
            '4'{Enable-ClientGuardedIps;Pause-Ui}
            '5'{Invoke-ClientGuardedIpsResponse;Pause-Ui}
            '6'{if(Confirm-Choice -Prompt 'Disable guarded IPS and remove assistant-managed firewall blocks?' -Default N){Disable-ClientGuardedIps};Pause-Ui}
            '7'{$w=Get-ClientWazuhInfo;if($w.Log){Get-Content -LiteralPath $w.Log -Tail 40 -ErrorAction SilentlyContinue|ForEach-Object{Write-Ui $_ Gray}}else{Write-Warn 'Wazuh agent log was not detected.'};Pause-Ui}
            '8'{Show-ClientDefenseGui}
            '9'{
                [void](Remove-ExpiredClientGuardedIpsRules);$state=Get-ClientGuardedIpsState;$cfg=Get-ClientDefenseConfig
                Write-Ui '';Write-Ui 'BLOCKED / TRUSTED IP MANAGEMENT' Cyan
                foreach($r in @($state.Rules)){Write-Ui ("  BLOCK {0,-16} expires={1}" -f $r.SourceIp,$r.Expires) Gray}
                Write-Ui ("Trusted: {0}" -f $(if(@($cfg.TrustedIps).Count){@($cfg.TrustedIps) -join ', '}else{'none'})) Gray
                Write-Ui '  [1] Unblock IP';Write-Ui '  [2] Unblock all';Write-Ui '  [3] Manual temporary block';Write-Ui '  [4] Trust IP';Write-Ui '  [0] Back'
                switch((Read-Value -Prompt 'Select operation' -Default '1')){'1'{Remove-ClientBlock}'2'{if(Confirm-Choice -Prompt 'Remove all assistant-managed blocks?' -Default N){Remove-AllClientBlocks}}'3'{Add-ClientManualBlock}'4'{Add-ClientTrustedIp}}
                Pause-Ui
            }
            '10'{Set-ClientAwarenessSchedule;Pause-Ui}
            '11'{Set-ClientTelegramHook;if(Confirm-Choice -Prompt 'Send test Telegram notification now?' -Default N){[void](Send-ClientTelegramMessage -Text ("AD Client Assistant test from {0}" -f $env:COMPUTERNAME))};if(Confirm-Choice -Prompt 'Enable 15-minute awareness notification task?' -Default Y){Register-ClientAwarenessTask};Pause-Ui}
            '12'{Invoke-ClientAwarenessCheck -Notify;Pause-Ui}
            '0'{return}
            default{Write-Warn 'Unknown option.';Pause-Ui}
        }
    }
}

function Initialize-EndpointSecurityAfterJoin {
    $s=Get-ClientSuricataInfo;$w=Get-ClientWazuhInfo
    if(-not $s.Installed -and -not $w.Installed){Write-Info 'Suricata/Wazuh are not installed; endpoint security integration can be configured later from option 13.';return}
    Write-Info 'Security sensors detected. Checking Suricata/Wazuh integration.'
    if($s.Installed){[void](Test-ClientSuricataConfiguration)}
    if($s.EvePath -and $w.Config){[void](Enable-ClientWazuhSuricataIngestion -NonInteractive)}
}


# ---------------------------------------------------------------------------
# Interactive control plane
# ---------------------------------------------------------------------------

function Show-MainMenu {
    while ($true) {
        Sync-LifecycleState
        Write-Header
        Write-Ui 'AD CLIENT OPERATIONS' Cyan
        Write-Ui ''
        Write-Ui ("  [1] {0}" -f (Get-UiText 'Readiness audit'))
        Write-Ui ("  [2] {0}" -f (Get-UiText 'Guided domain join'))
        Write-Ui ("  [3] {0}" -f (Get-UiText 'Domain client status'))
        Write-Ui ("  [4] {0}" -f (Get-UiText 'Leave domain cleanly'))
        Write-Ui ("  [5] {0}" -f (Get-UiText 'Switch to another domain')) Yellow
        Write-Ui ("  [6] {0}" -f (Get-UiText 'AD connectivity test'))
        Write-Ui ("  [7] {0}" -f (Get-UiText 'Troubleshoot / repair'))
        Write-Ui ("  [8] {0}" -f (Get-UiText 'Export diagnostic bundle'))
        Write-Ui ("  [9] {0}" -f (Get-UiText 'Restore pre-join state'))
        Write-Ui ("  [10] {0}" -f (Get-UiText 'List recovery snapshots'))
        Write-Ui ("  [11] {0}" -f (Get-UiText 'Recover interrupted lifecycle')) Yellow
        Write-Ui ("  [12] Remote management setup / readiness")
        Write-Ui ("  [13] {0}" -f (Get-UiText 'Suricata + Wazuh security / guarded IPS'))
        Write-Ui ("  [L] {0} [{1}]" -f (Get-UiText 'Language / Idioma'),$script:UiLanguage.ToUpperInvariant())
        Write-Ui ("  [0] {0}" -f (Get-UiText 'Exit'))
        Write-Ui ''

        $default = if ((Get-CurrentState) -and (Get-LifecycleLabel) -in @(
            'SNAPSHOT_CREATED','DNS_APPLIED','JOIN_SUBMITTED','JOIN_AMBIGUOUS','RESTORE_READY')) { '11' } else { '1' }
        $choice = Read-Value -Prompt 'Select operation' -Default $default

        try {
            switch ($choice.ToUpperInvariant()) {
                '1' { Invoke-ReadinessAudit; Pause-Ui }
                '2' { Invoke-GuidedJoin; Pause-Ui }
                '3' { Invoke-Status; Pause-Ui }
                '4' { Invoke-LeaveDomain; Pause-Ui }
                '5' { Invoke-DomainSwitch; Pause-Ui }
                '6' { Invoke-ConnectivityTest; Pause-Ui }
                '7' { Invoke-Troubleshoot; Pause-Ui }
                '8' { Export-DiagnosticBundle; Pause-Ui }
                '9' { Invoke-RestorePreJoin; Pause-Ui }
                '10' { Show-Snapshots; Pause-Ui }
                '11' { Invoke-Recovery; Pause-Ui }
                '12' { [void](Enable-RemoteManagementReadiness); Pause-Ui }
                '13' { Show-ClientSecurityMenu }
                'L' { Switch-UiLanguage }
                '0' { return }
                default { Write-Warn 'Unknown option.'; Pause-Ui }
            }
        }
        catch {
            Write-ErrorUi ("Recoverable menu error: {0}" -f $_.Exception.Message)
            Pause-Ui
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

try {
    Initialize-Runtime
    Write-Log ("Starting {0} v{1}; mode={2}." -f $script:ProductName,$script:Version,$Mode)

    switch ($Mode) {
        'Interactive' { Show-MainMenu }
        'Audit'       { Invoke-ReadinessAudit }
        'Join'        { Invoke-GuidedJoin }
        'Status'      { Invoke-Status }
        'Leave'       { Invoke-LeaveDomain }
        'Switch'      { Invoke-DomainSwitch }
        'Connectivity' { Invoke-ConnectivityTest }
        'Troubleshoot' { Invoke-Troubleshoot }
        'Diagnostics' { Export-DiagnosticBundle }
        'RemoteSetup' { [void](Enable-RemoteManagementReadiness -NonInteractive) }
        'Security' { Show-ClientSecurityMenu }
        'SecurityCleanup' { [void](Remove-ExpiredClientGuardedIpsRules); Invoke-ClientGuardedIpsResponse -NonInteractive }
        'SecurityAwareness' { Invoke-ClientAwarenessCheck -Notify }
        'Restore'     { Invoke-RestorePreJoin }
        'Snapshots'   { Show-Snapshots }
        'Recover'     { Invoke-Recovery }
    }
}
catch {
    $script:RunOutcome = 'ERROR'
    try { Write-ErrorUi ("Unhandled operation error: {0}" -f $_.Exception.Message) } catch {}
    exit 1
}
finally {
    Write-RunReport
    if ($script:LockStream) {
        try { $script:LockStream.Dispose() } catch {}
    }
}
