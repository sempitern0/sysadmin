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
    [switch]$NoColor,
    [switch]$Detailed,
    [string[]]$DisableStartupName=@(),
    [ValidatePattern('^$|^[a-zA-Z][a-zA-Z0-9_-]{0,19}$')][string]$StandardUserName='',
    [string]$SnapshotPath,
    [string]$StateRoot="$env:ProgramData\WorkstationAssistant"
)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'

function Get-OptionalProperty {
    param($Object,[string]$Name,$Default='No disponible')
    if ($null -eq $Object) { return $Default }
    $property=$Object.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value -or [string]$property.Value -eq '') { return $Default }
    return $property.Value
}
function Test-EnrollmentRecord {
    param($Record)
    # Empty registry keys can yield no object. Never enumerate .Properties.Name.
    return ($null -ne $Record -and $null -ne $Record.PSObject.Properties['EnrollmentType'])
}
function Get-WindowsLicenseSummary {
    try {
        $products=@(Get-WmiObject SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -ErrorAction Stop)
        $results=@(foreach ($product in $products) {
            $status=Get-OptionalProperty $product 'LicenseStatus' -1
            $states=@{0='Sin licencia';1='Activado';2='Periodo de gracia inicial';3='Periodo de gracia adicional';4='No genuino (gracia)';5='Notificacion';6='Gracia extendida'}
            $label='Desconocido'; if ($states.ContainsKey([int]$status)) { $label=$states[[int]$status] }
            $description=[string](Get-OptionalProperty $product 'Description' '')
            $channel='Canal no disponible'
            if ($description -match '(?i)OEM') { $channel='OEM' }
            elseif ($description -match '(?i)VOLUME_KMS') { $channel='Volumen / KMS' }
            elseif ($description -match '(?i)VOLUME_MAK') { $channel='Volumen / MAK' }
            elseif ($description -match '(?i)RETAIL') { $channel='Retail' }
            '{0}: {1} | {2}' -f (Get-OptionalProperty $product 'Name' 'Windows'),$label,$channel
        })
        if (-not $results.Count) { return 'No disponible: sin producto Windows con clave instalada detectable' }
        return ($results -join '; ')
    } catch { return 'No disponible: fallo al consultar el servicio de licencias' }
}
function Get-NativePowerShellPath {
    param([string]$WindowsDirectory, [bool]$Is64BitOS, [bool]$Is64BitProcess)
    $folder='System32'
    if ($Is64BitOS -and -not $Is64BitProcess) { $folder='Sysnative' }
    return Join-Path $WindowsDirectory "$folder\WindowsPowerShell\v1.0\powershell.exe"
}
function New-CompatibleLaunchCommand {
    param([string]$ScriptPath, [hashtable]$Parameters)
    # Serialize as data, not shell text. No execution-policy bypass or temp file.
    $payload=[Management.Automation.PSSerializer]::Serialize(@{Path=$ScriptPath;Parameters=$Parameters})
    $data=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
    $command='$data=[Management.Automation.PSSerializer]::Deserialize([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('''+$data+'''))); $p=@{}; foreach($k in $data.Parameters.Keys){$p[$k]=$data.Parameters[$k]}; $global:LASTEXITCODE=0; try { & $data.Path @p; $ok=$?; if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}; if(-not $ok){exit 1} } catch { [Console]::Error.WriteLine($_.Exception.Message); if ($_.InvocationInfo.ScriptName) { [Console]::Error.WriteLine(("Origen: {0}:{1}" -f $_.InvocationInfo.ScriptName,$_.InvocationInfo.ScriptLineNumber)) }; exit 1 }'
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
}
function Get-ConsoleWidth {
    try { return [math]::Max(24,[math]::Min(100,$Host.UI.RawUI.WindowSize.Width-1)) }
    catch { return 88 }
}
function Format-ConsoleText {
    param([string]$Text, [int]$Width=88)
    $Width=[math]::Max(12,$Width)
    # Prevent names imported from the machine from injecting terminal control codes.
    $clean=$Text -replace '[\x00-\x1f\x7f]',' '
    while ($clean.Length -gt $Width) {
        $cut=$clean.LastIndexOf(' ',$Width)
        if ($cut -lt 1) { $cut=$Width }
        $clean.Substring(0,$cut)
        $clean=$clean.Substring($cut).TrimStart()
    }
    if ($clean.Length) { $clean }
}
function Write-ConsoleMessage {
    param([string]$Text, [ValidateSet('Info','Title','OK','Warn')][string]$Tone='Info')
    $useColor=-not $NoColor -and -not (Test-Path Env:NO_COLOR)
    try { if ([Console]::IsOutputRedirected) { $useColor=$false } } catch { $useColor=$false }
    foreach ($line in @(Format-ConsoleText $Text (Get-ConsoleWidth))) {
        if ($useColor -and $Tone -ne 'Info') {
            $color=@{Title='Cyan';OK='Green';Warn='Yellow'}[$Tone]
            Write-Host $line -ForegroundColor $color
        } else { Write-Host $line }
    }
}
function Show-ConsoleSection {
    param([string]$Title)
    Write-Host ''
    Write-ConsoleMessage ('=' * (Get-ConsoleWidth)) 'Title'
    Write-ConsoleMessage ('>> '+$Title) 'Title'
    Write-ConsoleMessage ('=' * (Get-ConsoleWidth)) 'Title'
}
function Show-ConsoleCard {
    param([string]$Title,[string[]]$Lines,[string]$Tone='Title')
    $width=Get-ConsoleWidth
    $inner=$width-4
    $border='+'+('-'*($width-2))+'+'
    Write-Host ''
    Write-ConsoleMessage $border $Tone
    foreach ($line in @(Format-ConsoleText $Title $inner)) {
        Write-ConsoleMessage ('| '+$line.PadRight($inner)+' |') $Tone
    }
    Write-ConsoleMessage ('+'+('-'*($width-2))+'+') $Tone
    foreach ($paragraph in $Lines) {
        foreach ($line in @(Format-ConsoleText $paragraph $inner)) {
            Write-ConsoleMessage ('| '+$line.PadRight($inner)+' |')
        }
    }
    Write-ConsoleMessage $border $Tone
}
function Show-ProfileChoices {
    param([string]$SelectedProfile)
    foreach ($item in @(
        @{Key='Corporate';Title='[1] [#] CORPORATIVO';Lines=@('USO     Puesto de trabajo de empresa.','SESION  Bloqueo tras 15 min en Windows 8.1+.','RED     Retira SMBv1. TLS antiguo: opcional.','REVISAR GPO/MDM, VPN y EDR; no sustituye politicas centrales.')},
        @{Key='Academy';Title='[2] [=] ACADEMIA';Lines=@('USO     Equipos de alumnos y aulas.','SESION  Bloqueo tras 10 min en Windows 8.1+.','RED     Retira SMBv1. TLS antiguo: opcional.','CUENTAS Puedes crear una cuenta estandar; no restringe cuentas existentes.')},
        @{Key='Legacy';Title='[3] [!] LEGADO';Lines=@('USO     Software antiguo que necesita compatibilidad.','SESION  15 min en Windows 8.1+; no ajusta bloqueo en Windows 7.','RED     Conserva SMB/TLS antiguos salvo opcion expresa.','REVISAR Aislamiento de red y prueba del software antes de aplicar.')}
    )) {
        $title=$item.Title; $tone='Title'
        if ($item.Key -eq $SelectedProfile) { $title+='  < ACTUAL / ENTER'; $tone='OK' }
        Show-ConsoleCard $title $item.Lines $tone
    }
    Write-ConsoleMessage '[i] Base comun: UAC, firewall, AutoRun y ajustes compatibles con la version.'
    Write-ConsoleMessage '[i] Los perfiles no instalan software ni congelan el equipo.'
}
function Show-OperationChoices {
    Show-ConsoleCard '[1] [?] AUDITAR  < PREDETERMINADO' @('Lee el estado y genera informes.','No aplica ajustes al sistema. Ideal para la primera pasada.') 'OK'
    Show-ConsoleCard '[2] [>] PREPARAR Y APLICAR' @('Selecciona opciones y revisa el plan antes de confirmar.','Puede cambiar registro, energia, servicios y cuentas seleccionadas.') 'Warn'
}
function Get-ProfileDescription {
    param([string]$SelectedProfile)
    switch ($SelectedProfile) {
        'Corporate' { return 'CORPORATIVO | Puesto de trabajo. Revisar GPO/MDM, VPN y EDR. Bloqueo: 15 min en Windows 8.1+.' }
        'Academy' { return 'ACADEMIA | Alumnos con cuenta estandar, profesores separados. Bloqueo: 10 min en Windows 8.1+.' }
        'Legacy' { return 'LEGADO | Prioridad a compatibilidad. SMB/TLS antiguos se conservan salvo seleccion explicita. Revisar aislamiento de red.' }
    }
}
function Get-SettingCategory {
    param($Item)
    if ($Item.Kind -eq 'Delete') { return 'Aplicaciones de inicio' }
    if ($Item.Path -match 'SCHANNEL|mrxsmb|Lanman') { return 'Protocolos de red' }
    if ($Item.Path -match 'DataCollection|CloudContent|AdvertisingInfo') { return 'Privacidad' }
    if ($Item.Path -match '^HKCU:') { return 'Aspecto del usuario actual' }
    if ($Item.Name -eq 'HiberbootEnabled') { return 'Inicio rapido de Windows' }
    if ($Item.Name -eq 'Start') { return 'Servicios opcionales' }
    return 'Seguridad y sesiones'
}
function Get-PlanSummary {
    param([object[]]$Observed)
    foreach ($group in @($Observed | Group-Object Category)) {
        $pending=@($group.Group | Where-Object {-not $_.Matches}).Count
        [pscustomobject]@{Category=$group.Name;Pending=$pending;Matching=($group.Count-$pending)}
    }
}
function Read-ConsoleChoice {
    param([string]$Prompt,[string[]]$Allowed,[string]$Default='')
    while ($true) {
        $answer=(Read-Host $Prompt).Trim()
        if ($answer -eq '') { return $Default }
        if ($answer -in $Allowed) { return $answer }
        Write-ConsoleMessage ('[AVISO] Respuesta no valida. Opciones: '+($Allowed -join ', ')+'.') 'Warn'
    }
}
function Show-WorkstationHeader {
    param($Inventory,[string]$SelectedProfile)
    Show-ConsoleSection 'SYSADMIN / PREPARACION DE EQUIPOS'
    Write-ConsoleMessage (Get-ProfileDescription $SelectedProfile) 'Title'
    Write-ConsoleMessage ("Equipo: {0} | {1} {2} | {3}" -f $Inventory.Computer,$Inventory.Manufacturer,$Inventory.Model,$Inventory.Device)
    Write-ConsoleMessage ("Sistema: {0} | build {1} | {2}" -f $Inventory.OS,$Inventory.Build,$Inventory.Edition)
    Write-ConsoleMessage ("Licencia Windows: {0}" -f (Get-OptionalProperty $Inventory 'License'))
    Write-ConsoleMessage ("Motor: PowerShell {0} / {1} | Proceso: {2} bits" -f $PSVersionTable.PSVersion,$PSVersionTable.PSEdition,([IntPtr]::Size*8))
    Write-ConsoleMessage ("Usuario de ejecucion: {0}" -f $Inventory.User)
    if ($Inventory.Managed) { Write-ConsoleMessage '[REVISION] Equipo gestionado: las politicas centrales tienen prioridad.' 'Warn' }
    Write-ConsoleMessage 'La auditoria observa valores; no certifica cumplimiento ni efectividad tras reinicio.'
}
function Show-WorkstationPlan {
    param([object[]]$Observed,[bool]$PowerChange)
    Show-ConsoleSection 'PLAN / ANTES DE CONFIRMAR'
    $pending=@($Observed | Where-Object {-not $_.Matches}).Count
    Show-ConsoleCard '[>] RESUMEN DE AJUSTES' @(
        ('[!] {0} valores pendientes de cambio' -f $pending),
        ('[OK] {0} valores ya coinciden' -f (@($Observed).Count-$pending)),
        '[i] Energia y cuentas se detallan aparte. Aun no se ha aplicado este plan.')
    Write-ConsoleMessage '[OK] Coincide  |  [CAMBIO] Pendiente  |  [MANUAL] Revision del tecnico'
    foreach ($group in @(Get-PlanSummary $Observed)) {
        $tag='OK'; $tone='OK'
        if ($group.Pending) { $tag='CAMBIO'; $tone='Warn' }
        Write-ConsoleMessage ("[{0}] {1}: {2} pendientes / {3} valores coincidentes" -f $tag,$group.Category,$group.Pending,$group.Matching) $tone
    }
    if ($PowerChange) { Write-ConsoleMessage '[CAMBIO] Energia: seleccionar Equilibrado; conservar tiempos y ajustes existentes.' 'Warn' }
    else { Write-ConsoleMessage '[OK] Energia: Equilibrado ya seleccionado.' 'OK' }
    if ($StandardUserName) { Write-ConsoleMessage "[CAMBIO] Nueva cuenta estandar: $StandardUserName (password solicitado al crearla)." 'Warn' }
    Write-ConsoleMessage '[ALCANCE] Animaciones: solo el usuario ejecutor. Servicios/SMB: comprobar despues de reiniciar.'
    Write-ConsoleMessage '[MANUAL] Firmware, permisos de carpetas, cuotas de restauracion y prueba de aplicaciones.'
    if ($Detailed) {
        Show-ConsoleSection 'DETALLE TECNICO / SIN MOSTRAR COMANDOS DE ARRANQUE'
        foreach ($item in $Observed) {
            $tag='CAMBIO'; if ($item.Matches) { $tag='OK' }
            Write-ConsoleMessage "[$tag] $($item.Path) / $($item.Name)"
        }
    } else { Write-ConsoleMessage 'Usa -Detailed para ver rutas y nombres de valores. El informe conserva el detalle.' }
}
function Show-RunResult {
    param([string]$RunDirectory,[string]$Result,[int]$Applied=0)
    Show-ConsoleSection "RESULTADO / $Result"
    if ($Result -eq 'AUDITORIA') { Write-ConsoleMessage '[OK] Auditoria terminada. No se han cambiado ajustes del sistema.' 'OK' }
    else {
        Write-ConsoleMessage "[OK] $Applied operaciones registradas y aplicadas." 'OK'
        Write-ConsoleMessage '[PENDIENTE] Reiniciar manualmente y comprobar aplicaciones, red y politica efectiva.' 'Warn'
    }
    Write-ConsoleMessage "Informes: $RunDirectory"
    Write-ConsoleMessage 'diagnostics.txt: estado del equipo | manual-checklist.txt: tareas de entrega'
    if ($Result -ne 'AUDITORIA') { Write-ConsoleMessage 'state.clixml: recuperar con -Mode Restore -SnapshotPath (las cuentas se conservan).' }
}

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
            Test-EnrollmentRecord $data
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
        License=Get-WindowsLicenseSummary
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

# Preserve the native Windows APIs while accepting launch from PowerShell 7/x86.
if ($env:OS -eq 'Windows_NT' -and ($PSVersionTable.PSEdition -ne 'Desktop' -or
    ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess))) {
    $native=Get-NativePowerShellPath $env:WINDIR ([Environment]::Is64BitOperatingSystem) ([Environment]::Is64BitProcess)
    if (-not (Test-Path -LiteralPath $native)) { throw "Windows PowerShell no disponible: $native. Revisa los componentes de Windows." }
    if (-not $PSCommandPath) { throw 'Guarda el script como archivo .ps1 antes de ejecutarlo.' }
    Write-ConsoleMessage ("[MOTOR] PowerShell {0} / {1} / {2} bits -> Windows PowerShell nativo: {3}" -f $PSVersionTable.PSVersion,$PSVersionTable.PSEdition,([IntPtr]::Size*8),$native) 'Title'
    Write-ConsoleMessage 'El motor nativo consultara Windows, hardware y licencia antes de mostrar el asistente.' 
    $parameters=@{}
    foreach ($key in $PSBoundParameters.Keys) {
        $value=$PSBoundParameters[$key]
        if ($value -is [Management.Automation.SwitchParameter]) { $value=[bool]$value }
        $parameters[$key]=$value
    }
    if ($WhatIfPreference) { $parameters['WhatIf']=$true }
    $encoded=New-CompatibleLaunchCommand $PSCommandPath $parameters
    & $native -NoProfile -OutputFormat Text -EncodedCommand $encoded
    exit $LASTEXITCODE
}
if ($Mode -eq 'Preflight') {
    Write-Output "PowerShell: $($PSVersionTable.PSVersion) / $($PSVersionTable.PSEdition)"
    Write-Output 'Uses native Windows PowerShell 5.1 automatically; Windows 7 SP1 or later client OS; Apply requires elevation.'
    Write-Output 'No changes made.'
    if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') { exit 1 }
    exit 0
}
if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run with Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell to avoid redirected registry views.' }
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-ConsoleMessage 'Abre PowerShell o Terminal con Ejecutar como administrador y vuelve a lanzar este script. Para comprobar el entorno sin elevacion, usa -Mode Preflight.' 'Warn'
    exit 1
}
$machineId=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography').MachineGuid
$userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value

if ($Mode -eq 'Restore') {
    if (-not $SnapshotPath) { throw 'Specify -SnapshotPath state.clixml from this machine.' }
    $script:Journal=Import-Clixml -LiteralPath $SnapshotPath
    if ($Journal.Schema -ne 1 -or $Journal.MachineId -ne $machineId -or $Journal.UserSid -ne $userSid) { throw 'Snapshot version, machine or operator mismatch.' }
    Show-ConsoleSection 'RECUPERACION / AJUSTES REGISTRADOS'
    Write-ConsoleMessage "Diario: $SnapshotPath | Entradas: $(@($Journal.Entries).Count)"
    Write-ConsoleMessage '[MANUAL] Las cuentas creadas se conservan. Los cambios posteriores se respetan.' 'Warn'
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Restaurar ajustes registrados; conservar cambios posteriores en conflicto')) { return }
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
    Write-ConsoleMessage '[OK] Recuperacion de ajustes terminada. Reinicia y valida. Las cuentas se conservan.' 'OK'
    $global:LASTEXITCODE=0
    return
}
$inventory=Get-WorkstationInventory
if (-not (Test-WorkstationVersion ([version]$inventory.Version) $inventory.ProductType $inventory.ServicePack)) { throw 'Only Windows 7 SP1 through Windows 11 client editions are supported.' }
if ([version]$inventory.Version -lt [version]'10.0' -and -not $PSBoundParameters.ContainsKey('Profile')) { $Profile='Legacy' }
if ($Mode -eq 'Interactive') {
    Show-WorkstationHeader $inventory $Profile
    Show-ConsoleSection '1 / PERFIL Y OPERACION'
    Show-ProfileChoices $Profile
    $selection=Read-ConsoleChoice "Perfil: 1 Corporativo, 2 Academia, 3 Legado [Enter: $Profile]" @('1','2','3')
    switch ($selection) { '1' {$Profile='Corporate'} '2' {$Profile='Academy'} '3' {$Profile='Legacy'} }
    Write-ConsoleMessage (Get-ProfileDescription $Profile) 'Title'
    Show-ConsoleSection 'OPERACION / QUE QUIERES HACER'
    Show-OperationChoices
    $Mode='Audit'
    if ((Read-ConsoleChoice 'Operacion: 1 Auditar, 2 Preparar cambios [1]' @('1','2') '1') -eq '2') {
        $Mode='Apply'
        Show-ConsoleSection '2 / OPCIONES (ENTER CONSERVA EL VALOR ACTUAL)'
        Write-ConsoleMessage 'Solo responde S tras revisar la compatibilidad. Tambien se acepta Y.'
        foreach ($option in @(
            @{Name='DisableLegacyProtocols';Text='[1/4] [!] PROTOCOLOS ANTIGUOS';Detail='Desactiva SSL 2/3 y TLS 1.0/1.1, habilita TLS 1.2 y retira SMBv1. Puede romper aplicaciones antiguas.'},
            @{Name='DisableOptionalServices';Text='[2/4] [-] SERVICIOS OPCIONALES';Detail='Deshabilita servicios existentes de Xbox y mapas. Puede afectar juegos y mapas sin conexion.'},
            @{Name='UserExperience';Text='[3/4] [~] EFECTOS VISUALES';Detail="Reduce animaciones y, en Windows 10/11, transparencia. Solo para $($inventory.User)."},
            @{Name='CreateRestorePoint';Text='[4/4] [+] PUNTO DE RESTAURACION';Detail='Solicita un punto previo si Proteccion del sistema lo permite. No sustituye una copia de seguridad.'})) {
            $default='n'; if ([bool](Get-Variable -Name $option.Name -ValueOnly)) {$default='s'}
            $state='[ ] NO SELECCIONADO'; $tone='Title'
            if ($default -eq 's') { $state='[x] SELECCIONADO'; $tone='OK' }
            Show-ConsoleCard $option.Text @($option.Detail,($state+' | Enter conserva esta seleccion.')) $tone
            $answer=Read-ConsoleChoice ("Activar esta opcion? [S] Si / [N] No / [Enter: $default]") @('s','n','y') $default
            Set-Variable -Name $option.Name -Value ($answer -in @('s','y'))
        }
        Show-ConsoleSection '3 / ARRANQUE Y CUENTAS'
        Write-ConsoleMessage 'Se conservan todas las entradas salvo seleccion explicita. No selecciones AV, VPN o backup.'
        foreach ($startup in $inventory.Startup) {
            Write-ConsoleMessage ("- {0} | {1} | {2}" -f $startup.Name,$startup.User,$startup.Location)
        }
        if (-not @($inventory.Startup).Count) { Write-ConsoleMessage 'No se han encontrado entradas en este inventario.' }
        $startupSelection=Read-Host 'Nombres Run exactos separados por ; [Enter conserva seleccion previa]'
        if ($startupSelection) { $DisableStartupName=@($startupSelection.Split(';') | ForEach-Object { $_.Trim() }) }
        $userSelection=Read-Host "Cuenta estandar nueva [Enter conserva: $StandardUserName]"
        if ($userSelection) { $StandardUserName=$userSelection.Trim() }
        if ($StandardUserName -and $StandardUserName -notmatch '^[a-zA-Z][a-zA-Z0-9_-]{0,19}$') { throw 'Nombre de usuario no valido.' }
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
$observed=@(foreach ($item in $plan) {
    $current=Get-RegState $item.Path $item.Name
    $desired=[pscustomobject]@{Exists=($item.Kind -ne 'Delete');Kind=$item.Kind;Value=$item.Value}
    [pscustomobject]@{Category=(Get-SettingCategory $item);Path=$item.Path;Name=$item.Name;Current=$current;Desired=$desired;Matches=(Test-SameState $current $desired)}
})
Show-WorkstationHeader $inventory $Profile
Show-WorkstationPlan $observed ($inventory.PowerScheme -ne '381b4222-f694-41f0-9685-ff5bb260df2e')
if ($Mode -eq 'Apply' -and -not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Aplicar el plan mostrado; requiere validacion tras reinicio')) {
    if ($WhatIfPreference) { Write-ConsoleMessage '[SIMULACION] Sin cambios ni informes escritos.' }
    else { Write-ConsoleMessage '[CANCELADO] No se ha aplicado el plan.' }
    return
}
if ($WhatIfPreference) { Write-ConsoleMessage '[SIMULACION] Sin cambios ni informes escritos.'; return }
Write-ConsoleMessage '[1/4] Guardando inventario y diagnostico...'
$run=New-ProtectedRunDirectory $StateRoot
$inventory | Export-Clixml -LiteralPath (Join-Path $run 'inventory.clixml') -Depth 6
$plan | Export-Csv -LiteralPath (Join-Path $run 'plan.csv') -NoTypeInformation -Encoding UTF8
$observed | Export-Clixml -LiteralPath (Join-Path $run 'settings-audit.clixml') -Depth 6
Get-WorkstationDiagnostics | Set-Content -LiteralPath (Join-Path $run 'diagnostics.txt') -Encoding UTF8
Write-ManualChecklist $inventory (Join-Path $run 'manual-checklist.txt')
if ($Mode -eq 'Audit') { Show-RunResult $run 'AUDITORIA'; $global:LASTEXITCODE=0; return }
$script:JournalPath=Join-Path $run 'state.clixml'
$script:Journal=[pscustomobject]@{Schema=1;MachineId=$machineId;UserSid=$userSid;Profile=$Profile;Created=(Get-Date).ToString('o');Entries=@()}
Save-Journal
Write-ConsoleMessage '[2/4] Preparando recuperacion y diario de cambios...'
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
    Write-ConsoleMessage '[3/4] Aplicando ajustes del registro y energia...'
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
    Write-ConsoleMessage '[4/4] Comprobando cuenta opcional y cerrando resultados...'
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
    Show-RunResult $run 'APLICADO' @($Journal.Entries | Where-Object {$_.Status -eq 'Applied'}).Count
    $global:LASTEXITCODE=0
} catch {
    Write-ConsoleMessage '[ERROR] Ejecucion incompleta. No se presenta como finalizada.' 'Warn'
    Write-Warning "Partial application; recorded changes can be restored using -Mode Restore -SnapshotPath '$JournalPath'."
    throw
}
