#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$root=Split-Path -Parent $PSScriptRoot
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'windows-workstation-assistant.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) {throw ($errors | Out-String)}
foreach ($name in @('Get-NativePowerShellPath','New-CompatibleLaunchCommand','Format-ConsoleText',
    'Get-ProfileDescription','Get-SettingCategory','Get-PlanSummary','Read-ConsoleChoice',
    'Get-ConsoleWidth','Write-ConsoleMessage','Show-ConsoleSection','Show-WorkstationPlan','Show-RunResult','Show-WorkstationHeader')) {
    $nodes=@($ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true))
    if ($nodes.Count -ne 1) {throw "Missing function $name"}
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$checks=0
function Assert-UI { param([bool]$Condition,[string]$Message) $script:checks++; if (-not $Condition) {throw $Message} }
foreach ($width in @(24,40,80)) {
    $lines=@(Format-ConsoleText ('long/path/'*25+' a sentence with spaces') $width)
    Assert-UI (@($lines | Where-Object {$_.Length -gt $width}).Count -eq 0) 'No truncation or line overflow'
    Assert-UI ($lines.Count -gt 1) 'Long content wraps'
}
Assert-UI ((Format-ConsoleText "name$([char]27)[31m`tvalue" 80) -notmatch '[\x00-\x1f]') 'Control characters sanitized'
foreach ($profile in @('Corporate','Academy','Legacy')) { Assert-UI ([bool](Get-ProfileDescription $profile)) "Profile summary $profile" }
$summary=@(Get-PlanSummary @(
    [pscustomobject]@{Category='Security';Matches=$true},
    [pscustomobject]@{Category='Security';Matches=$false},
    [pscustomobject]@{Category='Privacy';Matches=$true}))
Assert-UI ($summary.Count -eq 2) 'Grouped categories'
Assert-UI (($summary | Where-Object {$_.Category -eq 'Security'}).Pending -eq 1) 'Pending count'
Assert-UI (($summary | Where-Object {$_.Category -eq 'Security'}).Matching -eq 1) 'Already configured count'
Assert-UI (@(Get-PlanSummary @()).Count -eq 0) 'Empty plan supported'
Assert-UI ((Get-SettingCategory ([pscustomobject]@{Kind='DWord';Path='HKLM:\SYSTEM\mrxsmb10';Name='Start'})) -eq 'Protocolos de red') 'SMB driver not mislabeled optional service'
$NoColor=$true; $Detailed=$false; $StandardUserName=''
$inventory=[pscustomobject]@{Computer='TEST-PC';Manufacturer='OEM';Model='Notebook';Device='Laptop';OS='Windows 11 Pro';Build='26100';Edition='Professional';User='TEST\operator';Managed=$true}
foreach ($profile in @('Corporate','Academy','Legacy')) {
    $header=(Show-WorkstationHeader $inventory $profile 6>&1 | Out-String)
    Assert-UI ($header -match 'Windows 11 Pro' -and $header -match 'gestionado') "Header shows OS and managed context: $profile"
}
$observed=@([pscustomobject]@{Category='Aplicaciones de inicio';Matches=$false;Path='HKCU:\fixture';Name='Startup';Current='SECRET-COMMAND';Desired='SECRET-VALUE'})
$text=(Show-WorkstationPlan $observed $true 6>&1 | Out-String)
Assert-UI ($text -match 'CAMBIO' -and $text -match 'Equilibrado') 'Plain-text plan conveys changes'
Assert-UI ($text -notmatch 'SECRET|HKCU:|\x1b') 'Compact output hides values and technical paths, no ANSI'
$Detailed=$true
$text=(Show-WorkstationPlan $observed $false 6>&1 | Out-String)
Assert-UI ($text -match 'HKCU:' -and $text -notmatch 'SECRET') 'Detailed output still hides startup command contents'
$text=(Show-RunResult 'fixture' 'AUDITORIA' 0 6>&1 | Out-String)
Assert-UI ($text -match 'No se han cambiado') 'Audit does not claim changes applied'
$answers=New-Object 'System.Collections.Generic.Queue[string]'
$answers.Enqueue('invalid');$answers.Enqueue('2')
function Read-Host {param($Prompt) return $answers.Dequeue()}
$result=Read-ConsoleChoice 'test' @('1','2') '1'
Assert-UI ($result -eq '2' -and $answers.Count -eq 0) 'Invalid selection re-prompts'
$temp=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
[void](New-Item -ItemType Directory -Path $temp)
try {
    Assert-UI ((Get-NativePowerShellPath $temp $true $false) -match 'Sysnative') '32-bit process routes to native 64-bit'
    Assert-UI ((Get-NativePowerShellPath $temp $true $true) -match 'System32') '64-bit process uses System32'
    Assert-UI ((Get-NativePowerShellPath $temp $false $false) -match 'System32') '32-bit OS remains 32-bit'
    $fixture=Join-Path $temp "fixture ' quoted.ps1"
    @'
[CmdletBinding(SupportsShouldProcess=$true)]
param([string]$Profile,[string[]]$DisableStartupName,[switch]$Detailed)
[pscustomobject]@{Profile=$Profile;Names=$DisableStartupName;Detailed=[bool]$Detailed;WhatIf=[bool]$WhatIfPreference;Confirm=[bool]$PSBoundParameters['Confirm']} | ConvertTo-Json -Compress
'@ | Set-Content -LiteralPath $fixture -Encoding UTF8
    $params=@{Profile='Academy';DisableStartupName=@('literal $value','quote''; & text');Detailed=$true;WhatIf=$true;Confirm=$false}
    $encoded=New-CompatibleLaunchCommand $fixture $params
    $exe=Join-Path $PSHOME $(if ($env:OS -eq 'Windows_NT') {if ($PSVersionTable.PSEdition -eq 'Desktop') {'powershell.exe'} else {'pwsh.exe'}} else {'pwsh'})
    $output=& $exe -NoProfile -EncodedCommand $encoded
    Assert-UI ($LASTEXITCODE -eq 0) 'Compatible child invocation succeeds'
    $data=($output -join '') | ConvertFrom-Json
    Assert-UI ($data.Profile -eq 'Academy' -and $data.Detailed) 'Named arguments preserved'
    Assert-UI ($data.WhatIf -and $data.Confirm -eq $false) 'WhatIf and explicit Confirm false preserved'
    Assert-UI ($data.Names[0] -ceq 'literal $value' -and $data.Names[1] -ceq "quote'; & text") 'Array arguments never interpreted as shell code'
    'exit 7' | Set-Content -LiteralPath $fixture -Encoding UTF8
    $encoded=New-CompatibleLaunchCommand $fixture @{}
    & $exe -NoProfile -EncodedCommand $encoded
    Assert-UI ($LASTEXITCODE -eq 7) 'Explicit child failure code retained'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Output "PASS: $checks workstation console and engine handoff checks"
