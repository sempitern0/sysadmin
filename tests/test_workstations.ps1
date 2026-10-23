#requires -Version 5.1
# Import only explicitly named functions; never execute workstation preparation.
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$root=Split-Path -Parent $PSScriptRoot
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'windows-workstation-assistant.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) { throw ($errors | Out-String) }
foreach ($name in @('Get-DeviceKind','Test-WorkstationVersion','New-RegSetting','Get-WorkstationPlan',
                     'Test-SameState','Restore-RecordedEntry','Invoke-RegistryPlan','Get-PowerScheme')) {
    $nodes=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
    if ($nodes.Count -ne 1) { throw "Expected one function $name" }
    . ([scriptblock]::Create($nodes[0].Extent.Text))
}
$script:checks=0
function Check { param([bool]$Condition,[string]$Label) $script:checks++; if (-not $Condition) { throw $Label } }
Check ((Get-DeviceKind @(9) 1) -eq 'Laptop') 'Notebook chassis'
Check ((Get-DeviceKind @(3) 1) -eq 'Desktop') 'Desktop chassis (UPS presence irrelevant)'
Check ((Get-DeviceKind @(0) 2) -eq 'Laptop') 'Mobile system type'
Check ((Get-DeviceKind @(0) 0) -eq 'Unknown') 'Unknown/VM not guessed'
foreach ($version in @('6.1','6.3','10.0.19045','10.0.26100')) {
    Check (Test-WorkstationVersion ([version]$version) 1 1) "Client $version"
    Check (-not (Test-WorkstationVersion ([version]$version) 3 1)) "Reject server $version"
}
Check (-not (Test-WorkstationVersion ([version]'6.1') 1 0)) 'Win7 requires SP1'
Check (-not (Test-WorkstationVersion ([version]'6.2') 1 0)) 'Win8 RTM cannot run supported WMF5.1'
$legacy=@(Get-WorkstationPlan ([version]'6.1') Legacy Professional $false $false $false)
Check (@($legacy | Where-Object {$_.Name -eq 'SMB1' -or $_.Path -match 'SCHANNEL|mrxsmb'}).Count -eq 0) 'Legacy keeps protocols pending explicit decision'
Check (@($legacy | Where-Object {$_.Name -eq 'HiberbootEnabled'}).Count -eq 0) 'No Fast Startup setting on Windows 7'
foreach ($edition in @('Core','Professional','Enterprise','Education','EnterpriseS','IoTEnterprise')) {
    $plan=@(Get-WorkstationPlan ([version]'10.0.26100') Corporate $edition $false $false $false)
    $expected=1; if ($edition -match '^(Enterprise|Education|IoTEnterprise)') {$expected=0}
    Check (($plan | Where-Object {$_.Name -eq 'AllowTelemetry'}).Value -eq $expected) "Telemetry edition $edition"
    Check (@($plan | Where-Object {$_.Path -match '^HKCU:|SCHANNEL' -or $_.Name -eq 'Start'}).Count -eq 0) 'Optional changes excluded by default'
    Check (@($plan | Where-Object {$_.Name -eq 'EnableFirewall'}).Count -eq 3) 'Three firewall profiles'
    Check (($plan | Where-Object {$_.Name -eq 'HiberbootEnabled'}).Value -eq 0) 'Fast Startup disabled'
}
$plan=@(Get-WorkstationPlan ([version]'10.0') Academy Professional $true $true $true)
Check (($plan | Where-Object {$_.Name -eq 'InactivityTimeoutSecs'}).Value -eq 600) 'Academy locks idle sessions'
Check (@($plan | Where-Object {$_.Path -match 'SCHANNEL'}).Count -eq 20) 'Old TLS/SSL disabled in both roles, TLS1.2 enabled'
Check (@($plan | Where-Object {$_.Path -match '^HKCU:'}).Count -eq 3) 'Explicit current-user visual settings'
Check (@($plan | Where-Object {$_.Name -eq 'Start'}).Count -eq 4) 'Only four optional services'
Check (@($plan | Where-Object {$_.Path -match 'wuauserv|WinDefend|SysMain|BITS|WlanSvc|Spooler'}).Count -eq 0) 'Critical services preserved'
$missing=[pscustomobject]@{Exists=$false;Kind='';Value=$null}
$zero=[pscustomobject]@{Exists=$true;Kind='DWord';Value=0}
$one=[pscustomobject]@{Exists=$true;Kind='DWord';Value=1}
Check (-not (Test-SameState $missing $zero)) 'Absent and zero differ'
Check (Test-SameState $zero $zero) 'Equal registry states'
Check (-not (Test-SameState $zero ([pscustomobject]@{Exists=$true;Kind='String';Value='0'}))) 'Registry type preserved'
$multi=[pscustomobject]@{Exists=$true;Kind='MultiString';Value=@('mrxsmb20','nsi')}
Check (Test-SameState $multi $multi) 'Array snapshot supported'

# Native I/O replaced by memory stubs. No registry, service or account changes.
$script:current=$zero; $script:writes=0; $script:saves=0; $script:failSave=$false
function Get-RegState { param($Path,$Name) return $script:current }
function Set-RegState { param($Path,$Name,$State) $script:writes++; $script:current=$State }
function Save-Journal { $script:saves++; if ($script:failSave) {throw 'Simulated disk failure'} }
$entry=[pscustomobject]@{Type='Registry';Path='fixture';Name='fixture';Before=$missing;After=$zero}
Check ((Restore-RecordedEntry $entry) -eq 'Restored') 'Restore removes only a value introduced by us'
Check (-not $script:current.Exists) 'Original absence restored'
Check ((Restore-RecordedEntry $entry) -eq 'Restored') 'Repeated restore safe'
$script:current=$one; $script:writes=0
Check ((Restore-RecordedEntry $entry) -eq 'Conflict') 'Preserve later administrator changes'
Check ($script:writes -eq 0) 'Conflict never writes'
Check ((Restore-RecordedEntry ([pscustomobject]@{Type='User'})) -eq 'ManualReview') 'Recovery never deletes user data'
$script:current=$missing; $script:Journal=[pscustomobject]@{Entries=@()}
$fixture=@(New-RegSetting 'fixture' 'fixture' 0 'fixture')
Invoke-RegistryPlan $fixture
Check ($script:Journal.Entries.Count -eq 1 -and $script:saves -eq 2) 'Journal before and after write'
Check ($script:Journal.Entries[0].Status -eq 'Applied') 'Applied requires readback'
$script:writes=0; Invoke-RegistryPlan $fixture
Check ($script:writes -eq 0) 'Repeated apply is idempotent'
$script:current=$missing; $script:failSave=$true
$failed=$false; try { Invoke-RegistryPlan $fixture } catch { $failed=$true }
Check ($failed -and $script:writes -eq 0) 'No mutation if durable journal write fails'
function powercfg.exe { param($Operation) $global:LASTEXITCODE=0; 'Esquema de energia GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Equilibrado)' }
Check ((Get-PowerScheme) -eq '381b4222-f694-41f0-9685-ff5bb260df2e') 'Localized powercfg output'
function powercfg.exe { param($Operation) $global:LASTEXITCODE=5; 'failure' }
$failed=$false; try { Get-PowerScheme } catch { $failed=$true }
Check $failed 'Native error propagated'
$exe=Join-Path $PSHOME $(if ($env:OS -eq 'Windows_NT') {if ($PSVersionTable.PSEdition -eq 'Desktop') {'powershell.exe'} else {'pwsh.exe'}} else {'pwsh'})
$output=& $exe -NoProfile -NonInteractive -File (Join-Path $root 'windows-workstation-assistant.ps1') -Mode Preflight 2>&1
Check (($output -join ' ') -match 'No changes made') 'Non-mutating preflight'
Check ($LASTEXITCODE -in @(0,1)) 'Preflight exit code'
Write-Output "PASS: $script:checks workstation planning, idempotency, recovery and preflight checks"
