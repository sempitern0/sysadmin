#requires -Version 5.1
$ErrorActionPreference='Stop'; Set-StrictMode -Version 2.0
$root=Split-Path -Parent $PSScriptRoot
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'windows-workstation-assistant.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) {throw ($errors | Out-String)}
foreach ($name in @('Get-RecoveryHistory','Select-RecoverySnapshot')) {
    $node=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    . ([scriptblock]::Create($node.Extent.Text))
}
$checks=0
function Assert-Recovery {param([bool]$Test,[string]$Message) $script:checks++; if (-not $Test) {throw $Message}}
function Write-ConsoleMessage {param($Text,$Tone)}
function Show-ConsoleCard {param($Title,$Lines,$Tone)}
function Read-ConsoleChoice {param($Prompt,$Allowed,$Default) return $script:choice}
$temp=Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
try {
    Assert-Recovery (@(Get-RecoveryHistory $temp 'machine' 'user').Count -eq 0) 'Missing history is empty'
    [void](New-Item -ItemType Directory $temp)
    foreach ($case in @(
        @{Folder='20260101';Machine='machine';User='user';Status='Applied'},
        @{Folder='20260102';Machine='machine';User='user';Status='Pending'},
        @{Folder='20260103';Machine='other';User='user';Status='Applied'},
        @{Folder='20260104';Machine='machine';User='other';Status='Applied'},
        @{Folder='20260105';Machine='machine';User='user';Status='Restored'})) {
        $dir=Join-Path $temp $case.Folder; [void](New-Item -ItemType Directory $dir)
        [pscustomobject]@{Schema=1;MachineId=$case.Machine;UserSid=$case.User;Created=$case.Folder;Profile='Academy';Entries=@(
            [pscustomobject]@{Type='Registry';Status=$case.Status},
            [pscustomobject]@{Type='User';Status='Applied'})} | Export-Clixml (Join-Path $dir 'state.clixml')
    }
    $bad=Join-Path $temp 'bad'; [void](New-Item -ItemType Directory $bad)
    'corrupt' | Set-Content (Join-Path $bad 'state.clixml')
    $history=@(Get-RecoveryHistory $temp 'machine' 'user' 3>$null)
    Assert-Recovery ($history.Count -eq 4) 'Foreign machine and corrupt journal excluded'
    Assert-Recovery ($history[0].Created -eq '20260105') 'Most recent first'
    Assert-Recovery ($history[0].Pending -eq 0 -and $history[0].Manual -eq 1) 'Restored entries excluded; accounts remain manual'
    Assert-Recovery (-not $history[1].Compatible) 'Other operator identified but cannot be selected'
    Assert-Recovery ($history[2].Pending -eq 1) 'Partial application is recoverable'
    $script:choice='1'
    $selected=Select-RecoverySnapshot $history
    Assert-Recovery ($selected -like '*20260102*') 'Most recent eligible run selected; restored and foreign user excluded'
    $script:choice='2'
    Assert-Recovery ((Select-RecoverySnapshot $history) -like '*20260101*') 'Older eligible run accessible'
    $script:choice='0'
    Assert-Recovery ((Select-RecoverySnapshot $history) -eq '') 'Cancel does not select a snapshot'
    Assert-Recovery ((Select-RecoverySnapshot @()) -eq '') 'Empty list returns without prompt'
    Assert-Recovery (@(Get-RecoveryHistory $temp 'unknown' 'user' 3>$null).Count -eq 0) 'No false detection on other machines'
} finally { if (Test-Path $temp) {Remove-Item -LiteralPath $temp -Recurse -Force} }
Write-Output "PASS: $checks recovery discovery and selection checks"
