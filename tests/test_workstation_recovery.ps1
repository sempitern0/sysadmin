#requires -Version 5.1
$ErrorActionPreference='Stop'; Set-StrictMode -Version 2.0
$root=Split-Path -Parent $PSScriptRoot
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'windows-workstation-assistant.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) {throw ($errors | Out-String)}
foreach ($name in @('Assert-RecoveryJournal','Invoke-JournalRecovery','Get-RecoveryHistory','Select-RecoverySnapshot')) {
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
        [pscustomobject]@{Schema=1;MachineId=$case.Machine;UserSid=$case.User;Created=('2026-01-'+$case.Folder.Substring(6,2)+'T00:00:00Z');Profile='Academy';Entries=@(
            [pscustomobject]@{Index=0;Type='Registry';Status=$case.Status;Path='HKLM:\Test';Name='Value';Before=[pscustomobject]@{Exists=$false};After=[pscustomobject]@{Exists=$true;Kind='DWord';Value=1}},
            [pscustomobject]@{Index=1;Type='User';Name='student';Status='Applied'})} | Export-Clixml (Join-Path $dir 'state.clixml')
    }
    $bad=Join-Path $temp 'bad'; [void](New-Item -ItemType Directory $bad)
    'corrupt' | Set-Content (Join-Path $bad 'state.clixml')
    Rename-Item -LiteralPath (Join-Path $temp '20260105') -NewName '000-renamed-latest'
    $history=@(Get-RecoveryHistory $temp 'machine' 'user' 3>$null)
    Assert-Recovery ($history.Count -eq 4) 'Foreign machine and corrupt journal excluded'
    Assert-Recovery ($history[0].Created -eq '2026-01-05T00:00:00Z') 'Actual timestamp wins over renamed directory order'
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
# These doubles exercise the real orchestration without touching Windows settings.
function New-RecoveryFixture {
    [pscustomobject]@{
        Schema=1; MachineId='machine'; UserSid='user'; Created='2026-01-01T00:00:00Z'
        Entries=@(0..2 | ForEach-Object {
            [pscustomobject]@{Index=$_;Type='User';Name="user$_";Status='Applied'}
        })
    }
}
function Restore-RecordedEntry {
    param($Entry)
    $script:visited.Add($Entry.Index)
    if ($script:entryFailure -eq $Entry.Index) { throw 'Simulated write failure' }
    if ($script:entryConflict -eq $Entry.Index) { return 'Conflict' }
    return $script:entryResult
}
function Save-Journal {
    $script:saves++
    if ($script:saveFailure) { throw 'Simulated storage failure' }
}
function Reset-RecoveryDoubles {
    $script:visited=New-Object 'System.Collections.Generic.List[int]'
    $script:saves=0
    $script:saveFailure=$false
    $script:entryFailure=-1
    $script:entryConflict=-1
    $script:entryResult='Restored'
}
Reset-RecoveryDoubles
$record=New-RecoveryFixture
$result=Invoke-JournalRecovery $record -WhatIf
Assert-Recovery ($visited.Count -eq 0 -and $saves -eq 0) 'WhatIf neither writes nor saves'
Assert-Recovery ($record.Entries[0].Status -eq 'Applied') 'WhatIf leaves journal unchanged'
$result=Invoke-JournalRecovery $record -Confirm:$false
Assert-Recovery (($visited -join ',') -eq '2,1,0') 'Entries restored in reverse order'
Assert-Recovery ($result.Restored -eq 3 -and $saves -eq 3) 'Each success persisted'
Reset-RecoveryDoubles
$result=Invoke-JournalRecovery $record -Confirm:$false
Assert-Recovery ($visited.Count -eq 0 -and $saves -eq 0 -and $result.Skipped -eq 3) 'Already restored entries never replayed'
Reset-RecoveryDoubles
$record=New-RecoveryFixture
$script:entryConflict=1
$result=Invoke-JournalRecovery $record -Confirm:$false 3>$null
Assert-Recovery ($result.Conflicts -eq 1 -and $result.Restored -eq 2) 'Conflict counted while independent entries recover'
Assert-Recovery ($record.Entries[1].Status -eq 'Applied' -and $saves -eq 2) 'Conflict remains retryable without misleading persistence'
Reset-RecoveryDoubles
$record=New-RecoveryFixture
$script:entryFailure=1
$result=Invoke-JournalRecovery $record -Confirm:$false 3>$null
Assert-Recovery ($result.Conflicts -eq 1 -and $saves -eq 2) 'Failed write is reported and not marked recovered'
Reset-RecoveryDoubles
$record=New-RecoveryFixture
$script:saveFailure=$true
$failed=$false
try { Invoke-JournalRecovery $record -Confirm:$false } catch { $failed=$true }
Assert-Recovery ($failed -and $visited.Count -eq 1) 'Storage failure stops all subsequent changes'
Assert-Recovery ($record.Entries[2].Status -eq 'Applied') 'Failed save leaves in-memory status retryable'
Reset-RecoveryDoubles
$record=New-RecoveryFixture
$script:entryResult='ManualReview'
$result=Invoke-JournalRecovery $record -Confirm:$false
Assert-Recovery ($result.Manual -eq 3 -and $result.Restored -eq 0) 'Manual account review not reported as restored'
foreach ($invalid in @('Schema','Date','Duplicate','Type','Status','Power','Registry')) {
    Reset-RecoveryDoubles
    $record=New-RecoveryFixture
    switch ($invalid) {
        'Schema' { $record.Schema=2 }
        'Date' { $record.Created='bad date' }
        'Duplicate' { $record.Entries[0].Index=1 }
        'Type' { $record.Entries[0].Type='Unknown' }
        'Status' { $record.Entries[0].Status='Unknown' }
        'Power' { $record.Entries[0]=[pscustomobject]@{Index=0;Type='Power';Status='Applied';Before='invalid';After='invalid'} }
        'Registry' { $record.Entries[0]=[pscustomobject]@{Index=0;Type='Registry';Status='Applied';Path='HKLM:\Test';Name='X';Before=$null;After=$null} }
    }
    $failed=$false
    try { Invoke-JournalRecovery $record -Confirm:$false | Out-Null } catch { $failed=$true }
    Assert-Recovery ($failed -and $visited.Count -eq 0 -and $saves -eq 0) "Invalid $invalid rejected before any writes"
}
Write-Output "PASS: $checks recovery discovery and selection checks"
