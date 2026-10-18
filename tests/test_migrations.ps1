#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$root = Split-Path -Parent $PSScriptRoot
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'migration-assistant.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) { throw 'Invalid migration script' }
# Load function declarations only: never launch an interactive/admin entrypoint.
foreach ($node in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$false)) {
    . ([scriptblock]::Create($node.Extent.Text))
}
function Must-Fail { param([scriptblock]$Action,[string]$Pattern)
    $caught = $false
    try { & $Action } catch {
        $caught = $true
        if ($_.Exception.Message -notmatch $Pattern) { throw "Unexpected error: $_ (expected $Pattern)" }
    }
    if (-not $caught) { throw "Expected failure: $Pattern" }
}
function Equal { param($Expected,$Actual)
    if ($Expected -ne $Actual) { throw "Expected $Expected, got $Actual" }
}
foreach ($value in @('nc:Migration/batch1','ubuntu:staging/team docs')) { Assert-FileTarget $value }
foreach ($value in @('nc:','nc:/','nc:a/../b',':webdav:a','https://host/path','nc:a//b','nc:a/./b','nc:a/','nc:a ','nc:a;id','nc:a`nb','C:\data')) {
    Must-Fail { Assert-FileTarget $value } 'Destination|segments'
}
$inv = [pscustomobject]@{Build='20348';ProductType=3;DomainRole=3;Features=@('File-Services')}
Equal 0 @(Get-UpgradeBlockers $inv).Count
$inv.DomainRole=5
Equal 1 @(Get-UpgradeBlockers $inv).Count
$inv.Features=@('Failover-Clustering'); $inv.Build='17763'
Equal 3 @(Get-UpgradeBlockers $inv).Count
$temp = Join-Path ([IO.Path]::GetTempPath()) ('sysadmin-migration-test-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try {
    $script:Schema=1
    $Profile='UbuntuFiles'; $Source=Join-Path $temp 'source'; $Destination='ubuntu:staging/test'
    [void][IO.Directory]::CreateDirectory($Source)
    Set-Content -LiteralPath (Join-Path $Source 'example.txt') -Value 'test'
    $ConfigPath=Join-Path $temp 'config'; Set-Content -LiteralPath $ConfigPath -Value 'fake config - no credentials'
    $Workspace=Join-Path $Source 'bad-workspace'
    Must-Fail { Invoke-MigrationAction Plan } 'outside the source'
    $Workspace=Join-Path $temp 'job'
    $BackupVerified=$false; $PermissionsReviewed=$false; $SourceFrozen=$false; $ConfirmDestination=''
    Invoke-MigrationAction Plan
    Must-Fail { Invoke-MigrationAction Plan } 'nonexistent workspace'
    function Read-State { Get-Content -LiteralPath (Join-Path $Workspace 'plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json }
    Equal 'Planned' (Read-State).Phase
    # Stub external transport, but exercise real persistence, gates and failure recovery.
    function Assert-RemoteType { param($Plan) }
    function Assert-RcloneEnvironment { }
    $script:Calls=@(); $script:FailTransport=$false
    function Invoke-Rclone { param([string[]]$Arguments)
        $script:Calls += ,$Arguments
        if ($script:FailTransport) { throw 'Simulated transport failure' }
    }
    Must-Fail { Invoke-MigrationAction Copy } 'DryRun'
    Equal 0 $script:Calls.Count
    Invoke-MigrationAction DryRun
    Equal 'Previewed' (Read-State).Phase
    if ('--dry-run' -notin $script:Calls[-1]) { throw 'Preview wrote data' }
    Must-Fail { Invoke-MigrationAction Copy } 'requires'
    $BackupVerified=$true; $PermissionsReviewed=$true; $SourceFrozen=$true; $ConfirmDestination='ubuntu:wrong'
    Must-Fail { Invoke-MigrationAction Copy } 'requires'
    $ConfirmDestination=$Destination
    Invoke-MigrationAction Copy
    Equal 'Copied' (Read-State).Phase
    if ('--immutable' -notin $script:Calls[-1] -or '--dry-run' -in $script:Calls[-1]) { throw 'Unsafe copy flags' }
    $SourceFrozen=$false
    Must-Fail { Invoke-MigrationAction Verify } 'SourceFrozen'
    $SourceFrozen=$true
    Invoke-MigrationAction Verify
    Equal 'ContentVerified' (Read-State).Phase
    if ('--download' -notin $script:Calls[-1] -or '--one-way' -in $script:Calls[-1]) { throw 'Weak verification' }
    Invoke-MigrationAction DryRun
    $script:FailTransport=$true
    Must-Fail { Invoke-MigrationAction Copy } 'Simulated'
    Equal 'Failed' (Read-State).Phase
    Must-Fail { Invoke-MigrationAction Verify } 'successful Copy'
    $script:FailTransport=$false
    Invoke-MigrationAction DryRun
    Invoke-MigrationAction Copy
    Invoke-MigrationAction Verify
    Equal 'ContentVerified' (Read-State).Phase
    $lock=[IO.File]::Open((Join-Path $Workspace '.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { Must-Fail { Invoke-MigrationAction DryRun } 'process|used|sharing' } finally { $lock.Dispose() }
    Add-Content -LiteralPath $ConfigPath -Value 'changed destination'
    Must-Fail { Invoke-MigrationAction DryRun } 'configuration changed'
    $state=Read-State; $state.HostName='another-host'; Save-Plan $state $Workspace
    Must-Fail { Invoke-MigrationAction Status } 'original source host'
    # HTML/code-like paths never become expressions; target syntax rejects them.
    Must-Fail { Assert-FileTarget 'nc:$(whoami)' } 'Destination'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Output 'PASS: migration validation, copy gates, content verification, locking and retry states'
