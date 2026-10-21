#requires -Version 5.1
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$root = Split-Path -Parent $PSScriptRoot
$files = @(Get-ChildItem -LiteralPath $root -Filter '*.ps1') +
         @(Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1') +
         @(Get-ChildItem -LiteralPath (Join-Path $root 'tests') -Filter '*.ps1')
$failed = $false
foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    foreach ($issue in $errors) {
        Write-Output ("FAIL {0}:{1}: {2}" -f $file.Name, $issue.Extent.StartLineNumber, $issue.Message)
        $failed = $true
    }
    if (-not $errors) { Write-Output ("PASS parse: {0}" -f $file.Name) }
}
if ($failed) { exit 1 }
& (Join-Path $root 'tests/test_powershell.ps1')

& (Join-Path $root 'tests/test_migrations.ps1')

& (Join-Path $root 'tests/test_workstations.ps1')

& (Join-Path $root 'tests/test_workstation_console.ps1')
