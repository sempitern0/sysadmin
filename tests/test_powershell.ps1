#requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
$root = Split-Path -Parent $PSScriptRoot

function Import-PureFunction {
    param([string]$File, [string[]]$Names)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root $File), [ref]$tokens, [ref]$errors)
    if ($errors) { throw "Cannot test an invalid script: $File" }
    foreach ($name in $Names) {
        $nodes = @($ast.FindAll({param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true))
        if ($nodes.Count -ne 1) { throw "Expected one function: ${File}:$name" }
        # Import only explicitly allowlisted functions; never dot-source an assistant.
        . ([scriptblock]::Create($nodes[0].Extent.Text))
        Set-Item -Path ("Function:script:{0}" -f $name) -Value (Get-Item "Function:$name").ScriptBlock
    }
}
function Assert-Equal {
    param($Expected, $Actual, [string]$Label)
    if ($Expected -ne $Actual) { throw "$Label expected=$Expected actual=$Actual" }
}

Import-PureFunction 'windows-ad-client-assistant.ps1' @('Test-DnsDomainName','Test-ComputerNameValue','Test-IPv4AddressList','Test-ClientPublicIpCandidate')
Import-PureFunction 'windows-ad-assistant.ps1' @('Test-PublicIpForGuardedIps')
foreach ($name in @('ad.example.test', 'a.b')) { Assert-Equal $true (Test-DnsDomainName $name) $name }
foreach ($name in @('ad..test', '-ad.test', 'ad.test.', 'a_1.test')) { Assert-Equal $false (Test-DnsDomainName $name) $name }
Assert-Equal $true (Test-ComputerNameValue 'CLIENT-01') 'computer name'
Assert-Equal $false (Test-ComputerNameValue 'TOO-LONG-COMPUTER-NAME') 'long computer name'
foreach ($ip in @('192.168.1.1','172.16.0.1','255.255.255.255')) {
    Assert-Equal $true (Test-IPv4AddressList @($ip)) $ip
}
foreach ($ip in @('127.1','1','0x7f000001','1.2.3.256','::1','1.2.3.4.')) {
    Assert-Equal $false (Test-IPv4AddressList @($ip)) $ip
}
# No system/network calls: these stubs isolate only address classification.
function Test-DefenseIpTrusted { param($Address) return $false }
function Test-ClientDefenseTrustedIp { param($Address) return $false }
function Get-NetIPAddress { param($AddressFamily, $ErrorAction) return @() }
foreach ($command in @('Test-PublicIpForGuardedIps','Test-ClientPublicIpCandidate')) {
    foreach ($ip in @('0.1.2.3','225.1.2.3','239.1.2.3','255.255.255.255','10.0.0.1','127.0.0.1','172.16.1.1','192.168.1.1','8.8.999.999')) {
        Assert-Equal $false (& $command $ip) "$command $ip"
    }
    Assert-Equal $true (& $command '8.8.8.8') "$command public address"
}
$executable = Join-Path $PSHOME $(if ($env:OS -eq 'Windows_NT') { if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' } } else { 'pwsh' })
foreach ($file in @('windows-ad-assistant.ps1','windows-ad-client-assistant.ps1')) {
    $output = & $executable -NoProfile -NonInteractive -File (Join-Path $root $file) -Mode Preflight 2>&1
    $status = $LASTEXITCODE
    if ($status -notin @(0,1)) { throw "Preflight crashed: $file $output" }
    if ($env:OS -eq 'Windows_NT') {
        if (($output -join "`n") -notmatch 'No changes made') { throw "Preflight incomplete: $file $output" }
    } elseif (($output -join "`n") -notmatch 'Windows is required') {
        throw "Missing platform guard: $file $output"
    }
}
Write-Output 'PASS: PowerShell address regression tests and safe preflight entry points'
