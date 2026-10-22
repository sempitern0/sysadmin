#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version 2.0
$root=Split-Path -Parent $PSScriptRoot
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'windows-workstation-assistant.ps1'),[ref]$tokens,[ref]$errors)
if ($errors) { throw ($errors | Out-String) }
foreach ($name in @('Get-OptionalProperty','Test-EnrollmentRecord','Get-ManagementEvidence','Assert-ManagedApplyPolicy','Get-WindowsLicenseSummary')) {
    $node=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
    . ([scriptblock]::Create($node.Extent.Text))
}
$checks=0
function Assert-Inventory { param([bool]$Condition,[string]$Message) $script:checks++; if (-not $Condition) {throw $Message} }
foreach ($record in @($null,[pscustomobject]@{},[pscustomobject]@{PSPath='empty'},[pscustomobject]@{Other=1})) {
    Assert-Inventory (-not (Test-EnrollmentRecord $record)) 'Empty/unrelated enrollment must not fail or imply MDM'
}
foreach ($value in @(0,1,6)) {
    Assert-Inventory (-not (Test-EnrollmentRecord ([pscustomobject]@{EnrollmentType=$value}))) 'EnrollmentType alone must not mark a local PC managed'
}
foreach ($provider in @('', '  ')) {
    Assert-Inventory (-not (Test-EnrollmentRecord ([pscustomobject]@{EnrollmentType=6;ProviderID=$provider}))) 'Blank MDM provider is not evidence'
}
$mdm=[pscustomobject]@{EnrollmentType=6;ProviderID='MS DM Server'}
Assert-Inventory (Test-EnrollmentRecord $mdm) 'MDM provider is a conservative management indication'
Assert-Inventory (@(Get-ManagementEvidence $false @()).Count -eq 0) 'Unmanaged standalone PC'
Assert-Inventory (@(Get-ManagementEvidence $false @([pscustomobject]@{EnrollmentType=0})).Count -eq 0) 'Placeholder MDM record ignored'
Assert-Inventory (@(Get-ManagementEvidence $true @()).Count -eq 1) 'Domain membership blocks Apply'
Assert-Inventory (@(Get-ManagementEvidence $false @($mdm)).Count -eq 1) 'MDM provider blocks Apply'
Assert-Inventory (@(Get-ManagementEvidence $true @($mdm)).Count -eq 2) 'Both management sources preserved'
$localInventory=[pscustomobject]@{Managed=$false;ManagedEvidence=@()}
Assert-ManagedApplyPolicy $localInventory $false
$managedInventory=[pscustomobject]@{Managed=$true;ManagedEvidence=@('Proveedor MDM registrado')}
$blocked=$false
try { Assert-ManagedApplyPolicy $managedInventory $false } catch { $blocked=($_.Exception.Message -match 'gestion') }
Assert-Inventory $blocked 'Managed Apply must fail without an explicit exception'
Assert-ManagedApplyPolicy $managedInventory $true
Assert-Inventory $true 'Explicit managed exception remains available'
foreach ($record in @($null,[pscustomobject]@{},[pscustomobject]@{Name=$null},[pscustomobject]@{Name=''})) {
    Assert-Inventory ((Get-OptionalProperty $record 'Name') -eq 'No disponible') 'Missing optional values explicit'
}
Assert-Inventory ((Get-OptionalProperty ([pscustomobject]@{Value=0}) 'Value' -1) -eq 0) 'Zero retained'
Assert-Inventory ((Get-OptionalProperty ([pscustomobject]@{Value=$false}) 'Value' $true) -eq $false) 'False retained'
$script:products=@(); $script:fail=$false
function Get-WmiObject {
    param($Class,$Filter,$ErrorAction)
    Assert-Inventory ($Class -eq 'SoftwareLicensingProduct' -and $Filter -match '55c92734-d682-4d71-983e-d6ec3f16059f') 'Only Windows licensing queried'
    if ($script:fail) { throw 'Service unavailable' }
    $script:products
}
Assert-Inventory ((Get-WindowsLicenseSummary) -like 'No disponible:*') 'No licensing records are unknown, not unlicensed'
foreach ($case in @(@('OEM_DM','OEM'),@('RETAIL','Retail'),@('VOLUME_KMSCLIENT','Volumen / KMS'),@('VOLUME_MAK','Volumen / MAK'))) {
    $script:products=@([pscustomobject]@{Name='Windows Pro';Description=$case[0];LicenseStatus=1;PartialProductKey='SECRET'})
    $result=Get-WindowsLicenseSummary
    Assert-Inventory ($result -like "*Activado*" -and $result.Contains($case[1])) 'Activation and channel shown'
    Assert-Inventory ($result -notmatch 'SECRET') 'Product key never shown'
}
foreach ($status in @(0,2,3,4,5,6,99)) {
    $script:products=@([pscustomobject]@{LicenseStatus=$status})
    Assert-Inventory ((Get-WindowsLicenseSummary) -notmatch 'Activado') 'Nonlicensed/unknown states never reported activated'
}
$script:products=@([pscustomobject]@{})
Assert-Inventory ((Get-WindowsLicenseSummary) -match 'Desconocido') 'Incomplete licensing object tolerated'
$script:fail=$true
Assert-Inventory ((Get-WindowsLicenseSummary) -like 'No disponible:*') 'Licensing service failures do not prevent audit'
# Exercise real Windows APIs on the existing Windows PowerShell CI job.
Remove-Item Function:\Get-WmiObject
if ($env:OS -eq 'Windows_NT' -and $PSVersionTable.PSEdition -eq 'Desktop') {
    foreach ($name in @('Get-WorkstationInventory','Get-LocalGroupMembers','Get-DeviceKind','Get-PowerScheme')) {
        $node=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
        . ([scriptblock]::Create($node.Extent.Text))
    }
    $inventory=Get-WorkstationInventory
    Assert-Inventory (-not [string]::IsNullOrWhiteSpace($inventory.OS)) 'Real WMI OS inventory'
    Assert-Inventory ($inventory.Version -match '^\d+\.') 'Real WMI version inventory'
    Assert-Inventory (-not [string]::IsNullOrWhiteSpace($inventory.License)) 'License result or explicit unknown present'
    Assert-Inventory ($null -ne $inventory.Startup) 'Startup collection present even if empty'
} else {
    Write-Output 'SKIP: real Windows inventory smoke test requires Windows PowerShell Desktop (CI matrix).'
}
Write-Output "PASS: $checks workstation inventory and licensing checks"
