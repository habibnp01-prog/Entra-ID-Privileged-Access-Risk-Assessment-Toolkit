<#
.SYNOPSIS
    Detects permanent (non-PIM) privileged role assignments in Microsoft Entra ID.

.DESCRIPTION
    Enumerates all users and service principals that hold a directory role via
    a permanent active assignment (i.e., NOT routed through PIM). Flags
    high-privilege roles with elevated severity. Outputs a structured JSON report.

.PARAMETER OutputPath
    Path to write the JSON report. Defaults to ./output/PermanentRoleReport.json

.PARAMETER HighPrivilegeOnly
    If set, only reports assignments to high-privilege roles.

.EXAMPLE
    .\Get-EntraPermanentRoleReport.ps1
    .\Get-EntraPermanentRoleReport.ps1 -HighPrivilegeOnly

.NOTES
    Requires: Microsoft.Graph module
    Scopes:   RoleManagement.Read.Directory, Directory.Read.All
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "./output/PermanentRoleReport.json",
    [switch]$HighPrivilegeOnly
)

# --- Ensure Graph module is available ---
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Error "Microsoft.Graph module not found. Run: Install-Module Microsoft.Graph -Scope CurrentUser -Force"
    return
}

# --- Ensure we're connected to Graph ---
if (-not (Get-MgContext)) {
    Write-Host "[*] Not connected to Microsoft Graph. Connecting..." -ForegroundColor Yellow
    Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All"
}

# --- High-privilege roles (used for severity escalation) ---
$highPrivilegeRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Password Administrator"
)

Write-Host "[*] Fetching all directory role assignments..." -ForegroundColor Cyan

# --- Build role name lookup map ---
$roleMap = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object {
    $roleMap[$_.Id] = $_.DisplayName
}

# --- Get ALL role assignments ---
$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty '*' -ErrorAction SilentlyContinue

# --- Get PIM-created active assignments so we can exclude them ---
$pimActive = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ErrorAction SilentlyContinue

$pimActiveIds = @{}
foreach ($p in $pimActive) {
    if ($p.Id) { $pimActiveIds[$p.Id] = $true }
}

$findings = @()

foreach ($a in $assignments) {
    # Skip if this assignment was created via PIM
    if ($pimActiveIds.ContainsKey($a.Id)) { continue }

    $roleName = if ($roleMap.ContainsKey($a.RoleDefinitionId)) {
        $roleMap[$a.RoleDefinitionId]
    } else {
        $a.RoleDefinitionId
    }

    $isHighPrivilege = $highPrivilegeRoles -contains $roleName
    if ($HighPrivilegeOnly -and -not $isHighPrivilege) { continue }

    # --- Resolve principal display name ---
    $principalName = $null
    $principalType = "Unknown"
    try {
        if ($a.Principal.AdditionalProperties.displayName) {
            $principalName  = $a.Principal.AdditionalProperties.displayName
            $principalType  = $a.Principal.AdditionalProperties.'@odata.type'
        }
    } catch { }

    if (-not $principalName) { $principalName = $a.PrincipalId }

    # --- Determine risk level ---
    if ($isHighPrivilege) {
        $risk   = "High"
        $reason = "Permanent assignment to high-privilege role (bypasses PIM)"
    } else {
        $risk   = "Medium"
        $reason = "Permanent assignment to directory role (should be PIM-managed)"
    }

    $findings += [PSCustomObject]@{
        RoleName         = $roleName
        RoleDefinitionId = $a.RoleDefinitionId
        PrincipalId      = $a.PrincipalId
        PrincipalName    = $principalName
        PrincipalType    = $principalType
        IsHighPrivilege  = $isHighPrivilege
        Risk             = $risk
        Reason           = $reason
        Discovered       = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
}

# --- Ensure output folder exists ---
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Write JSON report ---
$findings | ConvertTo-Json -Depth 5 | Out-File $OutputPath -Encoding UTF8

# --- Summary ---
$highCount = @($findings | Where-Object { $_.Risk -eq "High" }).Count
$medCount  = @($findings | Where-Object { $_.Risk -eq "Medium" }).Count
$userCount = @($findings | Where-Object { $_.PrincipalType -match "user" }).Count
$spCount   = @($findings | Where-Object { $_.PrincipalType -match "servicePrincipal" }).Count

Write-Host ""
Write-Host "[OK] Report saved to: $OutputPath" -ForegroundColor Green
Write-Host "[*]  Total permanent assignments: $($findings.Count)" -ForegroundColor Cyan
Write-Host "     Users:             $userCount" -ForegroundColor Gray
Write-Host "     Service principals: $spCount" -ForegroundColor Gray
Write-Host "[!]  High-risk findings: $highCount" -ForegroundColor Red
Write-Host "[!]  Medium-risk findings: $medCount" -ForegroundColor Yellow