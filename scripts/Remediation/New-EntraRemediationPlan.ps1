<#
.SYNOPSIS
    Generates a prioritized remediation plan (Markdown) from the risk score report.

.DESCRIPTION
    Reads ./output/RiskScoreReport.json produced by Get-EntraRiskScore.ps1 and
    emits ./output/RemediationPlan.md - a human-readable runbook with one
    section per identity containing:
      - Current risk tier and score
      - Every finding
      - Concrete remediation steps (Entra Portal + Microsoft Graph cmdlet)

    No Graph calls are made. This is a documentation generator.

.PARAMETER ScoreReportPath
    Path to RiskScoreReport.json. Defaults to ./output/RiskScoreReport.json

.PARAMETER OutputPath
    Path to write the Markdown plan. Defaults to ./output/RemediationPlan.md

.EXAMPLE
    .\New-EntraRemediationPlan.ps1

.NOTES
    Requires no Graph connectivity.
#>

[CmdletBinding()]
param(
    [string]$ScoreReportPath = "./output/RiskScoreReport.json",
    [string]$OutputPath      = "./output/RemediationPlan.md"
)

# --- Validate input ---
if (-not (Test-Path $ScoreReportPath)) {
    Write-Error "Score report not found at $ScoreReportPath. Run Get-EntraRiskScore.ps1 first."
    return
}

Write-Host "[*] Loading risk score report..." -ForegroundColor Cyan
$scored = Get-Content $ScoreReportPath -Raw | ConvertFrom-Json
if ($scored -isnot [array]) { $scored = @($scored) }

# --- Sort by severity ---
$tierOrder = @{ "Critical" = 0; "High" = 1; "Medium" = 2; "Low" = 3 }
$scored = $scored | Sort-Object @{ Expression = { $tierOrder[$_.Tier] } }, @{ Expression = { -$_.Score } }

# --- Helper: produce a concrete recommendation for a finding ---
function Get-Recommendation {
    param($Finding)

    $source = $Finding.Source
    $role   = $Finding.Role
    $reason = $Finding.Reason

    $portalPath  = ""
    $graphCmd    = ""
    $why         = ""
    $recommended = ""

    if ($source -eq "PermanentRole") {
        $portalPath = "Entra admin center > Identity > Roles & admins > All roles > '$role' > Assignments > find the principal > Remove"
        $graphCmd   = @'
# Replace <assignmentId> with the actual unifiedRoleAssignment ID
Remove-MgRoleManagementDirectoryRoleAssignment -UnifiedRoleAssignmentId <assignmentId>
'@
        $why = "Permanent privileged assignment bypasses PIM controls (no approval, no justification, no time-bound activation)."

        $recommended = @"
**Convert to PIM eligible** instead of removing entirely:

1. Entra admin center > Identity > Roles & admins > PIM > Microsoft Entra roles > Assignments
2. Click **Add assignments** > choose role **$role** > pick the principal
3. Set **Assignment type** = Eligible
4. Set **Duration** = e.g. 90 days or Permanent (with review), and require MFA + justification

Then remove the permanent assignment:
   - Entra admin center > Identity > Roles & admins > All roles > **$role** > Assignments > select the principal > **Remove**
"@
    }
    elseif ($source -eq "PIM" -and $reason -match "Active") {
        $portalPath = "Entra admin center > Identity > Roles & admins > PIM > Microsoft Entra roles > Active assignments > '$role'"
        $graphCmd   = @'
# Inspect active PIM assignments
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All
'@
        $why = "Active PIM assignment is currently in effect. If it has no expiration, it behaves like a permanent admin."

        $recommended = @"
1. Verify the activation is still needed.
2. If not: **Deactivate** it via PIM > Active assignments > select > Deactivate.
3. If ongoing need: ensure the role's PIM policy enforces:
   - Maximum activation duration (e.g. 8 hours)
   - MFA on activation
   - Justification required
   - Approval required for high-privilege roles
"@
    }
    elseif ($source -eq "PIM" -and $reason -match "Eligible") {
        $portalPath = "Entra admin center > Identity > Roles & admins > PIM > Microsoft Entra roles > Assignments > '$role'"
        $graphCmd   = @'
# Inspect eligible PIM assignments
Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All
'@
        $why = "Eligible assignment is a latent attack surface - the principal can activate the role with minimal friction."

        $recommended = @"
1. Confirm the principal still needs eligibility for **$role**.
2. If not: **Remove** the eligibility via PIM > Assignments.
3. If yes: ensure the role's PIM policy enforces MFA + justification + maximum duration.
4. Set an **access review** for the role (Entra ID Governance) so eligibility is re-certified periodically.
"@
    }
    else {
        $portalPath  = "Entra admin center > Identity > Roles & admins"
        $graphCmd    = "Get-MgRoleManagementDirectoryRoleAssignment -All"
        $why         = $reason
        $recommended = "Review the finding in the Entra admin center and apply Least Privilege principles."
    }

    return [PSCustomObject]@{
        Why         = $why
        Recommended = $recommended.Trim()
        PortalPath  = $portalPath
        GraphCmd    = $graphCmd.Trim()
    }
}

# --- Build the Markdown document ---
$sb = New-Object System.Text.StringBuilder

$null = $sb.AppendLine("# Entra ID Privileged Access Remediation Plan")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  ")
$null = $sb.AppendLine("**Source:** ``$ScoreReportPath``  ")
$null = $sb.AppendLine("**Total principals scored:** $($scored.Count)  ")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("---")
$null = $sb.AppendLine("")

# --- Executive summary ---
$crit = @($scored | Where-Object { $_.Tier -eq "Critical" }).Count
$high = @($scored | Where-Object { $_.Tier -eq "High" }).Count
$med  = @($scored | Where-Object { $_.Tier -eq "Medium" }).Count
$low  = @($scored | Where-Object { $_.Tier -eq "Low" }).Count

$null = $sb.AppendLine("## Executive Summary")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("| Tier | Count | Action Window |")
$null = $sb.AppendLine("|------|-------|---------------|")
$null = $sb.AppendLine("| Critical | $crit | Immediate (24h) |")
$null = $sb.AppendLine("| High     | $high | This week |")
$null = $sb.AppendLine("| Medium   | $med  | This month |")
$null = $sb.AppendLine("| Low      | $low  | Backlog / access review |")
$null = $sb.AppendLine("")
$null = $sb.AppendLine("---")
$null = $sb.AppendLine("")

# --- Per-identity sections ---
$index = 0
foreach ($p in $scored) {
    $index++
    $null = $sb.AppendLine("## $index. $($p.PrincipalName) - **$($p.Tier)** (score $($p.Score))")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("- **Principal ID:** ``$($p.PrincipalId)``")
    $null = $sb.AppendLine("- **High-privilege roles held:** $($p.HighPrivRoleCount)")
    $null = $sb.AppendLine("- **Findings:** $($p.Findings.Count)")
    $null = $sb.AppendLine("")

    # Findings table
    $null = $sb.AppendLine("### Findings")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("| Source | Role | Weight | Reason |")
    $null = $sb.AppendLine("|--------|------|--------|--------|")
    foreach ($f in $p.Findings) {
        $null = $sb.AppendLine("| $($f.Source) | $($f.Role) | $($f.Weight) | $($f.Reason) |")
    }
    $null = $sb.AppendLine("")

    # Recommendations per finding
    $null = $sb.AppendLine("### Recommended Remediation")
    $null = $sb.AppendLine("")

    $seen = @{}
    foreach ($f in $p.Findings) {
        $key = "$($f.Source)|$($f.Role)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $rec = Get-Recommendation -Finding $f

        $null = $sb.AppendLine("#### $($f.Source) - $($f.Role)")
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("**Why this matters:** $($rec.Why)")
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("**Steps:**")
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine($rec.Recommended)
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("**Entra Portal path:**")
        $null = $sb.AppendLine("")
        $null = $sb.AppendLine("> $($rec.PortalPath)")
        $null = $sb.AppendLine("")
        if ($rec.GraphCmd) {
            $null = $sb.AppendLine("**Microsoft Graph (optional):**")
            $null = $sb.AppendLine("")
            $null = $sb.AppendLine('```powershell')
            $null = $sb.AppendLine($rec.GraphCmd)
            $null = $sb.AppendLine('```')
            $null = $sb.AppendLine("")
        }
        $null = $sb.AppendLine("---")
        $null = $sb.AppendLine("")
    }
}

$null = $sb.AppendLine("_End of remediation plan._")

# --- Ensure output folder exists ---
$dir = Split-Path $OutputPath -Parent
if ($dir -and -not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

# --- Write file ---
$sb.ToString() | Out-File $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "[OK] Remediation plan saved to: $OutputPath" -ForegroundColor Green
Write-Host "[*]  Identities: $($scored.Count)  |  Critical: $crit  |  High: $high" -ForegroundColor Cyan
Write-Host ""
Write-Host "Top 3 to act on immediately:" -ForegroundColor Magenta
$scored | Select-Object -First 3 | ForEach-Object {
    Write-Host "  - $($_.PrincipalName)  [$($_.Tier)]  score=$($_.Score)  findings=$($_.Findings.Count)"
}