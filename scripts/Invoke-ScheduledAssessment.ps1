<#
.SYNOPSIS
    Scheduled/unattended wrapper for the Entra ID Risk Assessment Toolkit.

.DESCRIPTION
    Runs the read-only pipeline end-to-end:
      1. Full assessment (discovery + scoring)
      2. Remediation plan (Markdown)
      3. Audit bundle (CSV + HTML + manifest)
      4. Run log entry

    Designed for Azure Automation Runbooks and Windows Task Scheduler.

    SAFETY:
      - This wrapper NEVER applies remediation. It is read-only.
      - Remediation still requires human action: Invoke-EntraRemediation.ps1 -Apply -Confirm

.PARAMETER OutputFolder
    Where reports are written. Defaults to <repo>/output

.PARAMETER SkipGraphConnect
    Skip the automatic Connect-MgGraph call. Useful when the caller (e.g.
    Azure Automation) has already established the context.

.PARAMETER NonInteractive
    Fail fast on prompts. Recommended for scheduled runs.

.EXAMPLE
    .\Invoke-ScheduledAssessment.ps1
    .\Invoke-ScheduledAssessment.ps1 -NonInteractive

.NOTES
    Requires Microsoft.Graph module and a valid Graph connection
    (or -SkipGraphConnect if context is pre-established).
#>

[CmdletBinding()]
param(
    [string]$OutputFolder = "",
    [switch]$SkipGraphConnect,
    [switch]$NonInteractive
)

# =========================================================
# 0. Establish script root and paths
# =========================================================
$scriptRoot = $PSScriptRoot
if (-not $OutputFolder) {
    $OutputFolder = Join-Path (Split-Path $scriptRoot -Parent) "output"
}

$assessmentScript = Join-Path $scriptRoot "Invoke-EntraRiskAssessment.ps1"
$planScript       = Join-Path $scriptRoot "Remediation\New-EntraRemediationPlan.ps1"
$bundleScript     = Join-Path $scriptRoot "Remediation\Export-EntraAuditBundle.ps1"
$runLogPath       = Join-Path $OutputFolder "ScheduledRun.log"

# =========================================================
# 1. Setup
# =========================================================
if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$startedAt = Get-Date
$runId     = "RUN-" + $startedAt.ToString("yyyyMMdd-HHmmss")
$errors    = @()
$steps     = @()

function Get-LevelColor {
    param([string]$Level)
    switch ($Level) {
        "INFO"  { return "Cyan" }
        "OK"    { return "Green" }
        "WARN"  { return "Yellow" }
        "ERROR" { return "Red" }
        default { return "Gray" }
    }
}

function Write-RunLog {
    param([string]$Level, [string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$runId] [$Level] $Message"
    Add-Content -Path $runLogPath -Value $line -Encoding UTF8
    Write-Host $line -ForegroundColor (Get-LevelColor -Level $Level)
}

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  SCHEDULED ASSESSMENT - $runId" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  Output folder : $OutputFolder"
Write-Host "  Run log       : $runLogPath"
Write-Host ""

Write-RunLog "INFO" "Scheduled assessment started"

# =========================================================
# 2. Validate required scripts exist
# =========================================================
foreach ($s in @($assessmentScript, $planScript, $bundleScript)) {
    if (-not (Test-Path $s)) {
        Write-RunLog "ERROR" "Missing required script: $s"
        return
    }
}

# =========================================================
# 3. Ensure Graph connection (optional)
# =========================================================
if (-not $SkipGraphConnect) {
    Write-RunLog "INFO" "Checking Graph connection"

    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
        Write-RunLog "ERROR" "Microsoft.Graph module not found"
        return
    }

    if (-not (Get-MgContext)) {
        Write-RunLog "INFO" "Connecting to Microsoft Graph (interactive)"
        if ($NonInteractive) {
            Write-RunLog "ERROR" "Not connected and -NonInteractive set; cannot proceed"
            return
        }
        try {
            Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All" -NoWelcome
            Write-RunLog "OK" "Connected to Graph"
        } catch {
            Write-RunLog "ERROR" "Graph connect failed: $($_.Exception.Message)"
            return
        }
    } else {
        Write-RunLog "OK" "Graph context already present"
    }
} else {
    Write-RunLog "INFO" "Skipping Graph connect (-SkipGraphConnect)"
}

# =========================================================
# 4. Step 1: Run assessment
# =========================================================
$stepStart = Get-Date
Write-RunLog "INFO" "STEP 1/3 - Running full assessment"
try {
    & $assessmentScript -OutputFolder $OutputFolder
    $dur = [math]::Round(((Get-Date) - $stepStart).TotalSeconds, 2)
    Write-RunLog "OK" "Assessment completed in ${dur}s"
    $steps += [PSCustomObject]@{ Step = "Assessment"; Status = "OK"; Duration = $dur }
} catch {
    $dur = [math]::Round(((Get-Date) - $stepStart).TotalSeconds, 2)
    Write-RunLog "ERROR" "Assessment failed after ${dur}s: $($_.Exception.Message)"
    $errors += "Assessment: $($_.Exception.Message)"
    $steps  += [PSCustomObject]@{ Step = "Assessment"; Status = "FAILED"; Duration = $dur }
}

# =========================================================
# 5. Step 2: Generate remediation plan (only if assessment produced data)
# =========================================================
$scoreReport = Join-Path $OutputFolder "RiskScoreReport.json"
if (Test-Path $scoreReport) {
    $stepStart = Get-Date
    Write-RunLog "INFO" "STEP 2/3 - Generating remediation plan"
    try {
        & $planScript -ScoreReportPath $scoreReport -OutputPath (Join-Path $OutputFolder "RemediationPlan.md")
        $dur = [math]::Round(((Get-Date) - $stepStart).TotalSeconds, 2)
        Write-RunLog "OK" "Remediation plan generated in ${dur}s"
        $steps += [PSCustomObject]@{ Step = "Plan"; Status = "OK"; Duration = $dur }
    } catch {
        $dur = [math]::Round(((Get-Date) - $stepStart).TotalSeconds, 2)
        Write-RunLog "ERROR" "Plan generation failed: $($_.Exception.Message)"
        $errors += "Plan: $($_.Exception.Message)"
        $steps  += [PSCustomObject]@{ Step = "Plan"; Status = "FAILED"; Duration = $dur }
    }
} else {
    Write-RunLog "WARN" "Skipping plan - no RiskScoreReport.json produced"
    $steps += [PSCustomObject]@{ Step = "Plan"; Status = "SKIPPED"; Duration = 0 }
}

# =========================================================
# 6. Step 3: Export audit bundle
# =========================================================
$stepStart = Get-Date
Write-RunLog "INFO" "STEP 3/3 - Exporting audit bundle"
try {
    & $bundleScript -OutputFolder $OutputFolder -BundleRoot $OutputFolder
    $dur = [math]::Round(((Get-Date) - $stepStart).TotalSeconds, 2)
    Write-RunLog "OK" "Audit bundle exported in ${dur}s"
    $steps += [PSCustomObject]@{ Step = "Bundle"; Status = "OK"; Duration = $dur }
} catch {
    $dur = [math]::Round(((Get-Date) - $stepStart).TotalSeconds, 2)
    Write-RunLog "ERROR" "Bundle export failed: $($_.Exception.Message)"
    $errors += "Bundle: $($_.Exception.Message)"
    $steps  += [PSCustomObject]@{ Step = "Bundle"; Status = "FAILED"; Duration = $dur }
}

# =========================================================
# 7. Summary + top tier counts
# =========================================================
$critCount = 0
$highCount = 0
if (Test-Path $scoreReport) {
    $scored = Get-Content $scoreReport -Raw | ConvertFrom-Json
    if ($scored -isnot [array]) { $scored = @($scored) }
    $critCount = @($scored | Where-Object { $_.Tier -eq "Critical" }).Count
    $highCount = @($scored | Where-Object { $_.Tier -eq "High" }).Count
}

$elapsed = [math]::Round(((Get-Date) - $startedAt).TotalSeconds, 2)
$status  = "SUCCESS"
if ($errors.Count -gt 0) { $status = "FAILED" }

Write-RunLog "INFO" "Summary - Status=$status Critical=$critCount High=$highCount Elapsed=${elapsed}s"
if ($errors.Count -gt 0) {
    foreach ($e in $errors) { Write-RunLog "ERROR" "  $e" }
}

# Append a summary block to the run log (for easy grep)
$summaryLines = @()
$summaryLines += "----- RUN SUMMARY -----"
$summaryLines += "RunId    : $runId"
$summaryLines += "Status   : $status"
$summaryLines += "Elapsed  : ${elapsed}s"
$summaryLines += "Critical : $critCount"
$summaryLines += "High     : $highCount"
$summaryLines += "Steps    :"
foreach ($s in $steps) {
    $summaryLines += "  - $($s.Step): $($s.Status) ($($s.Duration)s)"
}
$summaryLines += "-----------------------"
Add-Content -Path $runLogPath -Value $summaryLines -Encoding UTF8

$finalColor = "Green"
if ($status -ne "SUCCESS") { $finalColor = "Red" }

Write-Host ""
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  RUN COMPLETE - $status" -ForegroundColor $finalColor
Write-Host "======================================================================" -ForegroundColor DarkGray
Write-Host "  RunId    : $runId"
Write-Host "  Elapsed  : ${elapsed}s"
Write-Host "  Critical : $critCount"
Write-Host "  High     : $highCount"
Write-Host "  Run log  : $runLogPath"
Write-Host ""

# =========================================================
# 8. Exit with appropriate code (useful for automation)
# =========================================================
if ($errors.Count -gt 0) {
    exit 1
} else {
    exit 0
}