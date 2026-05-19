# =============================================================================
# Script: inactive-account-detection.ps1
# Description: Identifies and reports on inactive Active Directory accounts
#              that have not logged in for a defined period (default 90 days).
#              Inactive accounts represent a significant security risk as they
#              can be exploited by attackers without detection.
# Author: Guilherme Alhinho
# Use Case: Access Review / Recertification - periodic security hygiene
# Prerequisites: ActiveDirectory PowerShell module, read access to AD
# Security Context: CIS Control 5.3 - Disable Dormant Accounts
#                   ISO 27001 A.9.2.5 - Review of user access rights
# =============================================================================
#
# --- ARCHITECTURE NOTE ---
# In this environment SailPoint IdentityNow acts as the Identity Governance
# source of truth. User provisioning, deprovisioning, and access changes
# are typically initiated and governed by SailPoint workflows.
# These scripts represent the downstream execution layer —
# they would be triggered by SailPoint provisioning policies or
# used for manual remediation and audit tasks outside of SailPoint workflows.
# Direct AD/Okta changes should be reconciled back to SailPoint
# to maintain governance integrity and prevent access drift.


# --- CONFIGURATION ---
# Define inactivity threshold - 90 days is industry standard
# Adjust based on organisational policy
$InactiveDays    = 90
$InactiveDate    = (Get-Date).AddDays(-$InactiveDays)
$ReportPath      = "C:\Logs\Inactive_Accounts_$(Get-Date -Format 'yyyy-MM-dd').csv"
$ExecutedBy      = $env:USERNAME

Write-Host "INFO: Searching for accounts inactive since $InactiveDate" `
    -ForegroundColor Cyan

# --- STEP 1: FIND INACTIVE ENABLED ACCOUNTS ---
# Only looks at enabled accounts - disabled accounts are already
# handled by the deprovisioning process
# LastLogonDate is replicated across domain controllers
try {
    $InactiveAccounts = Get-ADUser -Filter {
        LastLogonDate -lt $InactiveDate -and
        Enabled -eq $true
    } -Properties LastLogonDate, Department, Manager, `
        PasswordLastSet, Created, MemberOf |
    Where-Object {
        # Exclude service accounts - these may legitimately not log in
        # Service accounts should be in a dedicated OU
        $_.DistinguishedName -notlike "*Service Accounts*" -and
        $_.SamAccountName -notlike "svc_*"
    } |
    Sort-Object LastLogonDate

    Write-Host "INFO: Found $($InactiveAccounts.Count) inactive accounts" `
        -ForegroundColor Yellow

} catch {
    Write-Host "ERROR: Failed to query AD - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 2: CATEGORISE BY RISK LEVEL ---
# Accounts inactive longer are higher risk
# Categorisation helps prioritise remediation
$Results = foreach ($Account in $InactiveAccounts) {

    # Calculate days since last login
    $DaysSinceLogin = if ($Account.LastLogonDate) {
        ((Get-Date) - $Account.LastLogonDate).Days
    } else {
        # Never logged in - highest risk
        999
    }

    # Assign risk level based on inactivity duration
    $RiskLevel = switch ($true) {
        ($DaysSinceLogin -ge 365) { "CRITICAL - Never used or 1+ year" }
        ($DaysSinceLogin -ge 180) { "HIGH - 6+ months inactive" }
        ($DaysSinceLogin -ge 90)  { "MEDIUM - 90+ days inactive" }
        default                    { "LOW" }
    }

    # Build report object
    [PSCustomObject]@{
        Username         = $Account.SamAccountName
        DisplayName      = $Account.Name
        Department       = $Account.Department
        LastLogonDate    = $Account.LastLogonDate
        DaysSinceLogin   = $DaysSinceLogin
        RiskLevel        = $RiskLevel
        PasswordLastSet  = $Account.PasswordLastSet
        AccountCreated   = $Account.Created
        GroupCount       = $Account.MemberOf.Count
        Manager          = $Account.Manager
        Enabled          = $Account.Enabled
    }
}

# --- STEP 3: DISPLAY SUMMARY ---
Write-Host "`n=== INACTIVE ACCOUNT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total inactive accounts: $($Results.Count)" -ForegroundColor White

$Critical = $Results | Where-Object { $_.RiskLevel -like "CRITICAL*" }
$High     = $Results | Where-Object { $_.RiskLevel -like "HIGH*" }
$Medium   = $Results | Where-Object { $_.RiskLevel -like "MEDIUM*" }

Write-Host "CRITICAL: $($Critical.Count)" -ForegroundColor Red
Write-Host "HIGH:     $($High.Count)"     -ForegroundColor Magenta
Write-Host "MEDIUM:   $($Medium.Count)"   -ForegroundColor Yellow

# --- STEP 4: EXPORT REPORT ---
# CSV report for review by IAM team or manager
# Used as evidence for access review/recertification campaigns
$Results | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "`nSUCCESS: Report exported to $ReportPath" -ForegroundColor Green

# --- STEP 5: FLAG CRITICAL ACCOUNTS ---
# Display critical accounts immediately for urgent action
if ($Critical.Count -gt 0) {
    Write-Host "`n=== CRITICAL ACCOUNTS - IMMEDIATE ACTION REQUIRED ===" `
        -ForegroundColor Red
    $Critical | Select-Object Username, DisplayName, Department, `
        DaysSinceLogin, RiskLevel | Format-Table -AutoSize
}

# --- STEP 6: AUDIT LOG ---
$AuditEntry = [PSCustomObject]@{
    Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Action           = "INACTIVE_ACCOUNT_REVIEW"
    ExecutedBy       = $ExecutedBy
    InactiveDays     = $InactiveDays
    TotalFound       = $Results.Count
    CriticalCount    = $Critical.Count
    HighCount        = $High.Count
    MediumCount      = $Medium.Count
    ReportPath       = $ReportPath
}

$AuditEntry | Export-Csv -Path "C:\Logs\IAM_Audit.csv" `
    -Append -NoTypeInformation

Write-Host "AUDIT: Review logged to IAM_Audit.csv" -ForegroundColor Cyan

# --- RECOMMENDED NEXT STEPS ---
Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Magenta
Write-Host "  [ ] Review CRITICAL accounts with managers immediately" `
    -ForegroundColor Magenta
Write-Host "  [ ] Initiate recertification campaign for HIGH accounts" `
    -ForegroundColor Magenta
Write-Host "  [ ] Schedule deprovisioning for unresponded accounts" `
    -ForegroundColor Magenta
Write-Host "  [ ] Update service account exclusion list if needed" `
    -ForegroundColor Magenta
Write-Host "  [ ] Document findings for compliance audit evidence" `
    -ForegroundColor Magenta