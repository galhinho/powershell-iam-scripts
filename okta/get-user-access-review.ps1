# =============================================================================
# Script: get-user-access-review.ps1
# Description: Queries SailPoint IdentityNow API to retrieve a comprehensive
#              view of a user's current access entitlements for review.
#              Used during access reviews, recertification campaigns, and
#              security investigations to understand what access an identity
#              currently holds across all governed applications.
# Author: Guilherme Alhinho
# Use Case: Access Review / Recertification - Mover process (M in JML)
#           Security investigations - understanding blast radius of
#           a potentially compromised identity
# Prerequisites: SailPoint IdentityNow API credentials (Client ID + Secret)
#                OAuth 2.0 client credentials grant type
# Security Context: ISO 27001 A.9.2.5 - Review of user access rights
#                   Regular access reviews are a core IGA control
#
# --- ARCHITECTURE NOTE ---
# SailPoint IdentityNow is the Identity Governance source of truth.
# This script queries SailPoint directly to retrieve the authoritative
# view of user access - not AD or Okta individually.
# Access shown here reflects what SailPoint has aggregated from all
# connected sources and governs as the single source of truth.
# =============================================================================

# --- CONFIGURATION ---
# SailPoint IdentityNow uses OAuth 2.0 Client Credentials
# Never hardcode credentials - use environment variables
$TenantURL    = "https://yourcompany.api.identitynow.com"
$ClientID     = $env:SAILPOINT_CLIENT_ID
$ClientSecret = $env:SAILPOINT_CLIENT_SECRET
$TargetIdentity = "john.doe"
$ReportPath   = "C:\Logs\Access_Review_$TargetIdentity`_$(Get-Date -Format 'yyyy-MM-dd').csv"
$ExecutedBy   = $env:USERNAME

# --- VALIDATE CONFIGURATION ---
if (-not $ClientID -or -not $ClientSecret) {
    Write-Host "ERROR: SailPoint API credentials not configured" `
        -ForegroundColor Red
    Write-Host "INFO: Set SAILPOINT_CLIENT_ID and SAILPOINT_CLIENT_SECRET" `
        -ForegroundColor Yellow
    exit 1
}

# --- STEP 1: AUTHENTICATE TO SAILPOINT ---
# SailPoint uses OAuth 2.0 client credentials flow
# Token expires after 1 hour - refresh if running long reports
Write-Host "INFO: Authenticating to SailPoint IdentityNow..." -ForegroundColor Cyan

try {
    $TokenResponse = Invoke-RestMethod `
        -Uri "$TenantURL/oauth/token" `
        -Method POST `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $ClientID
            client_secret = $ClientSecret
        }

    $AccessToken = $TokenResponse.access_token
    Write-Host "SUCCESS: Authenticated to SailPoint" -ForegroundColor Green

} catch {
    Write-Host "ERROR: Authentication failed - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- BUILD AUTH HEADERS ---
$Headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

# --- STEP 2: FIND IDENTITY IN SAILPOINT ---
Write-Host "INFO: Searching for identity $TargetIdentity..." -ForegroundColor Cyan

try {
    $IdentityResponse = Invoke-RestMethod `
        -Uri "$TenantURL/v3/identities?filters=alias eq `"$TargetIdentity`"" `
        -Headers $Headers `
        -Method GET

    if ($IdentityResponse.Count -eq 0) {
        Write-Host "ERROR: Identity $TargetIdentity not found in SailPoint" `
            -ForegroundColor Red
        exit 1
    }

    $Identity   = $IdentityResponse[0]
    $IdentityId = $Identity.id
    $FullName   = $Identity.name
    $Department = $Identity.attributes.department
    $Manager    = $Identity.managerRef.name
    $RiskScore  = $Identity.attributes.riskScore

    Write-Host "INFO: Found identity $FullName (ID: $IdentityId)" `
        -ForegroundColor Cyan
    Write-Host "INFO: Department: $Department" -ForegroundColor Cyan
    Write-Host "INFO: Manager: $Manager" -ForegroundColor Cyan
    Write-Host "INFO: Risk Score: $RiskScore" -ForegroundColor Cyan

} catch {
    Write-Host "ERROR: Failed to retrieve identity - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 3: GET ALL ACCESS ENTITLEMENTS ---
# Retrieves all roles, entitlements and access profiles
# assigned to this identity across all governed applications
Write-Host "INFO: Retrieving access entitlements..." -ForegroundColor Cyan

try {
    $AccessResponse = Invoke-RestMethod `
        -Uri "$TenantURL/v3/identities/$IdentityId/access" `
        -Headers $Headers `
        -Method GET

    Write-Host "INFO: Found $($AccessResponse.Count) access items" `
        -ForegroundColor Cyan

} catch {
    Write-Host "ERROR: Failed to retrieve access - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 4: CATEGORISE AND ANALYSE ACCESS ---
$AccessReport = foreach ($AccessItem in $AccessResponse) {

    # Flag potentially excessive access for review
    $ReviewFlag = $false
    $ReviewReason = ""

    # Flag privileged roles
    if ($AccessItem.name -like "*Admin*" -or
        $AccessItem.name -like "*Privileged*" -or
        $AccessItem.name -like "*Super*") {
        $ReviewFlag   = $true
        $ReviewReason = "Privileged access - verify business justification"
    }

    # Flag access from previous role (potential access creep)
    if ($AccessItem.source -eq "ROLE_ASSIGNMENT" -and
        $AccessItem.assignedDate -lt (Get-Date).AddDays(-180)) {
        $ReviewFlag   = $true
        $ReviewReason = "Access older than 180 days - verify still required"
    }

    [PSCustomObject]@{
        IdentityName    = $FullName
        AccessName      = $AccessItem.name
        AccessType      = $AccessItem.type
        Application     = $AccessItem.source
        AssignedDate    = $AccessItem.assignedDate
        AssignmentType  = $AccessItem.assignmentType
        ReviewFlag      = $ReviewFlag
        ReviewReason    = $ReviewReason
        RiskScore       = $RiskScore
    }
}

# --- STEP 5: DISPLAY SUMMARY ---
$FlaggedItems = $AccessReport | Where-Object { $_.ReviewFlag -eq $true }

Write-Host "`n=== ACCESS REVIEW SUMMARY FOR $FullName ===" `
    -ForegroundColor Cyan
Write-Host "Total access items:    $($AccessReport.Count)" -ForegroundColor White
Write-Host "Flagged for review:    $($FlaggedItems.Count)" -ForegroundColor Yellow
Write-Host "Risk Score:            $RiskScore" -ForegroundColor White
Write-Host "Department:            $Department" -ForegroundColor White
Write-Host "Manager:               $Manager" -ForegroundColor White

if ($FlaggedItems.Count -gt 0) {
    Write-Host "`n=== FLAGGED ACCESS ITEMS ===" -ForegroundColor Yellow
    $FlaggedItems | Select-Object AccessName, Application, `
        AssignedDate, ReviewReason | Format-Table -AutoSize
}

# --- STEP 6: EXPORT REPORT ---
$AccessReport | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "SUCCESS: Access review report exported to $ReportPath" `
    -ForegroundColor Green

# --- STEP 7: AUDIT LOG ---
$AuditEntry = [PSCustomObject]@{
    Timestamp       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Action          = "ACCESS_REVIEW_GENERATED"
    TargetIdentity  = $TargetIdentity
    FullName        = $FullName
    Department      = $Department
    ExecutedBy      = $ExecutedBy
    TotalAccess     = $AccessReport.Count
    FlaggedItems    = $FlaggedItems.Count
    RiskScore       = $RiskScore
    ReportPath      = $ReportPath
}

$AuditEntry | Export-Csv -Path "C:\Logs\IAM_Audit.csv" `
    -Append -NoTypeInformation

Write-Host "AUDIT: Access review logged" -ForegroundColor Cyan

# --- RECOMMENDED ACTIONS ---
Write-Host "`nRECOMMENDED ACTIONS:" -ForegroundColor Magenta
Write-Host "  [ ] Send report to $Manager for certification" `
    -ForegroundColor Magenta
Write-Host "  [ ] Review flagged items with business justification" `
    -ForegroundColor Magenta
Write-Host "  [ ] Revoke any access no longer required" -ForegroundColor Magenta
Write-Host "  [ ] Document review completion for compliance evidence" `
    -ForegroundColor Magenta
Write-Host "  [ ] Update SailPoint with any access changes made" `
    -ForegroundColor Magenta