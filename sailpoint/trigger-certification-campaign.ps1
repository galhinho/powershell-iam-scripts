# =============================================================================
# Script: trigger-certification-campaign.ps1
# Description: Triggers a SailPoint IdentityNow access certification campaign
#              via API. Certification campaigns are a core IGA control that
#              require managers or application owners to review and certify
#              (or revoke) user access on a periodic basis.
#              Automating campaign creation ensures consistency, reduces
#              manual effort, and provides audit evidence of regular reviews.
# Author: Guilherme Alhinho
# Use Case: Periodic access recertification - scheduled or triggered
#           by events such as role changes, risk score increases,
#           or compliance audit requirements
# Prerequisites: SailPoint IdentityNow API credentials (Client ID + Secret)
#                Campaign Administrator role in SailPoint
# Security Context: ISO 27001 A.9.2.5 - Review of user access rights
#                   SOX - Periodic access reviews for financial systems
#                   GDPR - Data access reviews for personal data handlers
#
# --- ARCHITECTURE NOTE ---
# SailPoint IdentityNow is the Identity Governance source of truth.
# Certification campaigns are the primary mechanism through which
# SailPoint enforces the principle that access must be periodically
# justified - not just granted once and forgotten.
# Results of campaigns feed back into SailPoint's governance model,
# revoking access that cannot be justified by the business.
# =============================================================================

# --- CONFIGURATION ---
$TenantURL    = "https://yourcompany.api.identitynow.com"
$ClientID     = $env:SAILPOINT_CLIENT_ID
$ClientSecret = $env:SAILPOINT_CLIENT_SECRET
$ExecutedBy   = $env:USERNAME

# Campaign configuration
$CampaignName        = "Q2 2026 Access Recertification - Finance Department"
$CampaignDescription = "Quarterly access review for Finance department users. " +
                       "Managers must certify or revoke all access entitlements " +
                       "for their direct reports. Uncertified access will be " +
                       "automatically revoked after campaign deadline."
$CampaignDeadlineDays = 14
$CampaignDeadline    = (Get-Date).AddDays($CampaignDeadlineDays).ToString("yyyy-MM-ddTHH:mm:ssZ")

# --- VALIDATE CONFIGURATION ---
if (-not $ClientID -or -not $ClientSecret) {
    Write-Host "ERROR: SailPoint API credentials not configured" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 1: AUTHENTICATE TO SAILPOINT ---
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

$Headers = @{
    "Authorization" = "Bearer $AccessToken"
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

# --- STEP 2: DEFINE CAMPAIGN SCOPE ---
# Define which identities are included in this campaign
# Options: department, risk score threshold, specific roles,
# application owners, or entire organisation
# This example targets Finance department with elevated risk scores
$CampaignFilter = @{
    type = "IDENTITY_LIST"
    identityQueryFilter = @{
        type = "AND"
        filters = @(
            @{
                type      = "ATTRIBUTE"
                attribute = "department"
                operation = "EQUALS"
                value     = "Finance"
            },
            @{
                type      = "ATTRIBUTE"
                attribute = "riskScore"
                operation = "GREATER_THAN"
                value     = "30"
            }
        )
    }
}

Write-Host "INFO: Campaign scope defined - Finance department, risk score > 30" `
    -ForegroundColor Cyan

# --- STEP 3: BUILD CAMPAIGN PAYLOAD ---
$CampaignPayload = @{
    name        = $CampaignName
    description = $CampaignDescription
    type        = "MANAGER"
    deadline    = $CampaignDeadline
    filter      = $CampaignFilter
    emailNotificationEnabled = $true
    autoRevokeAllowed        = $true
    recommendationsEnabled   = $true
    correlatedStatus         = "CORRELATED"
} | ConvertTo-Json -Depth 10

Write-Host "INFO: Campaign payload built" -ForegroundColor Cyan
Write-Host "INFO: Deadline: $CampaignDeadline ($CampaignDeadlineDays days)" `
    -ForegroundColor Cyan

# --- STEP 4: CREATE THE CAMPAIGN ---
try {
    $CampaignResponse = Invoke-RestMethod `
        -Uri "$TenantURL/v3/campaigns" `
        -Headers $Headers `
        -Method POST `
        -Body $CampaignPayload

    $CampaignId     = $CampaignResponse.id
    $CampaignStatus = $CampaignResponse.status

    Write-Host "SUCCESS: Campaign created - ID: $CampaignId" `
        -ForegroundColor Green
    Write-Host "INFO: Campaign status: $CampaignStatus" -ForegroundColor Cyan

} catch {
    Write-Host "ERROR: Failed to create campaign - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 5: ACTIVATE THE CAMPAIGN ---
# Campaign is created in DRAFT status
# Must be explicitly activated to start sending notifications
# This two-step process allows review before launch
try {
    Invoke-RestMethod `
        -Uri "$TenantURL/v3/campaigns/$CampaignId/activate" `
        -Headers $Headers `
        -Method POST

    Write-Host "SUCCESS: Campaign activated - notifications sending to managers" `
        -ForegroundColor Green

} catch {
    Write-Host "ERROR: Failed to activate campaign - $($_.Exception.Message)" `
        -ForegroundColor Red
    Write-Host "INFO: Campaign created but not activated - ID: $CampaignId" `
        -ForegroundColor Yellow
    Write-Host "INFO: Manually activate in SailPoint UI if needed" `
        -ForegroundColor Yellow
}

# --- STEP 6: VERIFY CAMPAIGN STATUS ---
try {
    $VerifyResponse = Invoke-RestMethod `
        -Uri "$TenantURL/v3/campaigns/$CampaignId" `
        -Headers $Headers `
        -Method GET

    Write-Host "`n=== CAMPAIGN SUMMARY ===" -ForegroundColor Cyan
    Write-Host "Campaign ID:     $CampaignId" -ForegroundColor White
    Write-Host "Campaign Name:   $CampaignName" -ForegroundColor White
    Write-Host "Status:          $($VerifyResponse.status)" -ForegroundColor White
    Write-Host "Deadline:        $CampaignDeadline" -ForegroundColor White
    Write-Host "Total Certifiers: $($VerifyResponse.totalCertifiers)" `
        -ForegroundColor White
    Write-Host "Total Subjects:  $($VerifyResponse.totalSubjects)" `
        -ForegroundColor White

} catch {
    Write-Host "WARNING: Could not verify campaign status" -ForegroundColor Yellow
}

# --- STEP 7: AUDIT LOG ---
$AuditEntry = [PSCustomObject]@{
    Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Action           = "CERTIFICATION_CAMPAIGN_TRIGGERED"
    CampaignId       = $CampaignId
    CampaignName     = $CampaignName
    ExecutedBy       = $ExecutedBy
    Deadline         = $CampaignDeadline
    DeadlineDays     = $CampaignDeadlineDays
    Scope            = "Finance department - risk score > 30"
    AutoRevoke       = $true
}

$AuditEntry | Export-Csv -Path "C:\Logs\IAM_Audit.csv" `
    -Append -NoTypeInformation

Write-Host "AUDIT: Campaign creation logged" -ForegroundColor Cyan
Write-Host "COMPLETE: Certification campaign launched successfully" `
    -ForegroundColor Green

# --- POST LAUNCH ACTIONS ---
Write-Host "`nPOST LAUNCH ACTIONS:" -ForegroundColor Magenta
Write-Host "  [ ] Confirm managers received notification emails" `
    -ForegroundColor Magenta
Write-Host "  [ ] Monitor campaign progress in SailPoint UI" `
    -ForegroundColor Magenta
Write-Host "  [ ] Send reminder notifications at 7 days remaining" `
    -ForegroundColor Magenta
Write-Host "  [ ] Escalate to senior managers for incomplete reviews at 3 days" `
    -ForegroundColor Magenta
Write-Host "  [ ] Review auto-revoked access after campaign closes" `
    -ForegroundColor Magenta
Write-Host "  [ ] Export campaign results for compliance evidence" `
    -ForegroundColor Magenta
Write-Host "  [ ] Document campaign completion in audit log" `
    -ForegroundColor Magenta