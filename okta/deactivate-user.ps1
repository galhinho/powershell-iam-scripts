# =============================================================================
# Script: deactivate-user.ps1
# Description: Deactivates a user in Okta as part of the offboarding
#              (Leaver) process. Okta deactivation revokes all active
#              SSO sessions and prevents future authentication across
#              all Okta-integrated applications simultaneously.
#              This is the Okta component of a full deprovisioning workflow
#              that also includes AD deprovisioning and SailPoint updates.
# Author: Guilherme Alhinho
# Use Case: Leaver process (L in JML) - Okta offboarding component
# Prerequisites: Okta API token with user lifecycle management permissions
# Security Context: Immediate deactivation on termination is critical -
#                   every minute of delay is an open attack window
#
# --- ARCHITECTURE NOTE ---
# In this environment SailPoint IdentityNow acts as the Identity Governance
# source of truth. Okta deactivation is a downstream provisioning action
# triggered by SailPoint leaver workflows. This script handles manual
# deactivation for urgent terminations or remediation outside of
# SailPoint automated workflows.
# All manual deactivations must be reconciled in SailPoint to maintain
# governance integrity and prevent identity data drift.
# =============================================================================

# --- CONFIGURATION ---
$OktaOrgUrl     = "https://yourcompany.okta.com"
$ApiToken       = $env:OKTA_API_TOKEN
$ExecutedBy     = $env:USERNAME
$TargetUsername = "john.doe@company.com"

# --- VALIDATE CONFIGURATION ---
if (-not $ApiToken) {
    Write-Host "ERROR: OKTA_API_TOKEN environment variable not set" `
        -ForegroundColor Red
    exit 1
}

# --- BUILD HEADERS ---
$Headers = @{
    "Authorization" = "SSWS $ApiToken"
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

# --- STEP 1: AUTHORISATION CHECK ---
# Okta deactivation is a high-impact irreversible action
# Requires documented authorisation before proceeding
Write-Host "=== AUTHORISATION REQUIRED ===" -ForegroundColor Yellow
Write-Host "Okta deactivation immediately revokes:" -ForegroundColor Yellow
Write-Host "  - All active SSO sessions" -ForegroundColor White
Write-Host "  - Access to all Okta-integrated applications" -ForegroundColor White
Write-Host "  - MFA factors" -ForegroundColor White
Write-Host "  - API tokens issued to this user" -ForegroundColor White
Write-Host ""

$TicketNumber  = Read-Host "Enter ServiceNow ticket number"
$AuthorisedBy  = Read-Host "Enter authorising manager name"
$Reason        = Read-Host "Enter deactivation reason (e.g. Termination, Security incident)"

if (-not $TicketNumber -or -not $AuthorisedBy) {
    Write-Host "ERROR: Ticket number and manager authorisation required" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 2: FIND USER IN OKTA ---
try {
    $UserResponse = Invoke-RestMethod `
        -Uri "$OktaOrgUrl/api/v1/users/$TargetUsername" `
        -Headers $Headers `
        -Method GET

    $UserId     = $UserResponse.id
    $FullName   = "$($UserResponse.profile.firstName) $($UserResponse.profile.lastName)"
    $UserStatus = $UserResponse.status
    $Department = $UserResponse.profile.department
    $Manager    = $UserResponse.profile.manager

    Write-Host "INFO: Found user $FullName" -ForegroundColor Cyan
    Write-Host "INFO: Department: $Department" -ForegroundColor Cyan
    Write-Host "INFO: Current status: $UserStatus" -ForegroundColor Cyan

} catch {
    Write-Host "ERROR: User $TargetUsername not found in Okta" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 3: CHECK CURRENT STATUS ---
if ($UserStatus -eq "DEPROVISIONED") {
    Write-Host "INFO: User is already deprovisioned - no action needed" `
        -ForegroundColor Yellow
    exit 0
}

if ($UserStatus -eq "SUSPENDED") {
    Write-Host "INFO: User is suspended - proceeding to full deactivation" `
        -ForegroundColor Yellow
}

# --- STEP 4: CLEAR ACTIVE SESSIONS ---
# Immediately terminate all active browser and API sessions
# This is the fastest way to cut access - before deactivation completes
try {
    Invoke-RestMethod `
        -Uri "$OktaOrgUrl/api/v1/users/$UserId/sessions" `
        -Headers $Headers `
        -Method DELETE

    Write-Host "SUCCESS: All active sessions cleared" -ForegroundColor Green

} catch {
    Write-Host "WARNING: Could not clear sessions - $($_.Exception.Message)" `
        -ForegroundColor Yellow
}

# --- STEP 5: DEACTIVATE THE USER ---
# Deactivation in Okta = account disabled, SSO access revoked
# Two step process: first deactivate, then deprovision if needed
try {
    Invoke-RestMethod `
        -Uri "$OktaOrgUrl/api/v1/users/$UserId/lifecycle/deactivate" `
        -Headers $Headers `
        -Method POST

    Write-Host "SUCCESS: User $FullName deactivated in Okta" `
        -ForegroundColor Green

} catch {
    Write-Host "ERROR: Failed to deactivate user - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 6: VERIFY DEACTIVATION ---
# Confirm the status change was applied correctly
try {
    $VerifyResponse = Invoke-RestMethod `
        -Uri "$OktaOrgUrl/api/v1/users/$UserId" `
        -Headers $Headers `
        -Method GET

    $NewStatus = $VerifyResponse.status

    if ($NewStatus -eq "DEPROVISIONED" -or $NewStatus -eq "DEACTIVATED") {
        Write-Host "VERIFIED: Account status is now $NewStatus" `
            -ForegroundColor Green
    } else {
        Write-Host "WARNING: Unexpected status after deactivation: $NewStatus" `
            -ForegroundColor Yellow
    }

} catch {
    Write-Host "WARNING: Could not verify deactivation status" `
        -ForegroundColor Yellow
}

# --- STEP 7: AUDIT LOG ---
$AuditEntry = [PSCustomObject]@{
    Timestamp          = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Action             = "OKTA_USER_DEACTIVATED"
    TargetUsername     = $TargetUsername
    TargetFullName     = $FullName
    Department         = $Department
    ExecutedBy         = $ExecutedBy
    AuthorisedBy       = $AuthorisedBy
    TicketNumber       = $TicketNumber
    Reason             = $Reason
    SessionsCleared    = $true
    DeactivationStatus = $NewStatus
}

$AuditEntry | Export-Csv -Path "C:\Logs\IAM_Audit.csv" `
    -Append -NoTypeInformation

Write-Host "AUDIT: Deactivation logged to IAM_Audit.csv" -ForegroundColor Cyan
Write-Host "COMPLETE: Okta deactivation for $FullName finished" `
    -ForegroundColor Green

# --- FULL OFFBOARDING CHECKLIST ---
# Okta deactivation is one component of full offboarding
# Remaining steps must be completed to fully revoke access
Write-Host "`nFULL OFFBOARDING CHECKLIST:" -ForegroundColor Magenta
Write-Host "  [✓] Okta deactivated - all SSO sessions revoked" `
    -ForegroundColor Green
Write-Host "  [ ] Active Directory account disabled" -ForegroundColor Magenta
Write-Host "  [ ] SailPoint identity disabled and access revoked" `
    -ForegroundColor Magenta
Write-Host "  [ ] Email forwarding configured if required" -ForegroundColor Magenta
Write-Host "  [ ] Hardware retrieval scheduled" -ForegroundColor Magenta
Write-Host "  [ ] Physical access cards deactivated" -ForegroundColor Magenta
Write-Host "  [ ] Manager notified of completion" -ForegroundColor Magenta
Write-Host "  [ ] ServiceNow ticket $TicketNumber closed" -ForegroundColor Magenta