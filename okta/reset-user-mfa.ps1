# =============================================================================
# Script: reset-user-mfa.ps1
# Description: Resets a user's MFA factors in Okta via API.
#              Used when a user loses access to their authenticator app,
#              gets a new phone, or reports being locked out.
#              Includes identity verification requirement before reset
#              to prevent social engineering attacks.
# Author: Guilherme Alhinho
# Use Case: MFA helpdesk support - directly based on real-world
#           identity verification and MFA reset procedures
# Prerequisites: Okta API token with user factor management permissions
# Security Context: This script addresses a common attack vector -
#                   attackers impersonating users to reset MFA and
#                   gain unauthorised access. Identity verification
#                   before reset is critical.
#
# --- ARCHITECTURE NOTE ---
# In this environment SailPoint IdentityNow acts as the Identity Governance
# source of truth. MFA resets are downstream identity operations executed
# in Okta. Significant MFA reset patterns should be monitored and
# reconciled in SailPoint for governance visibility.
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

# --- STEP 1: IDENTITY VERIFICATION ---
# CRITICAL SECURITY STEP
# Before any MFA reset, identity must be verified through
# an out-of-band method to prevent social engineering
# In production this would be tied to a ServiceNow ticket
# with manager approval or verified through HR system
Write-Host "=== IDENTITY VERIFICATION REQUIRED ===" -ForegroundColor Yellow
Write-Host "Before proceeding, confirm the following:" -ForegroundColor Yellow
Write-Host "  [ ] Caller identity verified via employee ID or manager confirmation"
Write-Host "  [ ] ServiceNow ticket number obtained"
Write-Host "  [ ] Reset reason documented"
Write-Host ""

$TicketNumber = Read-Host "Enter ServiceNow ticket number"
$VerifiedBy   = Read-Host "Enter verification method (e.g. Manager confirmed)"
$ResetReason  = Read-Host "Enter reset reason"

if (-not $TicketNumber) {
    Write-Host "ERROR: ServiceNow ticket required before MFA reset" `
        -ForegroundColor Red
    exit 1
}

Write-Host "INFO: Identity verification recorded - proceeding with reset" `
    -ForegroundColor Green

# --- STEP 2: FIND USER IN OKTA ---
try {
    $UserResponse = Invoke-RestMethod `
        -Uri "$OktaOrgUrl/api/v1/users/$TargetUsername" `
        -Headers $Headers `
        -Method GET

    $UserId    = $UserResponse.id
    $FullName  = "$($UserResponse.profile.firstName) $($UserResponse.profile.lastName)"
    $UserStatus = $UserResponse.status

    Write-Host "INFO: Found user $FullName (ID: $UserId)" -ForegroundColor Cyan
    Write-Host "INFO: Account status: $UserStatus" -ForegroundColor Cyan

} catch {
    Write-Host "ERROR: User $TargetUsername not found in Okta" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 3: CHECK ACCOUNT STATUS ---
# Never reset MFA on suspended or deprovisioned accounts
# This could indicate a compromised or terminated user scenario
if ($UserStatus -ne "ACTIVE") {
    Write-Host "ERROR: Account is $UserStatus - MFA reset not permitted" `
        -ForegroundColor Red
    Write-Host "INFO: Escalate to senior analyst if reset is required" `
        -ForegroundColor Yellow
    exit 1
}

# --- STEP 4: GET ENROLLED FACTORS ---
try {
    $Factors = Invoke-RestMethod `
        -Uri "$OktaOrgUrl/api/v1/users/$UserId/factors" `
        -Headers $Headers `
        -Method GET

    if ($Factors.Count -eq 0) {
        Write-Host "INFO: No MFA factors enrolled for $TargetUsername" `
            -ForegroundColor Yellow
        exit 0
    }

    Write-Host "`nINFO: Currently enrolled factors:" -ForegroundColor Cyan
    foreach ($Factor in $Factors) {
        Write-Host "  - $($Factor.factorType) | $($Factor.provider) | $($Factor.status)" `
            -ForegroundColor White
    }

} catch {
    Write-Host "ERROR: Could not retrieve factors - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 5: RESET ALL ACTIVE FACTORS ---
$ResetFactors = @()

foreach ($Factor in $Factors) {
    if ($Factor.status -eq "ACTIVE") {
        try {
            Invoke-RestMethod `
                -Uri "$OktaOrgUrl/api/v1/users/$UserId/factors/$($Factor.id)" `
                -Headers $Headers `
                -Method DELETE

            $ResetFactors += $Factor.factorType
            Write-Host "SUCCESS: Reset factor $($Factor.factorType)" `
                -ForegroundColor Green

        } catch {
            Write-Host "WARNING: Could not reset factor $($Factor.factorType) - $($_.Exception.Message)" `
                -ForegroundColor Yellow
        }
    }
}

# --- STEP 6: AUDIT LOG ---
# Full audit trail is critical for MFA resets
# MFA resets are high-risk actions that must be f