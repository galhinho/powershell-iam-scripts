# =============================================================================
# Script: get-user-mfa-status.ps1
# Description: Queries Okta API to retrieve MFA enrollment status for all
#              users or a specific user. Identifies accounts without MFA
#              enrolled which represent a significant authentication risk.
#              Used for compliance reporting and security posture assessment.
# Author: Guilherme Alhinho
# Use Case: Security audit, MFA compliance reporting, access review
# Prerequisites: Okta API token with read permissions, Okta org URL
# Security Context: NIST 800-63B - Multi-Factor Authentication requirements
#                   ISO 27001 A.9.4.2 - Secure log-on procedures
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
# Store API token securely - never hardcode in production
# Use environment variables or a secrets manager like Azure Key Vault
$OktaOrgUrl  = "https://yourcompany.okta.com"
$ApiToken    = $env:OKTA_API_TOKEN
$ReportPath  = "C:\Logs\MFA_Status_$(Get-Date -Format 'yyyy-MM-dd').csv"
$ExecutedBy  = $env:USERNAME

# --- VALIDATE CONFIGURATION ---
if (-not $ApiToken) {
    Write-Host "ERROR: OKTA_API_TOKEN environment variable not set" `
        -ForegroundColor Red
    Write-Host "INFO: Set using: `$env:OKTA_API_TOKEN = 'your-token'" `
        -ForegroundColor Yellow
    exit 1
}

# --- BUILD HEADERS ---
# Okta API requires SSWS token authentication
$Headers = @{
    "Authorization" = "SSWS $ApiToken"
    "Accept"        = "application/json"
    "Content-Type"  = "application/json"
}

Write-Host "INFO: Connecting to Okta org $OktaOrgUrl" -ForegroundColor Cyan

# --- STEP 1: GET ALL ACTIVE USERS ---
# Okta API paginates results - handle pagination for large orgs
$Users    = @()
$NextPage = "$OktaOrgUrl/api/v1/users?filter=status eq `"ACTIVE`"&limit=200"

Write-Host "INFO: Retrieving active users from Okta..." -ForegroundColor Cyan

while ($NextPage) {
    try {
        $Response  = Invoke-WebRequest -Uri $NextPage -Headers $Headers -Method GET
        $PageUsers = $Response.Content | ConvertFrom-Json
        $Users    += $PageUsers

        # Check for next page in Link header - Okta pagination
        $LinkHeader = $Response.Headers["Link"]
        if ($LinkHeader -match '<(.+)>; rel="next"') {
            $NextPage = $Matches[1]
        } else {
            $NextPage = $null
        }

        Write-Host "INFO: Retrieved $($Users.Count) users so far..." `
            -ForegroundColor Cyan

    } catch {
        Write-Host "ERROR: Failed to retrieve users - $($_.Exception.Message)" `
            -ForegroundColor Red
        exit 1
    }
}

Write-Host "INFO: Total active users found: $($Users.Count)" -ForegroundColor Green

# --- STEP 2: CHECK MFA STATUS FOR EACH USER ---
$MFAResults = foreach ($User in $Users) {

    $UserId    = $User.id
    $Username  = $User.profile.login
    $FullName  = "$($User.profile.firstName) $($User.profile.lastName)"
    $Department = $User.profile.department

    # Query enrolled factors for each user
    try {
        $FactorsResponse = Invoke-RestMethod `
            -Uri "$OktaOrgUrl/api/v1/users/$UserId/factors" `
            -Headers $Headers `