# =============================================================================
# Script: user-deprovisioning.ps1
# Description: Automates the secure deprovisioning of a user in Active Directory
#              following IAM best practices. Ensures access is fully revoked
#              immediately upon termination, reducing attack surface.
# Author: Guilherme Alhinho
# Use Case: Leaver process (L in JML) - executed when an employee leaves
# Prerequisites: ActiveDirectory PowerShell module, delegated permissions
#                to disable accounts and modify group memberships
# Security Note: This script should be executed immediately upon termination
#                notification - delayed deprovisioning is a critical security risk
# =============================================================================

# --- CONFIGURATION ---
# In production this would come from an HR system or ServiceNow ticket
$Username       = "john.doe"
$TerminationDate = Get-Date -Format "yyyy-MM-dd"
$ExecutedBy     = $env:USERNAME

# --- STEP 1: VERIFY USER EXISTS ---
# Always verify before making changes - prevents errors on wrong username
try {
    $User = Get-ADUser -Identity $Username -Properties MemberOf, Manager, Department
    Write-Host "INFO: Found user $Username - $($User.DisplayName)" `
        -ForegroundColor Cyan
} catch {
    Write-Host "ERROR: User $Username not found in Active Directory" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 2: DISABLE THE ACCOUNT IMMEDIATELY ---
# First action is always account disable - cuts access instantly
# Even before group removal, a disabled account cannot authenticate
try {
    Disable-ADAccount -Identity $Username
    Write-Host "SUCCESS: Account $Username disabled" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Failed to disable account - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- STEP 3: RESET PASSWORD TO RANDOM VALUE ---
# Prevents anyone from using cached credentials or known passwords
# after the account is disabled - defence in depth
$RandomPassword = ConvertTo-SecureString `
    ([System.Web.Security.Membership]::GeneratePassword(16, 4)) `
    -AsPlainText -Force

Set-ADAccountPassword -Identity $Username `
    -NewPassword $RandomPassword -Reset
Write-Host "SUCCESS: Password reset to random value" -ForegroundColor Green

# --- STEP 4: REMOVE ALL GROUP MEMBERSHIPS ---
# Remove access to all resources - least privilege enforcement
# Records which groups were removed for audit purposes
$RemovedGroups = @()

foreach ($Group in $User.MemberOf) {
    try {
        Remove-ADGroupMember -Identity $Group -Members $Username -Confirm:$false
        $RemovedGroups += $Group
        Write-Host "SUCCESS: Removed from group $Group" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not remove from $Group - $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }
}

# --- STEP 5: MOVE TO DISABLED USERS OU ---
# Moves account to a dedicated OU for terminated users
# Keeps AD organised and applies restrictive GPOs automatically
$DisabledOU = "OU=Disabled Users,DC=company,DC=com"

try {
    Move-ADObject -Identity $User.DistinguishedName -TargetPath $DisabledOU
    Write-Host "SUCCESS: Account moved to Disabled Users OU" -ForegroundColor Green
} catch {
    Write-Host "WARNING: Could not move account to Disabled OU - $($_.Exception.Message)" `
        -ForegroundColor Yellow
}

# --- STEP 6: UPDATE ACCOUNT DESCRIPTION ---
# Documents when and why the account was disabled
# Visible in AD Users and Computers for quick reference
Set-ADUser -Identity $Username -Description `
    "DISABLED: Terminated on $TerminationDate by $ExecutedBy"
Write-Host "SUCCESS: Account description updated" -ForegroundColor Green

# --- STEP 7: AUDIT LOG ---
# Full audit trail of all deprovisioning actions
# Critical for compliance - proves access was revoked promptly
$AuditEntry = [PSCustomObject]@{
    Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Action           = "USER_DEPROVISIONED"
    Username         = $Username
    DisplayName      = $User.DisplayName
    Department       = $User.Department
    TerminationDate  = $TerminationDate
    ExecutedBy       = $ExecutedBy
    GroupsRemoved    = $RemovedGroups -join " | "
    AccountDisabled  = $true
    PasswordReset    = $true
    MovedToDisabledOU = $true
}

$AuditEntry | Export-Csv -Path "C:\Logs\IAM_Audit.csv" `
    -Append -NoTypeInformation

Write-Host "AUDIT: Deprovisioning logged to IAM_Audit.csv" -ForegroundColor Cyan
Write-Host "COMPLETE: User $Username fully deprovisioned" -ForegroundColor Green

# --- SECURITY NOTE ---
# This script handles AD deprovisioning only.
# Additional manual or automated steps required for:
# - SaaS application access revocation (Okta, SailPoint)
# - Physical access cards
# - Hardware retrieval
# - Email forwarding setup if required
# - Mailbox retention policy application
Write-Host "`nREMINDER: Complete deprovisioning checklist:" -ForegroundColor Magenta
Write-Host "  [ ] Okta account deactivated" -ForegroundColor Magenta
Write-Host "  [ ] SailPoint identity disabled" -ForegroundColor Magenta
Write-Host "  [ ] Hardware retrieval scheduled" -ForegroundColor Magenta
Write-Host "  [ ] Physical access revoked" -ForegroundColor Magenta
Write-Host "  [ ] Manager notified of completion" -ForegroundColor Magenta