# =============================================================================
# Script: new-user-provisioning.ps1
# Description: Automates the provisioning of a new user in Active Directory
#              following IAM best practices including least privilege,
#              group assignment based on role, and audit logging.
# Author: Guilherme Alhinho
# Use Case: Joiner process (J in JML) - executed when a new employee joins
# Prerequisites: ActiveDirectory PowerShell module, Domain Admin or
#                delegated account creation permissions
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
#

# --- CONFIGURATION ---
# Define the new user's details - in production these would come from
# an HR system feed or ITSM ticket (e.g. ServiceNow)

$FirstName     = "John"
$LastName      = "Doe"
$Department    = "Finance"
$JobTitle      = "Financial Analyst"
$Manager       = "jane.smith"
$Office        = "Porto"
$PasswordInit  = ConvertTo-SecureString "Welcome@12345!" -AsPlainText -Force

# --- BUILD USER ATTRIBUTES ---
# Construct standard naming convention - firstname.lastname
$Username      = "$($FirstName.ToLower()).$($LastName.ToLower())"
$DisplayName   = "$FirstName $LastName"
$UPN           = "$Username@company.com"

# Define OU path based on department - enforces organisational structure
# and makes GPO application predictable
$OUPath = "OU=$Department,OU=Users,DC=company,DC=com"

# --- ROLE-BASED GROUP ASSIGNMENT ---
# Groups are pre-defined per department following RBAC principles
# Only assign what the role requires - least privilege
$DepartmentGroups = @{
    "Finance"   = @("Finance-Users", "Finance-SharePoint", "Finance-Reports")
    "IT"        = @("IT-Admins", "IT-Systems", "VPN-Users")
    "HR"        = @("HR-Users", "HR-SharePoint", "HR-Confidential")
}

$GroupsToAssign = $DepartmentGroups[$Department]

# --- CREATE THE USER ---
try {
    New-ADUser `
        -SamAccountName $Username `
        -UserPrincipalName $UPN `
        -GivenName $FirstName `
        -Surname $LastName `
        -DisplayName $DisplayName `
        -Department $Department `
        -Title $JobTitle `
        -Office $Office `
        -Manager $Manager `
        -Path $OUPath `
        -AccountPassword $PasswordInit `
        -ChangePasswordAtLogon $true `
        -Enabled $true

    Write-Host "SUCCESS: User $Username created in $OUPath" -ForegroundColor Green

} catch {
    Write-Host "ERROR: Failed to create user $Username - $($_.Exception.Message)" `
        -ForegroundColor Red
    exit 1
}

# --- ASSIGN GROUPS BASED ON ROLE ---
# Iterates through pre-defined groups for the department
# Separation of duties: group assignment is separate from user creation
foreach ($Group in $GroupsToAssign) {
    try {
        Add-ADGroupMember -Identity $Group -Members $Username
        Write-Host "SUCCESS: Added $Username to group $Group" -ForegroundColor Green
    } catch {
        Write-Host "WARNING: Could not add $Username to $Group - $($_.Exception.Message)" `
            -ForegroundColor Yellow
    }
}

# --- FORCE PASSWORD RESET ON FIRST LOGIN ---
# Security requirement - initial password must be changed immediately
# Prevents IT staff from knowing the user's permanent password
Set-ADUser -Identity $Username -ChangePasswordAtLogon $true

# --- AUDIT LOG ---
# Record the provisioning action for compliance and audit purposes
# In production this would write to a SIEM or dedicated audit system
$AuditEntry = [PSCustomObject]@{
    Timestamp   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Action      = "USER_PROVISIONED"
    Username    = $Username
    Department  = $Department
    CreatedBy   = $env:USERNAME
    Groups      = $GroupsToAssign -join ", "
}

$AuditEntry | Export-Csv -Path "C:\Logs\IAM_Audit.csv" `
    -Append -NoTypeInformation

Write-Host "AUDIT: Provisioning logged to IAM_Audit.csv" -ForegroundColor Cyan
Write-Host "COMPLETE: User $Username successfully provisioned" -ForegroundColor Green
