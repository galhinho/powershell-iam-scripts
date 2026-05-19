# PowerShell IAM Scripts

## Overview

A collection of production-ready PowerShell scripts for Identity and Access 
Management operations across Active Directory, Okta, and SailPoint IdentityNow.

These scripts cover the full identity lifecycle — provisioning, deprovisioning, 
access reviews, MFA management, and recertification campaigns — following 
enterprise IAM best practices including least privilege, audit logging, 
and separation of duties.

---

## Architecture

### SailPoint as Source of Truth

In the architecture these scripts are designed for, SailPoint IdentityNow 
acts as the Identity Governance source of truth. All identity lifecycle 
decisions originate in SailPoint and propagate downstream to Active Directory 
and Okta as provisioning targets.

SailPoint IdentityNow (Source of Truth)
│
├── Active Directory (On-premises identities)
│
└── Okta (Cloud authentication & SSO)

Direct AD and Okta changes made outside SailPoint must be reconciled 
back to maintain governance integrity and prevent access drift.

---

## Scripts

### Active Directory

| Script | Use Case | JML Stage |
|---|---|---|
| `new-user-provisioning.ps1` | Create AD user with RBAC group assignment | Joiner |
| `user-deprovisioning.ps1` | Disable account, revoke access, move to disabled OU | Leaver |
| `inactive-account-detection.ps1` | Identify dormant accounts by risk level | Access Review |

### Okta

| Script | Use Case | JML Stage |
|---|---|---|
| `get-user-mfa-status.ps1` | MFA compliance report across all users | Access Review |
| `reset-user-mfa.ps1` | Secure MFA reset with identity verification | Support |
| `deactivate-user.ps1` | Revoke all SSO sessions and deactivate account | Leaver |

### SailPoint

| Script | Use Case | JML Stage |
|---|---|---|
| `get-user-access-review.ps1` | Retrieve full entitlement view for review | Access Review |
| `trigger-certification-campaign.ps1` | Launch recertification campaign via API | Recertification |

---

## IAM Concepts Demonstrated

### JML Process Coverage
- **Joiner** — Automated provisioning with RBAC group assignment
- **Mover** — Access review and entitlement analysis
- **Leaver** — Full deprovisioning across AD, Okta, and SailPoint

### Security Principles
- **Least privilege** — RBAC groups pre-defined per department
- **Separation of duties** — Authorisation required before high-impact actions
- **Audit trail** — Every action logged with timestamp, actor, and ticket reference
- **Defence in depth** — Multiple controls applied at each stage

### Compliance Frameworks Referenced
- ISO 27001 A.9.2.5 — Review of user access rights
- CIS Control 5.3 — Disable dormant accounts
- NIST 800-63B — Multi-factor authentication requirements
- SOX — Periodic access reviews for financial systems
- GDPR — Data access reviews for personal data handlers

---

## Security Features

### Identity Verification Before Sensitive Actions
MFA resets and account deactivations require:
- ServiceNow ticket number
- Manager authorisation
- Documented reason

This prevents social engineering attacks where an attacker 
impersonates an employee to gain access.

### Audit Logging
Every script appends to a centralised `IAM_Audit.csv` log containing:
- Timestamp
- Action performed
- Target identity
- Executing analyst
- Authorisation reference (ticket number)
- Result

### Service Account Exclusions
Inactive account detection excludes service accounts — 
they legitimately don't log in like human users and 
require separate governance processes.

---

## Prerequisites

### Active Directory Scripts
# Verify AD module is available
Import-Module ActiveDirectory


### Okta Scripts
# Set API token as environment variable - never hardcode
$env:OKTA_API_TOKEN = "your-okta-api-token"


### SailPoint Scripts
# Set credentials as environment variables
$env:SAILPOINT_CLIENT_ID     = "your-client-id"
$env:SAILPOINT_CLIENT_SECRET = "your-client-secret"


---

## Usage Notes

These scripts are designed as reference implementations demonstrating 
IAM best practices. In production environments:

- Credentials should be stored in a secrets manager (Azure Key Vault, 
  HashiCorp Vault) not environment variables
- Scripts should be integrated with ITSM workflows (ServiceNow) 
  for automated triggering
- Audit logs should feed into a SIEM (Microsoft Sentinel) rather 
  than local CSV files
- Error handling should include alerting to on-call IAM engineers
- SailPoint automated workflows should handle routine JML processes — 
  these scripts cover manual operations and exceptions

---

## Related Projects

- [Azure Entra ID Security Hardening Lab](https://github.com/galhinho/azure-entra-id-hardening-lab)
- [Azure Sentinel IAM Threat Detection Lab](https://github.com/galhinho/azure-sentinel-iam-detection)
- [Azure Infrastructure Deployment using Terraform](https://github.com/galhinho/azure-terraform-secure-infra)
- [Keycloak IAM Lab](https://github.com/galhinho/keycloak-iam-lab)

---

## Author

Guilherme Alhinho
Cloud Security & IAM | Azure | SailPoint | Okta | PowerShell
[LinkedIn](https://linkedin.com/in/guilhermealhinho) |
[GitHub](https://github.com/galhinho)
