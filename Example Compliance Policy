# PCI DSS Compliance Policy – Hybrid Cloud (AWS + Azure)

## Purpose
This policy defines the practices required to maintain PCI DSS compliance in our hybrid cloud environment spanning AWS and Microsoft Azure, including identity management via Azure Entra ID.

## Scope
Applies to all systems that process, store, or transmit cardholder data, and to all employees, contractors, or partners with access to those systems.

## Responsibilities
- **Security Team**: Oversees compliance, conducts audits, and manages incident response.
- **Cloud Engineers**: Implement and maintain technical controls in AWS and Azure.
- **DevOps**: Integrate secure coding and deployment practices.
- **End Users**: Adhere to policies around access control and data handling.

## Key Policies

### 1. Network Security
- AWS Security Groups and Azure NSGs must deny all traffic by default.
- All external access must go through AWS WAF or Azure Firewall.
- VPN or private endpoints must be used for administrative access.

### 2. Access Control
- Enforce MFA for all privileged and user accounts using Entra ID.
- Apply least-privilege RBAC in Azure and IAM policies in AWS.
- Entra PIM must be used for time-limited privileged access.

### 3. Data Protection
- All cardholder data must be encrypted at rest using KMS or Azure Key Vault.
- Data in transit must use TLS 1.2 or higher.
- Cardholder data should be tokenized or truncated whenever possible.

### 4. Monitoring & Logging
- All access to CDE systems must be logged using AWS CloudTrail and Azure Monitor.
- Logs must be retained for at least 1 year and reviewed monthly.
- GuardDuty (AWS) and Microsoft Defender (Azure) must be enabled.

### 5. Vulnerability Management
- Perform quarterly ASV scans and annual penetration testing.
- Patch all cloud VMs and services within 7 days of critical vulnerability discovery.
- Use automated patch management tools (AWS Systems Manager, Azure Automation).

### 6. Secure Development
- All deployments must pass security checks using CodePipeline or Azure DevOps.
- Developers must be trained annually on secure coding practices.

### 7. Incident Response
- All security incidents must be reported to the Security Team within 1 hour.
- Incident playbooks must be tested annually and stored in a secure location.

## Enforcement
Violations of this policy may result in disciplinary action, up to and including termination, as well as legal consequences.

---

Approved by: [CISO Name]  
Date: [Insert Date]  
Version: 1.0
