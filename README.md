PCI DSS (Payment Card Industry Data Security Standard) is essential for any FinTech company handling payment card data. It includes a comprehensive set of security standards designed to protect cardholder data and ensure secure processing, storage, and transmission.

Below is a breakdown of the **key PCI DSS requirements** (version 4.0 as of 2024), along with an explanation of how they relate to a company leveraging **AWS** and **Azure Entra ID (formerly Azure Active Directory)**:

---

### **🔐 PCI DSS Requirements & Their Relevance**

| PCI DSS Requirement | Summary | Application in AWS & Azure Entra ID Context |
| ----- | ----- | ----- |
| **1\. Install and maintain a firewall configuration** | Protect cardholder data environments (CDE) from unauthorized access. | Use **AWS Security Groups, NACLs**, and **Azure NSGs** to control traffic. Use **AWS WAF** and **Azure Firewall** for application layer protection. |
| **2\. Do not use vendor-supplied defaults** | Change all default passwords and security settings. | Ensure default credentials are removed for EC2, RDS, Azure VMs, and cloud services. Use **Entra ID policies** for strong credential management. |
| **3\. Protect stored cardholder data** | Encrypt and securely store card data when retention is required. | Use **AWS KMS**, **AWS Secrets Manager**, or **Azure Key Vault** for encryption and key management. Tokenize or truncate PANs. |
| **4\. Encrypt transmission of cardholder data across open networks** | Protect data in transit with strong encryption (TLS 1.2+). | Enforce TLS on all endpoints (e.g., ELB in AWS, Azure App Gateway). Use **VPN or Private Link** for internal services. |
| **5\. Protect systems against malware and update antivirus software** | Install and regularly update anti-malware tools. | Use **AWS Inspector, Systems Manager**, and **Azure Defender for Endpoint** to monitor and mitigate threats. |
| **6\. Develop and maintain secure systems and applications** | Patch management, secure SDLC, and code reviews. | Use **AWS CodePipeline**, **CodeBuild**, or **Azure DevOps** with integrated security scans. Ensure OS-level patching with Systems Manager or Azure Automation. |
| **7\. Restrict access to cardholder data by business need to know** | Principle of least privilege (PoLP). | Use **IAM roles and policies** in AWS and **Azure RBAC** \+ **Conditional Access Policies** in Entra ID to enforce access control. |
| **8\. Identify and authenticate access to system components** | Strong identity management and MFA. | Use **AWS IAM with MFA**, and **Azure Entra ID MFA**. Integrate with **SAML/OIDC** for centralized identity. Monitor access with CloudTrail and Entra logs. |
| **9\. Restrict physical access to cardholder data** | Physical security of systems storing cardholder data. | Responsibility is shared—**AWS and Azure data centers** meet PCI physical security. For on-prem components, enforce badge/access control systems. |
| **10\. Track and monitor all access to network resources and cardholder data** | Logging and monitoring of all access and changes. | Use **AWS CloudTrail, CloudWatch**, and **Azure Monitor, Sentinel**. Store logs securely, with access restricted and reviewed. |
| **11\. Regularly test security systems and processes** | Perform vulnerability scans and penetration testing. | Use tools like **AWS Inspector, Azure Defender**, and external PEN testing. Required **quarterly scans** with an approved scanning vendor (ASV). |
| **12\. Maintain a policy that addresses information security for all personnel** | Establish, maintain, and enforce security policies. | Ensure employees using AWS/Azure receive **security awareness training**. Implement policies around **incident response**, **access control**, and **data handling**. |

---

### **🔄 Shared Responsibility Model**

For companies using **AWS and Azure**, PCI compliance is **a shared responsibility**:

* **Cloud Providers (AWS/Azure)**: Responsible for the **security *of* the cloud** (physical infrastructure, hypervisors, etc.). Both are **PCI DSS Level 1 compliant**.

* **FinTech Company**: Responsible for the **security *in* the cloud** (app configuration, IAM, network setup, encryption, etc.).

---

### **🧩 Azure Entra ID Specific Considerations**

* **Identity and Access**: Entra ID manages users, groups, and authentication across Azure and SaaS apps.

* **MFA and Conditional Access**: Crucial for meeting PCI DSS 8.3. Use **Conditional Access Policies** to enforce MFA based on risk, device, or location.

* **Logging & Auditing**: Use **Azure Entra Sign-in Logs**, **Audit Logs**, and forward to **Sentinel or Log Analytics** for retention and review.

* **Privileged Identity Management (PIM)**: Implement **just-in-time (JIT) access** for admin roles to comply with least privilege.

---

Checklist for PCI compliance in a hybrid AWS–Azure.

| ✅ Requirement | AWS Actions | Azure/Entra ID Actions | Responsibility |
| ----- | ----- | ----- | ----- |
| **1\. Firewalls** | Configure **Security Groups**, NACLs, and **WAF** | Use **NSGs**, **Azure Firewall**, and DDoS Protection | Shared |
| **2\. No Default Settings** | Remove defaults from AMIs, RDS, IAM policies | Harden VMs, Entra ID policies | Customer |
| **3\. Cardholder Data Storage** | Use **KMS**, Secrets Manager, Tokenization | Use **Key Vault**, disk encryption | Customer |
| **4\. Data in Transit** | Enforce **TLS 1.2+**, ALB/ELB config | HTTPS-only endpoints, enforce TLS | Customer |
| **5\. Anti-Malware** | Use **AWS Inspector**, GuardDuty | Defender for Cloud, Microsoft Defender AV | Customer |
| **6\. Secure DevOps** | Secure CI/CD pipelines with CodeBuild | Use **Azure DevOps**, integrate scanning | Customer |
| **7\. Access Control** | IAM Roles, Policies, SCPs | RBAC, Conditional Access, PIM | Customer |
| **8\. Authentication** | IAM with MFA, SSO integrations | Entra ID \+ MFA, SSO, Passwordless options | Customer |
| **9\. Physical Access** | AWS handles physical data centers | Azure handles data centers | Cloud Provider |
| **10\. Logging & Monitoring** | **CloudTrail**, GuardDuty, CloudWatch | **Sentinel**, Log Analytics, Sign-in logs | Shared |
| **11\. Testing** | Use Inspector, penetration tests | Microsoft Defender, external ASV scans | Customer |
| **12\. Security Policies** | Internal policies enforced via IAM | Use Entra ID Governance and Security Center | Customer |

---
  
PCI DSS requirements — organized by control objective — together with notes on how an AWS-based environment and Azure Entra ID (formerly Azure AD) can help you satisfy each one.

 

## **1\. Build and maintain a secure network and systems**

**Requirement 1:** Install and maintain a firewall configuration to protect cardholder data

* **AWS**: Use VPCs with tightly scoped Security Groups and Network ACLs to isolate and filter inbound/outbound traffic to cardholder-data systems. Leverage AWS Network Firewall or third-party NGFW appliances from the Marketplace.

* **Azure**: Deploy Azure Firewall or NSGs to control network flows. Place workloads in isolated subnets (e.g. a “card-data” subnet) and enforce traffic via Azure Application Gateway or Azure Front Door.

**Requirement 2:** Do not use vendor-supplied defaults for system passwords and other security parameters

* **AWS**: Harden AMIs by baking in CIS-benchmarked configurations and use AWS Systems Manager Patch Manager and State Manager to enforce baseline settings.

* **Azure**: Use Azure Policy to audit and remediate default credentials, disable unused accounts, and enforce secure configuration on VMs and PaaS services.

---

## **2\. Protect cardholder data**

**Requirement 3:** Protect stored cardholder data

* Encrypt data at rest using AWS KMS-managed keys (SSE-KMS on S3, EBS encryption, RDS Transparent Data Encryption).

* On Azure, enable Azure Disk Encryption (backed by Key Vault) and Transparent Data Encryption on Azure SQL.

**Requirement 4:** Encrypt transmission of cardholder data across open, public networks

* Enforce TLS 1.2+ for all in-flight data. In AWS, use ACM to provision and rotate certificates on ELBs, API Gateway, CloudFront.

* In Azure, use App Service TLS settings or Azure Front Door, with certificates managed in Key Vault.

---

## **3\. Maintain a vulnerability management program**

**Requirement 5:** Protect all systems against malware and regularly update anti-virus software

* Deploy AWS Inspector or third-party anti-malware agents on EC2 and examine images in ECR.

* Use Microsoft Defender for Cloud on Azure VMs and containers.

**Requirement 6:** Develop and maintain secure systems and applications

* Integrate AWS CodePipeline with static code analysis (e.g. CodeGuru Reviewer) and SAST/SCA tools in your CI/CD.

* In Azure, integrate Azure DevOps or GitHub Actions with LGTM, WhiteSource or similar to scan code and container images, and enforce pipelines that only deploy pass-scanned artifacts.

---

## **4\. Implement strong access control measures**

**Requirement 7:** Restrict access to cardholder data by business need-to-know

* **AWS IAM**: Follow least-privilege – craft IAM policies that grant only the actions needed on specific resources (e.g. S3:GetObject on a “card-data” bucket).

* **Azure Entra ID**: Assign roles (built-in or custom) scoped to resource groups or subscriptions that house card-data resources; use PIM (Privileged Identity Management) to require just-in-time elevation.

**Requirement 8:** Identify and authenticate access to system components

* Enable MFA on all AWS accounts; require MFA for IAM users, root account, and API calls via conditions on `aws:MultiFactorAuthPresent`.

* In Entra ID, enforce Conditional Access requiring MFA for any login to card-data apps, and roll out passwordless options (FIDO2/WebAuthn) to eliminate weak passwords.

**Requirement 9:** Restrict physical access to cardholder data

* While cloud abstracts most physical concerns, ensure you only use PCI-validated, region-specific AWS/Azure datacenters (both are PCI DSS certified).

---

## **5\. Regularly monitor and test networks**

**Requirement 10:** Track and monitor all access to network resources and cardholder data

* **AWS**: Centralize logs in CloudWatch Logs/Log Lake, enable CloudTrail on all accounts, and forward to an SIEM (Splunk/QRadar). Use GuardDuty for anomaly detection.

* **Azure**: Enable Azure Monitor and Azure AD sign-in logs; send to Sentinel or another SIEM, turning on continuous export for audit trails.

**Requirement 11:** Regularly test security systems and processes

* Run quarterly external penetration tests and internal vulnerability scans on your AWS workloads (Inspector), and on Azure using Microsoft Defender vulnerability assessments.

* Validate WAF rules (AWS WAF, Azure WAF) through pen tests against OWASP Top 10\.

---

## **6\. Maintain an information security policy**

**Requirement 12:** Maintain a policy that addresses information security

* Document your use of AWS Shared Responsibility Model and Azure compliance framework mappings.

* Ensure policies cover user onboarding/offboarding in Entra ID, change management for IAM roles, incident response runbooks triggered by CloudWatch or Sentinel alerts, and periodic PCI-policy reviews.

---

### **How AWS \+ Azure Entra ID Fit into PCI DSS in Practice**

1. **Shared Responsibility**

   * AWS and Azure are responsible for the security “of” the cloud (physical datacenters, hypervisors, network fabric). You are responsible for security “in” the cloud (IAM, configs, data encryption).

2. **Identity Foundation**

   * Azure Entra ID (AAD) can federate with AWS IAM via SAML/OpenID Connect: users and service principals centrally managed in Entra ID can assume AWS roles without needing separate IAM user credentials. This makes enforcing Requirement 8 (MFA/strong authentication) and Requirement 7 (least privilege) far simpler and centralized.

3. **Automated Compliance**

   * Use AWS Config and Azure Policy to continuously evaluate resources against PCI DSS–aligned rules (e.g. “ensure all S3 buckets are not public,” “all SQL databases have TDE enabled”).

   * Automate remediation via Lambda (AWS) or Azure Automation runbooks to fix drift.

4. **Key Management & Encryption**

   * Both clouds offer native KMS/Key Vault services that integrate directly with compute, storage, and database services to satisfy Requirements 3 & 4 for encryption at rest/in transit without handling raw key material.

5. **Logging & Alerting**

   * Central SIEM ingestion of AWS CloudTrail, VPC Flow Logs, GuardDuty findings, plus Azure Monitor and Sentinel, provides the continuous monitoring required by Requirement 10 and feeds your incident response documented under Requirement 12\.

---

**Bottom Line:**  
 By leveraging AWS’s PCI-certified platform services, automating checks via Config/Policy, and centralizing identity and access controls in Azure Entra ID (with MFA, conditional access, and PIM), a FinTech company can build a compliant, scalable environment. Each of the 12 PCI DSS requirements maps naturally onto cloud-native controls in AWS and Azure, so long as you apply the Shared Responsibility Model and bake compliance into every layer of your architecture.


