# 🛡️ Entra ID Privileged Access & Identity Risk Assessment Toolkit

> **Mission:** Discover, assess, prioritize, explain, remediate, and continuously audit identity and privileged-access risks in Microsoft Entra ID.

This toolkit provides a comprehensive pipeline for Identity Governance in Microsoft Entra ID. It moves beyond simple reporting by integrating a **Risk Engine** that correlates user identities, groups, applications, and privileged access configurations (PIM/Roles) to generate actionable **Findings**, **Scores**, and **Remediation** paths.

---

## 🏗️ Architecture & Flow

The toolkit operates on the following logical pipeline, mirroring the structural hierarchy of an Entra ID Tenant:

```mermaid
graph TD
    Tenant[ENTRA ID TENANT] --> Users[USERS]
    Tenant --> Groups[GROUPS]
    Tenant --> Apps[APPLICATIONS]
    
    Users --> PrivAccess[PRIVILEGED ACCESS]
    Groups --> PrivAccess
    Apps --> PrivAccess
    
    PrivAccess --> PIM[PIM]
    PrivAccess --> Roles[ROLES]
    PrivAccess --> Perms[PERMISSIONS]
    
    PIM --> RiskEngine[RISK ENGINE]
    Roles --> RiskEngine
    Perms --> RiskEngine
    
    RiskEngine --> Findings[FINDINGS]
    RiskEngine --> Score[SCORE]
    
    Findings --> Recs[RECOMMENDATIONS]
    Score --> Recs
    
    Recs --> WhatIf[WHAT-IF MODE]
    WhatIf --> Remediation[REMEDIATION]
    Remediation --> ReValidation[RE-VALIDATION]
    ReValidation --> Audit[AUDIT]
