# Enterprise-IAM-Engineering-Lab-v2
Production-inspired Identity and Access Management (IAM) platform built with Python, FastAPI, Active Directory, Entra ID, Okta, OrangeHRM, PostgreSQL, MariaDB, Jira, Splunk, Docker, and RBAC to automate identity lifecycle management and enterprise access provisioning.
---

# Enterprise IAM Engineering Lab v2

Enterprise IAM Engineering Lab v2 is a production-inspired Identity and Access Management (IAM) platform that automates the complete employee identity lifecycle across enterprise environments.

The platform integrates an HR system (OrangeHRM with MariaDB) as the authoritative identity source with Active Directory to automate Joiner, Mover, and Leaver (JML) workflows. Built with Python, FastAPI, PostgreSQL, Docker, Redis, and Nginx, it provides REST APIs, RBAC enforcement, workflow automation, audit logging, and integrations with Jira and Splunk for ticketing, monitoring, and compliance.

This project demonstrates enterprise IAM architecture, identity governance, directory services, API development, infrastructure automation, and security operations using technologies commonly deployed in modern enterprise environments.

---

## Technologies

### Identity & Access Management
- Active Directory
- LDAP
- Kerberos
- RBAC
- JML Automation

### Backend
- Python
- FastAPI
- Uvicorn
- REST API

### Databases
- PostgreSQL
- MariaDB

### Infrastructure
- Ubuntu Server
- Windows Server
- Docker
- Docker Compose
- Nginx
- Redis
- Git

### HR System
- OrangeHRM

### Ticketing
- Jira

### Monitoring & Logging
- Splunk Enterprise
- Splunk Universal Forwarder

### Future Integrations
- Microsoft Entra ID
- Okta
- Google Workspace

## APP01 API Authentication and RBAC

APP01 operational endpoints use API-key authentication through the `X-API-Key` header. Secret values exist only in `/opt/iam-platform/.env`, which has `0600` permissions and is excluded from Git.

| Principal | Authorized responsibility |
| --- | --- |
| `iam.viewer` | Read employees, OAuth status, and identity requests |
| `iam.sync` | Run OrangeHRM employee synchronization |
| `iam.approver` | Read, approve, and reject identity requests |
| `iam.provisioner` | Read, provision, and retry identity requests |
| `iam.admin` | Administrative override across all roles |

Approval and rejection audit identities come from the authenticated API-key principal. Client-provided `approved_by` and `rejected_by` values are not trusted as the actor identity.

Security controls include constant-time key comparison, HTTP `401` for invalid credentials, HTTP `403` for insufficient roles, HTTP `503` for missing key configuration, and separation of approval and provisioning responsibilities.

Validation completed successfully with `34 passed` automated tests, including API authentication, role boundaries, JML regression, retries, idempotency, and OAuth security.
