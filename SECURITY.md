# Security Policy

## Supported Versions

The following versions of OROCHI are currently maintained with security patches and critical vulnerability fixes:

| Version | Supported          | Notes                                     |
| ------- | ------------------ | ----------------------------------------- |
| 2.7.x   | :white_check_mark: | Current stable release                    |
| 2.6.x   | :white_check_mark: | Critical security patches only            |
| < 2.6   | :x:                | End of Life (upgrade immediately)         |

---

## Security Architecture & Defenses

Orochi incorporates multiple defense-in-depth security layers to safeguard forensic memory artifacts, analysis pipelines, and API integrations:

### 1. Protected Media Streaming (`X-Accel-Redirect`)
All memory dumps, extracted payloads, symbol packages, and forensic artifacts are served via internal Nginx `X-Accel-Redirect` headers. The Django application authenticates and authorizes the requesting user, resolves canonical storage paths, verifies bounds against storage roots, and instructs Nginx to stream the file internally. Direct user access to storage directories or arbitrary path traversal is strictly prohibited.

### 2. Symmetric Secrets Cryptography (AES-256-GCM)
API keys and secrets for third-party services (VirusTotal, MISP, AbuseIPDB, GreyNoise, Slack, Webhooks) are encrypted at rest in PostgreSQL using AES-256 in Galois/Counter Mode (GCM). Encryption keys are derived deterministically using HKDF from Django's `SECRET_KEY`, providing confidentiality and cryptographic authenticity against tampering.

### 3. Dual-Authentication API Gateway
Orochi's REST API supports both active web session authentication and personal API Bearer Tokens (`Authorization: Bearer oro_<secret>`). Bearer tokens are validated using a dual-component scheme: an 8-character lookup prefix and a 64-character SHA-256 hash. The plaintext secret is displayed only once upon generation and is never stored in plaintext within the database.

### 4. WebSocket Channel & User Isolation
Real-time notification consumers (`NotifyConsumer`) and collaborative presence channels (`CasePresenceConsumer`) validate active Django session credentials upon connection. Unauthenticated connections are rejected with WebSocket code `4401`. Requests targeting foreign user channels are rejected with code `4403`, and arbitrary client-originated broadcast messages are discarded to prevent cross-analyst spoofing.

### 5. Multi-Backend Authentication & RBAC
Authentication supports local credentials, MFA/TOTP, and enterprise directory integrations (LDAP, Active Directory) with granular Role-Based Access Control (RBAC) governing plugin execution, dump management, and case investigations.

---

## Reporting a Vulnerability

Please report suspected security vulnerabilities directly to the CERT team:

- **Email**: cert@leonardocompany.com
- **Response SLA**: Initial response within 48 hours.
- **Remediation SLA**: Confirmed security vulnerabilities are patched in a dedicated minor or patch release as rapidly as possible, typically within a few business days.

Please include:
1. A clear description of the vulnerability and potential impact.
2. Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
3. The affected component, endpoint, or configuration.
