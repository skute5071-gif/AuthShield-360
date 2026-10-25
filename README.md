# AuthShield 360 — Secure Account Protection and Suspicious Login Detection System

> **Department of Computer Engineering · Practical Cybersecurity & Cryptography Capstone Mini-Project**  
> **Academic Year 2026**

---

## 1. Project Abstract
**AuthShield 360** is a full-stack, production-grade cybersecurity application engineered to provide proactive account protection, behavioral threat detection, and real-time security auditing. Designed as a practical college mini-project for Computer Engineering students, the platform moves beyond static cybersecurity awareness by providing functional, verifiable defense engines:
1. **Suspicious Login Detection Engine** operating five automated heuristic rules with configurable thresholds.
2. **Dual-Mode Heuristic Phishing Checker** inspecting URLs and suspicious messages in an isolated sandbox without network traversal.
3. **Synthetic Payment Risk Analyzer** detecting duplicate transaction IDs, high-value anomalies, and velocity bursts, contextualized within Reserve Bank of India (RBI) customer protection circulars and the Payment and Settlement Systems Act, 2007 (PSSA).
4. **Cryptographic File Integrity Monitoring (FIM)** utilizing SHA-256/SHA-512 hashing and Shannon entropy calculation to detect unauthorized modifications and ransomware encryption.
5. **Security Controls Checklist & Audit Dossier** maintaining persistent compliance tracking across eight essential defense-in-depth domains with print-ready and sanitized CSV export capabilities.

---

## 2. Problem Statement
Modern cyber threats—such as credential stuffing, distributed brute-force attacks, sophisticated typosquatting, advance-fee scams, and transaction replay attacks—frequently exploit weak authentication and inadequate telemetry monitoring. Traditional academic projects often present static slideshows or simulated mockups that lack server-authoritative state, cryptographic integrity, or regulatory grounding. 

**AuthShield 360** bridges this gap by delivering a fully operational, responsive, and secure web application that implements deterministic threat detection algorithms, robust authentication (PBKDF2 hashing with 100,000 rounds, server-enforced RBAC, rate-limiting, and TOTP 2FA), and real-time audit logging while upholding strict ethical isolation principles.

---

## 3. Objectives and Scope
### Primary Objectives
- **Account Protection**: Deliver tamper-resistant user authentication with password complexity enforcement, salt-based hashing, role-based access control (Admin vs. User), and rate-limited account lockouts.
- **Behavioral Anomaly Detection**: Implement a 5-rule suspicious login detection engine with sliding-window evaluation and transparent risk scoring (0–100 scale: Low, Medium, High).
- **Social Engineering Defense**: Develop an offline lexical scanner for URLs and message text to identify homoglyphs, excessive subdomains, shortener obfuscation, and extortion keywords.
- **Financial Risk Modeling**: Analyze simulated payment telemetry for duplicate transaction identifiers, velocity bursts, and baseline spikes without connecting to live banking infrastructure.
- **Endpoint Integrity**: Implement SHA-256 baseline hashing and Shannon information entropy analysis to detect code tampering and high-entropy encryption payloads.
- **Academic Alignment**: Provide a verifiable syllabus mapping cross-referenced with foundational cybercrime case studies.

### Scope & Boundaries
- **In-Scope**: Pure software-level defensive heuristics, cryptographic digest calculation, stateful session handling, audit logging, and administrative review workflows.
- **Out-of-Scope**: Active scanning of remote networks, live penetration testing against third-party websites, execution of untrusted user uploads, or live bank/UPI gateway settlements.

---

## 4. System Architecture
AuthShield 360 is built upon a **Three-Tier Defense-in-Depth Architecture**:

```
+-------------------------------------------------------------------------------+
|                             PRESENTATION TIER                                 |
|  - React 19 (TypeScript) Single Page Application                             |
|  - Tailwind CSS Responsive Cybersecurity UI (Dark Navy / Slate Theme)         |
|  - Real-time Telemetry Dashboard, Review Drawers, and Interactive Tests       |
+-------------------------------------------------------------------------------+
                                      |
                     REST APIs (JSON / Bearer JWT Tokens)
                                      |
+-------------------------------------------------------------------------------+
|                       APPLICATION & DETECTION ENGINE TIER                     |
|  - Node.js & Express Server Runtime                                           |
|  - PBKDF2 Password Hashing & Time-Limited Reset Tokens                        |
|  - Heuristic Engine: Haversine Kinematics, Shannon Entropy, Levenshtein Metric|
|  - 5-Rule Suspicious Login Evaluator & Rate-Limiter (Sliding Window)          |
|  - Payment Risk Scorer & RBI Statutory Compliance Validator                   |
+-------------------------------------------------------------------------------+
                                      |
                     Server-Authoritative In-Memory State
                                      |
+-------------------------------------------------------------------------------+
|                              PERSISTENCE TIER                                 |
|  - In-Memory State Engine (Events, Alerts, Baseline Files, Audit Logs)        |
|  - Ready for Firebase Authentication & Cloud Firestore Provisioning           |
+-------------------------------------------------------------------------------+
```

---

## 5. Technology Stack
| Layer | Technology | Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Frontend** | React, TypeScript | 19.x / 5.x | Modular UI components, stateful hooks, type safety |
| **Styling** | Tailwind CSS | 4.x | Dark navy cybersecurity theme, zero-pill discipline |
| **Icons** | Lucide React | Latest | Clean, consistent security telemetry iconography |
| **Backend** | Node.js & Express | 22.x / 4.x | REST API server, authentication middleware, rate limiting |
| **Cryptography** | Node.js `node:crypto` & Web Crypto API | Standard | PBKDF2-HMAC-SHA512, SHA-256, SHA-512, MD5, Shannon entropy |
| **Build & Dev** | Vite, tsx, esbuild | Latest | Fast bundler, HMR in development, static production build |
| **Database** | Built-in State Engine / Firestore-Ready | Current | Persistent events, alerts, baselines, and audit logs |

---

## 6. Module Descriptions

### Module 1: Dashboard (`/`)
- Aggregates overall system security metrics: Total login events, failed logins, active suspicious alerts, and firewall perimeter drop count.
- Visual risk distribution chart (Low, Medium, High).
- Suspicious events review table with interactive detail drawer, review status selector (**REVIEWED**, **DISMISSED**, **ESCALATED**), and investigation note recording.
- Administrative audit log feed tracking all operator actions.

### Module 2: Login Security (`login-security`)
- Interactive Suspicious Login Simulator testing Rules 1 through 5.
- Preset test scenarios: Ordinary Domestic Login, Brute-Force Credential Guessing, Rapid Success After Failures, Velocity Burst, and False-Positive Baseline Anomaly.
- Visual breakdown of factors, rule penalty points, recommended actions, and non-proof disclaimers.

### Module 3: Security Events (`security-events`)
- Searchable and filterable audit trail for all system events.
- Filter by severity (**ALL**, **LOW**, **MEDIUM**, **HIGH**) and event type.
- Forensic detail modal showing full event context, IP addresses, geo-locations, and timestamps.

### Module 4: Phishing Checker (`phishing-checker`)
- **Mode 1 (URL Analysis)**: Static inspection of submitted URLs for IP hostnames, URL shorteners, Cyrillic IDN homoglyphs (Punycode), deep subdomain nesting, and brand typosquatting. Never sends HTTP requests to destination domains.
- **Mode 2 (Message Analysis)**: Text scanner identifying psychological urgency, credential exfiltration requests, bank/KYC deactivation threats, and lottery lures.
- **User History**: Authenticated user audit trail of performed scans with a "Clear History" button.

### Module 5: Payment Risk Analyzer (`payment-risk`)
- **Synthetic Telemetry Sandbox**: 100% synthetic records; no real financial accounts or gateways are contacted.
- **Input Channels**: Synthetic batch generator, manual fictional entry, and bulk CSV ingestion with line-by-line schema validation.
- **Analysis Rules**: Duplicate transaction ID collisions, amount spikes exceeding $500 baseline, rapid 5-minute repetitions, and preceding failures.
- **Regulatory Framework**: Educational breakdown of the Reserve Bank of India (RBI) Zero Customer Liability circular (2017) and the Payment and Settlement Systems Act, 2007 (PSSA).
- **Export & Verification**: Export reports in CSV and JSON; built-in automated test suite.

### Module 6: File Integrity Monitoring (`file-integrity`)
- **User File Upload**: Allows the user to select or drag-and-drop any local file to compute SHA-256, SHA-512, and MD5 hashes using trusted crypto implementations.
- **Baseline Comparison**: Compares calculated hash with authoritative golden baselines or user-supplied reference hashes, reporting status (**MATCH / UNCHANGED** vs. **MISMATCH / TAMPERED**).
- **Ransomware & Entropy Detection**: Computes Shannon entropy; values exceeding 7.5 bits indicate encryption or packing.
- **Tamper Simulation Lab**: In-browser code workspace to simulate backdoor injection and ransomware high-entropy scrambling.
- **Safety Policy**: Processes only intentionally provided files; never executes uploads; explains that a matching hash proves integrity relative to a baseline, not inherent trustworthiness.

### Module 7: Security Checklist & Reports (`reports`)
- **Executive Dossier**: Aggregates login counts, suspicious alerts, phishing totals, payment risk results, FIM comparisons, and checklist completion percentage.
- **Sanitized Export**: Print-friendly layout and sanitized CSV export omitting credentials, hashes of secrets, and session tokens.
- **Security Checklist**: Interactive 8-domain controls verification (Passwords & MFA, Software Updates, Backups, Firewall/Antivirus, Wi-Fi, Permissions, Dependencies, Session Protection) with cloud persistence for signed-in users.
- **Curriculum Mapping**: Syllabus mapping table cross-referenced with foundational cybercrime case studies.

### Module 8: Settings (`settings`)
- Configurable detection thresholds: `failedLoginsThreshold` (default: 5), `failedLoginsWindowMinutes` (default: 5m), `burstVelocityThresholdPerMinute` (default: 8), and `paymentBaselineAmount` (default: $500).
- Perimeter firewall IP blocklist management (Ban / Unban with audit log recording).
- User profile management and Two-Factor Authentication (2FA) toggle.

---

## 7. Database Structure

The internal state engine operates with structured entities ready for Cloud Firestore synchronization:

### 1. `users` Collection
```typescript
interface User {
  id: string;
  name: string;
  email: string; // Unique primary key
  passwordHash: string; // PBKDF2-HMAC-SHA512 (100,000 iterations)
  salt: string; // 16-byte random salt
  role: 'admin' | 'user';
  twoFactorEnabled: boolean;
  createdAt: string;
}
```

### 2. `security_events` Collection
```typescript
interface SecurityEvent {
  id: string; // e.g. "evt-101"
  timestamp: string;
  type: 'LOGIN_SUCCESS' | 'LOGIN_FAILED' | 'IMPOSSIBLE_TRAVEL' | 'BRUTE_FORCE_BURST' | 'FILE_INTEGRITY_TAMPER' | 'PHISHING_BLOCKED' | 'PAYMENT_FLAGGED';
  userEmail: string;
  ip: string;
  location: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'LOGGED' | 'ACTION_TAKEN' | 'BLOCKED' | 'FLAGGED';
  description: string;
  details?: Record<string, any>;
  isDemo: boolean;
}
```

### 3. `security_alerts` Collection
```typescript
interface SecurityAlert {
  id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  category: 'LOGIN_SECURITY' | 'CREDENTIAL_ATTACK' | 'MALICIOUS_NETWORK' | 'FILE_SYSTEM' | 'FRAUD_RISK';
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
  sourceIp: string;
  userEmail: string;
  riskScore: number; // 0 to 100
  timestamp: string;
  recommendation: string;
  isReviewed?: boolean;
  reviewedBy?: string;
  investigationNotes?: Array<{ id: string; timestamp: string; author: string; note: string }>;
}
```

### 4. `baseline_files` Collection
```typescript
interface BaselineFile {
  id: string;
  filename: string;
  filepath: string;
  baselineSha256: string;
  baselineSha512: string;
  entropy: number;
  sizeBytes: number;
  lastVerified: string;
  status: 'HEALTHY' | 'MODIFIED' | 'TAMPERED';
  isCriticalSystemFile: boolean;
}
```

### 5. `security_checklist` Collection (Per-User)
```typescript
interface SecurityChecklistState {
  userEmail: string;
  items: Array<{
    id: string;
    category: string;
    title: string;
    description: string;
    completed: boolean;
    notes?: string;
    lastChecked?: string;
  }>;
  lastUpdated: string;
  completionPercentage: number;
}
```

---

## 8. Syllabus Mapping Table

| Academic Unit | Syllabus Subject Matter | AuthShield 360 Implemented Feature | Reference Case Study & Academic Context |
| :--- | :--- | :--- | :--- |
| **Unit I** | Cybersecurity fundamentals, defense-in-depth, three-tier web application architecture, and access control. | Three-tier perimeter architecture, server-side RBAC authorization, sliding-window rate limiting, and HTTP security headers. | **OWASP Top 10 Web Vulnerabilities**: Architectural prevention of Broken Access Control (A01:2021) and Cryptographic Failures (A02:2021). |
| **Unit II** | Cybercrime concepts, brute-force attacks, suspicious login anomalies, and incident response. | Suspicious Login Detection Engine (Rules 1–5), configurable failure thresholds, and admin investigation audit logs. | **WannaCry Ransomware (2017)**: Exploited the EternalBlue SMB flaw (MS17-010), infecting 200,000+ computers across 150 countries; emphasizes automated perimeter isolation and rapid incident handling. |
| **Unit III** | Social engineering, phishing indicators, psychological manipulation, and digital privacy. | Dual-Mode Phishing Checker (URL lexical analysis for Punycode/homoglyphs & message extortion keyword scanner). | **WhatsApp Pegasus Spyware (2019) & Cambridge Analytica (2018)**: Exploitation of user trust, zero-click buffer overflows, and unauthorized harvesting of 87M user profiles for psychographic manipulation. |
| **Unit IV** | Digital payment risk, transaction fraud scoring, duplicate charges, and statutory regulations. | Synthetic Payment Risk Analyzer, duplicate ID detection, CSV ingestion with schema validation, and risk distribution metrics. | **Cosmos Bank Cyber Attack (Pune, 2018) & RBI Directives**: $13.5M exfiltrated via ATM switch malware and clone cards; Reserve Bank of India Zero Customer Liability circular (2017) and Payment and Settlement Systems Act, 2007 (PSSA). |
| **Unit V** | Authentication protocols, endpoint security, file integrity monitoring, cryptographic hashing, backups, and patching. | Cryptographic FIM (SHA-256/SHA-512, Shannon entropy), PBKDF2 password security, and 8-domain Security Checklist. | **Endpoint Integrity & 3-2-1 Backups**: Principles of one-way hash resistance, detection of encrypted ransomware payloads, and automated patch management. |

---

## 9. Installation and Configuration Steps

### Prerequisites
- Node.js version 20.x or 22.x LTS
- npm version 9.x or higher

### Step-by-Step Setup
1. **Clone or Extract Project Files**:
   ```bash
   cd /app/applet
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Copy `.env.example` to `.env` (development defaults are pre-configured):
   ```bash
   cp .env.example .env
   ```

4. **Run Development Server**:
   ```bash
   npm run dev
   ```
   The application initializes on port `3000` (`http://localhost:3000`).

5. **Build for Production**:
   ```bash
   npm run build
   ```

6. **Seed Test Accounts**:
   - **Administrator**: `admin@authshield.internal` | Password: `Admin@AuthShield2026!`
   - **Standard Student**: `priya.student@college.edu` | Password: `Student@AuthShield2026!`

---

## 10. Test Cases and Verification Results

The built-in automated **Verification Suite** (`ShieldCheck` icon in top bar) executes nine comprehensive test assertions:

| Test ID | Test Name | Assertion Criteria | Result |
| :--- | :--- | :--- | :--- |
| **TC-01** | Password Complexity & Registration | Requires >=8 characters, mixed case, numbers, symbols; prevents duplicate emails. | **PASSED** |
| **TC-02** | Zero Plaintext & PBKDF2 Hashing | Confirms passwords/salts are omitted from API responses; verifies HMAC-SHA512 iterations. | **PASSED** |
| **TC-03** | Session Invalidation on Logout | Verifies cryptographic bearer token invalidation upon calling `/api/auth/logout`. | **PASSED** |
| **TC-04** | Server-Side RBAC Enforcement | Ensures standard users attempting administrative actions (e.g., IP bans) receive 403 Forbidden. | **PASSED** |
| **TC-05** | Rate-Limiting & Lockout | Confirms 5 consecutive failed logins trigger 429 Too Many Requests and rate-limit lockout. | **PASSED** |
| **TC-06** | Cryptographic Password Reset | Validates 32-byte single-use reset token and session revocation upon password update. | **PASSED** |
| **TC-07** | Suspicious Login Engine (Rules 1–5) | Confirms sliding-window failure count, velocity bursts, and headless signals yield risk score >=70. | **PASSED** |
| **TC-08** | Phishing Heuristics (URL & Message) | Confirms typosquatting, Cyrillic homoglyphs, and urgent OTP extortion keywords flag High Risk. | **PASSED** |
| **TC-09** | Payment Risk & Duplicate ID Anomaly | Confirms duplicate ID collisions and $1,850 amount spikes trigger anomaly warnings and risk >=30. | **PASSED** |

---

## 11. Limitations
1. **Rule-Based Heuristic Nature**: Detection algorithms evaluate behavioral patterns and structural indicators. They do not claim 100% accuracy and can produce false positives (e.g., authentic executive travel) or false negatives (e.g., zero-day evasion techniques).
2. **Synthetic Data Boundaries**: Payment telemetry and sample attack data are purely simulated fixtures for academic laboratory demonstration.
3. **Static File Analysis**: File integrity verification establishes data consistency relative to a recorded baseline; it does not perform dynamic malware detonation or runtime kernel hooks.
4. **Offline Phishing Isolation**: URLs are parsed syntactically and never traversed over the network, meaning server-side redirects or cloaked landing pages cannot be fetched.

---

## 12. Future Scope
- **Hardware Security Key Integration**: Extend WebAuthn to support physical FIDO2/U2F security keys and platform biometrics (TouchID/Windows Hello).
- **Machine Learning Anomaly Clustering**: Implement unsupervised clustering (DBSCAN / Isolation Forests) to dynamically adjust risk penalties based on multi-user baseline drift.
- **SIEM / Syslog Forwarding**: Export RFC 5424 compliant syslog feeds to external security operations platforms (Splunk, Elastic SIEM, Wazuh).
- **Cloud Firestore Real-Time Subscriptions**: Activate Firestore real-time snapshot listeners for multi-operator concurrent incident triaging.

---

## 13. Ethical and Privacy Considerations
- **Non-Proof Disclaimer**: Every risk score output clearly states that numeric scores are defensive behavioral indicators, not legal proof of malicious conduct.
- **Privacy by Design**: Sensitive user parameters (passwords, plaintext tokens) are never logged or stored. IP addresses and locations are treated as sensitive telemetry.
- **Proportional Response**: The platform favors step-up authentication challenges (MFA/biometric verification) over permanent lockouts to prevent denial-of-service against legitimate users.
- **Academic Integrity**: Sample data is explicitly labeled as `[DEMO DATA]` or `[SYNTHETIC]` to avoid misrepresenting simulations as real-world security breaches.

---

*AuthShield 360 — Built with precision for the Computer Engineering Department.*
