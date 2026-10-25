import crypto from 'node:crypto';
import {
  PaymentTransactionRecord,
  evaluatePaymentTransactions,
} from './engine.ts';

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type:
    | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILED'
    | 'IMPOSSIBLE_TRAVEL'
    | 'BRUTE_FORCE_BURST'
    | 'TOR_ACCESS'
    | 'NEW_DEVICE'
    | 'FILE_INTEGRITY_TAMPER'
    | 'PHISHING_BLOCKED'
    | 'PAYMENT_FLAGGED'
    | 'UNAUTHORIZED_ACCESS_ATTEMPT'
    | 'ADMIN_ACTION';
  userEmail: string;
  ip: string;
  location: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  status: 'LOGGED' | 'ACTION_TAKEN' | 'BLOCKED' | 'FLAGGED';
  description: string;
  details?: Record<string, any>;
  isDemo: boolean;
}

export interface AlertInvestigationNote {
  id: string;
  timestamp: string;
  author: string;
  note: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
  category: 'LOGIN_SECURITY' | 'CREDENTIAL_ATTACK' | 'MALICIOUS_NETWORK' | 'FILE_SYSTEM' | 'FRAUD_RISK';
  status: 'ACTIVE' | 'INVESTIGATING' | 'RESOLVED' | 'DISMISSED';
  sourceIp: string;
  userEmail: string;
  riskScore: number;
  timestamp: string;
  recommendation: string;
  mitigationActionTaken?: string;
  isDemo: boolean;
  isReviewed?: boolean;
  reviewedBy?: string;
  reviewedAt?: string;
  investigationNotes?: AlertInvestigationNote[];
}

export interface BaselineFile {
  id: string;
  filename: string;
  filepath: string;
  baselineSha256: string;
  baselineSha512: string;
  entropy: number;
  sizeBytes: number;
  lastVerified: string;
  status: 'HEALTHY' | 'MODIFIED' | 'TAMPERED' | 'MISSING';
  isCriticalSystemFile: boolean;
}

export interface SecuritySettings {
  failedLoginsThreshold: number; // default: 5
  failedLoginsWindowMinutes: number; // default: 5
  burstVelocityThresholdPerMinute: number; // default: 8
  geoVelocityThresholdKmH: number;
  maxFailedAttempts: number;
  mfaScoreThreshold: number;
  blockScoreThreshold: number;
  blockTorByDefault: boolean;
  autoLockMinutes: number;
  paymentBaselineAmount: number; // default: 500
  defenseMode: 'NORMAL' | 'ELEVATED' | 'HIGH_ALERT';
}

export interface AdminAuditLog {
  id: string;
  timestamp: string;
  adminEmail: string;
  actionType:
    | 'ALERT_STATUS_UPDATE'
    | 'ALERT_NOTE_ADDED'
    | 'SETTINGS_UPDATE'
    | 'IP_BLOCK'
    | 'IP_UNBLOCK'
    | 'SYNTHETIC_DATA_GENERATE'
    | 'BATCH_DETECTION_RUN'
    | 'PHISHING_HISTORY_CLEAR';
  targetId?: string;
  details: string;
  note?: string;
}

export interface PhishingHistoryItem {
  id: string;
  userEmail: string;
  timestamp: string;
  type: 'URL' | 'MESSAGE';
  targetPreview: string;
  riskScore: number;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  indicatorsCount: number;
  verdict: string;
}

export interface SecurityChecklistItem {
  id: string;
  category: string;
  title: string;
  description: string;
  completed: boolean;
  notes?: string;
  lastChecked?: string;
}

export interface SecurityChecklistState {
  userEmail: string;
  items: SecurityChecklistItem[];
  lastUpdated: string;
  completionPercentage: number;
}

export const DEFAULT_CHECKLIST_ITEMS: SecurityChecklistItem[] = [
  {
    id: 'passwords-mfa',
    category: 'Identity & Access Management',
    title: 'Strong Passwords and Multifactor Authentication',
    description: 'Enforce >=12 characters with uppercase, lowercase, numbers, and symbols; mandate Time-based OTP (TOTP/FIDO2) across all administrator and user profiles.',
    completed: true,
    notes: 'PBKDF2-HMAC-SHA512 hashing with 100,000 rounds and mandatory 6-digit TOTP verification implemented.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'software-updates',
    category: 'Vulnerability Management',
    title: 'Software Updates & Automated Patching',
    description: 'Keep operating systems, runtime engines, and web servers updated to latest stable releases; apply zero-day security advisories within 72 hours.',
    completed: true,
    notes: 'Node.js LTS runtime and latest security patches verified.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'backups',
    category: 'Data Resilience & Continuity',
    title: 'Backups & 3-2-1 Immutability Strategy',
    description: 'Maintain 3 copies of vital data across 2 separate storage media, with at least 1 offsite or air-gapped immutable backup to defend against ransomware.',
    completed: false,
    notes: 'Need to configure weekly immutable snapshot archival to secondary cloud region.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'firewall-antivirus',
    category: 'Endpoint & Perimeter Protection',
    title: 'Firewall and Antivirus / EDR Defenses',
    description: 'Enforce host-based stateful firewall packet filtering, drop known malicious IP blocks, and run real-time behavioral heuristics.',
    completed: true,
    notes: 'Perimeter gateway firewall drop table active with automated Tor exit-node mitigation.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'wifi-security',
    category: 'Network Security',
    title: 'Wi-Fi Security & Network Segmentation',
    description: 'Enforce WPA3-Personal or WPA2-Enterprise (802.1X); disable legacy Wi-Fi Protected Setup (WPS); isolate IoT devices and guest traffic into separate VLANs.',
    completed: false,
    notes: 'Campus network audit recommended to verify VLAN isolation for administrative endpoints.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'app-permissions',
    category: 'Device Hardening & Least Privilege',
    title: 'App Permissions & Sensor Access Control',
    description: 'Audit applications and revoke unnecessary access to hardware camera, microphone, keystroke accessibility, and background geolocation.',
    completed: true,
    notes: 'Principle of least privilege enforced; zero unnecessary client device permissions requested.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'dependency-updates',
    category: 'Application Security & Supply Chain',
    title: 'Third-Party Dependency Updates & SBOM Audits',
    description: 'Scan npm/pip libraries for known CVEs using automated scanners (npm audit, Snyk/Dependabot) to guard against supply chain poisoning.',
    completed: true,
    notes: 'Zero critical vulnerabilities reported across project package dependency manifest.',
    lastChecked: '2026-10-25',
  },
  {
    id: 'session-account-protection',
    category: 'Web Application Defense',
    title: 'Session and Account Protection Controls',
    description: 'Enforce HttpOnly/Secure/SameSite cookies, 15-minute inactivity timeout, sliding-window rate limiting, and brute-force temporary lockout.',
    completed: true,
    notes: 'Server-side token invalidation, 5-minute brute-force lockout, and rate limiting active.',
    lastChecked: '2026-10-25',
  },
];

const DEFAULT_SETTINGS: SecuritySettings = {
  failedLoginsThreshold: 5,
  failedLoginsWindowMinutes: 5,
  burstVelocityThresholdPerMinute: 8,
  geoVelocityThresholdKmH: 800,
  maxFailedAttempts: 5,
  mfaScoreThreshold: 30,
  blockScoreThreshold: 70,
  blockTorByDefault: true,
  autoLockMinutes: 15,
  paymentBaselineAmount: 500,
  defenseMode: 'NORMAL',
};

// Seed baseline files for File Integrity Monitoring
const INITIAL_BASELINE_FILES: BaselineFile[] = [
  {
    id: 'fim-01',
    filename: 'auth.service.ts',
    filepath: '/server/services/auth.service.ts',
    baselineSha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    baselineSha512: 'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e470f8819a189b21ed7389da53ee5df46966f81317ced6ab51116021cbcdf0c64d4e412fff4ced46e9b',
    entropy: 4.82,
    sizeBytes: 4210,
    lastVerified: '2026-10-25 01:15 UTC',
    status: 'HEALTHY',
    isCriticalSystemFile: true,
  },
  {
    id: 'fim-02',
    filename: 'security.rules',
    filepath: '/config/security.rules',
    baselineSha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    baselineSha512: 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
    entropy: 4.21,
    sizeBytes: 1540,
    lastVerified: '2026-10-25 01:20 UTC',
    status: 'HEALTHY',
    isCriticalSystemFile: true,
  },
  {
    id: 'fim-03',
    filename: 'credentials.vault.enc',
    filepath: '/secrets/credentials.vault.enc',
    baselineSha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    baselineSha512: 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86',
    entropy: 7.91,
    sizeBytes: 8192,
    lastVerified: '2026-10-25 01:10 UTC',
    status: 'HEALTHY',
    isCriticalSystemFile: true,
  },
];

const INITIAL_EVENTS: SecurityEvent[] = [
  {
    id: 'evt-101',
    timestamp: '2026-10-25 02:10:15',
    type: 'IMPOSSIBLE_TRAVEL',
    userEmail: 'dev.sarah@college.edu',
    ip: '185.220.101.5',
    location: 'Frankfurt, Germany',
    severity: 'HIGH',
    status: 'BLOCKED',
    description: '[DEMO DATA] Impossible Travel: Account accessed from Frankfurt 14 minutes after legitimate login in San Francisco, USA (Velocity: 3,740 km/h).',
    details: { geoVelocityKmH: 3740, distanceKm: 8720, timeDeltaMin: 14, blocked: true },
    isDemo: true,
  },
  {
    id: 'evt-102',
    timestamp: '2026-10-25 02:05:50',
    type: 'BRUTE_FORCE_BURST',
    userEmail: 'admin@college.edu',
    ip: '194.26.29.112',
    location: 'Bucharest, Romania',
    severity: 'HIGH',
    status: 'BLOCKED',
    description: '[DEMO DATA] Rule 1 Trigger: 5 failed attempts within 3 minutes from same source IP against administrator endpoint.',
    details: { attempts: 5, windowMinutes: 3, policyAction: 'IP_TEMPORARY_BLOCK' },
    isDemo: true,
  },
  {
    id: 'evt-103',
    timestamp: '2026-10-25 01:52:10',
    type: 'TOR_ACCESS',
    userEmail: 'finance.lead@college.edu',
    ip: '176.10.99.200',
    location: 'Zurich, Switzerland (Tor Node)',
    severity: 'MEDIUM',
    status: 'ACTION_TAKEN',
    description: '[DEMO DATA] Rule 5 Signal: Login attempted through verified Tor Exit Node. MFA challenge triggered.',
    details: { isTor: true, action: 'REQUIRE_MFA', mfaSuccess: true },
    isDemo: true,
  },
  {
    id: 'evt-104',
    timestamp: '2026-10-25 01:35:00',
    type: 'NEW_DEVICE',
    userEmail: 'student.alex@college.edu',
    ip: '72.14.201.88',
    location: 'Chicago, USA',
    severity: 'LOW',
    status: 'LOGGED',
    description: '[DEMO DATA] Rule 4 Signal: First login from Firefox on Linux x86_64 compared to historical macOS baseline.',
    details: { browser: 'Firefox 135', os: 'Linux', isKnownDevice: false },
    isDemo: true,
  },
  {
    id: 'evt-105',
    timestamp: '2026-10-25 01:15:14',
    type: 'PHISHING_BLOCKED',
    userEmail: 'staff.marcus@college.edu',
    ip: '104.244.42.1',
    location: 'Ashburn, USA',
    severity: 'HIGH',
    status: 'BLOCKED',
    description: '[DEMO DATA] Phishing Defense: Intercepted link impersonating internal portal (paypa1-support-verify.xyz).',
    details: { targetedBrand: 'paypal', score: 85 },
    isDemo: true,
  },
  {
    id: 'evt-106',
    timestamp: '2026-10-25 00:55:05',
    type: 'LOGIN_SUCCESS',
    userEmail: 'priya.student@college.edu',
    ip: '24.180.12.9',
    location: 'San Jose, USA',
    severity: 'LOW',
    status: 'LOGGED',
    description: '[DEMO DATA] Legitimate Login: Standard student profile session verified from known campus network.',
    details: { riskScore: 8, policy: 'ALLOW' },
    isDemo: true,
  },
];

const INITIAL_ALERTS: SecurityAlert[] = [
  {
    id: 'alt-001',
    title: '[DEMO ALERT] Repeated Failed Logins within 5m Window (Rule 1)',
    severity: 'HIGH',
    category: 'CREDENTIAL_ATTACK',
    status: 'ACTIVE',
    sourceIp: '194.26.29.112',
    userEmail: 'admin@college.edu',
    riskScore: 88,
    timestamp: '2026-10-25 02:05:50',
    recommendation: 'Temporarily lock target account, blacklist source IP in gateway drop table, and require biometric step-up.',
    isDemo: true,
    isReviewed: false,
    investigationNotes: [
      {
        id: 'note-1',
        timestamp: '2026-10-25 02:07:10',
        author: 'admin@authshield.internal',
        note: 'Automated burst detection triggered on administrator portal. Source IP appended to perimeter review queue.',
      },
    ],
  },
  {
    id: 'alt-002',
    title: '[DEMO ALERT] Impossible Travel Anomaly (Velocity > 3,700 km/h)',
    severity: 'HIGH',
    category: 'LOGIN_SECURITY',
    status: 'INVESTIGATING',
    sourceIp: '185.220.101.5',
    userEmail: 'dev.sarah@college.edu',
    riskScore: 92,
    timestamp: '2026-10-25 02:10:15',
    recommendation: 'Enforce immediate credential revocation, invalidate active JWT session tokens, and require biometric re-enrollment.',
    isDemo: true,
    isReviewed: true,
    reviewedBy: 'admin@authshield.internal',
    reviewedAt: '2026-10-25 02:12:00',
    investigationNotes: [
      {
        id: 'note-2',
        timestamp: '2026-10-25 02:12:00',
        author: 'admin@authshield.internal',
        note: 'Reviewing employee travel schedule; confirmed employee was in SF. Probable credential compromise via German VPN.',
      },
    ],
  },
  {
    id: 'alt-003',
    title: '[DEMO ALERT] Multiple Failures Preceding Success (Rule 2)',
    severity: 'MEDIUM',
    category: 'LOGIN_SECURITY',
    status: 'ACTIVE',
    sourceIp: '176.10.99.200',
    userEmail: 'finance.lead@college.edu',
    riskScore: 58,
    timestamp: '2026-10-25 01:52:10',
    recommendation: 'Prompt user for immediate password change and verify recent financial ledger access audit.',
    isDemo: true,
    isReviewed: false,
    investigationNotes: [],
  },
];

// Initial Synthetic Payment Transactions
const INITIAL_SYNTHETIC_PAYMENTS: PaymentTransactionRecord[] = [
  {
    transactionId: 'TXN-SYNTH-1001',
    accountRef: 'ACC-****-4912',
    amount: 45.50,
    timestamp: '2026-10-25T02:00:10Z',
    paymentMethod: 'UPI',
    transactionResult: 'SUCCESS',
    merchantCategory: 'GROCERY',
    isSynthetic: true,
  },
  {
    transactionId: 'TXN-SYNTH-1002',
    accountRef: 'ACC-****-8819',
    amount: 3800.00,
    timestamp: '2026-10-25T02:02:45Z',
    paymentMethod: 'CREDIT_CARD',
    transactionResult: 'SUCCESS',
    merchantCategory: 'ELECTRONICS',
    isSynthetic: true,
  },
  {
    transactionId: 'TXN-SYNTH-1003',
    accountRef: 'ACC-****-8819',
    amount: 3800.00,
    timestamp: '2026-10-25T02:03:15Z',
    paymentMethod: 'CREDIT_CARD',
    transactionResult: 'SUCCESS',
    merchantCategory: 'ELECTRONICS',
    isSynthetic: true,
  },
  {
    transactionId: 'TXN-SYNTH-1004',
    accountRef: 'ACC-****-3301',
    amount: 15.00,
    timestamp: '2026-10-25T02:04:00Z',
    paymentMethod: 'DEBIT_CARD',
    transactionResult: 'FAILED',
    merchantCategory: 'GAMING',
    isSynthetic: true,
  },
  {
    transactionId: 'TXN-SYNTH-1004', // Duplicate ID
    accountRef: 'ACC-****-3301',
    amount: 15.00,
    timestamp: '2026-10-25T02:04:30Z',
    paymentMethod: 'DEBIT_CARD',
    transactionResult: 'FAILED',
    merchantCategory: 'GAMING',
    isSynthetic: true,
  },
  {
    transactionId: 'TXN-SYNTH-1005',
    accountRef: 'ACC-****-3301',
    amount: 15.00,
    timestamp: '2026-10-25T02:05:00Z',
    paymentMethod: 'DEBIT_CARD',
    transactionResult: 'SUCCESS',
    merchantCategory: 'GAMING',
    isSynthetic: true,
  },
  {
    transactionId: 'TXN-SYNTH-1006',
    accountRef: 'ACC-****-7102',
    amount: 120.00,
    timestamp: '2026-10-25T02:06:12Z',
    paymentMethod: 'NET_BANKING',
    transactionResult: 'SUCCESS',
    merchantCategory: 'UTILITIES',
    isSynthetic: true,
  },
];

class MemoryDatabase {
  private events: SecurityEvent[] = [];
  private alerts: SecurityAlert[] = [];
  private baselineFiles: BaselineFile[] = [];
  private settings: SecuritySettings = { ...DEFAULT_SETTINGS };
  private blockedIps: Set<string> = new Set(['185.220.101.5', '194.26.29.112']);
  private adminAuditLogs: AdminAuditLog[] = [];
  private phishingHistories: Map<string, PhishingHistoryItem[]> = new Map(); // userEmail -> items
  private paymentTransactions: PaymentTransactionRecord[] = [];
  private userChecklists: Map<string, SecurityChecklistState> = new Map();
  private fileAnalysisCount: number = 0;

  constructor() {
    this.resetToDemo();
  }

  resetToDemo() {
    this.events = JSON.parse(JSON.stringify(INITIAL_EVENTS));
    this.alerts = JSON.parse(JSON.stringify(INITIAL_ALERTS));
    this.baselineFiles = JSON.parse(JSON.stringify(INITIAL_BASELINE_FILES));
    this.settings = { ...DEFAULT_SETTINGS };
    this.blockedIps = new Set(['185.220.101.5', '194.26.29.112']);
    this.adminAuditLogs = [
      {
        id: 'audit-01',
        timestamp: '2026-10-25 02:07:10',
        adminEmail: 'admin@authshield.internal',
        actionType: 'ALERT_NOTE_ADDED',
        targetId: 'alt-001',
        details: 'Added investigation note to Alert alt-001 (Repeated Failed Logins).',
      },
      {
        id: 'audit-02',
        timestamp: '2026-10-25 02:12:00',
        adminEmail: 'admin@authshield.internal',
        actionType: 'ALERT_STATUS_UPDATE',
        targetId: 'alt-002',
        details: 'Updated alert alt-002 status to INVESTIGATING.',
        note: 'Employee travel itinerary verified.',
      },
    ];
    this.phishingHistories.clear();
    // Evaluate initial synthetic transactions
    this.paymentTransactions = evaluatePaymentTransactions(
      JSON.parse(JSON.stringify(INITIAL_SYNTHETIC_PAYMENTS)),
      this.settings.paymentBaselineAmount
    );
  }

  // ---------------- Security Events ----------------
  getEvents(filters?: { severity?: string; type?: string; query?: string; limit?: number }) {
    let result = [...this.events];
    if (filters?.severity && filters.severity !== 'ALL') {
      result = result.filter((e) => e.severity === filters.severity);
    }
    if (filters?.type && filters.type !== 'ALL') {
      result = result.filter((e) => e.type === filters.type);
    }
    if (filters?.query) {
      const q = filters.query.toLowerCase();
      result = result.filter(
        (e) =>
          e.userEmail.toLowerCase().includes(q) ||
          e.ip.toLowerCase().includes(q) ||
          e.location.toLowerCase().includes(q) ||
          e.description.toLowerCase().includes(q)
      );
    }
    return result.slice(0, filters?.limit || 100);
  }

  addEvent(event: Omit<SecurityEvent, 'id' | 'timestamp'>): SecurityEvent {
    const newEvent: SecurityEvent = {
      ...event,
      id: `evt-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };
    this.events.unshift(newEvent);
    if (this.events.length > 500) {
      this.events.pop();
    }
    return newEvent;
  }

  // ---------------- Security Alerts & Admin Review ----------------
  getAlerts(filters?: { status?: string; severity?: string; isReviewed?: boolean }) {
    let result = [...this.alerts];
    if (filters?.status && filters.status !== 'ALL') {
      result = result.filter((a) => a.status === filters.status);
    }
    if (filters?.severity && filters.severity !== 'ALL') {
      result = result.filter((a) => a.severity === filters.severity);
    }
    if (filters?.isReviewed !== undefined) {
      result = result.filter((a) => !!a.isReviewed === filters.isReviewed);
    }
    return result;
  }

  getAlertById(id: string): SecurityAlert | null {
    return this.alerts.find((a) => a.id === id) || null;
  }

  addAlert(alert: Omit<SecurityAlert, 'id' | 'timestamp'>): SecurityAlert {
    const newAlert: SecurityAlert = {
      ...alert,
      id: `alt-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      isReviewed: false,
      investigationNotes: [],
    };
    this.alerts.unshift(newAlert);
    return newAlert;
  }

  updateAlertStatus(
    id: string,
    status: SecurityAlert['status'],
    adminEmail: string,
    actionNote?: string
  ): SecurityAlert | null {
    const alert = this.alerts.find((a) => a.id === id);
    if (!alert) return null;

    alert.status = status;
    if (actionNote) {
      alert.mitigationActionTaken = actionNote;
    }

    // Record in Admin Audit Log
    this.addAdminAuditLog({
      adminEmail,
      actionType: 'ALERT_STATUS_UPDATE',
      targetId: id,
      details: `Alert status transitioned to ${status}.`,
      note: actionNote,
    });

    return alert;
  }

  addAlertInvestigationNote(id: string, author: string, noteText: string): SecurityAlert | null {
    const alert = this.alerts.find((a) => a.id === id);
    if (!alert) return null;

    if (!alert.investigationNotes) {
      alert.investigationNotes = [];
    }

    const noteObj: AlertInvestigationNote = {
      id: `note-${Date.now().toString(36)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
      author,
      note: noteText,
    };

    alert.investigationNotes.push(noteObj);
    alert.isReviewed = true;
    alert.reviewedBy = author;
    alert.reviewedAt = noteObj.timestamp;

    this.addAdminAuditLog({
      adminEmail: author,
      actionType: 'ALERT_NOTE_ADDED',
      targetId: id,
      details: `Added investigation note to alert: "${noteText.slice(0, 60)}..."`,
      note: noteText,
    });

    return alert;
  }

  // ---------------- Admin Audit Logs ----------------
  addAdminAuditLog(log: Omit<AdminAuditLog, 'id' | 'timestamp'>): AdminAuditLog {
    const item: AdminAuditLog = {
      ...log,
      id: `audit-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };
    this.adminAuditLogs.unshift(item);
    if (this.adminAuditLogs.length > 200) {
      this.adminAuditLogs.pop();
    }
    return item;
  }

  getAdminAuditLogs(limit: number = 50): AdminAuditLog[] {
    return this.adminAuditLogs.slice(0, limit);
  }

  // ---------------- IP Blocklist ----------------
  blockIp(ip: string, adminEmail: string = 'system.gateway'): boolean {
    this.blockedIps.add(ip);
    this.addEvent({
      type: 'TOR_ACCESS',
      userEmail: adminEmail,
      ip,
      location: 'Perimeter Firewall',
      severity: 'HIGH',
      status: 'BLOCKED',
      description: `Perimeter Defense: IP ${ip} successfully appended to firewall drop table by ${adminEmail}.`,
      isDemo: false,
    });
    this.addAdminAuditLog({
      adminEmail,
      actionType: 'IP_BLOCK',
      details: `Appended IP ${ip} to perimeter firewall drop table.`,
    });
    return true;
  }

  isIpBlocked(ip: string): boolean {
    return this.blockedIps.has(ip);
  }

  getBlockedIps(): string[] {
    return Array.from(this.blockedIps);
  }

  unblockIp(ip: string, adminEmail: string = 'system.gateway'): boolean {
    const success = this.blockedIps.delete(ip);
    if (success) {
      this.addAdminAuditLog({
        adminEmail,
        actionType: 'IP_UNBLOCK',
        details: `Removed IP ${ip} from perimeter drop table.`,
      });
    }
    return success;
  }

  // ---------------- Baseline Files (FIM) ----------------
  getBaselineFiles(): BaselineFile[] {
    return [...this.baselineFiles];
  }

  updateFileBaseline(id: string, update: Partial<BaselineFile>): BaselineFile | null {
    const file = this.baselineFiles.find((f) => f.id === id);
    if (!file) return null;
    Object.assign(file, update);
    return file;
  }

  // ---------------- Settings ----------------
  getSettings(): SecuritySettings {
    return { ...this.settings };
  }

  updateSettings(newSettings: Partial<SecuritySettings>, adminEmail: string = 'system'): SecuritySettings {
    this.settings = { ...this.settings, ...newSettings };
    this.addAdminAuditLog({
      adminEmail,
      actionType: 'SETTINGS_UPDATE',
      details: `Updated security thresholds: failedLoginsThreshold=${this.settings.failedLoginsThreshold}, window=${this.settings.failedLoginsWindowMinutes}m, defenseMode=${this.settings.defenseMode}`,
    });
    return { ...this.settings };
  }

  // ---------------- Phishing History (Per Authenticated User) ----------------
  addPhishingHistory(userEmail: string, item: Omit<PhishingHistoryItem, 'id' | 'timestamp' | 'userEmail'>): PhishingHistoryItem {
    const email = userEmail.toLowerCase().trim();
    if (!this.phishingHistories.has(email)) {
      this.phishingHistories.set(email, []);
    }
    const historyItem: PhishingHistoryItem = {
      ...item,
      id: `phish-hist-${Date.now().toString(36)}`,
      userEmail: email,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };
    const list = this.phishingHistories.get(email)!;
    list.unshift(historyItem);
    if (list.length > 50) list.pop();
    return historyItem;
  }

  getPhishingHistory(userEmail: string): PhishingHistoryItem[] {
    const email = userEmail.toLowerCase().trim();
    return this.phishingHistories.get(email) || [];
  }

  clearPhishingHistory(userEmail: string): boolean {
    const email = userEmail.toLowerCase().trim();
    return this.phishingHistories.delete(email);
  }

  // ---------------- Digital Payment Transactions ----------------
  getPaymentTransactions(): PaymentTransactionRecord[] {
    return [...this.paymentTransactions];
  }

  addPaymentTransactions(newTxns: PaymentTransactionRecord[]): PaymentTransactionRecord[] {
    const evaluated = evaluatePaymentTransactions(newTxns, this.settings.paymentBaselineAmount);
    this.paymentTransactions = [...evaluated, ...this.paymentTransactions].slice(0, 300);
    return evaluated;
  }

  generateSyntheticPaymentDataset(): PaymentTransactionRecord[] {
    const categories: Array<'ELECTRONICS' | 'GROCERY' | 'TRAVEL' | 'GAMING' | 'UTILITIES'> = [
      'ELECTRONICS', 'GROCERY', 'TRAVEL', 'GAMING', 'UTILITIES'
    ];
    const methods: Array<'UPI' | 'CREDIT_CARD' | 'DEBIT_CARD' | 'NET_BANKING' | 'WALLET'> = [
      'UPI', 'CREDIT_CARD', 'DEBIT_CARD', 'NET_BANKING', 'WALLET'
    ];

    const generated: PaymentTransactionRecord[] = [
      {
        transactionId: `TXN-SYNTH-${Math.floor(2000 + Math.random() * 8000)}`,
        accountRef: 'ACC-****-5510',
        amount: Math.floor(20 + Math.random() * 80),
        timestamp: new Date(Date.now() - Math.floor(Math.random() * 3600000)).toISOString(),
        paymentMethod: methods[Math.floor(Math.random() * methods.length)],
        transactionResult: 'SUCCESS',
        merchantCategory: categories[Math.floor(Math.random() * categories.length)],
        isSynthetic: true,
      },
      {
        transactionId: `TXN-SYNTH-${Math.floor(2000 + Math.random() * 8000)}`,
        accountRef: 'ACC-****-9921',
        amount: 4200, // Spike amount
        timestamp: new Date(Date.now() - 120000).toISOString(),
        paymentMethod: 'CREDIT_CARD',
        transactionResult: 'SUCCESS',
        merchantCategory: 'ELECTRONICS',
        isSynthetic: true,
      },
      {
        transactionId: `TXN-SYNTH-${Math.floor(2000 + Math.random() * 8000)}`,
        accountRef: 'ACC-****-9921',
        amount: 4200, // Rapid duplicate
        timestamp: new Date(Date.now() - 30000).toISOString(),
        paymentMethod: 'CREDIT_CARD',
        transactionResult: 'SUCCESS',
        merchantCategory: 'ELECTRONICS',
        isSynthetic: true,
      },
      {
        transactionId: `TXN-DUP-TEST-01`, // Intentional duplicate ID
        accountRef: 'ACC-****-1102',
        amount: 75.0,
        timestamp: new Date().toISOString(),
        paymentMethod: 'UPI',
        transactionResult: 'FAILED',
        merchantCategory: 'GAMING',
        isSynthetic: true,
      },
      {
        transactionId: `TXN-DUP-TEST-01`, // Intentional duplicate ID
        accountRef: 'ACC-****-1102',
        amount: 75.0,
        timestamp: new Date().toISOString(),
        paymentMethod: 'UPI',
        transactionResult: 'SUCCESS',
        merchantCategory: 'GAMING',
        isSynthetic: true,
      },
    ];

    return this.addPaymentTransactions(generated);
  }

  // ---------------- File Integrity Counter ----------------
  recordFileAnalysis(): number {
    this.fileAnalysisCount++;
    return this.fileAnalysisCount;
  }

  getFileAnalysisCount(): number {
    return this.fileAnalysisCount;
  }

  // ---------------- Security Checklist Progress (Per User) ----------------
  getSecurityChecklist(userEmail?: string): SecurityChecklistState {
    const email = userEmail ? userEmail.toLowerCase().trim() : 'guest.operator@authshield.internal';
    if (!this.userChecklists.has(email)) {
      const items = JSON.parse(JSON.stringify(DEFAULT_CHECKLIST_ITEMS));
      const completedCount = items.filter((i: any) => i.completed).length;
      const initial: SecurityChecklistState = {
        userEmail: email,
        items,
        lastUpdated: new Date().toISOString(),
        completionPercentage: Math.round((completedCount / items.length) * 100),
      };
      this.userChecklists.set(email, initial);
    }
    return this.userChecklists.get(email)!;
  }

  saveSecurityChecklist(userEmail: string, items: SecurityChecklistItem[]): SecurityChecklistState {
    const email = userEmail.toLowerCase().trim();
    const completedCount = items.filter((i) => i.completed).length;
    const state: SecurityChecklistState = {
      userEmail: email,
      items,
      lastUpdated: new Date().toISOString(),
      completionPercentage: Math.round((completedCount / items.length) * 100),
    };
    this.userChecklists.set(email, state);
    return state;
  }

  // ---------------- Aggregated Telemetry Stats ----------------
  getStats(userEmail?: string) {
    const totalEvents = this.events.length;
    const failedLogins = this.events.filter(
      (e) => e.type === 'LOGIN_FAILED' || e.type === 'BRUTE_FORCE_BURST'
    ).length;
    const suspiciousAlerts = this.alerts.filter((a) => a.status === 'ACTIVE').length;
    const highRiskEvents = this.events.filter((e) => e.severity === 'HIGH').length;

    const severityCount = {
      LOW: this.events.filter((e) => e.severity === 'LOW').length,
      MEDIUM: this.events.filter((e) => e.severity === 'MEDIUM').length,
      HIGH: this.events.filter((e) => e.severity === 'HIGH').length,
    };

    const categoryCount = {
      LOGIN_SECURITY: this.alerts.filter((a) => a.category === 'LOGIN_SECURITY').length,
      CREDENTIAL_ATTACK: this.alerts.filter((a) => a.category === 'CREDENTIAL_ATTACK').length,
      MALICIOUS_NETWORK: this.alerts.filter((a) => a.category === 'MALICIOUS_NETWORK').length,
      FILE_SYSTEM: this.alerts.filter((a) => a.category === 'FILE_SYSTEM').length,
      FRAUD_RISK: this.alerts.filter((a) => a.category === 'FRAUD_RISK').length,
    };

    // Aggregate phishing totals across all user histories
    let phishingScansTotal = 0;
    for (const list of this.phishingHistories.values()) {
      phishingScansTotal += list.length;
    }

    const checklist = this.getSecurityChecklist(userEmail);

    return {
      totalLoginEvents: totalEvents,
      failedLoginAttempts: failedLogins,
      suspiciousLoginAlerts: suspiciousAlerts,
      highRiskEvents,
      severityCount,
      categoryCount,
      blockedIpsCount: this.blockedIps.size,
      defenseMode: this.settings.defenseMode,
      reviewedAlertsCount: this.alerts.filter((a) => a.isReviewed).length,
      adminAuditLogsCount: this.adminAuditLogs.length,
      phishingScansTotal,
      paymentTransactionsTotal: this.paymentTransactions.length,
      fileAnalysisCount: this.fileAnalysisCount,
      baselineFilesCount: this.baselineFiles.length,
      checklistCompletionPercentage: checklist.completionPercentage,
      checklistCompletedCount: checklist.items.filter((i) => i.completed).length,
      checklistTotalCount: checklist.items.length,
    };
  }
}

export const db = new MemoryDatabase();
