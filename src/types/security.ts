export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH';

export type UserRole = 'user' | 'admin';

export interface User {
  id: string;
  name: string;
  email: string;
  role: UserRole;
  createdAt: string;
  twoFactorEnabled: boolean;
  lastLogin?: string;
}

export interface LoginEventRecord {
  id: string;
  timestamp: string;
  email: string;
  ip: string;
  success: boolean;
  reasonCode:
    | 'SUCCESS'
    | 'INVALID_CREDENTIALS'
    | 'ACCOUNT_NOT_FOUND'
    | 'RATE_LIMITED_LOCKOUT'
    | 'TWO_FACTOR_REQUIRED'
    | 'INVALID_2FA_CODE'
    | 'PASSWORD_RESET_REQUIRED'
    | 'FIREWALL_BLOCKED';
  userAgent?: string;
  severity: SeverityLevel;
}

export type EventType =
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

export interface SecurityEvent {
  id: string;
  timestamp: string;
  type: EventType;
  userEmail: string;
  ip: string;
  location: string;
  severity: SeverityLevel;
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
  severity: SeverityLevel;
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

export interface SecurityStats {
  totalLoginEvents: number;
  failedLoginAttempts: number;
  suspiciousLoginAlerts: number;
  highRiskEvents: number;
  severityCount: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
  };
  categoryCount: {
    LOGIN_SECURITY: number;
    CREDENTIAL_ATTACK: number;
    MALICIOUS_NETWORK: number;
    FILE_SYSTEM: number;
    FRAUD_RISK: number;
  };
  blockedIpsCount: number;
  defenseMode: 'NORMAL' | 'ELEVATED' | 'HIGH_ALERT';
  reviewedAlertsCount?: number;
  adminAuditLogsCount?: number;
  phishingScansTotal?: number;
  paymentTransactionsTotal?: number;
  fileAnalysisCount?: number;
  baselineFilesCount?: number;
  checklistCompletionPercentage?: number;
  checklistCompletedCount?: number;
  checklistTotalCount?: number;
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

export interface RiskFactor {
  factor: string;
  penalty: number;
  description: string;
  severity: SeverityLevel;
  ruleReference?: string;
}

export interface SuspiciousLoginResult {
  riskScore: number;
  riskLevel: SeverityLevel;
  detectionTime: string;
  action: 'ALLOW' | 'REQUIRE_MFA' | 'STEP_UP_BIOMETRIC' | 'TEMPORARY_LOCK' | 'HARD_BLOCK';
  recommendedAction: string;
  reasons: string[];
  factors: RiskFactor[];
  ruleEvaluation: {
    rule1_repeatedFailures: boolean;
    rule2_failuresFollowedBySuccess: boolean;
    rule3_unusuallyFrequentLogins: boolean;
    rule4_historicalAnomaly: boolean;
    rule5_unusualSignals: boolean;
  };
  relevantInfo: Record<string, any>;
  disclaimer: string;
}

// Backward compatibility alias
export type LoginAnalysisResult = SuspiciousLoginResult;

export interface PhishingFinding {
  rule: string;
  points: number;
  detail: string;
  type: 'PASS' | 'WARN' | 'DANGER';
}

export interface PhishingUrlResult {
  type: 'URL';
  target: string;
  domain: string;
  riskScore: number;
  riskLevel: SeverityLevel;
  verdict: string;
  indicators: string[];
  findings: PhishingFinding[];
  entropy: number;
  isShortener: boolean;
  hasPunycodeHomograph: boolean;
  targetedBrand?: string;
  recommendedAction: string;
  disclaimer: string;
}

export interface PhishingMessageResult {
  type: 'MESSAGE';
  samplePreview: string;
  riskScore: number;
  riskLevel: SeverityLevel;
  verdict: string;
  detectedCategories: {
    urgentCallToAction: boolean;
    credentialRequest: boolean;
    financialOrOtpRequest: boolean;
    unexpectedPrizeOrReward: boolean;
    fearOrAccountWarning: boolean;
    suspiciousLinksContained: string[];
  };
  matchedIndicators: string[];
  findings: PhishingFinding[];
  recommendedAction: string;
  disclaimer: string;
}

export interface PhishingHistoryItem {
  id: string;
  userEmail: string;
  timestamp: string;
  type: 'URL' | 'MESSAGE';
  targetPreview: string;
  riskScore: number;
  riskLevel: SeverityLevel;
  indicatorsCount: number;
  verdict: string;
}

export interface PaymentTransactionRecord {
  transactionId: string;
  accountRef: string;
  amount: number;
  timestamp: string;
  paymentMethod: 'UPI' | 'CREDIT_CARD' | 'DEBIT_CARD' | 'NET_BANKING' | 'WALLET';
  transactionResult: 'SUCCESS' | 'FAILED' | 'PENDING';
  merchantCategory: 'ELECTRONICS' | 'GROCERY' | 'TRAVEL' | 'GAMING' | 'UTILITIES';
  riskScore?: number;
  riskLevel?: SeverityLevel;
  reasons?: string[];
  triggeredRules?: string[];
  isSynthetic: boolean;
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

export interface FileIntegrityCheckResult {
  filename: string;
  hashes: {
    sha256: string;
    sha512: string;
    md5: string;
    sizeBytes: number;
    entropy: number;
  };
  matchedBaseline?: BaselineFile;
  status: 'HEALTHY' | 'MODIFIED' | 'TAMPERED';
  verdict: string;
  entropyAlert: boolean;
}
