import {
  SecurityStats,
  SecurityEvent,
  SecurityAlert,
  BaselineFile,
  SecuritySettings,
  SuspiciousLoginResult,
  PhishingUrlResult,
  PhishingMessageResult,
  PhishingHistoryItem,
  PaymentTransactionRecord,
  AdminAuditLog,
  User,
  LoginEventRecord,
  SecurityChecklistState,
  SecurityChecklistItem,
} from '../types/security';

const TOKEN_KEY = 'authshield_session_token';

function getStoredToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function setStoredToken(token: string | null) {
  try {
    if (token) {
      localStorage.setItem(TOKEN_KEY, token);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  } catch {
    // Ignore storage error
  }
}

function getAuthHeaders(): HeadersInit {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

export const api = {
  getToken: getStoredToken,
  setToken: setStoredToken,

  // ---------------- Authentication Methods ----------------
  async register(name: string, email: string, password: string): Promise<{ success: boolean; token: string; user: User }> {
    const res = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Registration failed');
    if (json.token) setStoredToken(json.token);
    return json;
  },

  async login(email: string, password: string): Promise<{
    success: boolean;
    token?: string;
    user?: User;
    twoFactorRequired?: boolean;
    challengeToken?: string;
    tempCode?: string;
    remainingAttempts?: number;
    error?: string;
  }> {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const json = await res.json();
    if (!res.ok) {
      const err: any = new Error(json.error || 'Login failed');
      err.remainingAttempts = json.remainingAttempts;
      err.code = json.code;
      throw err;
    }
    if (json.token) setStoredToken(json.token);
    return json;
  },

  async verify2FA(challengeToken: string, code: string): Promise<{ success: boolean; token: string; user: User }> {
    const res = await fetch('/api/auth/verify-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeToken, code }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || '2FA verification failed');
    if (json.token) setStoredToken(json.token);
    return json;
  },

  async logout(): Promise<void> {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: getAuthHeaders(),
      });
    } finally {
      setStoredToken(null);
    }
  },

  async getMe(): Promise<User | null> {
    const token = getStoredToken();
    if (!token) return null;
    try {
      const res = await fetch('/api/auth/me', { headers: getAuthHeaders() });
      if (!res.ok) {
        setStoredToken(null);
        return null;
      }
      const json = await res.json();
      return json.user;
    } catch {
      return null;
    }
  },

  async forgotPassword(email: string): Promise<{ success: boolean; message: string; resetToken?: string }> {
    const res = await fetch('/api/auth/forgot-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Failed to generate reset link');
    return json;
  },

  async resetPassword(token: string, newPassword: string): Promise<{ success: boolean; message: string }> {
    const res = await fetch('/api/auth/reset-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Password reset failed');
    return json;
  },

  async toggle2FA(enable: boolean): Promise<{ success: boolean; twoFactorEnabled: boolean; message: string }> {
    const res = await fetch('/api/auth/toggle-2fa', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ enable }),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(json.error || 'Failed to update 2FA status');
    return json;
  },

  async getLoginHistory(): Promise<LoginEventRecord[]> {
    const res = await fetch('/api/auth/login-history', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch login history');
    const json = await res.json();
    return json.data;
  },

  // ---------------- Suspicious Login Detection (Rules 1-5) ----------------
  async detectSuspiciousLogin(payload: any): Promise<{ data: SuspiciousLoginResult; eventId: string }> {
    const res = await fetch('/api/security/detect-suspicious-login', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Suspicious login evaluation failed');
    }
    return res.json();
  },

  async generateSyntheticLogins(): Promise<{ success: boolean; message: string; count: number }> {
    const res = await fetch('/api/security/generate-synthetic-logins', {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to generate synthetic logins');
    }
    return res.json();
  },

  async runBatchDetection(): Promise<{ success: boolean; message: string; scannedCount: number; flaggedCount: number }> {
    const res = await fetch('/api/security/run-batch-detection', {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to execute batch detection');
    }
    return res.json();
  },

  // Backward compatibility alias
  async analyzeLogin(payload: any): Promise<{ data: SuspiciousLoginResult; eventId: string }> {
    return this.detectSuspiciousLogin(payload);
  },

  // ---------------- Alerts & Admin Review Notes ----------------
  async getAlerts(params?: { status?: string; severity?: string }): Promise<SecurityAlert[]> {
    const query = new URLSearchParams();
    if (params?.status) query.set('status', params.status);
    if (params?.severity) query.set('severity', params.severity);
    const res = await fetch(`/api/security/alerts?${query.toString()}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch alerts');
    const json = await res.json();
    return json.data;
  },

  async reviewAlert(id: string, status: SecurityAlert['status'], note?: string): Promise<SecurityAlert> {
    const res = await fetch(`/api/security/alerts/${encodeURIComponent(id)}/review`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, note }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to review alert');
    }
    const json = await res.json();
    return json.data;
  },

  async addAlertNote(id: string, note: string): Promise<SecurityAlert> {
    const res = await fetch(`/api/security/alerts/${encodeURIComponent(id)}/notes`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ note }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to add investigation note');
    }
    const json = await res.json();
    return json.data;
  },

  async updateAlertStatus(id: string, status: SecurityAlert['status'], actionNote?: string): Promise<SecurityAlert> {
    const res = await fetch(`/api/security/alerts/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify({ status, actionNote }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to update alert');
    }
    const json = await res.json();
    return json.data;
  },

  async getAdminAuditLogs(): Promise<AdminAuditLog[]> {
    const res = await fetch('/api/security/admin-audit-logs', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch admin audit logs');
    const json = await res.json();
    return json.data;
  },

  // ---------------- Phishing Checker (URL & Message) ----------------
  async checkPhishingUrl(url: string): Promise<PhishingUrlResult> {
    const res = await fetch('/api/security/phishing-check-url', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ url }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'URL phishing scan failed');
    }
    const json = await res.json();
    return json.data;
  },

  async checkPhishingMessage(message: string): Promise<PhishingMessageResult> {
    const res = await fetch('/api/security/phishing-check-message', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ message }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Message phishing scan failed');
    }
    const json = await res.json();
    return json.data;
  },

  async getPhishingHistory(): Promise<PhishingHistoryItem[]> {
    const res = await fetch('/api/security/phishing-history', { headers: getAuthHeaders() });
    if (!res.ok) return [];
    const json = await res.json();
    return json.data;
  },

  async clearPhishingHistory(): Promise<void> {
    const res = await fetch('/api/security/phishing-history', {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to clear phishing history');
  },

  // Legacy alias
  async checkPhishing(url: string): Promise<PhishingUrlResult> {
    return this.checkPhishingUrl(url);
  },

  // ---------------- Digital Payment Risk Analyzer ----------------
  async getPaymentTransactions(): Promise<PaymentTransactionRecord[]> {
    const res = await fetch('/api/security/payment-transactions', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch payment transactions');
    const json = await res.json();
    return json.data;
  },

  async addPaymentTransaction(txn: Partial<PaymentTransactionRecord>): Promise<PaymentTransactionRecord> {
    const res = await fetch('/api/security/payment-transactions', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(txn),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to submit payment transaction');
    }
    const json = await res.json();
    return json.data;
  },

  async generateSyntheticPayments(): Promise<{ success: boolean; message: string; data: PaymentTransactionRecord[] }> {
    const res = await fetch('/api/security/payment-transactions/generate', {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to generate synthetic payments');
    return res.json();
  },

  async uploadPaymentCsv(csvContent: string): Promise<{
    success: boolean;
    message: string;
    evaluatedCount: number;
    rowErrors?: string[];
    data: PaymentTransactionRecord[];
  }> {
    const res = await fetch('/api/security/payment-transactions/upload-csv', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ csvContent }),
    });
    const json = await res.json();
    if (!res.ok) {
      const err: any = new Error(json.error || 'Failed to upload CSV');
      err.rowErrors = json.rowErrors;
      throw err;
    }
    return json;
  },

  // ---------------- Core Telemetry & Security Endpoints ----------------
  async getHealth() {
    const res = await fetch('/api/health');
    return res.json();
  },

  async getDatabaseStatus() {
    const res = await fetch('/api/database/status');
    return res.json();
  },

  async getStats(): Promise<SecurityStats> {
    const res = await fetch('/api/security/stats', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch security stats');
    const json = await res.json();
    return json.data;
  },

  async getEvents(params?: { severity?: string; type?: string; query?: string; limit?: number }): Promise<SecurityEvent[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.type) query.set('type', params.type);
    if (params?.query) query.set('query', params.query);
    if (params?.limit) query.set('limit', params.limit.toString());

    const res = await fetch(`/api/security/events?${query.toString()}`, { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch events');
    const json = await res.json();
    return json.data;
  },

  async blockIp(ip: string): Promise<string[]> {
    const res = await fetch('/api/security/block-ip', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ ip }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to block IP');
    }
    const json = await res.json();
    return json.data;
  },

  async unblockIp(ip: string): Promise<void> {
    const res = await fetch(`/api/security/block-ip/${encodeURIComponent(ip)}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to unblock IP');
    }
  },

  async getBlockedIps(): Promise<string[]> {
    const res = await fetch('/api/security/blocked-ips', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch blocked IPs');
    const json = await res.json();
    return json.data;
  },

  async getBaselineFiles(): Promise<BaselineFile[]> {
    const res = await fetch('/api/security/baseline-files', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch baseline files');
    const json = await res.json();
    return json.data;
  },

  async checkFileIntegrity(payload: { filename: string; content: string; targetFileId?: string }) {
    const res = await fetch('/api/security/file-integrity', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'File integrity check failed');
    }
    const json = await res.json();
    return json.data;
  },

  async getSettings(): Promise<SecuritySettings> {
    const res = await fetch('/api/security/settings', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch settings');
    const json = await res.json();
    return json.data;
  },

  async updateSettings(settings: Partial<SecuritySettings>): Promise<SecuritySettings> {
    const res = await fetch('/api/security/settings', {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify(settings),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to update settings');
    }
    const json = await res.json();
    return json.data;
  },

  async resetDemo(): Promise<void> {
    const res = await fetch('/api/security/reset-demo', {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to reset demo dataset');
  },

  // ---------------- Security Checklist ----------------
  async getSecurityChecklist(): Promise<SecurityChecklistState> {
    const res = await fetch('/api/security/checklist', { headers: getAuthHeaders() });
    if (!res.ok) throw new Error('Failed to fetch security checklist');
    const json = await res.json();
    return json.data;
  },

  async saveSecurityChecklist(items: SecurityChecklistItem[]): Promise<SecurityChecklistState> {
    const res = await fetch('/api/security/checklist', {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ items }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to save security checklist');
    }
    const json = await res.json();
    return json.data;
  },
};
