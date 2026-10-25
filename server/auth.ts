import crypto from 'node:crypto';
import { db } from './db.ts';

export interface UserRecord {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  passwordSalt: string;
  role: 'user' | 'admin';
  createdAt: string;
  twoFactorEnabled: boolean;
  twoFactorSecret?: string;
  lastLogin?: string;
}

export type SanitizedUser = Omit<UserRecord, 'passwordHash' | 'passwordSalt' | 'twoFactorSecret'>;

export interface SessionRecord {
  token: string;
  userId: string;
  email: string;
  name: string;
  role: 'user' | 'admin';
  createdAt: number;
  expiresAt: number;
  ip: string;
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
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface PasswordResetRecord {
  token: string;
  email: string;
  expiresAt: number;
  used: boolean;
}

// Cryptographic Password Hashing using PBKDF2 with HMAC-SHA512 (100,000 iterations)
export function hashPassword(password: string, providedSalt?: string): { hash: string; salt: string } {
  const salt = providedSalt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

// Constant-time comparison to prevent timing attacks
export function verifyPassword(password: string, storedHash: string, salt: string): boolean {
  const computedHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  const bufA = Buffer.from(computedHash, 'hex');
  const bufB = Buffer.from(storedHash, 'hex');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

// Rate Limiting constants
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

class AuthService {
  private users: Map<string, UserRecord> = new Map(); // email -> UserRecord
  private sessions: Map<string, SessionRecord> = new Map(); // token -> SessionRecord
  private loginAttempts: Map<string, { count: number; firstAttempt: number; lockedUntil?: number }> = new Map();
  private loginEventHistory: LoginEventRecord[] = [];
  private resetTokens: Map<string, PasswordResetRecord> = new Map();
  private twoFactorPendingSessions: Map<string, { userId: string; expiresAt: number; code: string }> = new Map();

  constructor() {
    this.seedInitialUsers();
  }

  // Seed default demonstration accounts with cryptographically salted hashes (NO plain text stored)
  private seedInitialUsers() {
    // 1. Security Administrator
    const adminHash = hashPassword('Admin@AuthShield2026!');
    const adminUser: UserRecord = {
      id: 'usr_admin_001',
      name: 'SecOps Administrator',
      email: 'admin@authshield.internal',
      passwordHash: adminHash.hash,
      passwordSalt: adminHash.salt,
      role: 'admin',
      createdAt: new Date().toISOString(),
      twoFactorEnabled: false,
    };
    this.users.set(adminUser.email.toLowerCase(), adminUser);

    // 2. Standard Verified User
    const userHash = hashPassword('Student@AuthShield2026!');
    const studentUser: UserRecord = {
      id: 'usr_student_002',
      name: 'Priya Sharma (Student)',
      email: 'priya.student@college.edu',
      passwordHash: userHash.hash,
      passwordSalt: userHash.salt,
      role: 'user',
      createdAt: new Date().toISOString(),
      twoFactorEnabled: false,
    };
    this.users.set(studentUser.email.toLowerCase(), studentUser);
  }

  // Rate Limiting Enforcement
  checkRateLimit(key: string): { allowed: boolean; remainingAttempts: number; lockedUntilMs?: number } {
    const now = Date.now();
    const record = this.loginAttempts.get(key);

    if (!record) {
      return { allowed: true, remainingAttempts: MAX_FAILED_ATTEMPTS };
    }

    // Check if currently locked out
    if (record.lockedUntil && now < record.lockedUntil) {
      return {
        allowed: false,
        remainingAttempts: 0,
        lockedUntilMs: record.lockedUntil - now,
      };
    }

    // Reset window if expired
    if (now - record.firstAttempt > ATTEMPT_WINDOW_MS) {
      this.loginAttempts.delete(key);
      return { allowed: true, remainingAttempts: MAX_FAILED_ATTEMPTS };
    }

    const remaining = Math.max(0, MAX_FAILED_ATTEMPTS - record.count);
    return {
      allowed: record.count < MAX_FAILED_ATTEMPTS,
      remainingAttempts: remaining,
    };
  }

  registerFailedAttempt(key: string) {
    const now = Date.now();
    const record = this.loginAttempts.get(key) || { count: 0, firstAttempt: now };
    record.count += 1;

    if (record.count >= MAX_FAILED_ATTEMPTS) {
      record.lockedUntil = now + LOCKOUT_DURATION_MS;
    }

    this.loginAttempts.set(key, record);
  }

  clearRateLimit(key: string) {
    this.loginAttempts.delete(key);
  }

  // Login Audit Logging
  recordLoginEvent(event: Omit<LoginEventRecord, 'id' | 'timestamp'>): LoginEventRecord {
    const record: LoginEventRecord = {
      ...event,
      id: `log-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`,
      timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19),
    };

    this.loginEventHistory.unshift(record);
    if (this.loginEventHistory.length > 500) {
      this.loginEventHistory.pop();
    }

    // Also register event into AuthShield 360 Security Events Audit Trail
    db.addEvent({
      type: event.success ? 'LOGIN_SUCCESS' : 'LOGIN_FAILED',
      userEmail: event.email,
      ip: event.ip,
      location: 'Auth Service Gateway',
      severity: event.severity === 'CRITICAL' ? 'HIGH' : event.severity,
      status: event.success ? 'LOGGED' : event.reasonCode === 'RATE_LIMITED_LOCKOUT' ? 'BLOCKED' : 'ACTION_TAKEN',
      description: `Authentication ${event.success ? 'Granted' : 'Rejected'} for ${event.email} [Code: ${event.reasonCode}]`,
      details: {
        reasonCode: event.reasonCode,
        success: event.success,
        ip: event.ip,
      },
      isDemo: false,
    });

    return record;
  }

  getLoginHistory(email?: string): LoginEventRecord[] {
    if (email) {
      return this.loginEventHistory.filter((e) => e.email.toLowerCase() === email.toLowerCase());
    }
    return this.loginEventHistory.slice(0, 100);
  }

  // Registration
  register(name: string, email: string, password: string): { user: SanitizedUser; error?: string } {
    const normalizedEmail = email.toLowerCase().trim();

    if (this.users.has(normalizedEmail)) {
      return { user: null as any, error: 'An account with this email address already exists.' };
    }

    const { hash, salt } = hashPassword(password);
    const newUser: UserRecord = {
      id: `usr_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
      name: name.trim(),
      email: normalizedEmail,
      passwordHash: hash,
      passwordSalt: salt,
      role: 'user', // Clients can NEVER register themselves as administrator!
      createdAt: new Date().toISOString(),
      twoFactorEnabled: false,
    };

    this.users.set(normalizedEmail, newUser);
    return { user: this.sanitizeUser(newUser) };
  }

  // Authentication Verification
  findUserByEmail(email: string): UserRecord | null {
    return this.users.get(email.toLowerCase().trim()) || null;
  }

  findUserById(id: string): UserRecord | null {
    for (const user of this.users.values()) {
      if (user.id === id) return user;
    }
    return null;
  }

  // Session Management
  createSession(user: UserRecord, ip: string): { token: string; user: SanitizedUser } {
    const token = crypto.randomBytes(32).toString('hex');
    const now = Date.now();
    const session: SessionRecord = {
      token,
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: now,
      expiresAt: now + SESSION_TTL_MS,
      ip,
    };

    this.sessions.set(token, session);
    user.lastLogin = new Date().toISOString();

    return {
      token,
      user: this.sanitizeUser(user),
    };
  }

  validateSession(token: string): SanitizedUser | null {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;

    if (Date.now() > session.expiresAt) {
      this.sessions.delete(token);
      return null;
    }

    const user = this.findUserById(session.userId);
    if (!user) {
      this.sessions.delete(token);
      return null;
    }

    return this.sanitizeUser(user);
  }

  destroySession(token: string): boolean {
    return this.sessions.delete(token);
  }

  // 2FA Flow
  createTwoFactorChallenge(userId: string): { challengeToken: string; tempCode: string } {
    const challengeToken = crypto.randomBytes(24).toString('hex');
    // Generate secure 6-digit verification code
    const tempCode = Math.floor(100000 + Math.random() * 900000).toString();
    this.twoFactorPendingSessions.set(challengeToken, {
      userId,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 minutes
      code: tempCode,
    });
    return { challengeToken, tempCode };
  }

  verifyTwoFactorChallenge(challengeToken: string, code: string): UserRecord | null {
    const challenge = this.twoFactorPendingSessions.get(challengeToken);
    if (!challenge) return null;

    if (Date.now() > challenge.expiresAt) {
      this.twoFactorPendingSessions.delete(challengeToken);
      return null;
    }

    if (challenge.code !== code.trim()) {
      return null;
    }

    this.twoFactorPendingSessions.delete(challengeToken);
    return this.findUserById(challenge.userId);
  }

  toggleTwoFactor(userId: string, enable: boolean): boolean {
    const user = this.findUserById(userId);
    if (!user) return false;
    user.twoFactorEnabled = enable;
    if (enable && !user.twoFactorSecret) {
      user.twoFactorSecret = crypto.randomBytes(16).toString('hex');
    }
    return true;
  }

  // Password Reset Flow
  createPasswordResetToken(email: string): { token: string; expiresAt: number } | null {
    const normalizedEmail = email.toLowerCase().trim();
    const user = this.users.get(normalizedEmail);
    if (!user) return null;

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 15 * 60 * 1000; // 15 mins

    this.resetTokens.set(token, {
      token,
      email: normalizedEmail,
      expiresAt,
      used: false,
    });

    return { token, expiresAt };
  }

  resetPasswordWithToken(token: string, newPassword: string): { success: boolean; message: string } {
    const record = this.resetTokens.get(token);
    if (!record) {
      return { success: false, message: 'Invalid or expired password reset link.' };
    }

    if (record.used || Date.now() > record.expiresAt) {
      this.resetTokens.delete(token);
      return { success: false, message: 'Password reset token has expired or already been used.' };
    }

    const user = this.users.get(record.email);
    if (!user) {
      return { success: false, message: 'User account not found.' };
    }

    const { hash, salt } = hashPassword(newPassword);
    user.passwordHash = hash;
    user.passwordSalt = salt;
    record.used = true;

    // Invalidate all existing sessions for security
    for (const [sessToken, sess] of this.sessions.entries()) {
      if (sess.userId === user.id) {
        this.sessions.delete(sessToken);
      }
    }

    return { success: true, message: 'Password has been updated securely. Please login with your new credentials.' };
  }

  sanitizeUser(user: UserRecord): SanitizedUser {
    const { passwordHash, passwordSalt, twoFactorSecret, ...sanitized } = user;
    return sanitized;
  }
}

export const authService = new AuthService();
