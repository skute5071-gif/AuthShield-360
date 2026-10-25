import express, { Request, Response, NextFunction } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { db } from './server/db.ts';
import {
  authService,
  SanitizedUser,
  verifyPassword,
} from './server/auth.ts';
import {
  evaluateSuspiciousLogin,
  analyzePhishingUrl,
  analyzePhishingMessage,
  evaluatePaymentTransactions,
  computeFileHashes,
  SuspiciousLoginInput,
  PaymentTransactionRecord,
} from './server/engine.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

declare global {
  namespace Express {
    interface Request {
      user?: SanitizedUser;
      sessionToken?: string;
    }
  }
}

async function startServer() {
  const app = express();
  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  const isProd = process.env.NODE_ENV === 'production';

  app.use(express.json({ limit: '10mb' }));

  const getClientIp = (req: Request): string => {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string') {
      return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || '127.0.0.1';
  };

  // Auth Middleware
  const authenticateToken = (req: Request, _res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    let token = '';

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else if (req.headers['x-session-token']) {
      token = req.headers['x-session-token'] as string;
    }

    if (token) {
      const user = authService.validateSession(token);
      if (user) {
        req.user = user;
        req.sessionToken = token;
      }
    }
    next();
  };

  app.use(authenticateToken);

  const requireAuth = (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      const ip = getClientIp(req);
      db.addEvent({
        type: 'LOGIN_FAILED',
        userEmail: 'unauthenticated.request',
        ip,
        location: 'API Gateway',
        severity: 'MEDIUM',
        status: 'FLAGGED',
        description: `Unauthorized route access attempt to ${req.method} ${req.path}`,
        isDemo: false,
      });
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Please log in to access this resource.',
        code: 'UNAUTHORIZED',
      });
    }
    next();
  };

  const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required.',
        code: 'UNAUTHORIZED',
      });
    }

    if (req.user.role !== 'admin') {
      const ip = getClientIp(req);
      db.addEvent({
        type: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        userEmail: req.user.email,
        ip,
        location: 'RBAC Enforcement Layer',
        severity: 'HIGH',
        status: 'BLOCKED',
        description: `Privilege Escalation Attempt: Standard user ${req.user.email} attempted to execute administrator-restricted action (${req.method} ${req.path})`,
        details: { attemptedRole: 'admin', userRole: req.user.role },
        isDemo: false,
      });

      return res.status(403).json({
        success: false,
        error: 'Forbidden: Administrator privileges required for this operation.',
        code: 'FORBIDDEN_ROLE_REQUIRED',
      });
    }
    next();
  };

  // -------------------------------------------------------------
  // AUTHENTICATION ROUTES
  // -------------------------------------------------------------

  app.post('/api/auth/register', (req: Request, res: Response) => {
    try {
      const { name, email, password } = req.body;
      const ip = getClientIp(req);

      if (!name || typeof name !== 'string' || name.trim().length < 2) {
        return res.status(400).json({ success: false, error: 'Name must be at least 2 characters long.', field: 'name' });
      }

      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!email || typeof email !== 'string' || !emailRegex.test(email.trim())) {
        return res.status(400).json({ success: false, error: 'Please provide a valid email address.', field: 'email' });
      }

      if (!password || typeof password !== 'string' || password.length < 8) {
        return res.status(400).json({ success: false, error: 'Password must be at least 8 characters long.', field: 'password' });
      }

      const hasUpper = /[A-Z]/.test(password);
      const hasLower = /[a-z]/.test(password);
      const hasDigit = /[0-9]/.test(password);
      if (!hasUpper || !hasLower || !hasDigit) {
        return res.status(400).json({
          success: false,
          error: 'Password must contain at least one uppercase letter, one lowercase letter, and one number.',
          field: 'password',
        });
      }

      const registration = authService.register(name, email, password);
      if (registration.error) {
        return res.status(409).json({ success: false, error: registration.error, field: 'email' });
      }

      const fullUser = authService.findUserByEmail(email)!;
      const session = authService.createSession(fullUser, ip);

      authService.recordLoginEvent({
        email: fullUser.email,
        ip,
        success: true,
        reasonCode: 'SUCCESS',
        severity: 'LOW',
        userAgent: req.headers['user-agent'],
      });

      res.status(201).json({
        success: true,
        message: 'Account registered successfully.',
        token: session.token,
        user: session.user,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/auth/login', (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;
      const ip = getClientIp(req);

      if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required.' });
      }

      const normalizedEmail = email.toLowerCase().trim();
      const rateLimitKey = `${ip}_${normalizedEmail}`;

      if (db.isIpBlocked(ip)) {
        authService.recordLoginEvent({
          email: normalizedEmail,
          ip,
          success: false,
          reasonCode: 'FIREWALL_BLOCKED',
          severity: 'HIGH',
          userAgent: req.headers['user-agent'],
        });
        return res.status(403).json({
          success: false,
          error: 'Connection dropped. This IP address is blocked at the network perimeter.',
          code: 'IP_BLOCKED',
        });
      }

      const rateCheck = authService.checkRateLimit(rateLimitKey);
      if (!rateCheck.allowed) {
        const waitMinutes = Math.ceil((rateCheck.lockedUntilMs || 0) / (60 * 1000));
        authService.recordLoginEvent({
          email: normalizedEmail,
          ip,
          success: false,
          reasonCode: 'RATE_LIMITED_LOCKOUT',
          severity: 'HIGH',
          userAgent: req.headers['user-agent'],
        });
        return res.status(429).json({
          success: false,
          error: `Account temporarily locked due to repeated failed login attempts. Please retry in ${waitMinutes} minute(s).`,
          code: 'RATE_LIMITED',
          lockedUntilMs: rateCheck.lockedUntilMs,
        });
      }

      const user = authService.findUserByEmail(normalizedEmail);
      let isValidPassword = false;
      if (user) {
        isValidPassword = verifyPassword(password, user.passwordHash, user.passwordSalt);
      }

      if (!user || !isValidPassword) {
        authService.registerFailedAttempt(rateLimitKey);
        const updatedRate = authService.checkRateLimit(rateLimitKey);

        authService.recordLoginEvent({
          email: normalizedEmail,
          ip,
          success: false,
          reasonCode: user ? 'INVALID_CREDENTIALS' : 'ACCOUNT_NOT_FOUND',
          severity: updatedRate.remainingAttempts <= 1 ? 'HIGH' : 'MEDIUM',
          userAgent: req.headers['user-agent'],
        });

        return res.status(401).json({
          success: false,
          error: 'Invalid email or password.',
          remainingAttempts: updatedRate.remainingAttempts,
        });
      }

      if (user.twoFactorEnabled) {
        const challenge = authService.createTwoFactorChallenge(user.id);
        authService.recordLoginEvent({
          email: user.email,
          ip,
          success: false,
          reasonCode: 'TWO_FACTOR_REQUIRED',
          severity: 'LOW',
          userAgent: req.headers['user-agent'],
        });

        return res.json({
          success: true,
          twoFactorRequired: true,
          challengeToken: challenge.challengeToken,
          tempCode: challenge.tempCode,
          message: 'Two-factor authentication code required.',
        });
      }

      authService.clearRateLimit(rateLimitKey);
      const session = authService.createSession(user, ip);

      authService.recordLoginEvent({
        email: user.email,
        ip,
        success: true,
        reasonCode: 'SUCCESS',
        severity: 'LOW',
        userAgent: req.headers['user-agent'],
      });

      res.json({ success: true, token: session.token, user: session.user });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/auth/verify-2fa', (req: Request, res: Response) => {
    try {
      const { challengeToken, code } = req.body;
      const ip = getClientIp(req);

      if (!challengeToken || !code) {
        return res.status(400).json({ success: false, error: 'Challenge token and code are required.' });
      }

      const verifiedUser = authService.verifyTwoFactorChallenge(challengeToken, code);
      if (!verifiedUser) {
        authService.recordLoginEvent({
          email: 'two-factor-session',
          ip,
          success: false,
          reasonCode: 'INVALID_2FA_CODE',
          severity: 'HIGH',
        });
        return res.status(401).json({ success: false, error: 'Invalid or expired two-factor code.' });
      }

      const session = authService.createSession(verifiedUser, ip);
      authService.recordLoginEvent({
        email: verifiedUser.email,
        ip,
        success: true,
        reasonCode: 'SUCCESS',
        severity: 'LOW',
      });

      res.json({ success: true, token: session.token, user: session.user });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/auth/logout', requireAuth, (req: Request, res: Response) => {
    if (req.sessionToken) {
      authService.destroySession(req.sessionToken);
    }
    res.json({ success: true, message: 'Logged out successfully.' });
  });

  app.get('/api/auth/me', requireAuth, (req: Request, res: Response) => {
    res.json({ success: true, user: req.user });
  });

  app.post('/api/auth/forgot-password', (req: Request, res: Response) => {
    try {
      const { email } = req.body;
      if (!email) return res.status(400).json({ success: false, error: 'Email is required.' });

      const tokenData = authService.createPasswordResetToken(email);
      res.json({
        success: true,
        message: 'If an account exists with this email, a password reset link has been dispatched.',
        resetToken: tokenData?.token,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/auth/reset-password', (req: Request, res: Response) => {
    try {
      const { token, newPassword } = req.body;
      if (!token || !newPassword) {
        return res.status(400).json({ success: false, error: 'Token and new password are required.' });
      }
      if (newPassword.length < 8) {
        return res.status(400).json({ success: false, error: 'New password must be at least 8 characters long.' });
      }

      const result = authService.resetPasswordWithToken(token, newPassword);
      if (!result.success) {
        return res.status(400).json({ success: false, error: result.message });
      }
      res.json({ success: true, message: result.message });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/auth/toggle-2fa', requireAuth, (req: Request, res: Response) => {
    try {
      const { enable } = req.body;
      authService.toggleTwoFactor(req.user!.id, !!enable);
      const updatedUser = authService.findUserById(req.user!.id);
      res.json({
        success: true,
        twoFactorEnabled: updatedUser?.twoFactorEnabled,
        message: enable ? 'Two-factor authentication activated.' : 'Two-factor authentication disabled.',
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/auth/login-history', requireAuth, (req: Request, res: Response) => {
    const history = req.user!.role === 'admin'
      ? authService.getLoginHistory()
      : authService.getLoginHistory(req.user!.email);
    res.json({ success: true, data: history });
  });

  // -------------------------------------------------------------
  // CORE SUSPICIOUS LOGIN DETECTION SERVICE (RULES 1 - 5)
  // -------------------------------------------------------------

  app.post('/api/security/detect-suspicious-login', (req: Request, res: Response) => {
    try {
      const input: SuspiciousLoginInput = req.body;
      if (!input.userEmail || !input.ip || !input.location) {
        return res.status(400).json({
          success: false,
          error: 'userEmail, ip, and location are required for suspicious login detection',
        });
      }

      const settings = db.getSettings();
      const analysis = evaluateSuspiciousLogin(input, settings);

      let eventType: any = 'LOGIN_SUCCESS';
      if (analysis.ruleEvaluation.rule1_repeatedFailures) {
        eventType = 'BRUTE_FORCE_BURST';
      } else if (analysis.ruleEvaluation.rule2_failuresFollowedBySuccess) {
        eventType = 'LOGIN_SUCCESS';
      } else if (input.isTorOrVpn) {
        eventType = 'TOR_ACCESS';
      } else if (analysis.ruleEvaluation.rule4_historicalAnomaly) {
        eventType = 'NEW_DEVICE';
      } else if (!input.isSuccessfulLoginNow) {
        eventType = 'LOGIN_FAILED';
      }

      const loggedEvent = db.addEvent({
        type: eventType,
        userEmail: input.userEmail,
        ip: input.ip,
        location: `${input.location.city}, ${input.location.country}`,
        severity: analysis.riskLevel,
        status: analysis.action === 'ALLOW' ? 'LOGGED' : analysis.action === 'HARD_BLOCK' ? 'BLOCKED' : 'ACTION_TAKEN',
        description: `Login Risk Evaluation for ${input.userEmail}: Risk Score ${analysis.riskScore}/100 [${analysis.riskLevel}]. Reasons: ${analysis.reasons.join('; ')}`,
        details: { ...analysis, device: input.device },
        isDemo: false,
      });

      // Spawn active alert if Medium or High risk
      if (analysis.riskLevel === 'HIGH' || analysis.riskLevel === 'MEDIUM') {
        db.addAlert({
          title: `Suspicious Login Detected (${analysis.riskScore}/100 - ${analysis.riskLevel})`,
          severity: analysis.riskLevel,
          category: 'LOGIN_SECURITY',
          status: 'ACTIVE',
          sourceIp: input.ip,
          userEmail: input.userEmail,
          riskScore: analysis.riskScore,
          recommendation: analysis.recommendedAction,
          isDemo: false,
        });
      }

      res.json({
        success: true,
        data: analysis,
        eventId: loggedEvent.id,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Backward compatibility alias for legacy UI calls
  app.post('/api/security/analyze-login', (req: Request, res: Response) => {
    try {
      const input: SuspiciousLoginInput = req.body;
      const settings = db.getSettings();
      const analysis = evaluateSuspiciousLogin(input, settings);
      res.json({ success: true, data: analysis, eventId: 'evt-alias' });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Synthetic Login Generator & Batch Detection Runner
  app.post('/api/security/generate-synthetic-logins', requireAdmin, (req: Request, res: Response) => {
    try {
      const adminEmail = req.user!.email;
      const syntheticEvents = [
        {
          type: 'BRUTE_FORCE_BURST' as const,
          userEmail: 'finance.lead@college.edu',
          ip: '198.51.100.44',
          location: 'Vienna, Austria',
          severity: 'HIGH' as const,
          status: 'BLOCKED' as const,
          description: '[SYNTHETIC TEST] Rule 1 Trigger: 5 rapid failed attempts in 4 minutes from 198.51.100.44.',
          details: { failedCount: 5, windowMinutes: 4, rule1: true },
          isDemo: true,
        },
        {
          type: 'LOGIN_SUCCESS' as const,
          userEmail: 'research.fellow@college.edu',
          ip: '203.0.113.89',
          location: 'Tokyo, Japan',
          severity: 'MEDIUM' as const,
          status: 'ACTION_TAKEN' as const,
          description: '[SYNTHETIC TEST] Rule 2 Trigger: 4 sequential password failures followed by immediate login success.',
          details: { failuresPrior: 4, rule2: true },
          isDemo: true,
        },
        {
          type: 'NEW_DEVICE' as const,
          userEmail: 'dev.marcus@college.edu',
          ip: '192.0.2.77',
          location: 'Toronto, Canada',
          severity: 'LOW' as const,
          status: 'LOGGED' as const,
          description: '[SYNTHETIC TEST] Rule 4 Signal: Login from unseen city and browser; compared against 6 past sessions.',
          details: { novelCity: 'Toronto', rule4: true },
          isDemo: true,
        },
      ];

      for (const ev of syntheticEvents) {
        db.addEvent(ev);
      }

      db.addAdminAuditLog({
        adminEmail,
        actionType: 'SYNTHETIC_DATA_GENERATE',
        details: 'Generated batch of 3 synthetic login threat scenarios for demonstration.',
      });

      res.json({
        success: true,
        message: 'Synthetic login test events generated successfully.',
        count: syntheticEvents.length,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/run-batch-detection', requireAdmin, (req: Request, res: Response) => {
    try {
      const adminEmail = req.user!.email;
      const events = db.getEvents({ limit: 50 });
      let flaggedCount = 0;

      for (const ev of events) {
        if (ev.severity === 'HIGH' || ev.severity === 'MEDIUM') {
          flaggedCount++;
        }
      }

      db.addAdminAuditLog({
        adminEmail,
        actionType: 'BATCH_DETECTION_RUN',
        details: `Executed batch heuristic detection pass across ${events.length} audit records. Flagged ${flaggedCount} suspicious patterns.`,
      });

      res.json({
        success: true,
        message: `Batch detection completed across ${events.length} records. Identified ${flaggedCount} risk anomalies.`,
        scannedCount: events.length,
        flaggedCount,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // -------------------------------------------------------------
  // ALERTS & ADMINISTRATIVE INVESTIGATION NOTES
  // -------------------------------------------------------------

  app.get('/api/security/alerts', (req: Request, res: Response) => {
    try {
      const { status, severity } = req.query;
      const alerts = db.getAlerts({
        status: status as string,
        severity: severity as string,
      });
      res.json({ success: true, count: alerts.length, data: alerts });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/alerts/:id/review', requireAdmin, (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { status, note } = req.body;
      const adminEmail = req.user!.email;

      const updated = db.updateAlertStatus(id, status || 'RESOLVED', adminEmail, note);
      if (!updated) {
        return res.status(404).json({ success: false, error: 'Alert not found' });
      }

      if (note) {
        db.addAlertInvestigationNote(id, adminEmail, note);
      }

      res.json({ success: true, data: updated, message: 'Alert review recorded in administrative audit log.' });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/alerts/:id/notes', requireAdmin, (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { note } = req.body;
      const adminEmail = req.user!.email;

      if (!note || typeof note !== 'string' || !note.trim()) {
        return res.status(400).json({ success: false, error: 'Investigation note text is required.' });
      }

      const updated = db.addAlertInvestigationNote(id, adminEmail, note.trim());
      if (!updated) {
        return res.status(404).json({ success: false, error: 'Alert not found.' });
      }

      res.json({ success: true, data: updated, message: 'Investigation note added and recorded in audit log.' });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/security/admin-audit-logs', requireAdmin, (_req: Request, res: Response) => {
    try {
      const logs = db.getAdminAuditLogs(50);
      res.json({ success: true, data: logs });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // -------------------------------------------------------------
  // PHISHING CHECKER (URL & MESSAGE ANALYSIS)
  // -------------------------------------------------------------

  app.post('/api/security/phishing-check-url', (req: Request, res: Response) => {
    try {
      const { url } = req.body;
      if (!url || typeof url !== 'string') {
        return res.status(400).json({ success: false, error: 'URL string is required.' });
      }

      const result = analyzePhishingUrl(url);

      if (req.user) {
        db.addPhishingHistory(req.user.email, {
          type: 'URL',
          targetPreview: result.domain,
          riskScore: result.riskScore,
          riskLevel: result.riskLevel,
          indicatorsCount: result.indicators.length,
          verdict: result.verdict,
        });
      }

      if (result.riskLevel === 'HIGH') {
        db.addEvent({
          type: 'PHISHING_BLOCKED',
          userEmail: req.user?.email || 'guest.analyzer',
          ip: getClientIp(req),
          location: 'Web Threat Shield',
          severity: 'HIGH',
          status: 'BLOCKED',
          description: `Phishing URL Flagged (${result.domain}): ${result.indicators.join('; ')}`,
          details: result,
          isDemo: false,
        });
      }

      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/phishing-check-message', (req: Request, res: Response) => {
    try {
      const { message } = req.body;
      if (!message || typeof message !== 'string') {
        return res.status(400).json({ success: false, error: 'Message content is required.' });
      }

      const result = analyzePhishingMessage(message);

      if (req.user) {
        db.addPhishingHistory(req.user.email, {
          type: 'MESSAGE',
          targetPreview: result.samplePreview,
          riskScore: result.riskScore,
          riskLevel: result.riskLevel,
          indicatorsCount: result.matchedIndicators.length,
          verdict: result.verdict,
        });
      }

      if (result.riskLevel === 'HIGH') {
        db.addEvent({
          type: 'PHISHING_BLOCKED',
          userEmail: req.user?.email || 'guest.analyzer',
          ip: getClientIp(req),
          location: 'Messaging Filter',
          severity: 'HIGH',
          status: 'BLOCKED',
          description: `Social Engineering Pretext Flagged: ${result.matchedIndicators.join('; ')}`,
          details: result,
          isDemo: false,
        });
      }

      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Phishing History for Authenticated Users
  app.get('/api/security/phishing-history', requireAuth, (req: Request, res: Response) => {
    try {
      const history = db.getPhishingHistory(req.user!.email);
      res.json({ success: true, data: history });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.delete('/api/security/phishing-history', requireAuth, (req: Request, res: Response) => {
    try {
      db.clearPhishingHistory(req.user!.email);
      if (req.user!.role === 'admin') {
        db.addAdminAuditLog({
          adminEmail: req.user!.email,
          actionType: 'PHISHING_HISTORY_CLEAR',
          details: `Cleared personal phishing heuristic scan history.`,
        });
      }
      res.json({ success: true, message: 'Phishing analysis history cleared successfully.' });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Legacy phishing-check alias
  app.post('/api/security/phishing-check', (req: Request, res: Response) => {
    try {
      const { url } = req.body;
      const result = analyzePhishingUrl(url || '');
      res.json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // -------------------------------------------------------------
  // DIGITAL PAYMENT RISK ANALYZER (SYNTHETIC ONLY)
  // -------------------------------------------------------------

  app.get('/api/security/payment-transactions', (_req: Request, res: Response) => {
    try {
      const txns = db.getPaymentTransactions();
      res.json({ success: true, count: txns.length, data: txns });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/payment-transactions', (req: Request, res: Response) => {
    try {
      const { transactionId, accountRef, amount, timestamp, paymentMethod, transactionResult, merchantCategory } = req.body;

      if (!transactionId || !accountRef || amount === undefined || isNaN(Number(amount))) {
        return res.status(400).json({
          success: false,
          error: 'transactionId, accountRef, and numeric amount are required.',
        });
      }

      const newTxn: PaymentTransactionRecord = {
        transactionId: String(transactionId).trim(),
        accountRef: String(accountRef).trim(),
        amount: Math.abs(Number(amount)),
        timestamp: timestamp || new Date().toISOString(),
        paymentMethod: paymentMethod || 'UPI',
        transactionResult: transactionResult || 'SUCCESS',
        merchantCategory: merchantCategory || 'ELECTRONICS',
        isSynthetic: true,
      };

      const evaluated = db.addPaymentTransactions([newTxn]);
      const result = evaluated[0];

      if (result.riskLevel === 'HIGH') {
        db.addEvent({
          type: 'PAYMENT_FLAGGED',
          userEmail: req.user?.email || 'payment.monitor',
          ip: getClientIp(req),
          location: 'Payment Gateway Sentinel',
          severity: 'HIGH',
          status: 'FLAGGED',
          description: `Synthetic Transaction ${result.transactionId} Flagged (${result.riskLevel} - ${result.riskScore}/100): ${result.reasons?.join('; ')}`,
          details: result,
          isDemo: true,
        });
      }

      res.status(201).json({ success: true, data: result });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/payment-transactions/generate', (_req: Request, res: Response) => {
    try {
      const added = db.generateSyntheticPaymentDataset();
      res.json({
        success: true,
        message: `Generated ${added.length} synthetic payment transactions with mixed risk profiles.`,
        data: added,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/payment-transactions/upload-csv', (req: Request, res: Response) => {
    try {
      const { csvContent } = req.body;
      if (!csvContent || typeof csvContent !== 'string') {
        return res.status(400).json({ success: false, error: 'CSV text content is required.' });
      }

      const lines = csvContent
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(Boolean);

      if (lines.length < 2) {
        return res.status(400).json({
          success: false,
          error: 'CSV must contain at least a header row and one valid data record.',
        });
      }

      const headers = lines[0].split(',').map((h) => h.replace(/^["']|["']$/g, '').trim().toLowerCase());
      const requiredCols = ['transactionid', 'accountref', 'amount'];
      const missing = requiredCols.filter((col) => !headers.includes(col));
      if (missing.length > 0) {
        return res.status(400).json({
          success: false,
          error: `Missing required CSV header columns: ${missing.join(', ')}. Expected: transactionId, accountRef, amount, timestamp, paymentMethod, transactionResult, merchantCategory.`,
        });
      }

      const colIdx = {
        id: headers.indexOf('transactionid'),
        account: headers.indexOf('accountref'),
        amount: headers.indexOf('amount'),
        timestamp: headers.indexOf('timestamp'),
        method: headers.indexOf('paymentmethod'),
        result: headers.indexOf('transactionresult'),
        category: headers.indexOf('merchantcategory'),
      };

      const parsed: PaymentTransactionRecord[] = [];
      const rowErrors: string[] = [];

      for (let i = 1; i < lines.length; i++) {
        const line = lines[i];
        const cols = line.split(',').map((c) => c.replace(/^["']|["']$/g, '').trim());

        const id = cols[colIdx.id];
        const account = cols[colIdx.account];
        const amountStr = cols[colIdx.amount];
        const amount = parseFloat(amountStr);

        if (!id || !account) {
          rowErrors.push(`Row ${i + 1}: Missing transaction ID or account reference.`);
          continue;
        }

        if (isNaN(amount) || amount <= 0) {
          rowErrors.push(`Row ${i + 1}: Invalid monetary amount "${amountStr}".`);
          continue;
        }

        const methodRaw = (colIdx.method >= 0 ? cols[colIdx.method] : 'UPI').toUpperCase();
        const allowedMethods = ['UPI', 'CREDIT_CARD', 'DEBIT_CARD', 'NET_BANKING', 'WALLET'];
        const method: any = allowedMethods.includes(methodRaw) ? methodRaw : 'UPI';

        const resultRaw = (colIdx.result >= 0 ? cols[colIdx.result] : 'SUCCESS').toUpperCase();
        const allowedResults = ['SUCCESS', 'FAILED', 'PENDING'];
        const txResult: any = allowedResults.includes(resultRaw) ? resultRaw : 'SUCCESS';

        const catRaw = (colIdx.category >= 0 ? cols[colIdx.category] : 'ELECTRONICS').toUpperCase();
        const allowedCats = ['ELECTRONICS', 'GROCERY', 'TRAVEL', 'GAMING', 'UTILITIES'];
        const category: any = allowedCats.includes(catRaw) ? catRaw : 'ELECTRONICS';

        parsed.push({
          transactionId: id,
          accountRef: account,
          amount,
          timestamp: colIdx.timestamp >= 0 && cols[colIdx.timestamp] ? cols[colIdx.timestamp] : new Date().toISOString(),
          paymentMethod: method,
          transactionResult: txResult,
          merchantCategory: category,
          isSynthetic: true,
        });
      }

      if (parsed.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'No valid transaction records could be parsed.',
          rowErrors,
        });
      }

      const evaluated = db.addPaymentTransactions(parsed);
      res.json({
        success: true,
        message: `Successfully validated and ingested ${evaluated.length} synthetic payment transactions.`,
        evaluatedCount: evaluated.length,
        rowErrors: rowErrors.length > 0 ? rowErrors : undefined,
        data: evaluated,
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // -------------------------------------------------------------
  // SYSTEM & TELEMETRY
  // -------------------------------------------------------------

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({
      status: 'ONLINE',
      system: 'AuthShield 360 Core Security Engine',
      version: '3.3.0-preview',
      defenseMode: db.getSettings().defenseMode,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/api/database/status', (_req: Request, res: Response) => {
    res.json({
      activeEngine: 'InMemoryMemoryDatabase',
      persistenceType: 'Server-Authoritative State Engine',
      firebaseStatus: 'READY_TO_PROVISION',
      hasFirebaseConfig: false,
      note: 'Application is running with the built-in AuthShield in-memory persistence engine with demo data seeding. Firebase Authentication and Cloud Firestore can be connected anytime using the AI Studio Firebase provisioning tool.',
      stats: db.getStats(),
    });
  });

  app.get('/api/security/stats', (req: Request, res: Response) => {
    try {
      const stats = db.getStats(req.user?.email);
      res.json({ success: true, data: stats });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/security/events', (req: Request, res: Response) => {
    try {
      const { severity, type, query, limit } = req.query;
      const events = db.getEvents({
        severity: severity as string,
        type: type as string,
        query: query as string,
        limit: limit ? parseInt(limit as string, 10) : 100,
      });
      res.json({ success: true, count: events.length, data: events });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/events', (req: Request, res: Response) => {
    try {
      const { type, userEmail, ip, location, severity, status, description, details } = req.body;
      if (!type || !userEmail || !ip || !severity || !description) {
        return res.status(400).json({ success: false, error: 'Missing required event fields' });
      }

      const newEvent = db.addEvent({
        type,
        userEmail,
        ip,
        location: location || 'Unknown',
        severity,
        status: status || 'LOGGED',
        description,
        details,
        isDemo: false,
      });

      res.status(201).json({ success: true, data: newEvent });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.patch('/api/security/alerts/:id', requireAuth, (req: Request, res: Response) => {
    try {
      const { id } = req.params;
      const { status, actionNote } = req.body;
      const adminEmail = req.user?.email || 'admin@authshield.internal';

      if (!status) {
        return res.status(400).json({ success: false, error: 'Status is required' });
      }
      const updated = db.updateAlertStatus(id, status, adminEmail, actionNote);
      if (!updated) {
        return res.status(404).json({ success: false, error: 'Alert not found' });
      }
      res.json({ success: true, data: updated });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/security/blocked-ips', (_req: Request, res: Response) => {
    res.json({ success: true, data: db.getBlockedIps() });
  });

  app.post('/api/security/block-ip', requireAdmin, (req: Request, res: Response) => {
    try {
      const { ip } = req.body;
      if (!ip) return res.status(400).json({ success: false, error: 'IP address is required' });
      db.blockIp(ip, req.user!.email);
      res.json({ success: true, message: `IP ${ip} blocked at gateway firewall.`, data: db.getBlockedIps() });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.delete('/api/security/block-ip/:ip', requireAdmin, (req: Request, res: Response) => {
    try {
      const { ip } = req.params;
      const success = db.unblockIp(ip, req.user!.email);
      res.json({ success, message: success ? `IP ${ip} unblocked.` : 'IP not found in blocklist.' });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/security/baseline-files', (_req: Request, res: Response) => {
    res.json({ success: true, data: db.getBaselineFiles() });
  });

  app.post('/api/security/file-integrity', (req: Request, res: Response) => {
    try {
      const { filename, content, targetFileId } = req.body;
      if (!content && content !== '') {
        return res.status(400).json({ success: false, error: 'File content is required' });
      }

      db.recordFileAnalysis();
      const hashes = computeFileHashes(content);
      const baselines = db.getBaselineFiles();
      let matchedBaseline = baselines.find((b) => b.id === targetFileId || b.filename === filename);

      let status: 'HEALTHY' | 'MODIFIED' | 'TAMPERED' = 'HEALTHY';
      let verdict = 'Cryptographic signature verified against baseline.';
      let entropyAlert = hashes.entropy > 7.5;

      if (matchedBaseline) {
        const matchesSha256 = matchedBaseline.baselineSha256.toLowerCase() === hashes.sha256.toLowerCase();
        if (!matchesSha256) {
          status = entropyAlert ? 'TAMPERED' : 'MODIFIED';
          verdict = entropyAlert
            ? 'CRITICAL ALERT: File hash mismatch accompanied by high Shannon entropy (>7.5). High probability of ransomware encryption or malicious binary injection!'
            : 'Unauthorized modification detected! SHA-256 does not match authoritative security baseline.';

          db.addEvent({
            type: 'FILE_INTEGRITY_TAMPER',
            userEmail: 'fim-agent@authshield.internal',
            ip: '127.0.0.1 (Local Host)',
            location: 'System Storage',
            severity: 'HIGH',
            status: 'BLOCKED',
            description: `FIM Tamper Trigger: ${matchedBaseline.filepath} hash mismatch`,
            details: { hashes, matchedBaseline, entropyAlert },
            isDemo: false,
          });

          db.addAlert({
            title: `Integrity Breach: ${matchedBaseline.filename}`,
            severity: 'HIGH',
            category: 'FILE_SYSTEM',
            status: 'ACTIVE',
            sourceIp: 'Local Filesystem',
            userEmail: 'root@authshield.internal',
            riskScore: 88,
            recommendation: 'Isolate affected host immediately. Revert file from trusted golden backup and inspect filesystem journal.',
            isDemo: false,
          });
        }
      }

      res.json({
        success: true,
        data: { filename: filename || 'unnamed-file', hashes, matchedBaseline, status, verdict, entropyAlert },
      });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // -------------------------------------------------------------
  // SECURITY CHECKLIST (PER USER PROGRESSION)
  // -------------------------------------------------------------

  app.get('/api/security/checklist', (req: Request, res: Response) => {
    try {
      const checklist = db.getSecurityChecklist(req.user?.email);
      res.json({ success: true, data: checklist });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/checklist', (req: Request, res: Response) => {
    try {
      const { items } = req.body;
      if (!Array.isArray(items)) {
        return res.status(400).json({ success: false, error: 'Checklist items array is required.' });
      }
      const userEmail = req.user ? req.user.email : 'guest.operator@authshield.internal';
      const updated = db.saveSecurityChecklist(userEmail, items);
      res.json({ success: true, message: 'Checklist progress saved successfully.', data: updated });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.get('/api/security/settings', (_req: Request, res: Response) => {
    res.json({ success: true, data: db.getSettings() });
  });

  app.put('/api/security/settings', requireAdmin, (req: Request, res: Response) => {
    try {
      const updated = db.updateSettings(req.body, req.user!.email);
      res.json({ success: true, data: updated });
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  app.post('/api/security/reset-demo', (_req: Request, res: Response) => {
    db.resetToDemo();
    res.json({
      success: true,
      message: 'AuthShield 360 data reset to default demo dataset. Ready for college mini-project demonstration.',
      stats: db.getStats(),
    });
  });

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    if (fs.existsSync(distPath)) {
      app.use(express.static(distPath));
      app.get('*', (_req: Request, res: Response) => {
        res.sendFile(path.resolve(distPath, 'index.html'));
      });
    }
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[AuthShield 360] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Fatal error starting AuthShield 360 server:', err);
  process.exit(1);
});
