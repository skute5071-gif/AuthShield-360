import React, { useState } from 'react';
import {
  ShieldAlert,
  Lock,
  Mail,
  User,
  X,
  KeyRound,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ShieldCheck,
  RefreshCw,
} from 'lucide-react';
import { api } from '../../services/api';
import { User as UserType } from '../../types/security';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAuthSuccess: (user: UserType) => void;
  initialMode?: 'login' | 'register';
}

export const AuthModal: React.FC<AuthModalProps> = ({
  isOpen,
  onClose,
  onAuthSuccess,
  initialMode = 'login',
}) => {
  const [mode, setMode] = useState<'login' | 'register' | '2fa' | 'forgot' | 'reset'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [twoFactorChallengeToken, setTwoFactorChallengeToken] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [twoFactorHint, setTwoFactorHint] = useState<string | null>(null);

  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [remainingAttempts, setRemainingAttempts] = useState<number | null>(null);

  if (!isOpen) return null;

  // Password validation criteria
  const hasMinLength = password.length >= 8;
  const hasUpper = /[A-Z]/.test(password);
  const hasLower = /[a-z]/.test(password);
  const hasDigit = /[0-9]/.test(password);
  const isPasswordValid = hasMinLength && hasUpper && hasLower && hasDigit;

  const quickFillAdmin = () => {
    setEmail('admin@authshield.internal');
    setPassword('Admin@AuthShield2026!');
    setError(null);
  };

  const quickFillStudent = () => {
    setEmail('priya.student@college.edu');
    setPassword('Student@AuthShield2026!');
    setError(null);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !password) {
      setError('Please provide your email and password.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await api.login(email, password);
      if (res.twoFactorRequired && res.challengeToken) {
        setTwoFactorChallengeToken(res.challengeToken);
        setTwoFactorHint(res.tempCode || null);
        setMode('2fa');
      } else if (res.user) {
        onAuthSuccess(res.user);
        onClose();
      }
    } catch (err: any) {
      setError(err.message || 'Login failed');
      if (err.remainingAttempts !== undefined) {
        setRemainingAttempts(err.remainingAttempts);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleVerify2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!twoFactorCode.trim()) {
      setError('Please enter the 6-digit verification code.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await api.verify2FA(twoFactorChallengeToken, twoFactorCode);
      onAuthSuccess(res.user);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Invalid two-factor code.');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError('Name is required.');
      return;
    }
    if (!isPasswordValid) {
      setError('Password does not meet required complexity standards.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await api.register(name, email, password);
      onAuthSuccess(res.user);
      onClose();
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) {
      setError('Please enter your email.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await api.forgotPassword(email);
      setSuccessMessage(res.message);
      if (res.resetToken) {
        setResetToken(res.resetToken);
        setMode('reset');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch reset request');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetToken || !newPassword) {
      setError('Token and new password are required.');
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const res = await api.resetPassword(resetToken, newPassword);
      setSuccessMessage(res.message);
      setMode('login');
      setPassword(newPassword);
    } catch (err: any) {
      setError(err.message || 'Reset failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md">
      <div className="relative w-full max-w-md rounded-2xl border border-slate-800 bg-[#0c1424] p-6 shadow-2xl">
        <button
          onClick={onClose}
          className="absolute right-4 top-4 text-slate-400 hover:text-white transition-colors"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3 mb-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-md shadow-cyan-500/20">
            <Lock className="h-5 w-5 text-slate-950 font-bold" />
          </div>
          <div>
            <h3 className="text-base font-bold text-slate-100">
              {mode === 'login' && 'Sign In to AuthShield 360'}
              {mode === 'register' && 'Create Protected Account'}
              {mode === '2fa' && 'Two-Factor Authentication'}
              {mode === 'forgot' && 'Reset Access Password'}
              {mode === 'reset' && 'Set New Strong Password'}
            </h3>
            <p className="text-xs text-slate-400">
              PBKDF2 HMAC-SHA512 · Zero Plain-Text Storage · RBAC Enforced
            </p>
          </div>
        </div>

        {/* Mode Selector Tabs (Login / Register) */}
        {(mode === 'login' || mode === 'register') && (
          <div className="flex rounded-lg border border-slate-800 bg-slate-950/80 p-1 mb-5">
            <button
              onClick={() => {
                setMode('login');
                setError(null);
              }}
              className={`flex-1 rounded-md py-1.5 text-xs font-semibold transition-all ${
                mode === 'login' ? 'bg-cyan-500/20 text-cyan-300 shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => {
                setMode('register');
                setError(null);
              }}
              className={`flex-1 rounded-md py-1.5 text-xs font-semibold transition-all ${
                mode === 'register' ? 'bg-cyan-500/20 text-cyan-300 shadow-sm' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Register
            </button>
          </div>
        )}

        {/* Demo Fast-Fill Helper Buttons */}
        {mode === 'login' && (
          <div className="rounded-lg border border-cyan-500/20 bg-cyan-950/20 p-2.5 mb-4">
            <span className="text-[10px] uppercase tracking-wider font-semibold text-cyan-400 block mb-1.5">
              College Viva Quick-Fill Credentials:
            </span>
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <button
                type="button"
                onClick={quickFillAdmin}
                className="rounded border border-slate-800 bg-slate-900/90 py-1 px-2 text-left font-mono text-cyan-300 hover:border-cyan-500/40 truncate"
                title="Fill SecOps Administrator Credentials"
              >
                ● Admin (Role: admin)
              </button>
              <button
                type="button"
                onClick={quickFillStudent}
                className="rounded border border-slate-800 bg-slate-900/90 py-1 px-2 text-left font-mono text-emerald-300 hover:border-emerald-500/40 truncate"
                title="Fill Student User Credentials"
              >
                ● Student (Role: user)
              </button>
            </div>
          </div>
        )}

        {/* Form Error Banner */}
        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 mb-4 text-xs text-rose-300 flex items-start gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
            <div>
              <div>{error}</div>
              {remainingAttempts !== null && remainingAttempts > 0 && (
                <div className="mt-1 font-mono text-[10px] text-amber-300">
                  Rate-limit warning: {remainingAttempts} attempt(s) remaining before account lockout.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Success Banner */}
        {successMessage && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 mb-4 text-xs text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            <span>{successMessage}</span>
          </div>
        )}

        {/* LOGIN FORM */}
        {mode === 'login' && (
          <form onSubmit={handleLogin} className="space-y-3.5 text-xs">
            <div>
              <label className="text-slate-300 font-medium">Email Address</label>
              <div className="relative mt-1">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@college.edu"
                  className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <div className="flex items-center justify-between">
                <label className="text-slate-300 font-medium">Password</label>
                <button
                  type="button"
                  onClick={() => {
                    setMode('forgot');
                    setError(null);
                  }}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300"
                >
                  Forgot password?
                </button>
              </div>
              <div className="relative mt-1">
                <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full mt-2 flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2.5 text-xs font-bold text-slate-950 shadow-lg shadow-cyan-500/20 hover:from-cyan-400 hover:to-blue-500 transition-all disabled:opacity-50"
            >
              {loading ? 'Authenticating Credentials...' : 'Sign In'}
            </button>
          </form>
        )}

        {/* TWO FACTOR AUTHENTICATION FORM */}
        {mode === '2fa' && (
          <form onSubmit={handleVerify2FA} className="space-y-4 text-xs">
            <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3 text-cyan-200">
              <div className="font-semibold text-xs mb-1">Two-Factor Authentication Required</div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Enter the 6-digit one-time verification passcode issued to your authenticator.
              </p>
              {twoFactorHint && (
                <div className="mt-2 font-mono text-xs bg-black/40 p-2 rounded border border-slate-800 text-cyan-300">
                  Academic Test Passcode: <span className="font-bold underline">{twoFactorHint}</span>
                </div>
              )}
            </div>

            <div>
              <label className="text-slate-300 font-medium">6-Digit Verification Code</label>
              <input
                type="text"
                maxLength={6}
                autoFocus
                value={twoFactorCode}
                onChange={(e) => setTwoFactorCode(e.target.value)}
                placeholder="123456"
                className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-2 text-center text-lg font-mono tracking-widest text-cyan-300 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setMode('login')}
                className="w-1/3 rounded-xl border border-slate-800 bg-slate-900 py-2.5 text-xs text-slate-300 hover:text-white"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 rounded-xl bg-cyan-500 py-2.5 text-xs font-bold text-slate-950 hover:bg-cyan-400"
              >
                {loading ? 'Verifying...' : 'Verify Code & Sign In'}
              </button>
            </div>
          </form>
        )}

        {/* REGISTRATION FORM */}
        {mode === 'register' && (
          <form onSubmit={handleRegister} className="space-y-3 text-xs">
            <div>
              <label className="text-slate-300 font-medium">Full Name</label>
              <div className="relative mt-1">
                <User className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Alex Rivera"
                  className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-slate-100 text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-300 font-medium">Email Address</label>
              <div className="relative mt-1">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="alex.rivera@college.edu"
                  className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-300 font-medium">Password</label>
              <div className="relative mt-1">
                <KeyRound className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>

              {/* Password Policy Checklist */}
              <div className="mt-2 space-y-1 rounded border border-slate-800 bg-[#090f1d] p-2 text-[11px]">
                <div className={`flex items-center gap-1.5 ${hasMinLength ? 'text-emerald-400' : 'text-slate-500'}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${hasMinLength ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  At least 8 characters
                </div>
                <div className={`flex items-center gap-1.5 ${hasUpper ? 'text-emerald-400' : 'text-slate-500'}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${hasUpper ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  At least 1 uppercase letter
                </div>
                <div className={`flex items-center gap-1.5 ${hasLower ? 'text-emerald-400' : 'text-slate-500'}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${hasLower ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  At least 1 lowercase letter
                </div>
                <div className={`flex items-center gap-1.5 ${hasDigit ? 'text-emerald-400' : 'text-slate-500'}`}>
                  <span className={`h-1.5 w-1.5 rounded-full ${hasDigit ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                  At least 1 numeric digit
                </div>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading || !isPasswordValid}
              className="w-full mt-2 flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2.5 text-xs font-bold text-slate-950 shadow-lg shadow-cyan-500/20 hover:from-cyan-400 hover:to-blue-500 transition-all disabled:opacity-50"
            >
              {loading ? 'Creating Salted Credentials...' : 'Create Account'}
            </button>
          </form>
        )}

        {/* FORGOT PASSWORD FORM */}
        {mode === 'forgot' && (
          <form onSubmit={handleForgotPassword} className="space-y-4 text-xs">
            <p className="text-slate-400 leading-relaxed text-[11px]">
              Enter the registered email associated with your account. A cryptographically random reset token will be generated.
            </p>

            <div>
              <label className="text-slate-300 font-medium">Registered Email</label>
              <div className="relative mt-1">
                <Mail className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
                <input
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="name@college.edu"
                  className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setMode('login')}
                className="w-1/3 rounded-xl border border-slate-800 bg-slate-900 py-2.5 text-xs text-slate-300 hover:text-white"
              >
                Back
              </button>
              <button
                type="submit"
                disabled={loading}
                className="flex-1 rounded-xl bg-cyan-500 py-2.5 text-xs font-bold text-slate-950 hover:bg-cyan-400"
              >
                {loading ? 'Generating...' : 'Dispatch Reset Token'}
              </button>
            </div>
          </form>
        )}

        {/* RESET PASSWORD WITH TOKEN */}
        {mode === 'reset' && (
          <form onSubmit={handleResetPassword} className="space-y-3.5 text-xs">
            <div className="rounded-lg border border-cyan-500/30 bg-cyan-950/20 p-3 text-[11px] text-cyan-200">
              Reset token acquired for <span className="font-mono text-white">{email}</span>. Enter your replacement password.
            </div>

            <div>
              <label className="text-slate-300 font-medium">Reset Token</label>
              <input
                type="text"
                required
                value={resetToken}
                onChange={(e) => setResetToken(e.target.value)}
                className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-2 font-mono text-xs text-cyan-300 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-300 font-medium">New Password</label>
              <input
                type="password"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="NewPassword123!"
                className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-2 font-mono text-xs text-slate-100 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-xl bg-cyan-500 py-2.5 text-xs font-bold text-slate-950 hover:bg-cyan-400"
            >
              {loading ? 'Updating Password...' : 'Save New Password & Invalidate Old Sessions'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
};
