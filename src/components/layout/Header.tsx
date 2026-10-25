import React, { useState } from 'react';
import {
  ShieldAlert,
  Database,
  RotateCcw,
  Bell,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Info,
  X,
  User,
  LogOut,
  ShieldCheck,
  KeyRound,
  ListChecks,
} from 'lucide-react';
import { SecurityStats, User as UserType } from '../../types/security';
import { UserRoleBadge } from '../auth/UserRoleBadge';

interface HeaderProps {
  stats: SecurityStats | null;
  currentUser: UserType | null;
  onResetDemo: () => Promise<void>;
  onSelectTab: (tab: string) => void;
  activeTab: string;
  onOpenAuthModal: (mode?: 'login' | 'register') => void;
  onOpenChecklistModal: () => void;
  onLogout: () => Promise<void>;
}

export const Header: React.FC<HeaderProps> = ({
  stats,
  currentUser,
  onResetDemo,
  onSelectTab,
  onOpenAuthModal,
  onOpenChecklistModal,
  onLogout,
}) => {
  const [showDbModal, setShowDbModal] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const handleReset = async () => {
    try {
      setIsResetting(true);
      await onResetDemo();
    } finally {
      setIsResetting(false);
    }
  };

  const defenseModeColor = {
    NORMAL: 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10',
    ELEVATED: 'text-amber-400 border-amber-500/30 bg-amber-500/10',
    HIGH_ALERT: 'text-rose-400 border-rose-500/30 bg-rose-500/10',
  }[stats?.defenseMode || 'NORMAL'];

  return (
    <>
      <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-slate-800/80 bg-[#080d1a]/95 px-4 sm:px-6 backdrop-blur-md">
        {/* Left: Branding & Tagline */}
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 shadow-md shadow-cyan-500/20">
            <ShieldAlert className="h-5 w-5 text-slate-950 font-bold" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-extrabold tracking-tight text-slate-100 text-lg sm:text-xl">
                Auth<span className="text-cyan-400">Shield</span> <span className="font-mono text-xs font-semibold text-cyan-400/80">360</span>
              </span>
              <span className="hidden sm:inline-flex items-center gap-1.5 font-mono text-[11px] text-emerald-400">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                ONLINE
              </span>
            </div>
            <p className="hidden md:block text-[11px] text-slate-400">
              Suspicious Login Detection & Defense Architecture · College Mini-Project
            </p>
          </div>
        </div>

        {/* Right: Controls & Badges */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Defense Mode Indicator */}
          <div className={`hidden xl:flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-mono font-medium ${defenseModeColor}`}>
            <Flame className="h-3.5 w-3.5" />
            <span>MODE: {stats?.defenseMode || 'NORMAL'}</span>
          </div>

          {/* Verification Suite Test Modal Trigger */}
          <button
            onClick={onOpenChecklistModal}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-all shadow-sm shadow-cyan-500/10"
            title="Run Automated Auth & RBAC Security Verification Tests"
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span className="hidden sm:inline">Verification Suite</span>
            <span className="sm:hidden">Tests</span>
          </button>

          {/* Security Controls Checklist Button */}
          <button
            onClick={() => onSelectTab('reports')}
            className="hidden lg:flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:text-white transition-colors"
            title="Essential Security Controls Checklist"
          >
            <ListChecks className="h-3.5 w-3.5 text-emerald-400" />
            <span>Checklist: {stats?.checklistCompletionPercentage ?? 75}%</span>
          </button>

          {/* Database Architecture Modal Button */}
          <button
            onClick={() => setShowDbModal(true)}
            className="hidden md:flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:text-white transition-colors"
            title="Database Architecture & Firebase Setup Status"
          >
            <Database className="h-3.5 w-3.5 text-cyan-400" />
            <span>DB Status</span>
          </button>

          {/* Reset Demo Data Button */}
          <button
            onClick={handleReset}
            disabled={isResetting}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900/80 px-2.5 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:text-white transition-all disabled:opacity-50"
            title="Reset system state to baseline demo dataset"
          >
            <RotateCcw className={`h-3.5 w-3.5 ${isResetting ? 'animate-spin' : ''}`} />
            <span className="hidden lg:inline">Reset Demo</span>
          </button>

          {/* Active Alerts Shortcut */}
          <button
            onClick={() => onSelectTab('alerts')}
            className="relative flex h-8 w-8 items-center justify-center rounded-lg border border-slate-800 bg-slate-900/80 text-slate-300 hover:border-slate-700 hover:text-white transition-colors"
            aria-label="View active security alerts"
          >
            <Bell className="h-4 w-4" />
            {(stats?.suspiciousLoginAlerts ?? 0) > 0 && (
              <span className="absolute -top-1 -right-1 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 font-mono text-[10px] font-bold text-white shadow-sm shadow-rose-500/40">
                {stats?.suspiciousLoginAlerts}
              </span>
            )}
          </button>

          {/* User Account State / Sign In / Logout */}
          {currentUser ? (
            <div className="flex items-center gap-2 border-l border-slate-800 pl-2 sm:pl-3">
              <div className="text-right hidden sm:block">
                <div className="font-semibold text-xs text-slate-200 truncate max-w-[120px]">
                  {currentUser.name}
                </div>
                <UserRoleBadge role={currentUser.role} />
              </div>
              <button
                onClick={onLogout}
                className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 p-2 text-xs text-slate-400 hover:border-rose-500/40 hover:text-rose-400 transition-colors"
                title={`Logged in as ${currentUser.email} (${currentUser.role}). Click to Logout.`}
              >
                <LogOut className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 border-l border-slate-800 pl-2 sm:pl-3">
              <button
                onClick={() => onOpenAuthModal('login')}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-bold text-cyan-300 hover:bg-cyan-500/20 transition-colors"
              >
                <KeyRound className="h-3.5 w-3.5" />
                <span>Sign In</span>
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Database Integration Info Modal */}
      {showDbModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-xl rounded-xl border border-slate-800 bg-[#0e1626] p-6 shadow-2xl">
            <button
              onClick={() => setShowDbModal(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Database className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-100">Database & Persistence Architecture</h3>
                <p className="text-xs text-slate-400">AuthShield 360 Storage Specification for Academic Evaluation</p>
              </div>
            </div>

            <div className="mt-5 space-y-3.5 text-xs text-slate-300">
              <div className="rounded-lg border border-slate-800 bg-slate-900/90 p-3.5">
                <div className="flex items-center gap-2 font-mono text-emerald-400 font-semibold mb-1">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>ACTIVE ENGINE: Server-Authoritative State Machine</span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Currently running high-performance Node.js memory persistence with PBKDF2 HMAC-SHA512 salted credentials, rate limiting, and RBAC authorization. All security events, IP blocks, and file baselines are processed live on the Express server.
                </p>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-900/90 p-3.5">
                <div className="flex items-center gap-2 font-mono text-cyan-400 font-semibold mb-1">
                  <Info className="h-4 w-4" />
                  <span>FIREBASE FIRESTORE & AUTHENTICATION READY</span>
                </div>
                <p className="text-slate-400 mb-2">
                  AuthShield 360 is schema-mapped for Firebase Cloud Firestore collections:
                </p>
                <div className="font-mono text-[11px] text-cyan-300/90 space-y-1 bg-black/40 p-2.5 rounded border border-slate-800/80">
                  <div>· <span className="text-slate-200">/users</span> (name, email, role, 2FA settings, PBKDF2 hash & salt)</div>
                  <div>· <span className="text-slate-200">/security_events</span> (login anomalies, geo-velocity logs, reason codes)</div>
                  <div>· <span className="text-slate-200">/security_alerts</span> (high & critical automated alerts)</div>
                  <div>· <span className="text-slate-200">/baseline_files</span> (FIM cryptographic SHA-256 signatures)</div>
                </div>
              </div>

              <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-amber-200/90">
                <div className="flex items-center gap-2 font-semibold mb-1">
                  <AlertTriangle className="h-4 w-4 text-amber-400" />
                  <span>College Project Viva Note</span>
                </div>
                <p className="text-slate-400">
                  To demonstrate both local containment and external cloud scaling in your project viva, show the Settings tab where the full Firestore rules, collections, and connection guide are documented!
                </p>
              </div>
            </div>

            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => {
                  setShowDbModal(false);
                  onSelectTab('settings');
                }}
                className="rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20"
              >
                View Firebase Architecture in Settings
              </button>
              <button
                onClick={() => setShowDbModal(false)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
