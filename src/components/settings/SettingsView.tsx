import React, { useState, useEffect } from 'react';
import {
  Settings,
  Shield,
  Sliders,
  Database,
  Ban,
  CheckCircle2,
  Trash2,
  Plus,
  Flame,
  FileCode,
  Copy,
  Info,
  KeyRound,
  ShieldAlert,
  Smartphone,
  Lock,
  History,
} from 'lucide-react';
import { SecuritySettings, User, LoginEventRecord } from '../../types/security';
import { UserRoleBadge } from '../auth/UserRoleBadge';
import { api } from '../../services/api';

interface SettingsViewProps {
  settings: SecuritySettings | null;
  currentUser: User | null;
  onUpdateSettings: (newSettings: Partial<SecuritySettings>) => Promise<void>;
  onResetDemo: () => Promise<void>;
  onUserUpdated?: (user: User) => void;
  onOpenAuthModal?: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  settings,
  currentUser,
  onUpdateSettings,
  onResetDemo,
  onUserUpdated,
  onOpenAuthModal,
}) => {
  const [formData, setFormData] = useState<SecuritySettings>({
    failedLoginsThreshold: 5,
    failedLoginsWindowMinutes: 5,
    burstVelocityThresholdPerMinute: 8,
    geoVelocityThresholdKmH: 800,
    maxFailedAttempts: 4,
    mfaScoreThreshold: 35,
    blockScoreThreshold: 75,
    blockTorByDefault: true,
    autoLockMinutes: 30,
    paymentBaselineAmount: 500,
    defenseMode: 'NORMAL',
  });

  const [blockedIps, setBlockedIps] = useState<string[]>([]);
  const [newIpToBlock, setNewIpToBlock] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [copiedSection, setCopiedSection] = useState<string | null>(null);

  // User 2FA & Login Audit History State
  const [isToggling2FA, setIsToggling2FA] = useState(false);
  const [loginHistory, setLoginHistory] = useState<LoginEventRecord[]>([]);

  useEffect(() => {
    if (settings) {
      setFormData(settings);
    }
    loadBlockedIps();
    if (currentUser) {
      loadLoginHistory();
    }
  }, [settings, currentUser]);

  const loadBlockedIps = async () => {
    try {
      const ips = await api.getBlockedIps();
      setBlockedIps(ips);
    } catch (err) {
      console.error(err);
    }
  };

  const loadLoginHistory = async () => {
    try {
      const history = await api.getLoginHistory();
      setLoginHistory(history);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSave = async () => {
    setIsSaving(true);
    try {
      await onUpdateSettings(formData);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err: any) {
      alert(err.message || 'Failed to update settings. Admin access required.');
    } finally {
      setIsSaving(false);
    }
  };

  const handleAddIpBlock = async () => {
    if (!newIpToBlock.trim()) return;
    try {
      await api.blockIp(newIpToBlock.trim());
      setNewIpToBlock('');
      await loadBlockedIps();
    } catch (err: any) {
      alert(err.message || 'Failed to block IP. Administrator privileges required.');
    }
  };

  const handleUnblock = async (ip: string) => {
    try {
      await api.unblockIp(ip);
      await loadBlockedIps();
    } catch (err: any) {
      alert(err.message || 'Failed to unblock IP. Administrator privileges required.');
    }
  };

  const handleToggle2FA = async () => {
    if (!currentUser) return;
    setIsToggling2FA(true);
    try {
      const res = await api.toggle2FA(!currentUser.twoFactorEnabled);
      if (onUserUpdated) {
        onUserUpdated({ ...currentUser, twoFactorEnabled: res.twoFactorEnabled });
      }
    } catch (err: any) {
      alert(err.message || 'Failed to toggle 2FA');
    } finally {
      setIsToggling2FA(false);
    }
  };

  const copyToClipboard = (text: string, section: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSection(section);
    setTimeout(() => setCopiedSection(null), 2000);
  };

  const firestoreRulesSnippet = `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Only authenticated security operators may access audit records
    match /security_events/{eventId} {
      allow read, create: if request.auth != null;
      allow update, delete: if false; // Immutable audit log
    }
    match /security_alerts/{alertId} {
      allow read, write: if request.auth != null;
    }
    match /baseline_files/{fileId} {
      allow read: if request.auth != null;
      allow write: if request.auth.token.role == 'secops_admin';
    }
    match /users/{userId} {
      allow read: if request.auth != null && (request.auth.uid == userId || request.auth.token.role == 'admin');
      allow write: if request.auth.token.role == 'admin';
    }
  }
}`;

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
          <Settings className="h-5 w-5 text-cyan-400" />
          <span>Security Policy Settings, Role Access & Persistence</span>
        </h2>
        <p className="text-xs text-slate-400">
          Configure multi-factor authentication, RBAC authorization, detection thresholds, and Firebase Firestore mapping
        </p>
      </div>

      {/* USER ACCOUNT SECURITY & RBAC CARD */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <KeyRound className="h-4 w-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-200">Current Session & Access Control (RBAC)</h3>
          </div>
          {currentUser && <UserRoleBadge role={currentUser.role} />}
        </div>

        {currentUser ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            {/* Account Details */}
            <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3.5 space-y-2">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Account Identity</span>
              <div className="font-bold text-slate-100 text-sm">{currentUser.name}</div>
              <div className="font-mono text-cyan-300 text-xs">{currentUser.email}</div>
              <div className="text-slate-500 text-[11px] pt-1">
                Role: <span className="font-mono text-slate-300 capitalize">{currentUser.role}</span>
              </div>
            </div>

            {/* 2FA Controller */}
            <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3.5 space-y-2 flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                    Two-Factor Auth (2FA)
                  </span>
                  <span
                    className={`font-mono text-[10px] font-bold ${
                      currentUser.twoFactorEnabled ? 'text-emerald-400' : 'text-slate-500'
                    }`}
                  >
                    {currentUser.twoFactorEnabled ? '● ENABLED' : '○ DISABLED'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed mt-1">
                  Enforces step-up 6-digit one-time code verification during authentication.
                </p>
              </div>

              <button
                onClick={handleToggle2FA}
                disabled={isToggling2FA}
                className={`mt-2 w-full rounded-lg py-1.5 px-3 text-xs font-semibold transition-colors ${
                  currentUser.twoFactorEnabled
                    ? 'border border-rose-500/30 bg-rose-500/10 text-rose-300 hover:bg-rose-500/20'
                    : 'border border-cyan-500/40 bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20'
                }`}
              >
                {isToggling2FA
                  ? 'Updating...'
                  : currentUser.twoFactorEnabled
                  ? 'Disable Two-Factor Auth'
                  : 'Enable Two-Factor Auth'}
              </button>
            </div>

            {/* Role Privilege Matrix */}
            <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3.5 space-y-1.5">
              <span className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                Server-Side Privileges
              </span>
              <div className="space-y-1 text-[11px]">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">View Telemetry & Run Scans</span>
                  <span className="font-mono text-emerald-400 font-bold">ALL USERS</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Modify Perimeter Firewall</span>
                  <span className="font-mono text-cyan-400 font-bold">ADMIN ONLY</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Alter Detection Thresholds</span>
                  <span className="font-mono text-cyan-400 font-bold">ADMIN ONLY</span>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-slate-800 p-6 text-center text-xs text-slate-400">
            <Lock className="h-6 w-6 text-cyan-400 mx-auto mb-2" />
            <p>You are currently browsing with a guest session. Sign in to view account controls and audit records.</p>
            {onOpenAuthModal && (
              <button
                onClick={onOpenAuthModal}
                className="mt-3 rounded-lg bg-cyan-500 px-4 py-1.5 text-xs font-bold text-slate-950 hover:bg-cyan-400"
              >
                Sign In / Switch Role
              </button>
            )}
          </div>
        )}

        {/* Recent Authentication Event History Table */}
        {loginHistory.length > 0 && (
          <div className="pt-2">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <History className="h-3.5 w-3.5 text-cyan-400" />
                Login Event Audit Log ({loginHistory.length} records)
              </span>
              <button
                onClick={loadLoginHistory}
                className="text-[11px] text-cyan-400 hover:text-cyan-300"
              >
                Refresh Log
              </button>
            </div>

            <div className="overflow-x-auto rounded-lg border border-slate-800 bg-[#090f1d]">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] uppercase font-semibold text-slate-400">
                    <th className="py-2.5 pl-3">Timestamp</th>
                    <th className="py-2.5">User Email</th>
                    <th className="py-2.5">Result</th>
                    <th className="py-2.5">Reason Code</th>
                    <th className="py-2.5 pr-3 text-right">Connecting IP</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {loginHistory.slice(0, 5).map((log) => (
                    <tr key={log.id} className="hover:bg-slate-800/20">
                      <td className="py-2 pl-3 text-slate-400 whitespace-nowrap">{log.timestamp}</td>
                      <td className="py-2 text-slate-200">{log.email}</td>
                      <td className="py-2">
                        <span className={log.success ? 'text-emerald-400 font-bold' : 'text-rose-400 font-bold'}>
                          {log.success ? 'SUCCESS' : 'FAILED'}
                        </span>
                      </td>
                      <td className="py-2 text-slate-300">[{log.reasonCode}]</td>
                      <td className="py-2 pr-3 text-right text-slate-400">{log.ip}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* THRESHOLDS & PERIMETER DROP TABLE */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Security Threshold Configuration (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Sliders className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Detection & Policy Thresholds</h3>
            </div>
            {saveSuccess && (
              <span className="flex items-center gap-1 font-mono text-xs text-emerald-400">
                <CheckCircle2 className="h-3.5 w-3.5" />
                Saved to Engine
              </span>
            )}
          </div>

          <div className="space-y-4 text-xs">
            {/* Defense Mode Segmented Controller */}
            <div>
              <label className="text-slate-300 font-medium">System-Wide Defense Mode</label>
              <div className="mt-1.5 grid grid-cols-3 gap-2">
                {(['NORMAL', 'ELEVATED', 'HIGH_ALERT'] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setFormData({ ...formData, defenseMode: mode })}
                    className={`rounded-lg border px-3 py-2 text-center text-xs font-mono font-bold transition-all ${
                      formData.defenseMode === mode
                        ? mode === 'HIGH_ALERT'
                          ? 'border-rose-500 bg-rose-500/20 text-rose-300'
                          : mode === 'ELEVATED'
                          ? 'border-amber-500 bg-amber-500/20 text-amber-300'
                          : 'border-emerald-500 bg-emerald-500/20 text-emerald-300'
                        : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {mode}
                  </button>
                ))}
              </div>
            </div>

            {/* Geo Velocity */}
            <div className="rounded-lg border border-slate-800/80 bg-[#090f1d] p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-200">Geo-Velocity Speed Ceiling (km/h)</div>
                  <div className="text-[11px] text-slate-400">
                    Maximum plausible transit speed before triggering Impossible Travel alert
                  </div>
                </div>
                <span className="font-mono text-sm font-bold text-cyan-400">
                  {formData.geoVelocityThresholdKmH} km/h
                </span>
              </div>
              <input
                type="range"
                min="400"
                max="2000"
                step="50"
                value={formData.geoVelocityThresholdKmH}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    geoVelocityThresholdKmH: parseInt(e.target.value, 10),
                  })
                }
                className="w-full accent-cyan-500 cursor-pointer"
              />
            </div>

            {/* Max Failed Attempts */}
            <div className="rounded-lg border border-slate-800/80 bg-[#090f1d] p-3.5 space-y-2">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-200">Brute-Force Lockout Threshold</div>
                  <div className="text-[11px] text-slate-400">
                    Consecutive authentication failures allowed before automated account lock
                  </div>
                </div>
                <span className="font-mono text-sm font-bold text-cyan-400">
                  {formData.maxFailedAttempts} attempts
                </span>
              </div>
              <input
                type="range"
                min="2"
                max="10"
                step="1"
                value={formData.maxFailedAttempts}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    maxFailedAttempts: parseInt(e.target.value, 10),
                  })
                }
                className="w-full accent-cyan-500 cursor-pointer"
              />
            </div>

            {/* Suspicious Login Detection Thresholds (Rules 1-3) */}
            <div className="rounded-lg border border-cyan-500/30 bg-[#090f1d] p-3.5 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <div className="font-semibold text-cyan-300 text-xs">Suspicious Login Threshold (Rule 1 & Rule 3)</div>
                  <div className="text-[11px] text-slate-400">
                    Configurable failed attempt count within sliding time window before triggering suspicious event
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Failed Attempts Threshold</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min="2"
                      max="20"
                      value={formData.failedLoginsThreshold ?? 5}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          failedLoginsThreshold: parseInt(e.target.value, 10) || 5,
                        })
                      }
                      className="w-full rounded border border-slate-800 bg-slate-900 px-2.5 py-1.5 font-mono text-slate-100 focus:border-cyan-500"
                    />
                    <span className="text-slate-400 font-mono text-[11px]">fails</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Evaluation Window</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min="1"
                      max="60"
                      value={formData.failedLoginsWindowMinutes ?? 5}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          failedLoginsWindowMinutes: parseInt(e.target.value, 10) || 5,
                        })
                      }
                      className="w-full rounded border border-slate-800 bg-slate-900 px-2.5 py-1.5 font-mono text-slate-100 focus:border-cyan-500"
                    />
                    <span className="text-slate-400 font-mono text-[11px]">mins</span>
                  </div>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs pt-1 border-t border-slate-800">
                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Burst Velocity Cap (Rule 3)</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min="3"
                      max="30"
                      value={formData.burstVelocityThresholdPerMinute ?? 8}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          burstVelocityThresholdPerMinute: parseInt(e.target.value, 10) || 8,
                        })
                      }
                      className="w-full rounded border border-slate-800 bg-slate-900 px-2.5 py-1.5 font-mono text-slate-100 focus:border-cyan-500"
                    />
                    <span className="text-slate-400 font-mono text-[11px]">req/min</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400">Payment Spike Baseline</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      min="50"
                      max="10000"
                      step="50"
                      value={formData.paymentBaselineAmount ?? 500}
                      onChange={(e) =>
                        setFormData({
                          ...formData,
                          paymentBaselineAmount: parseFloat(e.target.value) || 500,
                        })
                      }
                      className="w-full rounded border border-slate-800 bg-slate-900 px-2.5 py-1.5 font-mono text-slate-100 focus:border-cyan-500"
                    />
                    <span className="text-slate-400 font-mono text-[11px]">USD/INR</span>
                  </div>
                </div>
              </div>
            </div>

            {/* MFA Threshold & Block Threshold */}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg border border-slate-800/80 bg-[#090f1d] p-3 space-y-1">
                <label className="text-[11px] text-slate-400">MFA Challenge Threshold</label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="10"
                    max="60"
                    value={formData.mfaScoreThreshold}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        mfaScoreThreshold: parseInt(e.target.value, 10) || 30,
                      })
                    }
                    className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-slate-100"
                  />
                  <span className="text-slate-500 font-mono">pts</span>
                </div>
              </div>

              <div className="rounded-lg border border-slate-800/80 bg-[#090f1d] p-3 space-y-1">
                <label className="text-[11px] text-slate-400">Hard Block Threshold</label>
                <div className="flex items-center gap-2">
                  <input
                    type="number"
                    min="60"
                    max="95"
                    value={formData.blockScoreThreshold}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        blockScoreThreshold: parseInt(e.target.value, 10) || 75,
                      })
                    }
                    className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-slate-100"
                  />
                  <span className="text-slate-500 font-mono">pts</span>
                </div>
              </div>
            </div>

            {/* Tor Network Checkbox */}
            <label className="flex items-center gap-2.5 rounded-lg border border-slate-800/80 bg-[#090f1d] p-3 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.blockTorByDefault}
                onChange={(e) => setFormData({ ...formData, blockTorByDefault: e.target.checked })}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0"
              />
              <div>
                <span className="text-xs text-slate-200 font-medium">
                  Automatically Block Known Tor Exit Nodes
                </span>
                <p className="text-[11px] text-slate-500">
                  Assigns immediate critical risk score when login originates from Tor directory relays
                </p>
              </div>
            </label>

            <button
              onClick={handleSave}
              disabled={isSaving}
              className="w-full rounded-xl bg-cyan-500 px-4 py-2.5 text-xs font-bold text-slate-950 hover:bg-cyan-400 transition-colors disabled:opacity-50"
            >
              {isSaving ? 'Updating Engine Settings...' : 'Save Policy Changes (Admin)'}
            </button>
          </div>
        </div>

        {/* Right: Edge Firewall Drop List & DB Architecture (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Edge Firewall IP Blocklist */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Ban className="h-4 w-4 text-rose-400" />
                <h3 className="text-sm font-semibold text-slate-200">Perimeter Firewall Drop Table</h3>
              </div>
              <span className="font-mono text-xs text-rose-400">{blockedIps.length} Banned</span>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                placeholder="IP Address to ban (e.g. 194.26.29.112)..."
                value={newIpToBlock}
                onChange={(e) => setNewIpToBlock(e.target.value)}
                className="flex-1 rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-rose-500 focus:outline-none"
              />
              <button
                onClick={handleAddIpBlock}
                className="flex items-center gap-1 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-semibold text-rose-300 hover:bg-rose-500/20"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>Ban IP</span>
              </button>
            </div>

            <div className="space-y-1.5 max-h-44 overflow-y-auto">
              {blockedIps.map((ip) => (
                <div
                  key={ip}
                  className="flex items-center justify-between rounded border border-slate-800/60 bg-[#090f1d] px-3 py-2 text-xs"
                >
                  <span className="font-mono text-rose-300 font-semibold">{ip}</span>
                  <button
                    onClick={() => handleUnblock(ip)}
                    className="text-slate-400 hover:text-white"
                    title="Remove IP ban"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}

              {blockedIps.length === 0 && (
                <div className="py-4 text-center text-xs text-slate-500">
                  No IPs blocked in perimeter firewall table.
                </div>
              )}
            </div>
          </div>

          {/* Database Setup & Firebase Integration Specification */}
          <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-200">Firebase Firestore Specification</h3>
              </div>
              <span className="font-mono text-[10px] text-cyan-400">READY</span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              AuthShield 360 models map directly to Firebase Firestore documents. To enable cloud persistence in production, accept the interactive Firebase setup:
            </p>

            <div className="relative">
              <button
                onClick={() => copyToClipboard(firestoreRulesSnippet, 'rules')}
                className="absolute right-2 top-2 rounded bg-slate-800 p-1 text-slate-300 hover:text-white"
                title="Copy Firestore Security Rules"
              >
                <Copy className="h-3 w-3" />
              </button>
              <pre className="font-mono text-[10px] text-slate-300 bg-black/50 p-2.5 rounded border border-slate-800/80 overflow-x-auto max-h-36">
                {firestoreRulesSnippet}
              </pre>
            </div>

            {copiedSection === 'rules' && (
              <span className="font-mono text-[11px] text-emerald-400">
                Copied Firestore rules to clipboard!
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
