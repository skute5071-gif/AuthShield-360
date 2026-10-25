import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Save,
  RotateCcw,
  Lock,
  Smartphone,
  RefreshCw,
  HardDrive,
  ShieldAlert,
  Wifi,
  Sliders,
  PackageCheck,
  KeyRound,
  Info,
  Check,
  Sparkles,
} from 'lucide-react';
import { SecurityChecklistItem, SecurityChecklistState, User } from '../../types/security';
import { api } from '../../services/api';

interface SecurityChecklistViewProps {
  currentUser: User | null;
  onOpenAuthModal?: (mode?: 'login' | 'register') => void;
  onChecklistUpdated?: () => void;
}

export const SecurityChecklistView: React.FC<SecurityChecklistViewProps> = ({
  currentUser,
  onOpenAuthModal,
  onChecklistUpdated,
}) => {
  const [items, setItems] = useState<SecurityChecklistItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const categoryIcons: Record<string, React.ElementType> = {
    'Identity & Access Management': KeyRound,
    'Vulnerability Management': RefreshCw,
    'Data Resilience & Continuity': HardDrive,
    'Endpoint & Perimeter Protection': ShieldAlert,
    'Network Security': Wifi,
    'Device Hardening & Least Privilege': Sliders,
    'Application Security & Supply Chain': PackageCheck,
    'Web Application Defense': Lock,
  };

  const loadChecklist = async () => {
    setIsLoading(true);
    try {
      const state = await api.getSecurityChecklist();
      setItems(state.items);
      setLastUpdated(state.lastUpdated);
    } catch (err: any) {
      console.error('Failed to load checklist:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadChecklist();
  }, [currentUser]);

  const handleToggleItem = (id: string) => {
    setItems((prev) =>
      prev.map((item) =>
        item.id === id ? { ...item, completed: !item.completed } : item
      )
    );
  };

  const handleUpdateNotes = (id: string, notes: string) => {
    setItems((prev) =>
      prev.map((item) => (item.id === id ? { ...item, notes } : item))
    );
  };

  const handleSave = async () => {
    setIsSaving(true);
    setSaveSuccess(false);
    setSaveError(null);
    try {
      const updatedState = await api.saveSecurityChecklist(items);
      setItems(updatedState.items);
      setLastUpdated(updatedState.lastUpdated);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
      if (onChecklistUpdated) onChecklistUpdated();
    } catch (err: any) {
      setSaveError(err.message || 'Failed to save checklist progress');
    } finally {
      setIsSaving(false);
    }
  };

  const completedCount = items.filter((i) => i.completed).length;
  const totalCount = items.length;
  const percentage = totalCount > 0 ? Math.round((completedCount / totalCount) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="h-6 w-6 text-cyan-400" />
            <span>Essential Security Controls Checklist</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Practical defense-in-depth baseline verification covering identity, patch management, backups, perimeter, and network hardening
          </p>
        </div>

        <div className="flex items-center gap-2">
          {currentUser ? (
            <span className="text-[11px] font-mono text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 px-2.5 py-1">
              User: {currentUser.email}
            </span>
          ) : (
            <button
              onClick={() => onOpenAuthModal && onOpenAuthModal('login')}
              className="text-xs text-amber-300 hover:text-amber-200 bg-amber-500/10 border border-amber-500/30 px-2.5 py-1 transition-colors"
            >
              Sign in to save cloud progress
            </button>
          )}

          <button
            onClick={handleSave}
            disabled={isSaving}
            className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-4 py-1.5 text-xs uppercase tracking-wider flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            {isSaving ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent animate-spin inline-block" />
                <span>Saving...</span>
              </>
            ) : (
              <>
                <Save className="h-3.5 w-3.5" />
                <span>Save Progress</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Save Feedback Alerts */}
      {saveSuccess && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 p-3 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
          <span>Security checklist progress saved successfully to user profile.</span>
        </div>
      )}

      {saveError && (
        <div className="bg-rose-500/10 border border-rose-500/30 p-3 text-xs text-rose-300 flex items-center gap-2">
          <XCircle className="h-4 w-4 text-rose-400 shrink-0" />
          <span>{saveError}</span>
        </div>
      )}

      {/* Progress Metric Card */}
      <div className="bg-slate-900 border border-slate-800 p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Implementation Compliance Score
            </div>
            <div className="text-2xl font-mono font-bold text-slate-100 mt-1 flex items-center gap-3">
              <span>{percentage}% Compliant</span>
              <span
                className={`text-xs px-2.5 py-0.5 border font-sans font-semibold ${
                  percentage >= 80
                    ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                    : percentage >= 50
                    ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    : 'bg-rose-500/10 text-rose-300 border-rose-500/30'
                }`}
              >
                {percentage >= 80 ? 'STRONG POSTURE' : percentage >= 50 ? 'ELEVATED RISK' : 'CRITICAL GAPS'}
              </span>
            </div>
            <div className="text-xs text-slate-400 mt-0.5">
              {completedCount} of {totalCount} mandatory security domains implemented
            </div>
          </div>

          <div className="text-right text-xs text-slate-400 font-mono">
            {lastUpdated && <div>Last Updated: {new Date(lastUpdated).toLocaleDateString()}</div>}
            <div className="text-[11px] text-slate-400 mt-0.5">8 Essential Verification Domains</div>
          </div>
        </div>

        {/* Visual Progress Bar */}
        <div className="w-full h-3 bg-slate-950 border border-slate-800 overflow-hidden">
          <div
            style={{ width: `${percentage}%` }}
            className={`h-full transition-all duration-500 ${
              percentage >= 80 ? 'bg-emerald-500' : percentage >= 50 ? 'bg-amber-500' : 'bg-rose-500'
            }`}
          />
        </div>
      </div>

      {/* Checklist Items Grid */}
      {isLoading ? (
        <div className="p-12 text-center text-xs text-slate-400">Loading security checklist...</div>
      ) : (
        <div className="space-y-3">
          {items.map((item, idx) => {
            const Icon = categoryIcons[item.category] || ShieldCheck;
            return (
              <div
                key={item.id}
                className={`p-4 border transition-all ${
                  item.completed
                    ? 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                    : 'bg-slate-900/60 border-amber-500/30 hover:border-amber-500/50'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  {/* Left: Checkbox & Info */}
                  <div className="flex items-start gap-3">
                    <input
                      type="checkbox"
                      id={`chk-${item.id}`}
                      checked={item.completed}
                      onChange={() => handleToggleItem(item.id)}
                      className="mt-1 h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0 cursor-pointer"
                    />

                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <label
                          htmlFor={`chk-${item.id}`}
                          className={`text-sm font-bold cursor-pointer transition-colors ${
                            item.completed ? 'text-slate-100 line-through opacity-80' : 'text-slate-100'
                          }`}
                        >
                          {idx + 1}. {item.title}
                        </label>
                        <span className="text-[10px] font-mono px-2 py-0.5 bg-slate-800 text-slate-400 border border-slate-700 flex items-center gap-1">
                          <Icon className="h-3 w-3 text-cyan-400" />
                          <span>{item.category}</span>
                        </span>
                      </div>

                      <p className="text-xs text-slate-400 leading-relaxed max-w-3xl">
                        {item.description}
                      </p>

                      {/* Technical Notes / Verification details */}
                      <div className="pt-1">
                        <input
                          type="text"
                          placeholder="Add technical notes or compliance evidence..."
                          value={item.notes || ''}
                          onChange={(e) => handleUpdateNotes(item.id, e.target.value)}
                          className="w-full bg-slate-950/80 border border-slate-800 text-slate-300 text-[11px] font-mono px-2.5 py-1 focus:border-cyan-500 focus:outline-none"
                        />
                      </div>
                    </div>
                  </div>

                  {/* Right: Compliance Status Badge */}
                  <div className="shrink-0 self-start sm:self-center">
                    <span
                      className={`text-[10px] font-mono font-bold px-2.5 py-1 border flex items-center gap-1 ${
                        item.completed
                          ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
                          : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                      }`}
                    >
                      {item.completed ? (
                        <>
                          <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                          <span>COMPLIANT</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="h-3 w-3 text-amber-400" />
                          <span>ACTION NEEDED</span>
                        </>
                      )}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
