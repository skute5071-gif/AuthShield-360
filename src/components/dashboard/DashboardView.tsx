import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  UserX,
  Activity,
  ArrowRight,
  ShieldCheck,
  CheckCircle,
  Eye,
  Ban,
  FileCheck2,
  Globe,
  Radio,
  ExternalLink,
  Filter,
  Sparkles,
  Play,
  FileText,
  X,
  History,
  Lock,
  MessageSquare,
} from 'lucide-react';
import { SecurityStats, SecurityEvent, SecurityAlert, User } from '../../types/security';
import { StatCard } from '../common/StatCard';
import { RiskBadge } from '../common/RiskBadge';
import { RiskChart } from './RiskChart';
import { api } from '../../services/api';

interface DashboardViewProps {
  stats: SecurityStats | null;
  events: SecurityEvent[];
  alerts: SecurityAlert[];
  currentUser?: User | null;
  isLoading: boolean;
  onSelectTab: (tab: string) => void;
  onUpdateAlertStatus: (id: string, status: SecurityAlert['status'], note?: string) => Promise<void>;
  onBlockIp: (ip: string) => Promise<void>;
  onRefresh: () => Promise<void>;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  events,
  alerts,
  currentUser,
  isLoading,
  onSelectTab,
  onUpdateAlertStatus,
  onBlockIp,
  onRefresh,
}) => {
  const [selectedRiskFilter, setSelectedRiskFilter] = useState<string>('ALL');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Admin Alert Review & Note Modal State
  const [reviewingAlert, setReviewingAlert] = useState<SecurityAlert | null>(null);
  const [investigationNote, setInvestigationNote] = useState('');
  const [isSavingReview, setIsSavingReview] = useState(false);
  const [actingAlertId, setActingAlertId] = useState<string | null>(null);

  // Admin Audit Log Modal
  const [showAdminLogsModal, setShowAdminLogsModal] = useState(false);
  const [adminLogs, setAdminLogs] = useState<any[]>([]);

  // Batch actions
  const [isBatchGenerating, setIsBatchGenerating] = useState(false);
  const [isBatchScanning, setIsBatchScanning] = useState(false);
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  const isAdmin = currentUser?.role === 'admin';

  // Filter alerts by risk level
  const filteredAlerts = alerts.filter((a) => {
    if (selectedRiskFilter === 'ALL') return true;
    return a.severity === selectedRiskFilter;
  });

  const handleAlertAction = async (id: string, status: SecurityAlert['status'], note?: string) => {
    try {
      setActingAlertId(id);
      await onUpdateAlertStatus(id, status, note);
    } finally {
      setActingAlertId(null);
    }
  };

  const handleOpenReviewModal = (alert: SecurityAlert) => {
    setReviewingAlert(alert);
    setInvestigationNote('');
  };

  const handleSaveInvestigationNote = async () => {
    if (!reviewingAlert || !investigationNote.trim()) return;
    setIsSavingReview(true);
    try {
      await api.addAlertNote(reviewingAlert.id, investigationNote.trim());
      await onRefresh();
      setReviewingAlert(null);
      setActionNotice('Investigation note added and recorded in administrative audit log.');
      setTimeout(() => setActionNotice(null), 4000);
    } catch (err: any) {
      alert(err.message || 'Failed to save investigation note. Administrator role required.');
    } finally {
      setIsSavingReview(false);
    }
  };

  const handleGenerateSynthetic = async () => {
    setIsBatchGenerating(true);
    try {
      const res = await api.generateSyntheticLogins();
      setActionNotice(res.message);
      await onRefresh();
      setTimeout(() => setActionNotice(null), 4000);
    } catch (err: any) {
      alert(err.message || 'Admin access required to generate synthetic data.');
    } finally {
      setIsBatchGenerating(false);
    }
  };

  const handleRunBatchDetection = async () => {
    setIsBatchScanning(true);
    try {
      const res = await api.runBatchDetection();
      setActionNotice(res.message);
      await onRefresh();
      setTimeout(() => setActionNotice(null), 4000);
    } catch (err: any) {
      alert(err.message || 'Batch detection execution failed.');
    } finally {
      setIsBatchScanning(false);
    }
  };

  const handleViewAdminLogs = async () => {
    try {
      const logs = await api.getAdminAuditLogs();
      setAdminLogs(logs);
      setShowAdminLogsModal(true);
    } catch (err: any) {
      alert(err.message || 'Admin privileges required to view administrative audit logs.');
    }
  };

  if (isLoading && !stats) {
    return (
      <div className="flex h-96 items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
          <p className="font-mono text-xs text-slate-400">Loading AuthShield 360 telemetry...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Disclaimer Banner */}
      <div className="relative overflow-hidden rounded-xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/40 via-slate-900/60 to-blue-950/40 p-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <span className="flex h-2.5 w-2.5 rounded-full bg-cyan-400 animate-pulse shrink-0" />
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-bold text-cyan-300 uppercase tracking-wide">
                  [SUSPICIOUS LOGIN DETECTION ACTIVE]
                </span>
                <span className="text-slate-400 text-xs hidden md:inline">· Rules 1–5 Behavioral Engine</span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 leading-relaxed">
                Risk scores (0–100) are behavioral anomaly indicators, not legal proof of compromise. Low (0–29), Medium (30–69), and High (70–100).
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {isAdmin ? (
              <>
                <button
                  onClick={handleGenerateSynthetic}
                  disabled={isBatchGenerating}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs font-semibold text-slate-300 hover:text-white transition-colors disabled:opacity-50"
                  title="Generate synthetic login threat records"
                >
                  <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
                  <span className="hidden sm:inline">Generate Samples</span>
                </button>
                <button
                  onClick={handleRunBatchDetection}
                  disabled={isBatchScanning}
                  className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
                  title="Run detection pass over event stream"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span className="hidden sm:inline">Run Detection</span>
                </button>
                <button
                  onClick={handleViewAdminLogs}
                  className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-2.5 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200"
                  title="View Administrative Action Audit Log"
                >
                  <History className="h-3.5 w-3.5 text-cyan-400" />
                  <span className="hidden lg:inline">Admin Audit</span>
                </button>
              </>
            ) : (
              <button
                onClick={() => onSelectTab('login-security')}
                className="flex items-center gap-1.5 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20"
              >
                <span>Login Simulator</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>

      {actionNotice && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{actionNotice}</span>
        </div>
      )}

      {/* 4 Primary Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Login Events"
          value={stats?.totalLoginEvents ?? 0}
          subtitle="Monitored authentication requests"
          icon={Activity}
          variant="cyan"
          trend={{ label: 'Live streaming', neutral: true }}
          onClick={() => onSelectTab('security-events')}
        />
        <StatCard
          title="Failed Login Attempts"
          value={stats?.failedLoginAttempts ?? 0}
          subtitle="Rule 1 tracking window (5m)"
          icon={UserX}
          variant="amber"
          trend={{ label: 'Threshold: 5 attempts', isUp: true }}
          onClick={() => onSelectTab('security-events')}
        />
        <StatCard
          title="Suspicious Login Alerts"
          value={stats?.suspiciousLoginAlerts ?? 0}
          subtitle="Requires security response"
          icon={AlertTriangle}
          variant="rose"
          trend={{ label: `${stats?.reviewedAlertsCount || 0} reviewed`, neutral: true }}
          onClick={() => onSelectTab('login-security')}
        />
        <StatCard
          title="High-Risk Events"
          value={stats?.highRiskEvents ?? 0}
          subtitle="Score >= 70 / 100"
          icon={ShieldAlert}
          variant="blue"
          trend={{ label: 'Perimeter blocked', neutral: true }}
          onClick={() => onSelectTab('security-events')}
        />
      </div>

      {/* Middle Row: Risk Distribution Chart + Live Activity Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Risk Distribution Chart (5 cols) */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Threat Risk Distribution</h3>
              <p className="text-xs text-slate-400">Classified by heuristic risk score</p>
            </div>
            <span className="font-mono text-xs text-cyan-400">Scale 0–100</span>
          </div>

          {stats && (
            <RiskChart
              severityCount={{
                LOW: stats.severityCount.LOW,
                MEDIUM: stats.severityCount.MEDIUM,
                HIGH: stats.severityCount.HIGH,
                CRITICAL: 0,
              }}
              total={stats.totalLoginEvents}
            />
          )}

          <div className="mt-4 border-t border-slate-800/80 pt-3 text-[11px] text-slate-500 flex items-center justify-between">
            <span>Low: 0–29 · Med: 30–69 · High: 70–100</span>
            <span className="font-mono text-slate-400">Blocked IPs: {stats?.blockedIpsCount ?? 0}</span>
          </div>
        </div>

        {/* Recent Security Activity Stream (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Recent Security Activity</h3>
              <p className="text-xs text-slate-400">Live forensic stream from detection perimeter</p>
            </div>
            <button
              onClick={() => onSelectTab('security-events')}
              className="text-xs font-medium text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>View All Log</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          </div>

          <div className="space-y-2.5">
            {events.slice(0, 6).map((evt) => (
              <div
                key={evt.id}
                onClick={() => setSelectedEvent(evt)}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-lg border border-slate-800/50 bg-[#0b1220] p-3 text-xs hover:border-cyan-500/40 cursor-pointer transition-colors"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <RiskBadge severity={evt.severity} />
                    <span className="text-slate-500">·</span>
                    <span className="font-mono text-[11px] text-slate-300">{evt.userEmail}</span>
                    <span className="text-slate-500">·</span>
                    <span className="font-mono text-[11px] text-slate-400">{evt.ip}</span>
                    <span className="text-slate-500">·</span>
                    <span className="text-[11px] text-slate-400">{evt.location}</span>
                  </div>
                  <p className="text-slate-300 line-clamp-1">{evt.description}</p>
                </div>

                <div className="flex items-center justify-between sm:justify-end gap-3 shrink-0 pt-1 sm:pt-0 border-t sm:border-0 border-slate-800/60">
                  <span className="font-mono text-[10px] text-slate-400">{evt.timestamp.slice(11)}</span>
                  <span
                    className={`font-mono text-[10px] font-semibold uppercase ${
                      evt.status === 'BLOCKED'
                        ? 'text-rose-400'
                        : evt.status === 'ACTION_TAKEN'
                        ? 'text-amber-400'
                        : 'text-slate-400'
                    }`}
                  >
                    [{evt.status}]
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* SUSPICIOUS EVENTS & ALERTS TABLE WITH RISK-LEVEL FILTERS */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 backdrop-blur-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-200">Suspicious Login Events & Threat Alerts</h3>
              <span className="font-mono text-xs text-rose-400">({filteredAlerts.length} total)</span>
            </div>
            <p className="text-xs text-slate-400">
              Heuristic alerts generated by Rules 1 through 5 requiring administrator investigation
            </p>
          </div>

          {/* Risk-level Filter Tabs */}
          <div className="flex items-center gap-1 bg-slate-950/70 p-1 rounded-lg border border-slate-800">
            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSelectedRiskFilter(lvl)}
                className={`px-3 py-1 text-xs font-medium rounded transition-colors ${
                  selectedRiskFilter === lvl
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl === 'ALL' ? 'All Risks' : `${lvl} Risk`}
              </button>
            ))}
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <th className="pb-3 pl-2">Risk Level</th>
                <th className="pb-3">Event Anomaly Title</th>
                <th className="pb-3">Origin & Target</th>
                <th className="pb-3">Risk Score</th>
                <th className="pb-3">Review Status</th>
                <th className="pb-3 text-right pr-2">Investigation Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAlerts.map((alert) => (
                <tr key={alert.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 pl-2">
                    <RiskBadge severity={alert.severity} />
                  </td>
                  <td className="py-3 pr-3 font-medium text-slate-200">
                    <div>{alert.title}</div>
                    <div className="text-[11px] text-slate-400 line-clamp-1">{alert.recommendation}</div>
                    {alert.investigationNotes && alert.investigationNotes.length > 0 && (
                      <div className="text-[10px] text-cyan-400 font-mono mt-0.5">
                        · {alert.investigationNotes.length} investigation note(s) logged
                      </div>
                    )}
                  </td>
                  <td className="py-3 font-mono text-[11px]">
                    <div className="text-slate-200">{alert.userEmail}</div>
                    <div className="text-slate-500">{alert.sourceIp}</div>
                  </td>
                  <td className="py-3">
                    <span className="font-mono font-bold text-rose-400">{alert.riskScore}/100</span>
                  </td>
                  <td className="py-3 font-mono text-[11px]">
                    {alert.isReviewed ? (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle className="h-3 w-3" />
                        Reviewed
                      </span>
                    ) : (
                      <span className="text-amber-400 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" />
                        Pending
                      </span>
                    )}
                  </td>
                  <td className="py-3 text-right pr-2">
                    <div className="flex items-center justify-end gap-1.5">
                      {isAdmin ? (
                        <button
                          onClick={() => handleOpenReviewModal(alert)}
                          className="rounded border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-semibold text-cyan-300 hover:bg-cyan-500/20"
                          title="Review alert and add investigation notes"
                        >
                          <MessageSquare className="h-3 w-3 inline mr-1" />
                          Review / Note
                        </button>
                      ) : (
                        <button
                          onClick={() => handleAlertAction(alert.id, 'INVESTIGATING', 'Flagged for analyst review')}
                          className="rounded border border-slate-700 bg-slate-800 px-2.5 py-1 text-[11px] text-slate-300 hover:text-white"
                        >
                          <Eye className="h-3 w-3 inline mr-1" />
                          View
                        </button>
                      )}

                      {isAdmin && (
                        <button
                          onClick={() => onBlockIp(alert.sourceIp)}
                          className="rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1 text-[11px] font-semibold text-rose-300 hover:bg-rose-500/20"
                          title="Block IP at perimeter firewall"
                        >
                          <Ban className="h-3 w-3 inline mr-1" />
                          Block IP
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}

              {filteredAlerts.length === 0 && (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-xs text-slate-400">
                    No suspicious events matched the {selectedRiskFilter} risk criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* EVENT DETAIL MODAL / DRAWER */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md">
          <div className="relative w-full max-w-xl rounded-2xl border border-slate-800 bg-[#0c1424] p-6 shadow-2xl space-y-4">
            <button
              onClick={() => setSelectedEvent(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <ShieldAlert className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100">Suspicious Login Event Record</h3>
                <p className="font-mono text-xs text-slate-400">Event ID: {selectedEvent.id}</p>
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Severity Assessment:</span>
                <RiskBadge severity={selectedEvent.severity} />
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Detection Timestamp:</span>
                <span className="font-mono text-slate-200">{selectedEvent.timestamp}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Target User Identity:</span>
                <span className="font-mono text-cyan-300">{selectedEvent.userEmail}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-slate-400">Connecting IP & Location:</span>
                <span className="font-mono text-slate-200">{selectedEvent.ip} ({selectedEvent.location})</span>
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs space-y-1">
              <span className="text-[10px] uppercase font-semibold text-slate-400">Narrative Summary</span>
              <p className="text-slate-200 leading-relaxed">{selectedEvent.description}</p>
            </div>

            {selectedEvent.details && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs space-y-1">
                <span className="text-[10px] uppercase font-semibold text-slate-400">Telemetry Payload</span>
                <pre className="font-mono text-[10px] text-cyan-300 bg-black/50 p-2 rounded overflow-x-auto max-h-36">
                  {JSON.stringify(selectedEvent.details, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700"
              >
                Close Record
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADMIN INVESTIGATION NOTE & REVIEW MODAL */}
      {reviewingAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md">
          <div className="relative w-full max-w-lg rounded-2xl border border-slate-800 bg-[#0c1424] p-6 shadow-2xl space-y-4">
            <button
              onClick={() => setReviewingAlert(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <FileText className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100">Administrator Alert Investigation</h3>
                <p className="font-mono text-xs text-slate-400">Alert ID: {reviewingAlert.id}</p>
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 text-xs space-y-1">
              <div className="font-semibold text-slate-200">{reviewingAlert.title}</div>
              <div className="text-[11px] text-slate-400">User: {reviewingAlert.userEmail} · IP: {reviewingAlert.sourceIp}</div>
            </div>

            {/* Existing notes */}
            {reviewingAlert.investigationNotes && reviewingAlert.investigationNotes.length > 0 && (
              <div className="space-y-2 max-h-36 overflow-y-auto pr-1">
                <span className="text-[10px] uppercase font-semibold text-slate-400">Prior Investigation Notes:</span>
                {reviewingAlert.investigationNotes.map((n) => (
                  <div key={n.id} className="rounded border border-slate-800 bg-slate-900/90 p-2 text-xs space-y-0.5">
                    <div className="flex items-center justify-between font-mono text-[10px] text-slate-400">
                      <span>{n.author}</span>
                      <span>{n.timestamp}</span>
                    </div>
                    <p className="text-slate-200 text-[11px]">{n.note}</p>
                  </div>
                ))}
              </div>
            )}

            {/* New Note Input */}
            <div className="space-y-1.5 text-xs">
              <label className="text-slate-300 font-medium">Add Investigation Note & Forensic Finding</label>
              <textarea
                rows={3}
                value={investigationNote}
                onChange={(e) => setInvestigationNote(e.target.value)}
                placeholder="Document your findings, e.g. confirmed travel with user via corporate phone, verified legitimate ISP change..."
                className="w-full rounded-lg border border-slate-800 bg-[#090e1a] p-3 text-xs text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div className="flex gap-2 justify-end pt-2">
              <button
                type="button"
                onClick={() => setReviewingAlert(null)}
                className="rounded-lg bg-slate-800 px-3 py-2 text-xs text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSaveInvestigationNote}
                disabled={isSavingReview || !investigationNote.trim()}
                className="rounded-lg bg-cyan-500 px-4 py-2 text-xs font-bold text-slate-950 hover:bg-cyan-400 transition-colors disabled:opacity-50"
              >
                {isSavingReview ? 'Saving to Audit Log...' : 'Save & Mark Reviewed'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ADMIN AUDIT LOGS MODAL */}
      {showAdminLogsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4 backdrop-blur-md">
          <div className="relative w-full max-w-2xl rounded-2xl border border-slate-800 bg-[#0c1424] p-6 shadow-2xl space-y-4">
            <button
              onClick={() => setShowAdminLogsModal(false)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <History className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100">Administrator Security Audit Log</h3>
                <p className="text-xs text-slate-400">Immutable trail of administrative overrides, investigations, and policy updates</p>
              </div>
            </div>

            <div className="max-h-72 overflow-y-auto divide-y divide-slate-800/80 rounded-lg border border-slate-800 bg-[#090f1d]">
              {adminLogs.map((log) => (
                <div key={log.id} className="p-3 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] text-cyan-400 font-bold">[{log.actionType}]</span>
                    <span className="font-mono text-[10px] text-slate-500">{log.timestamp}</span>
                  </div>
                  <p className="text-slate-200">{log.details}</p>
                  <div className="text-[10px] text-slate-400">By: <span className="font-mono text-slate-300">{log.adminEmail}</span></div>
                </div>
              ))}

              {adminLogs.length === 0 && (
                <div className="py-6 text-center text-xs text-slate-500">
                  No administrative actions logged yet.
                </div>
              )}
            </div>

            <div className="flex justify-end">
              <button
                onClick={() => setShowAdminLogsModal(false)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700"
              >
                Close Audit Log
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
