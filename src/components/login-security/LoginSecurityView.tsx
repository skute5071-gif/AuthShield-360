import React, { useState } from 'react';
import {
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertOctagon,
  Clock,
  Compass,
  Monitor,
  Flame,
  ArrowRight,
  RotateCcw,
  Sliders,
  Shield,
  MapPin,
  Lock,
  ShieldCheck,
  AlertTriangle,
  History,
  Info,
  Sparkles,
} from 'lucide-react';
import { SuspiciousLoginResult, User } from '../../types/security';
import { RiskBadge } from '../common/RiskBadge';
import { api } from '../../services/api';

interface LoginSecurityViewProps {
  currentUser?: User | null;
  onEventCreated: () => Promise<void>;
  onSelectTab: (tab: string) => void;
}

export const LoginSecurityView: React.FC<LoginSecurityViewProps> = ({ currentUser, onEventCreated, onSelectTab }) => {
  // Preset scenarios covering all required test cases
  const scenarios = [
    {
      id: 'ordinary-login',
      category: 'Ordinary Login',
      label: 'Ordinary Legitimate User Session',
      badge: 'Low Risk Baseline',
      desc: 'Standard student login from verified campus location with matching historical device.',
      data: {
        userId: 'usr_priya',
        userEmail: 'priya.student@college.edu',
        ip: '140.211.9.87',
        location: { city: 'San Jose', country: 'USA', lat: 37.3382, lon: -121.8863 },
        device: {
          browser: 'Chrome 122',
          os: 'macOS Sonoma',
          userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
          isKnownDevice: true,
        },
        recentFailedAttemptsCount: 0,
        windowMinutes: 5,
        isSuccessfulLoginNow: true,
        hadRecentMultipleFailuresPrior: false,
        recentAttemptsRatePerMin: 1,
        historicalBaseline: {
          totalLogins: 12,
          knownCities: ['San Jose', 'Santa Clara'],
          knownCountries: ['USA'],
          knownBrowsers: ['Chrome 122', 'Chrome 121'],
          knownOperatingSystems: ['macOS Sonoma'],
          typicalHours: [9, 10, 11, 14, 15, 16],
        },
        isTorOrVpn: false,
        attemptHour: 10,
      },
    },
    {
      id: 'rule1-repeated-failures',
      category: 'Rule 1: Repeated Failures',
      label: '5 Failed Logins within 5 Minutes',
      badge: 'Brute-Force Pattern',
      desc: '5 consecutive authentication failures from single source IP within detection window.',
      data: {
        userId: 'usr_admin',
        userEmail: 'admin@authshield.internal',
        ip: '194.26.29.112',
        location: { city: 'Bucharest', country: 'Romania', lat: 44.4268, lon: 26.1025 },
        device: {
          browser: 'Firefox 135',
          os: 'Linux x86_64',
          userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
          isKnownDevice: false,
        },
        recentFailedAttemptsCount: 5,
        windowMinutes: 4,
        isSuccessfulLoginNow: false,
        hadRecentMultipleFailuresPrior: false,
        recentAttemptsRatePerMin: 4,
        historicalBaseline: {
          totalLogins: 45,
          knownCities: ['San Jose', 'San Francisco'],
          knownCountries: ['USA'],
          knownBrowsers: ['Chrome 122'],
          knownOperatingSystems: ['macOS Sonoma'],
          typicalHours: [9, 10, 11, 12, 13, 14, 15, 16, 17],
        },
        isTorOrVpn: false,
        attemptHour: 3,
      },
    },
    {
      id: 'rule2-failures-then-success',
      category: 'Rule 2: Guessing Success',
      label: 'Multiple Failures Followed by Success',
      badge: 'Credential Guessing',
      desc: 'Account experienced 4 rapid failures, followed immediately by a successful authentication.',
      data: {
        userId: 'usr_research',
        userEmail: 'fellow.research@college.edu',
        ip: '203.0.113.89',
        location: { city: 'Tokyo', country: 'Japan', lat: 35.6762, lon: 139.6503 },
        device: {
          browser: 'Edge 122',
          os: 'Windows 11',
          userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
          isKnownDevice: false,
        },
        recentFailedAttemptsCount: 4,
        windowMinutes: 3,
        isSuccessfulLoginNow: true,
        hadRecentMultipleFailuresPrior: true,
        recentAttemptsRatePerMin: 3,
        historicalBaseline: {
          totalLogins: 8,
          knownCities: ['Chicago'],
          knownCountries: ['USA'],
          knownBrowsers: ['Firefox 130'],
          knownOperatingSystems: ['Windows 10'],
          typicalHours: [10, 11, 14],
        },
        isTorOrVpn: false,
        attemptHour: 2,
      },
    },
    {
      id: 'rule3-burst-velocity',
      category: 'Rule 3: Frequency Anomaly',
      label: 'Unusually Frequent Login Attempts',
      badge: 'Burst Velocity',
      desc: 'Submission frequency spikes to 14 requests/min, indicating automated credential stuffing script.',
      data: {
        userId: 'usr_student',
        userEmail: 'student.priya@college.edu',
        ip: '198.51.100.22',
        location: { city: 'Frankfurt', country: 'Germany', lat: 50.1109, lon: 8.6821 },
        device: {
          browser: 'Python-Requests',
          os: 'Linux',
          userAgent: 'python-requests/2.31.0',
          isKnownDevice: false,
        },
        recentFailedAttemptsCount: 3,
        windowMinutes: 1,
        isSuccessfulLoginNow: false,
        hadRecentMultipleFailuresPrior: false,
        recentAttemptsRatePerMin: 14, // > 8
        isTorOrVpn: true,
        attemptHour: 4,
      },
    },
    {
      id: 'false-positive-scenario',
      category: 'False-Positive Scenario',
      label: 'Legitimate Traveler on Airport Wi-Fi',
      badge: 'Benign Anomaly',
      desc: 'Legitimate student connects from airport departure lounge using a newly purchased tablet.',
      data: {
        userId: 'usr_student',
        userEmail: 'priya.student@college.edu',
        ip: '192.178.4.11',
        location: { city: 'Denver', country: 'USA', lat: 39.7392, lon: -104.9903 },
        device: {
          browser: 'Safari Mobile 18',
          os: 'iPadOS',
          userAgent: 'Mozilla/5.0 (iPad; CPU OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
          isKnownDevice: false,
        },
        recentFailedAttemptsCount: 0,
        windowMinutes: 5,
        isSuccessfulLoginNow: true,
        hadRecentMultipleFailuresPrior: false,
        recentAttemptsRatePerMin: 1,
        historicalBaseline: {
          totalLogins: 14,
          knownCities: ['San Jose'],
          knownCountries: ['USA'],
          knownBrowsers: ['Chrome 122'],
          knownOperatingSystems: ['macOS Sonoma'],
          typicalHours: [9, 10, 11, 14],
        },
        isTorOrVpn: false,
        attemptHour: 15,
      },
    },
  ];

  const [formData, setFormData] = useState(scenarios[0].data);
  const [activeScenario, setActiveScenario] = useState('ordinary-login');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<SuspiciousLoginResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isGeneratingBatch, setIsGeneratingBatch] = useState(false);
  const [isRunningBatch, setIsRunningBatch] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const applyScenario = (sc: (typeof scenarios)[0]) => {
    setActiveScenario(sc.id);
    setFormData(JSON.parse(JSON.stringify(sc.data)));
    setResult(null);
    setStatusMessage(null);
  };

  const handleRunDetection = async () => {
    setIsAnalyzing(true);
    setError(null);
    setStatusMessage(null);
    try {
      const response = await api.detectSuspiciousLogin(formData);
      setResult(response.data);
      await onEventCreated();
    } catch (err: any) {
      setError(err.message || 'Detection analysis failed');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleGenerateSyntheticBatch = async () => {
    setIsGeneratingBatch(true);
    setStatusMessage(null);
    try {
      const res = await api.generateSyntheticLogins();
      setStatusMessage(res.message);
      await onEventCreated();
    } catch (err: any) {
      setError(err.message || 'Failed to generate synthetic events');
    } finally {
      setIsGeneratingBatch(false);
    }
  };

  const handleRunBatchDetection = async () => {
    setIsRunningBatch(true);
    setStatusMessage(null);
    try {
      const res = await api.runBatchDetection();
      setStatusMessage(res.message);
      await onEventCreated();
    } catch (err: any) {
      setError(err.message || 'Failed to run batch detection');
    } finally {
      setIsRunningBatch(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Batch Action Buttons */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-cyan-400" />
            <span>Suspicious Login Detection Engine (Rules 1–5)</span>
          </h2>
          <p className="text-xs text-slate-400">
            Heuristic detection evaluating repeated failures, credential guessing patterns, burst frequency, and signal anomalies
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleGenerateSyntheticBatch}
            disabled={isGeneratingBatch}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:text-white transition-colors disabled:opacity-50"
            title="Generate a batch of 3 synthetic login events"
          >
            <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
            <span>Generate Sample Logins</span>
          </button>
          <button
            onClick={handleRunBatchDetection}
            disabled={isRunningBatch}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
            title="Run detection pass across all recent login records"
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>Run Batch Detection</span>
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
          <span>{statusMessage}</span>
        </div>
      )}

      {/* Test Scenarios Selector */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <label className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Select Test Scenario (Evaluator Test Matrix)
          </label>
          <span className="text-[11px] text-slate-500">Documented Rules 1 through 5</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {scenarios.map((sc) => {
            const isSelected = activeScenario === sc.id;
            return (
              <button
                key={sc.id}
                onClick={() => applyScenario(sc)}
                className={`rounded-xl border p-3 text-left transition-all ${
                  isSelected
                    ? 'border-cyan-500 bg-cyan-500/10 shadow-md shadow-cyan-500/10'
                    : 'border-slate-800/80 bg-slate-900/60 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-[9px] uppercase tracking-wider text-cyan-400 font-bold">
                    {sc.category}
                  </span>
                </div>
                <div className="font-semibold text-xs text-slate-200 line-clamp-1">{sc.label}</div>
                <p className="mt-1 text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                  {sc.desc}
                </p>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Grid: Input Parameters (7 cols) + Real-time Analysis (5 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Input Parameters (7 cols) */}
        <div className="lg:col-span-7 rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Sliders className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-200">Authentication Context Parameters</h3>
            </div>
            <span className="font-mono text-[11px] text-slate-400">{formData.userEmail}</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 text-xs">
            <div>
              <label className="text-slate-400 font-medium">User Email</label>
              <input
                type="email"
                value={formData.userEmail}
                onChange={(e) => setFormData({ ...formData, userEmail: e.target.value })}
                className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 font-medium">Origin IP Address</label>
              <input
                type="text"
                value={formData.ip}
                onChange={(e) => setFormData({ ...formData, ip: e.target.value })}
                className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="text-slate-400 font-medium">Origin Location (City, Country)</label>
              <div className="grid grid-cols-2 gap-2 mt-1">
                <input
                  type="text"
                  placeholder="City"
                  value={formData.location.city}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      location: { ...formData.location, city: e.target.value },
                    })
                  }
                  className="rounded-lg border border-slate-800 bg-[#090e1a] px-2.5 py-2 text-slate-100 text-xs focus:border-cyan-500 focus:outline-none"
                />
                <input
                  type="text"
                  placeholder="Country"
                  value={formData.location.country}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      location: { ...formData.location, country: e.target.value },
                    })
                  }
                  className="rounded-lg border border-slate-800 bg-[#090e1a] px-2.5 py-2 text-slate-100 text-xs focus:border-cyan-500 focus:outline-none"
                />
              </div>
            </div>

            <div>
              <label className="text-slate-400 font-medium">User-Agent / Client Identity</label>
              <input
                type="text"
                value={formData.device.userAgent}
                onChange={(e) =>
                  setFormData({
                    ...formData,
                    device: { ...formData.device, userAgent: e.target.value },
                  })
                }
                className="mt-1 w-full rounded-lg border border-slate-800 bg-[#090e1a] px-3 py-2 text-slate-100 font-mono text-xs focus:border-cyan-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Rule Variables: Failures, Windows, Frequency */}
          <div className="rounded-lg border border-slate-800/90 bg-[#0a101f] p-3.5 space-y-3">
            <span className="text-xs font-semibold text-slate-300 block">
              Behavioral Heuristic Inputs (Rules 1, 2, 3)
            </span>
            <div className="grid grid-cols-3 gap-3 text-xs">
              <div>
                <label className="text-[10px] text-slate-400 uppercase font-semibold">
                  Rule 1: Failures in Window
                </label>
                <div className="flex items-center gap-1.5 mt-1">
                  <input
                    type="number"
                    min="0"
                    max="20"
                    value={formData.recentFailedAttemptsCount}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        recentFailedAttemptsCount: parseInt(e.target.value, 10) || 0,
                      })
                    }
                    className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-center text-slate-100"
                  />
                  <span className="text-slate-500 text-[10px]">att.</span>
                </div>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 uppercase font-semibold">
                  Rule 3: Rate (Req/Min)
                </label>
                <div className="flex items-center gap-1.5 mt-1">
                  <input
                    type="number"
                    min="0"
                    max="60"
                    value={formData.recentAttemptsRatePerMin}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        recentAttemptsRatePerMin: parseInt(e.target.value, 10) || 0,
                      })
                    }
                    className="w-full rounded border border-slate-800 bg-slate-900 px-2 py-1 font-mono text-center text-slate-100"
                  />
                  <span className="text-slate-500 text-[10px]">/min</span>
                </div>
              </div>

              <div className="flex flex-col justify-end">
                <label className="flex items-center gap-2 rounded border border-slate-800 bg-slate-900 p-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.hadRecentMultipleFailuresPrior}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        hadRecentMultipleFailuresPrior: e.target.checked,
                      })
                    }
                    className="rounded border-slate-700 text-cyan-500 focus:ring-0"
                  />
                  <span className="text-[10px] text-slate-300 font-semibold">
                    Rule 2: Failures Prior
                  </span>
                </label>
              </div>
            </div>
          </div>

          {/* Historical Baseline Card (Rule 4) */}
          {formData.historicalBaseline && (
            <div className="rounded-lg border border-slate-800 bg-[#0a101f] p-3 text-xs space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <History className="h-3.5 w-3.5 text-cyan-400" />
                  Rule 4: Historical Baseline Profile ({formData.historicalBaseline.totalLogins} verified sessions)
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-400">
                <div>Known Cities: <span className="font-mono text-slate-300">{formData.historicalBaseline.knownCities.join(', ')}</span></div>
                <div>Known Devices: <span className="font-mono text-slate-300">{formData.historicalBaseline.knownBrowsers.join(', ')}</span></div>
              </div>
            </div>
          )}

          {/* Toggles: Tor, Success Status */}
          <div className="grid grid-cols-2 gap-3 pt-1">
            <label className="flex items-center gap-2.5 rounded-lg border border-slate-800 bg-[#0a101f] p-2.5 cursor-pointer hover:border-slate-700">
              <input
                type="checkbox"
                checked={formData.isTorOrVpn}
                onChange={(e) => setFormData({ ...formData, isTorOrVpn: e.target.checked })}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span className="text-xs text-slate-300 font-medium">Tor Exit Node / VPN Relay</span>
            </label>

            <label className="flex items-center gap-2.5 rounded-lg border border-slate-800 bg-[#0a101f] p-2.5 cursor-pointer hover:border-slate-700">
              <input
                type="checkbox"
                checked={formData.isSuccessfulLoginNow}
                onChange={(e) => setFormData({ ...formData, isSuccessfulLoginNow: e.target.checked })}
                className="rounded border-slate-700 text-cyan-500 focus:ring-0"
              />
              <span className="text-xs text-slate-300 font-medium">Incoming Event is Success</span>
            </label>
          </div>

          <button
            onClick={handleRunDetection}
            disabled={isAnalyzing}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-3 text-sm font-bold text-slate-950 shadow-lg shadow-cyan-500/20 hover:from-cyan-400 hover:to-blue-500 active:scale-[0.99] transition-all disabled:opacity-50"
          >
            {isAnalyzing ? (
              <>
                <div className="h-4 w-4 animate-spin rounded-full border-2 border-slate-950 border-t-transparent" />
                <span>Evaluating Behavioral Risk Rules...</span>
              </>
            ) : (
              <>
                <Play className="h-4 w-4 fill-current" />
                <span>Run Suspicious Detection Engine</span>
              </>
            )}
          </button>

          {error && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">
              {error}
            </div>
          )}
        </div>

        {/* Right: Output Dossier (5 cols) */}
        <div className="lg:col-span-5 rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-4">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-sm font-semibold text-slate-200">Detection Evaluation Dossier</h3>
            <p className="text-xs text-slate-400">Score scale: Low 0–29 · Medium 30–69 · High 70–100</p>
          </div>

          {result ? (
            <div className="space-y-4 text-xs">
              {/* Score Card */}
              <div
                className={`rounded-xl border p-4 ${
                  result.riskLevel === 'HIGH'
                    ? 'border-rose-500/40 bg-rose-500/10'
                    : result.riskLevel === 'MEDIUM'
                    ? 'border-amber-500/40 bg-amber-500/10'
                    : 'border-emerald-500/40 bg-emerald-500/10'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">
                      Evaluated Risk Score
                    </span>
                    <div className="mt-1 flex items-baseline gap-2">
                      <span className="font-mono text-4xl font-extrabold text-slate-100">
                        {result.riskScore}
                      </span>
                      <span className="text-sm text-slate-400 font-mono">/ 100</span>
                    </div>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] uppercase tracking-wider text-slate-400">Classification</span>
                    <div className="mt-1">
                      <RiskBadge severity={result.riskLevel} />
                    </div>
                  </div>
                </div>

                <div className="mt-3 border-t border-slate-800/80 pt-2 text-[11px] text-slate-300">
                  <span className="text-slate-400 font-medium">Detection Timestamp: </span>
                  <span className="font-mono text-cyan-300">{result.detectionTime.replace('T', ' ').slice(0, 19)}</span>
                </div>
              </div>

              {/* Recommended Action */}
              <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 space-y-1">
                <span className="text-[10px] uppercase tracking-wider font-semibold text-cyan-400">
                  Recommended Defensive Action
                </span>
                <p className="text-slate-200 leading-relaxed text-xs">{result.recommendedAction}</p>
              </div>

              {/* Documented Rules Evaluation Checklist */}
              <div className="rounded-lg border border-slate-800 bg-[#090f1d] p-3 space-y-2">
                <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">
                  Documented Rules Checklist
                </span>
                <div className="space-y-1.5 text-[11px]">
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule 1: Repeated Failed Logins</span>
                    <span className={`font-mono font-bold ${result.ruleEvaluation.rule1_repeatedFailures ? 'text-rose-400' : 'text-slate-500'}`}>
                      {result.ruleEvaluation.rule1_repeatedFailures ? 'FLAGGED' : 'CLEAN'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule 2: Failures Followed by Success</span>
                    <span className={`font-mono font-bold ${result.ruleEvaluation.rule2_failuresFollowedBySuccess ? 'text-rose-400' : 'text-slate-500'}`}>
                      {result.ruleEvaluation.rule2_failuresFollowedBySuccess ? 'FLAGGED' : 'CLEAN'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule 3: Unusually Frequent Attempts</span>
                    <span className={`font-mono font-bold ${result.ruleEvaluation.rule3_unusuallyFrequentLogins ? 'text-rose-400' : 'text-slate-500'}`}>
                      {result.ruleEvaluation.rule3_unusuallyFrequentLogins ? 'FLAGGED' : 'CLEAN'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule 4: Historical Baseline Divergence</span>
                    <span className={`font-mono font-bold ${result.ruleEvaluation.rule4_historicalAnomaly ? 'text-amber-400' : 'text-slate-500'}`}>
                      {result.ruleEvaluation.rule4_historicalAnomaly ? 'FLAGGED' : 'CLEAN'}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-slate-300">Rule 5: Missing / Unusual Signals</span>
                    <span className={`font-mono font-bold ${result.ruleEvaluation.rule5_unusualSignals ? 'text-amber-400' : 'text-slate-500'}`}>
                      {result.ruleEvaluation.rule5_unusualSignals ? 'FLAGGED' : 'CLEAN'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Reasons */}
              <div>
                <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">
                  Scoring Justification ({result.reasons.length})
                </span>
                <div className="mt-1.5 space-y-1.5">
                  {result.factors.map((f, i) => (
                    <div key={i} className="rounded border border-slate-800/80 bg-[#090f1d] p-2.5 text-[11px] space-y-0.5">
                      <div className="flex items-center justify-between font-semibold text-slate-200">
                        <span>{f.factor}</span>
                        <span className="font-mono text-rose-400">+{f.penalty} pts</span>
                      </div>
                      <p className="text-slate-400 text-[10px] leading-relaxed">{f.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Disclaimer */}
              <div className="rounded border border-slate-800/80 bg-slate-950 p-2.5 text-[10px] text-slate-400 flex items-start gap-1.5 leading-relaxed">
                <Info className="h-3.5 w-3.5 text-cyan-400 shrink-0 mt-0.5" />
                <span>{result.disclaimer}</span>
              </div>
            </div>
          ) : (
            <div className="flex h-72 flex-col items-center justify-center text-center p-6 border border-dashed border-slate-800 rounded-xl">
              <Shield className="h-10 w-10 text-slate-600 mb-3" />
              <h4 className="text-sm font-semibold text-slate-300">Ready for Detection Pass</h4>
              <p className="mt-1 text-xs text-slate-500 max-w-xs leading-relaxed">
                Select a scenario preset above or tune inputs, then click &quot;Run Suspicious Detection Engine&quot;.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
