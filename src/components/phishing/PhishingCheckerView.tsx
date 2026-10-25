import React, { useState, useEffect } from 'react';
import {
  Globe,
  MessageSquare,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  History,
  Trash2,
  ExternalLink,
  Info,
  CheckCircle2,
  XCircle,
  Copy,
  Check,
  Sparkles,
  Lock,
  Search,
} from 'lucide-react';
import {
  PhishingUrlResult,
  PhishingMessageResult,
  PhishingHistoryItem,
} from '../../types/security';
import { api } from '../../services/api';
import { RiskBadge } from '../common/RiskBadge';

export const PhishingCheckerView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'URL' | 'MESSAGE' | 'HISTORY'>('URL');

  // URL state
  const sampleUrls = [
    {
      label: 'Typosquatting & Suspicious TLD',
      url: 'https://paypa1-update-security.xyz/login/verify-identity',
      tag: 'Phishing',
      desc: 'Replaces "l" with "1" and uses high-abuse .xyz TLD with credential subpaths',
    },
    {
      label: 'Cyrillic IDN Homoglyph Spoof',
      // Cyrillic 'о' (\u043e) in google
      url: 'https://g\u043e\u043egle.com/accounts/update-security',
      tag: 'Homograph',
      desc: 'Visual spoofing using Punycode Cyrillic letters to imitate legitimate brands',
    },
    {
      label: 'Raw IP Hostname & Insecure HTTP',
      url: 'http://192.168.1.105:8080/secure/bank-login.php',
      tag: 'Malware Host',
      desc: 'Raw IP address instead of registered domain, unencrypted HTTP transmission',
    },
    {
      label: 'URL Shortener with Tax Refund Lure',
      url: 'https://bit.ly/urgent-claim-tax-refund-2026',
      tag: 'Shortener Obfuscation',
      desc: 'Hides true destination domain behind URL redirection service',
    },
    {
      label: 'Excessive Subdomain Obfuscation',
      url: 'https://security.login.verification.portal.bank-update.top/auth',
      tag: 'Multi-Subdomain',
      desc: 'Deep subdomain nesting designed to push fake domain name off mobile address bar',
    },
    {
      label: 'Legitimate Authorized Campus Portal',
      url: 'https://campus.college.edu/student-hub/grades',
      tag: 'Safe Baseline',
      desc: 'Standard .edu domain with HTTPS and clean path structure',
    },
  ];

  const [inputUrl, setInputUrl] = useState(sampleUrls[0].url);
  const [isScanningUrl, setIsScanningUrl] = useState(false);
  const [urlResult, setUrlResult] = useState<PhishingUrlResult | null>(null);
  const [urlError, setUrlError] = useState<string | null>(null);

  // Message state
  const sampleMessages = [
    {
      label: 'Urgent Bank KYC & OTP Threat',
      tag: 'High Risk Banking',
      text: 'URGENT NOTICE: Your State Bank savings account will be permanently frozen within 24 hours due to incomplete KYC verification. Click https://fictional-sbi-kyc.top immediately and enter your netbanking password, OTP, and debit card PIN to avoid service termination.',
    },
    {
      label: 'International Lottery Winner Scam',
      tag: 'Advance Fee Fraud',
      text: 'CONGRATULATIONS! Your mobile number has won $75,000 in the 2026 Global Cyber Welfare Lottery. To claim your cash prize today, reply with your full bank account number, IFSC code, and OTP immediately to disbursement@lottery-winner.xyz.',
    },
    {
      label: 'Corporate Password Expiry Notice',
      tag: 'Credential Harvesting',
      text: 'IT Service Desk: Your corporate password expires in 30 minutes. Failure to renew will lock you out of all work systems. Update your password here: https://workplace-auth-portal.xyz/reset or contact your system administrator.',
    },
    {
      label: 'Legitimate Computer Science Class Update',
      tag: 'Normal Baseline',
      text: 'Hello Priya, the lecture slides for tomorrow\'s Operating Systems seminar have been published to the university learning portal. Please read chapter 4 on process scheduling before class at 10 AM. Best regards, Prof. Sharma.',
    },
  ];

  const [inputMessage, setInputMessage] = useState(sampleMessages[0].text);
  const [isScanningMsg, setIsScanningMsg] = useState(false);
  const [msgResult, setMsgResult] = useState<PhishingMessageResult | null>(null);
  const [msgError, setMsgError] = useState<string | null>(null);

  // History state
  const [history, setHistory] = useState<PhishingHistoryItem[]>([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [isClearingHistory, setIsClearingHistory] = useState(false);
  const [copiedText, setCopiedText] = useState(false);

  // Load history on mount or when switching to history tab
  const loadHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const items = await api.getPhishingHistory();
      setHistory(items);
    } catch {
      // Ignore if unauthenticated
    } finally {
      setIsLoadingHistory(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'HISTORY') {
      loadHistory();
    }
  }, [activeTab]);

  const handleScanUrl = async (urlOverride?: string) => {
    const target = urlOverride || inputUrl;
    if (!target.trim()) return;

    setIsScanningUrl(true);
    setUrlError(null);
    try {
      const res = await api.checkPhishingUrl(target);
      setUrlResult(res);
      // Reload history in background
      loadHistory();
    } catch (err: any) {
      setUrlError(err.message || 'URL Phishing analysis failed');
    } finally {
      setIsScanningUrl(false);
    }
  };

  const handleScanMessage = async (msgOverride?: string) => {
    const target = msgOverride || inputMessage;
    if (!target.trim()) return;

    setIsScanningMsg(true);
    setMsgError(null);
    try {
      const res = await api.checkPhishingMessage(target);
      setMsgResult(res);
      loadHistory();
    } catch (err: any) {
      setMsgError(err.message || 'Message Phishing analysis failed');
    } finally {
      setIsScanningMsg(false);
    }
  };

  const handleClearHistory = async () => {
    if (!window.confirm('Are you sure you want to clear your phishing analysis history?')) return;
    setIsClearingHistory(true);
    try {
      await api.clearPhishingHistory();
      setHistory([]);
    } catch (err: any) {
      alert(err.message || 'Failed to clear history');
    } finally {
      setIsClearingHistory(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(true);
    setTimeout(() => setCopiedText(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Globe className="h-6 w-6 text-cyan-400" />
            <span>Phishing & Social Engineering Threat Analyzer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Defensive heuristic scanner for misleading URL patterns, brand lookalikes, credential harvesting, and urgent extortion language
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1">
          <button
            onClick={() => setActiveTab('URL')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'URL'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Globe className="h-3.5 w-3.5" />
            <span>1. URL Analysis</span>
          </button>
          <button
            onClick={() => setActiveTab('MESSAGE')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'MESSAGE'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <MessageSquare className="h-3.5 w-3.5" />
            <span>2. Suspicious Message Analysis</span>
          </button>
          <button
            onClick={() => setActiveTab('HISTORY')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'HISTORY'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <History className="h-3.5 w-3.5" />
            <span>Analysis History ({history.length})</span>
          </button>
        </div>
      </div>

      {/* Safety Policy Banner */}
      <div className="bg-slate-900/80 border border-cyan-900/50 p-3.5 text-xs text-slate-300 flex items-start gap-3">
        <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-cyan-300">Defensive Isolation & Safety Protocol:</div>
          <p className="text-slate-400">
            • <strong>Never Visits Destination:</strong> AuthShield 360 inspects syntax and lexical features strictly in offline isolation. It never sends HTTP requests to submitted URLs.
            <br />
            • <strong>Privacy Preserved:</strong> Messages are parsed locally on the server engine; no content is broadcast to third-party advertisers or external search engines.
            <br />
            • <strong>Safety Advisory:</strong> Never enter real passwords, bank OTPs, PINs, or confidential personal data into test forms.
          </p>
        </div>
      </div>

      {/* TAB 1: URL ANALYSIS */}
      {activeTab === 'URL' && (
        <div className="space-y-6">
          {/* Preset Buttons */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
              <span>Educational Preset Test Cases (Fictional Domains):</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              {sampleUrls.map((s, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setInputUrl(s.url);
                    handleScanUrl(s.url);
                  }}
                  className="text-left bg-slate-900 border border-slate-800 hover:border-cyan-500/50 p-2.5 transition-all group"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">{s.label}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 text-slate-400 border border-slate-700">
                      {s.tag}
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 truncate">{s.url}</div>
                  <div className="text-[10px] text-slate-400 mt-1 line-clamp-1">{s.desc}</div>
                </button>
              ))}
            </div>
          </div>

          {/* URL Input Form */}
          <div className="bg-slate-900 border border-slate-800 p-4 space-y-3">
            <label className="block text-xs font-medium text-slate-300">Target URL to Evaluate:</label>
            <div className="flex flex-col sm:flex-row gap-2">
              <div className="relative flex-1">
                <input
                  type="text"
                  value={inputUrl}
                  onChange={(e) => setInputUrl(e.target.value)}
                  placeholder="https://example.com/login"
                  className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 text-sm px-3 py-2 font-mono"
                />
              </div>
              <button
                onClick={() => handleScanUrl()}
                disabled={isScanningUrl || !inputUrl.trim()}
                className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-5 py-2 text-xs uppercase tracking-wider flex items-center justify-center gap-2 disabled:opacity-50 transition-colors"
              >
                {isScanningUrl ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent animate-spin inline-block" />
                    <span>Evaluating...</span>
                  </>
                ) : (
                  <>
                    <Search className="h-3.5 w-3.5" />
                    <span>Inspect URL</span>
                  </>
                )}
              </button>
            </div>
            {urlError && (
              <div className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 p-2">
                {urlError}
              </div>
            )}
          </div>

          {/* URL Results */}
          {urlResult && (
            <div className="bg-slate-900 border border-slate-800 p-5 space-y-6">
              {/* Score & Verdict Banner */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-3">
                    <span className="text-3xl font-mono font-bold text-slate-100">
                      {urlResult.riskScore}
                      <span className="text-sm text-slate-400 font-normal"> / 100</span>
                    </span>
                    <RiskBadge severity={urlResult.riskLevel} />
                    <span className="text-xs font-mono px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300">
                      {urlResult.verdict}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1 font-mono break-all">
                    Evaluated Target: {urlResult.target}
                  </div>
                </div>

                {urlResult.targetedBrand && (
                  <div className="bg-rose-500/10 border border-rose-500/30 px-3 py-1.5 text-xs text-rose-300">
                    Targeted Brand Mimicry: <strong className="font-mono">{urlResult.targetedBrand}</strong>
                  </div>
                )}
              </div>

              {/* Lexical Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                <div className="bg-slate-950 border border-slate-800 p-3">
                  <div className="text-slate-400 text-[11px]">Domain Host</div>
                  <div className="font-mono text-slate-200 font-semibold truncate mt-0.5">{urlResult.domain}</div>
                </div>
                <div className="bg-slate-950 border border-slate-800 p-3">
                  <div className="text-slate-400 text-[11px]">Shannon Entropy</div>
                  <div className="font-mono text-slate-200 font-semibold mt-0.5">
                    {urlResult.entropy.toFixed(3)}
                    <span className="text-[10px] text-slate-400 ml-1">
                      {urlResult.entropy > 4.2 ? '(High / Random)' : '(Normal)'}
                    </span>
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800 p-3">
                  <div className="text-slate-400 text-[11px]">Punycode / Homograph</div>
                  <div className="font-mono text-slate-200 font-semibold mt-0.5">
                    {urlResult.hasPunycodeHomograph ? (
                      <span className="text-rose-400 flex items-center gap-1">
                        <AlertTriangle className="h-3 w-3" /> Spoof Detected
                      </span>
                    ) : (
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> Standard ASCII
                      </span>
                    )}
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800 p-3">
                  <div className="text-slate-400 text-[11px]">URL Redirection Shortener</div>
                  <div className="font-mono text-slate-200 font-semibold mt-0.5">
                    {urlResult.isShortener ? (
                      <span className="text-amber-400">Yes (Shortened)</span>
                    ) : (
                      <span className="text-slate-400">No (Direct)</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Detailed Heuristic Rule Findings */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Static Heuristic Findings ({urlResult.findings.length}):
                </h3>
                <div className="space-y-2">
                  {urlResult.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className={`p-3 border flex items-start justify-between gap-3 text-xs ${
                        f.type === 'DANGER'
                          ? 'bg-rose-500/10 border-rose-500/30 text-rose-200'
                          : f.type === 'WARN'
                          ? 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                          : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="font-semibold flex items-center gap-2">
                          {f.type === 'DANGER' && <XCircle className="h-4 w-4 text-rose-400 shrink-0" />}
                          {f.type === 'WARN' && <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />}
                          {f.type === 'PASS' && <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />}
                          <span>{f.rule}</span>
                        </div>
                        <div className="text-[11px] opacity-90">{f.detail}</div>
                      </div>
                      <span className="font-mono font-bold shrink-0 text-xs">
                        {f.points > 0 ? `+${f.points} pts` : '0 pts'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recommended Action */}
              <div className="bg-slate-950 border border-cyan-500/30 p-3 text-xs">
                <div className="text-cyan-400 font-semibold mb-1 flex items-center gap-1.5">
                  <ShieldAlert className="h-4 w-4" />
                  <span>Recommended Defensive Response:</span>
                </div>
                <p className="text-slate-300 leading-relaxed">{urlResult.recommendedAction}</p>
              </div>

              {/* False Positive / Negative Technical Disclaimer */}
              <div className="bg-slate-950/70 border border-slate-800 p-3 text-[11px] text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300">Technical Model Limitation Notice:</div>
                <p className="leading-relaxed">{urlResult.disclaimer}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: SUSPICIOUS MESSAGE ANALYSIS */}
      {activeTab === 'MESSAGE' && (
        <div className="space-y-6">
          {/* Preset Buttons */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
              <span>Sample Social Engineering Scenarios (SMS / Email / Chat):</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {sampleMessages.map((m, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setInputMessage(m.text);
                    handleScanMessage(m.text);
                  }}
                  className="text-left bg-slate-900 border border-slate-800 hover:border-cyan-500/50 p-2.5 transition-all group"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">{m.label}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 bg-slate-800 text-slate-400 border border-slate-700">
                      {m.tag}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 line-clamp-2 italic">"{m.text}"</div>
                </button>
              ))}
            </div>
          </div>

          {/* Message Input Textarea */}
          <div className="bg-slate-900 border border-slate-800 p-4 space-y-3">
            <label className="block text-xs font-medium text-slate-300">
              Paste Suspicious Email, SMS, or Direct Message:
            </label>
            <textarea
              rows={5}
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              placeholder="Paste email text, WhatsApp alert, or SMS notification here..."
              className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 text-slate-100 text-xs p-3 font-mono leading-relaxed"
            />
            <div className="flex items-center justify-between">
              <span className="text-[11px] text-slate-400">
                Rule engine checks for psychological extortion, OTP/password exfiltration, and deceptive urgency.
              </span>
              <button
                onClick={() => handleScanMessage()}
                disabled={isScanningMsg || !inputMessage.trim()}
                className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-5 py-2 text-xs uppercase tracking-wider flex items-center justify-center gap-2 disabled:opacity-50 transition-colors shrink-0"
              >
                {isScanningMsg ? (
                  <>
                    <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent animate-spin inline-block" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Search className="h-3.5 w-3.5" />
                    <span>Analyze Message</span>
                  </>
                )}
              </button>
            </div>
            {msgError && (
              <div className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 p-2">
                {msgError}
              </div>
            )}
          </div>

          {/* Message Results */}
          {msgResult && (
            <div className="bg-slate-900 border border-slate-800 p-5 space-y-6">
              {/* Score & Verdict Banner */}
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-3">
                    <span className="text-3xl font-mono font-bold text-slate-100">
                      {msgResult.riskScore}
                      <span className="text-sm text-slate-400 font-normal"> / 100</span>
                    </span>
                    <RiskBadge severity={msgResult.riskLevel} />
                    <span className="text-xs font-mono px-2 py-0.5 bg-slate-800 border border-slate-700 text-slate-300">
                      {msgResult.verdict}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1 italic">
                    Sample preview: "{msgResult.samplePreview}"
                  </div>
                </div>
              </div>

              {/* Categorical Detection Flags */}
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Social Engineering Vectors Identified:
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                  <div
                    className={`p-2.5 border ${
                      msgResult.detectedCategories.urgentCallToAction
                        ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-semibold">Urgency & Pressure</div>
                    <div className="text-[10px] mt-0.5">
                      {msgResult.detectedCategories.urgentCallToAction ? 'FLAGGED: Immediate action deadline' : 'Not detected'}
                    </div>
                  </div>

                  <div
                    className={`p-2.5 border ${
                      msgResult.detectedCategories.credentialRequest
                        ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-semibold">Credential Harvesting</div>
                    <div className="text-[10px] mt-0.5">
                      {msgResult.detectedCategories.credentialRequest ? 'FLAGGED: Demands password/PIN' : 'Not detected'}
                    </div>
                  </div>

                  <div
                    className={`p-2.5 border ${
                      msgResult.detectedCategories.financialOrOtpRequest
                        ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-semibold">Financial & OTP Demands</div>
                    <div className="text-[10px] mt-0.5">
                      {msgResult.detectedCategories.financialOrOtpRequest ? 'FLAGGED: Requests OTP or account info' : 'Not detected'}
                    </div>
                  </div>

                  <div
                    className={`p-2.5 border ${
                      msgResult.detectedCategories.fearOrAccountWarning
                        ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-semibold">Fear / Suspension Threat</div>
                    <div className="text-[10px] mt-0.5">
                      {msgResult.detectedCategories.fearOrAccountWarning ? 'FLAGGED: Account deactivation threat' : 'Not detected'}
                    </div>
                  </div>

                  <div
                    className={`p-2.5 border ${
                      msgResult.detectedCategories.unexpectedPrizeOrReward
                        ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-semibold">Unexpected Prize / Lure</div>
                    <div className="text-[10px] mt-0.5">
                      {msgResult.detectedCategories.unexpectedPrizeOrReward ? 'FLAGGED: Lottery or cashback bait' : 'Not detected'}
                    </div>
                  </div>

                  <div
                    className={`p-2.5 border ${
                      msgResult.detectedCategories.suspiciousLinksContained.length > 0
                        ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-semibold">Embedded Links</div>
                    <div className="text-[10px] mt-0.5 font-mono">
                      {msgResult.detectedCategories.suspiciousLinksContained.length > 0
                        ? `${msgResult.detectedCategories.suspiciousLinksContained.length} link(s) extracted`
                        : 'No hyperlinks present'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Exact Matched Indicators */}
              <div className="space-y-3">
                <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
                  Rule Engine Detailed Findings:
                </h3>
                <div className="space-y-2">
                  {msgResult.findings.map((f, idx) => (
                    <div
                      key={idx}
                      className={`p-3 border flex items-start justify-between gap-3 text-xs ${
                        f.type === 'DANGER'
                          ? 'bg-rose-500/10 border-rose-500/30 text-rose-200'
                          : f.type === 'WARN'
                          ? 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                          : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="font-semibold flex items-center gap-2">
                          {f.type === 'DANGER' && <XCircle className="h-4 w-4 text-rose-400 shrink-0" />}
                          {f.type === 'WARN' && <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />}
                          {f.type === 'PASS' && <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />}
                          <span>{f.rule}</span>
                        </div>
                        <div className="text-[11px] opacity-90">{f.detail}</div>
                      </div>
                      <span className="font-mono font-bold shrink-0 text-xs">
                        {f.points > 0 ? `+${f.points} pts` : '0 pts'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Practical Safety Advice */}
              <div className="bg-slate-950 border border-cyan-500/30 p-3 text-xs">
                <div className="text-cyan-400 font-semibold mb-1 flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4" />
                  <span>Practical Defense & Mitigation Advice:</span>
                </div>
                <p className="text-slate-300 leading-relaxed">{msgResult.recommendedAction}</p>
              </div>

              {/* Accuracy Notice */}
              <div className="bg-slate-950/70 border border-slate-800 p-3 text-[11px] text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300">Accuracy & False Positive/Negative Disclaimer:</div>
                <p className="leading-relaxed">{msgResult.disclaimer}</p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: ANALYSIS HISTORY */}
      {activeTab === 'HISTORY' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Authenticated Analysis History</h3>
              <p className="text-xs text-slate-400">
                Audit trail of phishing scans performed under your active authenticated session
              </p>
            </div>
            {history.length > 0 && (
              <button
                onClick={handleClearHistory}
                disabled={isClearingHistory}
                className="px-3 py-1.5 text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 border border-rose-500/30 flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>{isClearingHistory ? 'Clearing...' : 'Clear History'}</span>
              </button>
            )}
          </div>

          {isLoadingHistory ? (
            <div className="p-8 text-center text-xs text-slate-400">Loading analysis history...</div>
          ) : history.length === 0 ? (
            <div className="bg-slate-900 border border-slate-800 p-8 text-center text-xs text-slate-400 space-y-2">
              <History className="h-8 w-8 text-slate-600 mx-auto" />
              <div className="font-semibold text-slate-300">No Analysis History Yet</div>
              <p className="text-slate-400 max-w-sm mx-auto">
                Scan URLs or messages using the tabs above. Your evaluations will be recorded in this session history.
              </p>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/50">
                    <th className="p-3 font-semibold">Timestamp</th>
                    <th className="p-3 font-semibold">Type</th>
                    <th className="p-3 font-semibold">Target / Preview</th>
                    <th className="p-3 font-semibold">Risk Score</th>
                    <th className="p-3 font-semibold">Risk Level</th>
                    <th className="p-3 font-semibold">Verdict</th>
                    <th className="p-3 font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {history.map((item) => (
                    <tr key={item.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="p-3 text-slate-400 whitespace-nowrap">
                        {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td className="p-3 whitespace-nowrap">
                        <span
                          className={`px-1.5 py-0.5 text-[10px] font-semibold border ${
                            item.type === 'URL'
                              ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/30'
                              : 'bg-purple-500/10 text-purple-300 border-purple-500/30'
                          }`}
                        >
                          {item.type}
                        </span>
                      </td>
                      <td className="p-3 text-slate-300 max-w-xs truncate" title={item.targetPreview}>
                        {item.targetPreview}
                      </td>
                      <td className="p-3 text-slate-200 font-bold">{item.riskScore} / 100</td>
                      <td className="p-3">
                        <RiskBadge severity={item.riskLevel} />
                      </td>
                      <td className="p-3 text-slate-400">{item.verdict}</td>
                      <td className="p-3 text-right">
                        <button
                          onClick={() => {
                            if (item.type === 'URL') {
                              setInputUrl(item.targetPreview);
                              setActiveTab('URL');
                              handleScanUrl(item.targetPreview);
                            } else {
                              setInputMessage(item.targetPreview);
                              setActiveTab('MESSAGE');
                              handleScanMessage(item.targetPreview);
                            }
                          }}
                          className="text-cyan-400 hover:text-cyan-300 text-xs font-sans hover:underline"
                        >
                          Re-scan
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
