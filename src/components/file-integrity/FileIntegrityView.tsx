import React, { useState, useEffect, useRef } from 'react';
import {
  FileCheck2,
  FileCode,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Binary,
  Flame,
  ArrowRight,
  Upload,
  Copy,
  Check,
  FileText,
  Info,
  ShieldCheck,
  Search,
  Sparkles,
  Lock,
} from 'lucide-react';
import { BaselineFile, FileIntegrityCheckResult } from '../../types/security';
import { api } from '../../services/api';

interface FileIntegrityViewProps {
  onEventCreated: () => Promise<void>;
  onSelectTab: (tab: string) => void;
}

export const FileIntegrityView: React.FC<FileIntegrityViewProps> = ({ onEventCreated, onSelectTab }) => {
  const [activeTab, setActiveTab] = useState<'USER_FILE' | 'BASELINE_REGISTRY'>('USER_FILE');
  const [baselines, setBaselines] = useState<BaselineFile[]>([]);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // User File Analysis State
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [userFileName, setUserFileName] = useState<string>('sample-config.json');
  const [userFileSize, setUserFileSize] = useState<number>(1420);
  const [userFileContent, setUserFileContent] = useState<string>(
    `{\n  "appName": "AuthShield 360",\n  "environment": "production",\n  "mfaRequired": true,\n  "sessionTimeoutMinutes": 15\n}`
  );
  const [userSha256, setUserSha256] = useState<string>('');
  const [userSha512, setUserSha512] = useState<string>('');
  const [userMd5, setUserMd5] = useState<string>('');
  const [userEntropy, setUserEntropy] = useState<number>(4.12);
  const [isHashing, setIsHashing] = useState<boolean>(false);

  // Comparison State
  const [comparisonMode, setComparisonMode] = useState<'BASELINE' | 'MANUAL'>('BASELINE');
  const [selectedBaselineId, setSelectedBaselineId] = useState<string>('fim-01');
  const [manualExpectedHash, setManualExpectedHash] = useState<string>('');
  const [comparisonResult, setComparisonResult] = useState<{
    status: 'MATCH' | 'MISMATCH' | 'HIGH_ENTROPY_TAMPER' | 'PENDING';
    verdict: string;
    details: string;
  } | null>(null);

  // Golden Baseline Simulation Editor State
  const [simFileContent, setSimFileContent] = useState<string>(
    `// Authoritative Authentication Service v3.2\nexport function verifyToken(token: string) {\n  if (!token) return false;\n  return token.startsWith("authshield_jwt_sec_");\n}`
  );
  const [simCheckResult, setSimCheckResult] = useState<any>(null);
  const [isCheckingSim, setIsCheckingSim] = useState(false);

  // Helper to compute SHA-256 in browser using Web Crypto API
  const computeClientSha256 = async (text: string): Promise<{
    sha256: string;
    sizeBytes: number;
    entropy: number;
  }> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const sha256 = hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');

    // Calculate Shannon entropy
    const len = data.length;
    let entropy = 0;
    if (len > 0) {
      const freq = new Array(256).fill(0);
      for (let i = 0; i < len; i++) freq[data[i]]++;
      for (let i = 0; i < 256; i++) {
        if (freq[i] > 0) {
          const p = freq[i] / len;
          entropy -= p * Math.log2(p);
        }
      }
    }

    return { sha256, sizeBytes: len, entropy: Number(entropy.toFixed(3)) };
  };

  const loadBaselines = async () => {
    try {
      const data = await api.getBaselineFiles();
      setBaselines(data);
    } catch (err: any) {
      console.error('Failed to load baselines:', err);
    }
  };

  useEffect(() => {
    loadBaselines();
    // Calculate initial hash for default sample
    handleAnalyzeContent(userFileContent, userFileName);
  }, []);

  const handleAnalyzeContent = async (content: string, name: string) => {
    setIsHashing(true);
    try {
      // Server-side trusted calculation
      const serverRes = await api.checkFileIntegrity({
        filename: name,
        content,
        targetFileId: comparisonMode === 'BASELINE' ? selectedBaselineId : undefined,
      });

      setUserSha256(serverRes.hashes.sha256);
      setUserSha512(serverRes.hashes.sha512);
      setUserMd5(serverRes.hashes.md5);
      setUserFileSize(serverRes.hashes.sizeBytes);
      setUserEntropy(serverRes.hashes.entropy);

      // Perform comparison
      evaluateHashComparison(serverRes.hashes.sha256, serverRes.hashes.entropy);
    } catch {
      // Fallback to client-side Web Crypto API
      const client = await computeClientSha256(content);
      setUserSha256(client.sha256);
      setUserFileSize(client.sizeBytes);
      setUserEntropy(client.entropy);
      evaluateHashComparison(client.sha256, client.entropy);
    } finally {
      setIsHashing(false);
    }
  };

  const evaluateHashComparison = (calculatedHash: string, entropy: number) => {
    let expectedHash = '';

    if (comparisonMode === 'BASELINE') {
      const baseline = baselines.find((b) => b.id === selectedBaselineId);
      expectedHash = baseline?.baselineSha256 || '';
    } else {
      expectedHash = manualExpectedHash.trim();
    }

    if (!expectedHash) {
      setComparisonResult({
        status: 'PENDING',
        verdict: 'Comparison Pending Expected Hash',
        details: 'Select an authoritative baseline or paste an expected vendor hash above to verify file integrity.',
      });
      return;
    }

    const isMatch = calculatedHash.toLowerCase() === expectedHash.toLowerCase();
    const isHighEntropy = entropy > 7.5;

    if (isMatch) {
      setComparisonResult({
        status: 'MATCH',
        verdict: 'MATCH: Content Verified Unchanged',
        details: 'Calculated SHA-256 hash matches the authoritative reference baseline bit-for-bit. No unauthorized modifications detected.',
      });
    } else if (isHighEntropy) {
      setComparisonResult({
        status: 'HIGH_ENTROPY_TAMPER',
        verdict: 'CRITICAL ALERT: Hash Mismatch with High Entropy (>7.5)',
        details: 'Hash mismatch accompanied by near-maximum Shannon entropy. Strong indicator of ransomware payload encryption, obfuscation, or packed executable tampering.',
      });
    } else {
      setComparisonResult({
        status: 'MISMATCH',
        verdict: 'MISMATCH: Unauthorized Alteration Detected',
        details: 'Calculated SHA-256 hash deviates from the expected baseline. File contents have been modified, updated, or corrupted.',
      });
    }
  };

  // Re-run evaluation when comparison baseline or manual hash changes
  useEffect(() => {
    if (userSha256) {
      evaluateHashComparison(userSha256, userEntropy);
    }
  }, [comparisonMode, selectedBaselineId, manualExpectedHash, baselines]);

  // Handle local user file upload via file picker
  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUserFileName(file.name);
    setUserFileSize(file.size);

    const reader = new FileReader();
    reader.onload = async (event) => {
      const text = event.target?.result as string;
      setUserFileContent(text || '');
      await handleAnalyzeContent(text || '', file.name);
      await onEventCreated();
    };
    reader.readAsText(file);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Pre-configured test sample buttons
  const loadCleanBaselineSample = () => {
    const clean = `{\n  "appName": "AuthShield 360",\n  "environment": "production",\n  "mfaRequired": true,\n  "sessionTimeoutMinutes": 15\n}`;
    setUserFileName('app.config.json');
    setUserFileContent(clean);
    handleAnalyzeContent(clean, 'app.config.json');
  };

  const loadTamperedSample = () => {
    const tampered = `{\n  "appName": "AuthShield 360",\n  "environment": "production",\n  "mfaRequired": false,\n  "backdoorPort": 4444,\n  "sessionTimeoutMinutes": 99999\n}`;
    setUserFileName('app.config.json [MODIFIED]');
    setUserFileContent(tampered);
    handleAnalyzeContent(tampered, 'app.config.json');
  };

  const loadRansomwareHighEntropySample = () => {
    let encryptedChars = '';
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';
    for (let i = 0; i < 2048; i++) {
      encryptedChars += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
    }
    setUserFileName('vault_credentials.bin.enc');
    setUserFileContent(encryptedChars);
    handleAnalyzeContent(encryptedChars, 'vault_credentials.bin.enc');
  };

  // Run simulation on Golden baseline tab
  const handleRunSimFim = async (customContent?: string) => {
    const content = customContent !== undefined ? customContent : simFileContent;
    setIsCheckingSim(true);
    try {
      const selected = baselines.find((b) => b.id === selectedBaselineId);
      const res = await api.checkFileIntegrity({
        filename: selected?.filename || 'auth.service.ts',
        content,
        targetFileId: selectedBaselineId,
      });
      setSimCheckResult(res);
      await onEventCreated();
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsCheckingSim(false);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1048576) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${(bytes / 1048576).toFixed(2)} MB`;
  };

  const currentBaseline = baselines.find((b) => b.id === selectedBaselineId);

  return (
    <div className="space-y-6">
      {/* Title & Navigation Tabs */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FileCheck2 className="h-6 w-6 text-cyan-400" />
            <span>File Integrity Monitoring (FIM) & SHA-256 Analyzer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic cryptographic hashing, baseline comparison, and Shannon entropy ransomware inspection
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1">
          <button
            onClick={() => setActiveTab('USER_FILE')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'USER_FILE'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="h-3.5 w-3.5" />
            <span>1. File Upload & Hash Analysis</span>
          </button>
          <button
            onClick={() => setActiveTab('BASELINE_REGISTRY')}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'BASELINE_REGISTRY'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="h-3.5 w-3.5" />
            <span>2. Golden Baseline Registry & Lab</span>
          </button>
        </div>
      </div>

      {/* Strict Privacy & Safety Protocol Banner */}
      <div className="bg-slate-900/80 border border-cyan-900/50 p-3.5 text-xs text-slate-300 flex items-start gap-3">
        <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-cyan-300">File Processing & Defensive Isolation Protocol:</div>
          <p className="text-slate-400 leading-relaxed">
            • <strong>User-Initiated Only:</strong> Only processes files intentionally selected or uploaded by the user.
            <br />
            • <strong>Non-Executable Sandbox:</strong> Files are parsed strictly as binary streams for cryptographic digests. Uploaded files are <em>never executed</em> or interpreted as scripts.
            <br />
            • <strong>Privacy Preserved:</strong> AuthShield 360 does not perform automated filesystem crawling or unauthorized background directory scanning on client workstations.
          </p>
        </div>
      </div>

      {/* TAB 1: USER FILE UPLOAD & HASH ANALYSIS */}
      {activeTab === 'USER_FILE' && (
        <div className="space-y-6">
          {/* Preset Buttons for Quick Testing */}
          <div className="space-y-2">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5 text-cyan-400" />
              <span>Educational Sample Presets:</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              <button
                onClick={loadCleanBaselineSample}
                className="text-left bg-slate-900 border border-slate-800 hover:border-cyan-500/50 p-2.5 transition-all group"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-slate-200 group-hover:text-cyan-300">Clean Config Baseline</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    Safe Baseline
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">Authentic application settings with MFA enabled.</div>
              </button>

              <button
                onClick={loadTamperedSample}
                className="text-left bg-slate-900 border border-slate-800 hover:border-amber-500/50 p-2.5 transition-all group"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-slate-200 group-hover:text-amber-300">Backdoor Tamper Sample</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    Tampered
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">Unauthorized backdoor port and disabled MFA.</div>
              </button>

              <button
                onClick={loadRansomwareHighEntropySample}
                className="text-left bg-slate-900 border border-slate-800 hover:border-rose-500/50 p-2.5 transition-all group"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-slate-200 group-hover:text-rose-300">Ransomware High-Entropy</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 bg-rose-500/10 text-rose-400 border border-rose-500/30">
                    Encrypted Payload
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">Randomized byte frequencies exceeding 7.5 bits.</div>
              </button>
            </div>
          </div>

          {/* Upload Drop Zone & Content Editor */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left: File Ingestion (7 cols) */}
            <div className="lg:col-span-7 bg-slate-900 border border-slate-800 p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Upload className="h-4 w-4 text-cyan-400" />
                    <span>Select or Upload File for Analysis</span>
                  </h3>
                  <p className="text-xs text-slate-400">Upload any document, configuration, or source code file</p>
                </div>

                <div className="flex items-center gap-2">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-3 py-1.5 text-xs uppercase tracking-wider flex items-center gap-1.5 transition-colors"
                  >
                    <Upload className="h-3 w-3" />
                    <span>Choose Local File</span>
                  </button>
                </div>
              </div>

              {/* File Metadata Overview */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs">
                <div className="bg-slate-950 border border-slate-800 p-2.5">
                  <div className="text-[10px] text-slate-400">Target Filename</div>
                  <div className="font-mono text-slate-200 font-semibold truncate mt-0.5" title={userFileName}>
                    {userFileName}
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800 p-2.5">
                  <div className="text-[10px] text-slate-400">File Size</div>
                  <div className="font-mono text-slate-200 font-semibold mt-0.5">
                    {formatFileSize(userFileSize)}
                    <span className="text-[10px] text-slate-400 ml-1">({userFileSize.toLocaleString()} B)</span>
                  </div>
                </div>
                <div className="bg-slate-950 border border-slate-800 p-2.5 col-span-2 sm:col-span-1">
                  <div className="text-[10px] text-slate-400">Shannon Entropy</div>
                  <div className="font-mono text-slate-200 font-semibold mt-0.5">
                    {userEntropy.toFixed(3)} bits
                    <span className={`text-[10px] ml-1.5 ${userEntropy > 7.5 ? 'text-rose-400 font-bold' : 'text-slate-400'}`}>
                      {userEntropy > 7.5 ? '(High / Encrypted)' : '(Normal)'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Editable Content Workspace */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs text-slate-400">
                  <span>File In-Memory Buffer (Edit text to immediately recalculate hash):</span>
                  <span>{userFileContent.length} characters</span>
                </div>
                <textarea
                  rows={8}
                  value={userFileContent}
                  onChange={(e) => {
                    setUserFileContent(e.target.value);
                    handleAnalyzeContent(e.target.value, userFileName);
                  }}
                  className="w-full bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono p-3 focus:border-cyan-500 focus:outline-none leading-relaxed"
                  placeholder="Paste or edit file payload here..."
                />
              </div>

              {/* Calculated Hashes Display */}
              <div className="space-y-2 pt-1">
                <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                  Calculated Cryptographic Hashes:
                </div>

                {/* SHA-256 */}
                <div className="bg-slate-950 border border-cyan-500/30 p-2.5 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-semibold text-cyan-300 font-mono">SHA-256 (Primary Standard)</span>
                    <button
                      onClick={() => copyToClipboard(userSha256, 'sha256')}
                      className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] font-sans"
                    >
                      {copiedHash === 'sha256' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedHash === 'sha256' ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="font-mono text-[11px] text-slate-200 break-all bg-slate-900/60 p-1.5 border border-slate-800">
                    {userSha256 || 'Calculating...'}
                  </div>
                </div>

                {/* SHA-512 & MD5 Collapsible or side-by-side */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div className="bg-slate-950 border border-slate-800 p-2 space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-mono">SHA-512</span>
                      <button
                        onClick={() => copyToClipboard(userSha512, 'sha512')}
                        className="text-slate-400 hover:text-slate-200 text-[10px]"
                      >
                        {copiedHash === 'sha512' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div className="font-mono text-[10px] text-slate-300 truncate">
                      {userSha512 || 'Calculating...'}
                    </div>
                  </div>

                  <div className="bg-slate-950 border border-slate-800 p-2 space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-mono">MD5 (Legacy Fingerprint)</span>
                      <button
                        onClick={() => copyToClipboard(userMd5, 'md5')}
                        className="text-slate-400 hover:text-slate-200 text-[10px]"
                      >
                        {copiedHash === 'md5' ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div className="font-mono text-[10px] text-slate-300 truncate">
                      {userMd5 || 'Calculating...'}
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Hash Comparison & Trustworthiness Disclaimer (5 cols) */}
            <div className="lg:col-span-5 space-y-5">
              {/* Baseline Comparison Card */}
              <div className="bg-slate-900 border border-slate-800 p-5 space-y-4">
                <div className="border-b border-slate-800 pb-3">
                  <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-cyan-400" />
                    <span>Cryptographic Baseline Comparison</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Verify calculated hash against expected reference baseline
                  </p>
                </div>

                {/* Mode Selector */}
                <div className="flex items-center bg-slate-950 border border-slate-800 p-1 text-xs">
                  <button
                    onClick={() => setComparisonMode('BASELINE')}
                    className={`flex-1 py-1.5 font-medium transition-colors ${
                      comparisonMode === 'BASELINE'
                        ? 'bg-slate-800 text-cyan-300 border border-cyan-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Select Golden Baseline
                  </button>
                  <button
                    onClick={() => setComparisonMode('MANUAL')}
                    className={`flex-1 py-1.5 font-medium transition-colors ${
                      comparisonMode === 'MANUAL'
                        ? 'bg-slate-800 text-cyan-300 border border-cyan-500/30'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    Paste Expected Hash
                  </button>
                </div>

                {/* Mode 1: Select Baseline */}
                {comparisonMode === 'BASELINE' ? (
                  <div className="space-y-2 text-xs">
                    <label className="block text-slate-400">Authoritative Baseline Target:</label>
                    <select
                      value={selectedBaselineId}
                      onChange={(e) => setSelectedBaselineId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 text-slate-200 p-2 font-mono text-xs focus:border-cyan-500"
                    >
                      {baselines.map((b) => (
                        <option key={b.id} value={b.id}>
                          {b.filename} ({b.filepath})
                        </option>
                      ))}
                    </select>
                    {currentBaseline && (
                      <div className="bg-slate-950 p-2.5 border border-slate-800 text-[11px] font-mono space-y-1">
                        <div className="text-slate-400">Baseline SHA-256:</div>
                        <div className="text-cyan-300 break-all">{currentBaseline.baselineSha256}</div>
                      </div>
                    )}
                  </div>
                ) : (
                  /* Mode 2: Manual Hash Input */
                  <div className="space-y-2 text-xs">
                    <label className="block text-slate-400">Expected Reference SHA-256 Hash:</label>
                    <input
                      type="text"
                      placeholder="Paste 64-character hex hash provided by vendor..."
                      value={manualExpectedHash}
                      onChange={(e) => setManualExpectedHash(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 text-slate-100 p-2 font-mono text-xs focus:border-cyan-500"
                    />
                  </div>
                )}

                {/* Comparison Result Banner */}
                {comparisonResult && (
                  <div
                    className={`p-4 border text-xs space-y-2 ${
                      comparisonResult.status === 'MATCH'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                        : comparisonResult.status === 'HIGH_ENTROPY_TAMPER'
                        ? 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                        : comparisonResult.status === 'MISMATCH'
                        ? 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                        : 'bg-slate-950 border-slate-800 text-slate-400'
                    }`}
                  >
                    <div className="font-bold flex items-center gap-2 text-sm">
                      {comparisonResult.status === 'MATCH' && (
                        <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                      )}
                      {comparisonResult.status === 'HIGH_ENTROPY_TAMPER' && (
                        <Flame className="h-5 w-5 text-rose-400 shrink-0" />
                      )}
                      {comparisonResult.status === 'MISMATCH' && (
                        <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0" />
                      )}
                      <span>{comparisonResult.verdict}</span>
                    </div>
                    <p className="leading-relaxed text-[11px] opacity-90">{comparisonResult.details}</p>
                  </div>
                )}
              </div>

              {/* CRUCIAL ACADEMIC SECURITY ADVISORY (Requirement: explain matching hash != trustworthy) */}
              <div className="bg-slate-950 border border-slate-800 p-4 space-y-2 text-xs">
                <div className="font-semibold text-slate-200 flex items-center gap-1.5">
                  <ShieldAlert className="h-4 w-4 text-amber-400 shrink-0" />
                  <span>Important Security Limitation & Academic Principle:</span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  <strong>A matching hash does not prove a file is trustworthy or safe.</strong>
                  <br />
                  Cryptographic hashing verifies <em>data integrity</em> (that the content has not changed since the baseline hash was recorded). It does not evaluate <em>benevolence</em>:
                </p>
                <ul className="list-disc pl-5 space-y-1 text-[11px] text-slate-400">
                  <li>A malicious Trojan or backdoor also possesses a completely valid SHA-256 hash.</li>
                  <li>If the baseline hash was captured from an already-compromised artifact, a 100% hash match simply verifies that the file remains compromised.</li>
                  <li>True trust requires multi-layer defense: PKI digital code signatures, CA root validation, and behavior-based heuristic sandboxing.</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: GOLDEN BASELINE REGISTRY & TAMPER INJECTION LAB */}
      {activeTab === 'BASELINE_REGISTRY' && (
        <div className="space-y-6">
          {/* Golden Baselines Table */}
          <div className="bg-slate-900 border border-slate-800 p-5 space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-semibold text-slate-200">Authoritative Golden Baseline Registry</h3>
                <p className="text-xs text-slate-400">System critical artifacts monitored for unauthorized code injection</p>
              </div>
              <span className="font-mono text-xs text-cyan-400">SHA-256 / SHA-512</span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400 bg-slate-950/50">
                    <th className="p-3">Artifact</th>
                    <th className="p-3">Filesystem Path</th>
                    <th className="p-3">Authoritative SHA-256</th>
                    <th className="p-3">Baseline Entropy</th>
                    <th className="p-3">Last Verified</th>
                    <th className="p-3 text-right">Target</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                  {baselines.map((file) => (
                    <tr
                      key={file.id}
                      onClick={() => setSelectedBaselineId(file.id)}
                      className={`cursor-pointer transition-colors ${
                        selectedBaselineId === file.id ? 'bg-cyan-500/10' : 'hover:bg-slate-800/30'
                      }`}
                    >
                      <td className="p-3 font-semibold text-slate-200 flex items-center gap-2">
                        <FileCode className="h-4 w-4 text-cyan-400" />
                        <span>{file.filename}</span>
                      </td>
                      <td className="p-3 text-slate-400">{file.filepath}</td>
                      <td className="p-3 text-slate-300">
                        {file.baselineSha256.slice(0, 16)}...{file.baselineSha256.slice(-8)}
                      </td>
                      <td className="p-3 text-slate-300">{file.entropy} bits</td>
                      <td className="p-3 text-slate-400 text-[11px]">{file.lastVerified}</td>
                      <td className="p-3 text-right">
                        <span
                          className={`font-mono text-[11px] font-semibold ${
                            selectedBaselineId === file.id ? 'text-cyan-400' : 'text-slate-500'
                          }`}
                        >
                          {selectedBaselineId === file.id ? '● ACTIVE TARGET' : 'Select'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Tamper Simulation Lab */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-7 bg-slate-900 border border-slate-800 p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-semibold text-slate-200">Active Baseline Content Inspection</h3>
                  <p className="text-xs text-slate-400">Target Artifact: {currentBaseline?.filename}</p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      const clean = `// Authoritative Authentication Service v3.2\nexport function verifyToken(token: string) {\n  if (!token) return false;\n  return token.startsWith("authshield_jwt_sec_");\n}`;
                      setSimFileContent(clean);
                      setSimCheckResult(null);
                    }}
                    className="flex items-center gap-1 bg-slate-800 hover:bg-slate-700 text-slate-300 px-2.5 py-1 text-xs transition-colors"
                  >
                    <RotateCcw className="h-3 w-3" />
                    <span>Reset</span>
                  </button>
                </div>
              </div>

              <div>
                <textarea
                  rows={8}
                  value={simFileContent}
                  onChange={(e) => setSimFileContent(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 p-3 font-mono text-xs text-cyan-300/90 focus:border-cyan-500 focus:outline-none"
                  placeholder="Edit baseline content to test tamper detection..."
                />
              </div>

              {/* Simulation Action Triggers */}
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <button
                  onClick={() => {
                    const tampered =
                      simFileContent +
                      `\n\n// [MALICIOUS INJECTION - SIMULATED ATTACK]\napp.use((req, res, next) => { if (req.headers['x-backdoor']) exec(req.headers['x-backdoor']); next(); });`;
                    setSimFileContent(tampered);
                    handleRunSimFim(tampered);
                  }}
                  className="flex items-center gap-1.5 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/40 text-amber-300 px-3 py-1.5 text-xs font-semibold transition-colors"
                >
                  <AlertTriangle className="h-3.5 w-3.5" />
                  <span>Simulate Backdoor Tamper</span>
                </button>

                <button
                  onClick={() => {
                    let highEntropy = '';
                    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';
                    for (let i = 0; i < 2048; i++) {
                      highEntropy += chars.charAt(Math.floor(Math.random() * chars.length));
                    }
                    setSimFileContent(highEntropy);
                    handleRunSimFim(highEntropy);
                  }}
                  className="flex items-center gap-1.5 bg-rose-500/10 hover:bg-rose-500/20 border border-rose-500/40 text-rose-300 px-3 py-1.5 text-xs font-semibold transition-colors"
                >
                  <Flame className="h-3.5 w-3.5" />
                  <span>Simulate Ransomware High-Entropy</span>
                </button>
              </div>

              <button
                onClick={() => handleRunSimFim()}
                disabled={isCheckingSim}
                className="w-full bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-4 py-2.5 text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-colors disabled:opacity-50"
              >
                {isCheckingSim ? 'Computing Digest & Verifying...' : 'Verify Baseline Integrity'}
              </button>
            </div>

            {/* Simulation Feedback Card */}
            <div className="lg:col-span-5 bg-slate-900 border border-slate-800 p-5 space-y-4">
              <h3 className="text-sm font-semibold text-slate-200 border-b border-slate-800 pb-3">
                FIM Engine Verification Response
              </h3>

              {simCheckResult ? (
                <div className="space-y-4 text-xs">
                  <div
                    className={`p-3.5 border ${
                      simCheckResult.status === 'HEALTHY'
                        ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-200'
                        : simCheckResult.status === 'TAMPERED'
                        ? 'bg-rose-500/15 border-rose-500/40 text-rose-200'
                        : 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                    }`}
                  >
                    <div className="font-bold text-sm mb-1">{simCheckResult.verdict}</div>
                    <div className="text-[11px] opacity-90">
                      Status: <strong>{simCheckResult.status}</strong>
                    </div>
                  </div>

                  <div className="space-y-2 font-mono text-[11px]">
                    <div className="bg-slate-950 p-2.5 border border-slate-800 space-y-1">
                      <div className="text-slate-400">Current Computed SHA-256:</div>
                      <div className="text-slate-200 break-all">{simCheckResult.hashes.sha256}</div>
                    </div>
                    <div className="bg-slate-950 p-2.5 border border-slate-800 space-y-1">
                      <div className="text-slate-400">Golden Baseline SHA-256:</div>
                      <div className="text-cyan-300 break-all">{simCheckResult.matchedBaseline?.baselineSha256}</div>
                    </div>
                    <div className="bg-slate-950 p-2.5 border border-slate-800 space-y-1">
                      <div className="text-slate-400">Calculated Entropy:</div>
                      <div className="text-slate-200">{simCheckResult.hashes.entropy} bits</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-8 text-center text-xs text-slate-400">
                  Click "Verify Baseline Integrity" or simulate a tampering event to test the server integrity engine.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
