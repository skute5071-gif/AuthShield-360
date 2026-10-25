import React, { useState, useEffect } from 'react';
import {
  CreditCard,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Upload,
  Plus,
  RefreshCw,
  FileText,
  Download,
  ShieldCheck,
  ShieldAlert,
  Info,
  BookOpen,
  Filter,
  Check,
  Sparkles,
  Search,
} from 'lucide-react';
import { PaymentTransactionRecord } from '../../types/security';
import { api } from '../../services/api';
import { RiskBadge } from '../common/RiskBadge';

interface PaymentRiskViewProps {
  onEventCreated: () => Promise<void>;
  onSelectTab: (tab: string) => void;
}

export const PaymentRiskView: React.FC<PaymentRiskViewProps> = ({ onEventCreated, onSelectTab }) => {
  const [activeTab, setActiveTab] = useState<'TRANSACTIONS' | 'ADD_MANUAL' | 'UPLOAD_CSV' | 'REGULATORY_REF' | 'TEST_SUITE'>('TRANSACTIONS');
  const [transactions, setTransactions] = useState<PaymentTransactionRecord[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedTxn, setSelectedTxn] = useState<PaymentTransactionRecord | null>(null);
  const [filterRisk, setFilterRisk] = useState<'ALL' | 'LOW' | 'MEDIUM' | 'HIGH'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Manual Entry Form state
  const [manualForm, setManualForm] = useState<{
    transactionId: string;
    accountRef: string;
    amount: string;
    timestamp: string;
    paymentMethod: 'UPI' | 'CREDIT_CARD' | 'DEBIT_CARD' | 'NET_BANKING' | 'WALLET';
    transactionResult: 'SUCCESS' | 'FAILED' | 'PENDING';
    merchantCategory: 'ELECTRONICS' | 'GROCERY' | 'TRAVEL' | 'GAMING' | 'UTILITIES';
  }>({
    transactionId: `TXN-MANUAL-${Math.floor(1000 + Math.random() * 9000)}`,
    accountRef: 'acc_student_2026',
    amount: '650.00',
    timestamp: new Date().toISOString(),
    paymentMethod: 'UPI',
    transactionResult: 'SUCCESS',
    merchantCategory: 'ELECTRONICS',
  });
  const [isSubmittingManual, setIsSubmittingManual] = useState(false);
  const [manualSuccessMsg, setManualSuccessMsg] = useState<string | null>(null);
  const [manualErrorMsg, setManualErrorMsg] = useState<string | null>(null);

  // CSV Upload state
  const [csvContent, setCsvContent] = useState('');
  const [isUploadingCsv, setIsUploadingCsv] = useState(false);
  const [csvSuccessMsg, setCsvSuccessMsg] = useState<string | null>(null);
  const [csvRowErrors, setCsvRowErrors] = useState<string[]>([]);
  const [csvGeneralError, setCsvGeneralError] = useState<string | null>(null);

  // Load transactions
  const loadTransactions = async () => {
    setIsLoading(true);
    try {
      const data = await api.getPaymentTransactions();
      setTransactions(data);
      if (data.length > 0 && !selectedTxn) {
        setSelectedTxn(data[0]);
      }
    } catch (err: any) {
      console.error('Failed to load transactions:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadTransactions();
  }, []);

  const handleGenerateSynthetic = async () => {
    setIsLoading(true);
    try {
      const res = await api.generateSyntheticPayments();
      setTransactions(res.data);
      if (res.data.length > 0) setSelectedTxn(res.data[0]);
      await onEventCreated();
    } catch (err: any) {
      alert(err.message || 'Failed to generate synthetic data');
    } finally {
      setIsLoading(false);
    }
  };

  const handleManualSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmittingManual(true);
    setManualSuccessMsg(null);
    setManualErrorMsg(null);

    const parsedAmount = parseFloat(manualForm.amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      setManualErrorMsg('Amount must be a positive number');
      setIsSubmittingManual(false);
      return;
    }

    try {
      const created = await api.addPaymentTransaction({
        transactionId: manualForm.transactionId.trim(),
        accountRef: manualForm.accountRef.trim(),
        amount: parsedAmount,
        timestamp: manualForm.timestamp,
        paymentMethod: manualForm.paymentMethod,
        transactionResult: manualForm.transactionResult,
        merchantCategory: manualForm.merchantCategory,
      });

      setManualSuccessMsg(`Transaction ${created.transactionId} evaluated. Risk Score: ${created.riskScore}/100 (${created.riskLevel})`);
      setManualForm({
        transactionId: `TXN-MANUAL-${Math.floor(1000 + Math.random() * 9000)}`,
        accountRef: manualForm.accountRef,
        amount: '120.00',
        timestamp: new Date().toISOString(),
        paymentMethod: 'UPI',
        transactionResult: 'SUCCESS',
        merchantCategory: 'GROCERY',
      });
      await loadTransactions();
      setSelectedTxn(created);
      await onEventCreated();
    } catch (err: any) {
      setManualErrorMsg(err.message || 'Submission failed');
    } finally {
      setIsSubmittingManual(false);
    }
  };

  const handleCsvUploadSubmit = async () => {
    if (!csvContent.trim()) {
      setCsvGeneralError('CSV text cannot be empty');
      return;
    }

    setIsUploadingCsv(true);
    setCsvSuccessMsg(null);
    setCsvRowErrors([]);
    setCsvGeneralError(null);

    try {
      const res = await api.uploadPaymentCsv(csvContent);
      setCsvSuccessMsg(res.message);
      if (res.rowErrors && res.rowErrors.length > 0) {
        setCsvRowErrors(res.rowErrors);
      }
      setTransactions(res.data);
      if (res.data.length > 0) setSelectedTxn(res.data[0]);
      await onEventCreated();
    } catch (err: any) {
      setCsvGeneralError(err.message || 'CSV upload failed');
      if (err.rowErrors) setCsvRowErrors(err.rowErrors);
    } finally {
      setIsUploadingCsv(false);
    }
  };

  const handleExportCsv = () => {
    const headers = ['transactionId', 'accountRef', 'amount', 'timestamp', 'paymentMethod', 'transactionResult', 'merchantCategory', 'riskScore', 'riskLevel', 'reasons'];
    const rows = transactions.map((t) => [
      t.transactionId,
      t.accountRef,
      t.amount,
      t.timestamp,
      t.paymentMethod,
      t.transactionResult,
      t.merchantCategory,
      t.riskScore ?? 0,
      t.riskLevel ?? 'LOW',
      `"${(t.reasons || []).join('; ')}"`,
    ]);
    const csvStr = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvStr], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `authshield-payment-risk-report-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(transactions, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `authshield-payment-risk-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Pre-fill sample CSVs for testing
  const loadValidSampleCsv = () => {
    const sample = `transactionId,accountRef,amount,timestamp,paymentMethod,transactionResult,merchantCategory
TXN-CSV-1001,acc_priya_55,120.50,${new Date(Date.now() - 3600000).toISOString()},UPI,SUCCESS,GROCERY
TXN-CSV-1002,acc_vikram_88,950.00,${new Date(Date.now() - 1800000).toISOString()},CREDIT_CARD,SUCCESS,ELECTRONICS
TXN-CSV-1003,acc_vikram_88,950.00,${new Date(Date.now() - 1200000).toISOString()},CREDIT_CARD,FAILED,ELECTRONICS
TXN-CSV-1004,acc_vikram_88,950.00,${new Date().toISOString()},CREDIT_CARD,SUCCESS,ELECTRONICS
TXN-CSV-1005,acc_rahul_99,45.00,${new Date().toISOString()},WALLET,SUCCESS,UTILITIES`;
    setCsvContent(sample);
  };

  const loadMalformedSampleCsv = () => {
    const sample = `transactionId,accountRef,amount,timestamp,paymentMethod,transactionResult,merchantCategory
TXN-ERR-2001,acc_valid_01,85.00,${new Date().toISOString()},UPI,SUCCESS,GROCERY
TXN-ERR-2002,,INVALID_AMOUNT,${new Date().toISOString()},BITCOIN,UNKNOWN,FOOD
TXN-ERR-2003,acc_valid_02,-500,2026-99-99,DEBIT_CARD,SUCCESS,TRAVEL
TXN-ERR-2001,acc_valid_03,300.00,${new Date().toISOString()},UPI,SUCCESS,ELECTRONICS`;
    setCsvContent(sample);
  };

  // Filter transactions
  const filteredTransactions = transactions.filter((t) => {
    if (filterRisk !== 'ALL' && t.riskLevel !== filterRisk) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        t.transactionId.toLowerCase().includes(q) ||
        t.accountRef.toLowerCase().includes(q) ||
        t.paymentMethod.toLowerCase().includes(q) ||
        t.merchantCategory.toLowerCase().includes(q)
      );
    }
    return true;
  });

  // Calculate statistics
  const totalCount = transactions.length;
  const highRiskCount = transactions.filter((t) => t.riskLevel === 'HIGH').length;
  const mediumRiskCount = transactions.filter((t) => t.riskLevel === 'MEDIUM').length;
  const lowRiskCount = transactions.filter((t) => t.riskLevel === 'LOW').length;
  const duplicateIdCount = transactions.filter((t) => t.triggeredRules?.includes('RULE_DUP_TXN_ID')).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <CreditCard className="h-6 w-6 text-cyan-400" />
            <span>Digital Payment Risk Analyzer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Simulated payment telemetry engine evaluating velocity bursts, duplicate identifiers, amount anomalies, and compliance safeguards
          </p>
        </div>

        {/* Tab Controls */}
        <div className="flex flex-wrap items-center gap-1 bg-slate-900 border border-slate-800 p-1">
          <button
            onClick={() => setActiveTab('TRANSACTIONS')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'TRANSACTIONS'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Transactions ({transactions.length})
          </button>
          <button
            onClick={() => setActiveTab('ADD_MANUAL')}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'ADD_MANUAL'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Plus className="h-3 w-3" />
            <span>Manual Entry</span>
          </button>
          <button
            onClick={() => setActiveTab('UPLOAD_CSV')}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'UPLOAD_CSV'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Upload className="h-3 w-3" />
            <span>CSV Upload</span>
          </button>
          <button
            onClick={() => setActiveTab('REGULATORY_REF')}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'REGULATORY_REF'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <BookOpen className="h-3 w-3" />
            <span>RBI & PSSA Guidelines</span>
          </button>
          <button
            onClick={() => setActiveTab('TEST_SUITE')}
            className={`flex items-center gap-1 px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === 'TEST_SUITE'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sparkles className="h-3 w-3" />
            <span>Verification Tests</span>
          </button>
        </div>
      </div>

      {/* Synthetic Isolation Banner */}
      <div className="bg-slate-900/80 border border-cyan-900/50 p-3.5 text-xs text-slate-300 flex items-start gap-3">
        <Info className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-cyan-300">Synthetic Sandbox Architecture:</div>
          <p className="text-slate-400">
            All records displayed are <strong>100% synthetic simulated telemetry</strong>. No live banking APIs, UPI interfaces, payment gateways, or financial card networks are contacted. Card numbers, accounts, and names are generated test fixtures.
          </p>
        </div>
      </div>

      {/* METRIC CARDS & RISK DISTRIBUTION CHART */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
        <div className="bg-slate-900 border border-slate-800 p-3">
          <div className="text-slate-400 text-[11px]">Total Telemetry Records</div>
          <div className="text-2xl font-mono font-bold text-slate-100 mt-1">{totalCount}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Synthetic transaction events</div>
        </div>
        <div className="bg-slate-900 border border-rose-500/30 p-3">
          <div className="text-rose-400 text-[11px] font-semibold">High Risk Anomaly (70–100)</div>
          <div className="text-2xl font-mono font-bold text-rose-300 mt-1">{highRiskCount}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">
            {totalCount > 0 ? ((highRiskCount / totalCount) * 100).toFixed(0) : 0}% of evaluated batch
          </div>
        </div>
        <div className="bg-slate-900 border border-amber-500/30 p-3">
          <div className="text-amber-400 text-[11px] font-semibold">Medium Risk (30–69)</div>
          <div className="text-2xl font-mono font-bold text-amber-300 mt-1">{mediumRiskCount}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Step-up authentication required</div>
        </div>
        <div className="bg-slate-900 border border-emerald-500/30 p-3">
          <div className="text-emerald-400 text-[11px] font-semibold">Low Risk (0–29)</div>
          <div className="text-2xl font-mono font-bold text-emerald-300 mt-1">{lowRiskCount}</div>
          <div className="text-[10px] text-slate-400 mt-0.5">Within baseline thresholds</div>
        </div>
      </div>

      {/* Visual Risk Distribution Bar */}
      {totalCount > 0 && (
        <div className="bg-slate-900 border border-slate-800 p-3 text-xs space-y-2">
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span>Heuristic Risk Distribution:</span>
            <span>{totalCount} Total Evaluated</span>
          </div>
          <div className="w-full h-3 bg-slate-950 flex overflow-hidden">
            <div
              style={{ width: `${(lowRiskCount / totalCount) * 100}%` }}
              className="bg-emerald-500 h-full transition-all"
              title={`Low Risk: ${lowRiskCount}`}
            />
            <div
              style={{ width: `${(mediumRiskCount / totalCount) * 100}%` }}
              className="bg-amber-500 h-full transition-all"
              title={`Medium Risk: ${mediumRiskCount}`}
            />
            <div
              style={{ width: `${(highRiskCount / totalCount) * 100}%` }}
              className="bg-rose-500 h-full transition-all"
              title={`High Risk: ${highRiskCount}`}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] font-mono text-slate-400">
            <span className="text-emerald-400">Low: {lowRiskCount} ({((lowRiskCount / totalCount) * 100).toFixed(1)}%)</span>
            <span className="text-amber-400">Med: {mediumRiskCount} ({((mediumRiskCount / totalCount) * 100).toFixed(1)}%)</span>
            <span className="text-rose-400">High: {highRiskCount} ({((highRiskCount / totalCount) * 100).toFixed(1)}%)</span>
          </div>
        </div>
      )}

      {/* TAB 1: TRANSACTIONS LIST & DETAIL DRAWER */}
      {activeTab === 'TRANSACTIONS' && (
        <div className="space-y-4">
          {/* Action & Filter Toolbar */}
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="h-3.5 w-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Search ID, account, method..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-slate-900 border border-slate-800 text-xs text-slate-200 pl-8 pr-3 py-1.5 focus:border-cyan-500"
                />
              </div>

              {/* Risk Level Filter */}
              <div className="flex items-center bg-slate-900 border border-slate-800 text-xs">
                {(['ALL', 'LOW', 'MEDIUM', 'HIGH'] as const).map((lvl) => (
                  <button
                    key={lvl}
                    onClick={() => setFilterRisk(lvl)}
                    className={`px-2.5 py-1.5 font-medium transition-colors ${
                      filterRisk === lvl
                        ? 'bg-slate-800 text-cyan-300'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {lvl}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={handleGenerateSynthetic}
                disabled={isLoading}
                className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-3 py-1.5 text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`h-3 w-3 ${isLoading ? 'animate-spin' : ''}`} />
                <span>Generate Synthetic Batch</span>
              </button>

              <button
                onClick={handleExportCsv}
                className="bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 px-2.5 py-1.5 text-xs flex items-center gap-1.5 transition-colors"
                title="Export as CSV"
              >
                <Download className="h-3 w-3 text-cyan-400" />
                <span>CSV</span>
              </button>

              <button
                onClick={handleExportJson}
                className="bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 px-2.5 py-1.5 text-xs flex items-center gap-1.5 transition-colors"
                title="Export as JSON"
              >
                <Download className="h-3 w-3 text-cyan-400" />
                <span>JSON</span>
              </button>
            </div>
          </div>

          {/* Grid Layout: Table on left, Detail Drawer on right */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Table (7 cols on lg) */}
            <div className="lg:col-span-7 bg-slate-900 border border-slate-800 overflow-x-auto">
              {isLoading ? (
                <div className="p-12 text-center text-xs text-slate-400">Loading payment telemetry...</div>
              ) : filteredTransactions.length === 0 ? (
                <div className="p-12 text-center text-xs text-slate-400 space-y-2">
                  <CreditCard className="h-8 w-8 text-slate-600 mx-auto" />
                  <div className="text-slate-300 font-semibold">No Transactions Match Current Filters</div>
                  <p>Click "Generate Synthetic Batch" or adjust search criteria.</p>
                </div>
              ) : (
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60 font-semibold">
                      <th className="p-2.5">Transaction ID</th>
                      <th className="p-2.5">Account Ref</th>
                      <th className="p-2.5">Amount</th>
                      <th className="p-2.5">Method</th>
                      <th className="p-2.5">Result</th>
                      <th className="p-2.5">Risk Score</th>
                      <th className="p-2.5">Risk Level</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {filteredTransactions.map((t) => {
                      const isSelected = selectedTxn?.transactionId === t.transactionId;
                      return (
                        <tr
                          key={`${t.transactionId}-${t.timestamp}`}
                          onClick={() => setSelectedTxn(t)}
                          className={`cursor-pointer transition-colors ${
                            isSelected ? 'bg-cyan-500/10 border-l-2 border-l-cyan-400' : 'hover:bg-slate-800/30'
                          }`}
                        >
                          <td className="p-2.5 font-bold text-slate-200">{t.transactionId}</td>
                          <td className="p-2.5 text-slate-400">{t.accountRef}</td>
                          <td className="p-2.5 text-slate-200 font-semibold">${t.amount.toFixed(2)}</td>
                          <td className="p-2.5">
                            <span className="px-1.5 py-0.5 text-[10px] bg-slate-800 text-slate-300 border border-slate-700">
                              {t.paymentMethod}
                            </span>
                          </td>
                          <td className="p-2.5">
                            <span
                              className={`text-[10px] font-semibold ${
                                t.transactionResult === 'SUCCESS'
                                  ? 'text-emerald-400'
                                  : t.transactionResult === 'FAILED'
                                  ? 'text-rose-400'
                                  : 'text-amber-400'
                              }`}
                            >
                              {t.transactionResult}
                            </span>
                          </td>
                          <td className="p-2.5 text-slate-200 font-bold">{t.riskScore ?? 0} / 100</td>
                          <td className="p-2.5">
                            <RiskBadge severity={t.riskLevel || 'LOW'} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>

            {/* Selected Transaction Detail Drawer (5 cols on lg) */}
            <div className="lg:col-span-5 bg-slate-900 border border-slate-800 p-5 space-y-5">
              {selectedTxn ? (
                <>
                  {/* Top Header */}
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                    <div>
                      <div className="text-[11px] text-slate-400">Selected Evaluation Record</div>
                      <div className="text-base font-mono font-bold text-slate-100">{selectedTxn.transactionId}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-2xl font-mono font-bold text-slate-100">
                        {selectedTxn.riskScore ?? 0}
                        <span className="text-xs text-slate-400 font-normal"> / 100</span>
                      </div>
                      <RiskBadge severity={selectedTxn.riskLevel || 'LOW'} />
                    </div>
                  </div>

                  {/* Attributes Grid */}
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="bg-slate-950 border border-slate-800 p-2.5">
                      <div className="text-[10px] text-slate-400">Account Reference</div>
                      <div className="font-mono text-slate-200 font-semibold truncate mt-0.5">{selectedTxn.accountRef}</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5">
                      <div className="text-[10px] text-slate-400">Transaction Amount</div>
                      <div className="font-mono text-slate-100 font-bold mt-0.5">${selectedTxn.amount.toFixed(2)}</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5">
                      <div className="text-[10px] text-slate-400">Payment Instrument</div>
                      <div className="font-mono text-slate-200 mt-0.5">{selectedTxn.paymentMethod}</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5">
                      <div className="text-[10px] text-slate-400">Merchant Category</div>
                      <div className="font-mono text-slate-200 mt-0.5">{selectedTxn.merchantCategory}</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5 col-span-2">
                      <div className="text-[10px] text-slate-400">Timestamp</div>
                      <div className="font-mono text-slate-300 text-[11px] mt-0.5">{selectedTxn.timestamp}</div>
                    </div>
                  </div>

                  {/* Triggered Heuristic Rules & Penalties */}
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                      Triggered Anomaly Rules & Reasons:
                    </div>
                    {selectedTxn.reasons && selectedTxn.reasons.length > 0 ? (
                      <div className="space-y-1.5">
                        {selectedTxn.reasons.map((r, i) => (
                          <div
                            key={i}
                            className="bg-rose-500/10 border border-rose-500/30 p-2 text-xs text-rose-200 flex items-start gap-2"
                          >
                            <AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0 mt-0.5" />
                            <span>{r}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="bg-emerald-500/10 border border-emerald-500/30 p-2.5 text-xs text-emerald-300 flex items-center gap-2">
                        <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                        <span>All velocity and baseline indicators within normal operating tolerances.</span>
                      </div>
                    )}
                  </div>

                  {/* Recommended Defensive Action */}
                  <div className="bg-slate-950 border border-cyan-500/30 p-3 text-xs space-y-1">
                    <div className="text-cyan-400 font-semibold flex items-center gap-1.5">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      <span>Recommended Defensive Control:</span>
                    </div>
                    <p className="text-slate-300 leading-relaxed">
                      {(selectedTxn.riskScore ?? 0) >= 70
                        ? 'Trigger immediate transaction hold; prompt for biometric step-up / OTP confirmation before settlement authorization.'
                        : (selectedTxn.riskScore ?? 0) >= 30
                        ? 'Require standard SMS/app-based 2FA push confirmation; log event for fraud post-processing review.'
                        : 'Allow transaction to proceed to settlement clearing without additional step-up barriers.'}
                    </p>
                  </div>

                  {/* Academic Disclaimer */}
                  <div className="bg-slate-950/70 border border-slate-800 p-2.5 text-[11px] text-slate-400">
                    <span className="font-semibold text-slate-300">Statistical Heuristic Notice: </span>
                    Risk scores represent behavioral outlier scores based on velocity and historical thresholds. They serve as fraud indicators and do not constitute legal proof of financial crime.
                  </div>
                </>
              ) : (
                <div className="p-8 text-center text-xs text-slate-400">
                  Select a transaction row from the table to view its risk breakdown.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: MANUAL TRANSACTION ENTRY */}
      {activeTab === 'ADD_MANUAL' && (
        <div className="bg-slate-900 border border-slate-800 p-6 space-y-5 max-w-2xl">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Submit Fictional Payment Record</h3>
            <p className="text-xs text-slate-400">
              Input custom simulated transaction attributes to test the heuristic evaluation engine
            </p>
          </div>

          {manualSuccessMsg && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 p-3 text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              <span>{manualSuccessMsg}</span>
            </div>
          )}

          {manualErrorMsg && (
            <div className="bg-rose-500/10 border border-rose-500/30 p-3 text-xs text-rose-300 flex items-center gap-2">
              <XCircle className="h-4 w-4 text-rose-400 shrink-0" />
              <span>{manualErrorMsg}</span>
            </div>
          )}

          <form onSubmit={handleManualSubmit} className="space-y-4 text-xs">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Transaction ID (Must be unique)</label>
                <input
                  type="text"
                  required
                  value={manualForm.transactionId}
                  onChange={(e) => setManualForm({ ...manualForm, transactionId: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-100 p-2 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Account Reference</label>
                <input
                  type="text"
                  required
                  value={manualForm.accountRef}
                  onChange={(e) => setManualForm({ ...manualForm, accountRef: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-100 p-2 font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Amount ($ / INR)</label>
                <input
                  type="number"
                  step="0.01"
                  required
                  value={manualForm.amount}
                  onChange={(e) => setManualForm({ ...manualForm, amount: e.target.value })}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-100 p-2 font-mono"
                />
                <span className="text-[10px] text-slate-400">Baseline threshold is $500.00</span>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Payment Method</label>
                <select
                  value={manualForm.paymentMethod}
                  onChange={(e) => setManualForm({ ...manualForm, paymentMethod: e.target.value as any })}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-100 p-2 font-mono"
                >
                  <option value="UPI">UPI (Unified Payments Interface)</option>
                  <option value="CREDIT_CARD">Credit Card</option>
                  <option value="DEBIT_CARD">Debit Card</option>
                  <option value="NET_BANKING">Net Banking</option>
                  <option value="WALLET">Digital Wallet</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Transaction Result</label>
                <select
                  value={manualForm.transactionResult}
                  onChange={(e) => setManualForm({ ...manualForm, transactionResult: e.target.value as any })}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-100 p-2 font-mono"
                >
                  <option value="SUCCESS">SUCCESS</option>
                  <option value="FAILED">FAILED</option>
                  <option value="PENDING">PENDING</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Merchant Category</label>
                <select
                  value={manualForm.merchantCategory}
                  onChange={(e) => setManualForm({ ...manualForm, merchantCategory: e.target.value as any })}
                  className="w-full bg-slate-950 border border-slate-700 text-slate-100 p-2 font-mono"
                >
                  <option value="ELECTRONICS">Electronics (High Resale Risk)</option>
                  <option value="GROCERY">Grocery (Routine Domestic)</option>
                  <option value="TRAVEL">Travel / Flight Booking</option>
                  <option value="GAMING">Digital Gaming / Virtual Goods</option>
                  <option value="UTILITIES">Utility Bills / Municipal</option>
                </select>
              </div>
            </div>

            <div className="pt-2 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setActiveTab('TRANSACTIONS')}
                className="px-4 py-2 text-slate-400 hover:text-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmittingManual}
                className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-5 py-2 text-xs flex items-center gap-2 transition-colors disabled:opacity-50"
              >
                {isSubmittingManual ? 'Evaluating...' : 'Evaluate & Store Record'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* TAB 3: CSV UPLOAD & VALIDATION */}
      {activeTab === 'UPLOAD_CSV' && (
        <div className="bg-slate-900 border border-slate-800 p-6 space-y-5 max-w-3xl">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Bulk CSV Telemetry Ingestion</h3>
              <p className="text-xs text-slate-400">
                Upload or paste CSV transactions with strict schema validation
              </p>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={loadValidSampleCsv}
                className="text-[11px] px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              >
                Load Valid Sample
              </button>
              <button
                type="button"
                onClick={loadMalformedSampleCsv}
                className="text-[11px] px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700 transition-colors"
              >
                Load Sample with Errors
              </button>
            </div>
          </div>

          <div className="text-[11px] text-slate-400 font-mono bg-slate-950 p-2.5 border border-slate-800">
            <strong>Required Header Format:</strong>
            <br />
            transactionId,accountRef,amount,timestamp,paymentMethod,transactionResult,merchantCategory
          </div>

          {csvSuccessMsg && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 p-3 text-xs text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              <span>{csvSuccessMsg}</span>
            </div>
          )}

          {csvGeneralError && (
            <div className="bg-rose-500/10 border border-rose-500/30 p-3 text-xs text-rose-300 flex items-center gap-2">
              <XCircle className="h-4 w-4 text-rose-400 shrink-0" />
              <span>{csvGeneralError}</span>
            </div>
          )}

          {csvRowErrors.length > 0 && (
            <div className="bg-amber-500/10 border border-amber-500/30 p-3 text-xs text-amber-200 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                <span>Row Validation Warnings ({csvRowErrors.length}):</span>
              </div>
              <ul className="list-disc pl-5 space-y-0.5 text-[11px] font-mono">
                {csvRowErrors.map((err, i) => (
                  <li key={i}>{err}</li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <textarea
              rows={8}
              value={csvContent}
              onChange={(e) => setCsvContent(e.target.value)}
              placeholder="Paste comma-separated transaction records here..."
              className="w-full bg-slate-950 border border-slate-700 text-slate-100 text-xs font-mono p-3 leading-relaxed"
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-[11px] text-slate-400">
              Valid rows are ingested and risk-scored; invalid rows are highlighted above.
            </span>
            <button
              type="button"
              onClick={handleCsvUploadSubmit}
              disabled={isUploadingCsv || !csvContent.trim()}
              className="bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-5 py-2 text-xs flex items-center gap-2 transition-colors disabled:opacity-50"
            >
              {isUploadingCsv ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent animate-spin inline-block" />
                  <span>Validating & Ingesting...</span>
                </>
              ) : (
                <>
                  <Upload className="h-3.5 w-3.5" />
                  <span>Ingest & Run Detection</span>
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* TAB 4: REGULATORY & LEGAL COMPLIANCE FRAMEWORK */}
      {activeTab === 'REGULATORY_REF' && (
        <div className="space-y-6">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <BookOpen className="h-5 w-5 text-cyan-400" />
              <span>Regulatory Framework: Payment Security & Customer Protection</span>
            </h3>
            <p className="text-xs text-slate-400">
              Academic review of statutory directives governing electronic payment architectures and customer liability
            </p>
          </div>

          {/* RBI Section */}
          <div className="bg-slate-900 border border-slate-800 p-5 space-y-4">
            <div className="flex items-center gap-2 text-sm font-bold text-cyan-300">
              <ShieldCheck className="h-4 w-4" />
              <span>Reserve Bank of India (RBI) Circular on Limiting Customer Liability</span>
            </div>
            <div className="text-xs text-slate-300 leading-relaxed space-y-3">
              <p>
                <strong>Reference:</strong> RBI Circular DBR.No.Leg.BC.78/09.07.005/2017-18 dated July 6, 2017 on <em>"Customer Protection — Limiting Liability of Customers in Unauthorised Electronic Banking Transactions"</em>.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
                <div className="bg-slate-950 border border-emerald-500/30 p-3 space-y-1">
                  <div className="font-semibold text-emerald-400">1. Zero Customer Liability</div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    • Contributory fraud, negligence, or deficiency on the part of the bank (irrespective of whether the customer reports it).
                    <br />
                    • Third-party breach where neither the bank nor the customer is at fault, and the customer notifies the bank within <strong>three working days</strong> of receiving the transaction alert.
                  </p>
                </div>

                <div className="bg-slate-950 border border-amber-500/30 p-3 space-y-1">
                  <div className="font-semibold text-amber-400">2. Limited Customer Liability</div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    • If notification delay is between <strong>four to seven working days</strong>:
                    <br />
                    - Basic Savings (BSBD) accounts: Maximum liability capped at <strong>Rs. 5,000</strong>.
                    <br />
                    - Other savings, credit card limit &lt; Rs. 5 lakh: Capped at <strong>Rs. 10,000</strong>.
                    <br />
                    - Current accounts / credit card limit &gt; Rs. 5 lakh: Capped at <strong>Rs. 25,000</strong>.
                  </p>
                </div>

                <div className="bg-slate-950 border border-slate-800 p-3 space-y-1">
                  <div className="font-semibold text-slate-300">3. Beyond 7 Working Days</div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    • Customer liability is determined in accordance with the individual bank's <strong>Board-Approved Policy</strong>.
                    <br />
                    • Banks must credit the shadow reversal value back to the customer's account within <strong>10 working days</strong> from the date of intimation.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* PSSA 2007 Section */}
          <div className="bg-slate-900 border border-slate-800 p-5 space-y-4">
            <div className="flex items-center gap-2 text-sm font-bold text-cyan-300">
              <ShieldAlert className="h-4 w-4" />
              <span>Payment and Settlement Systems Act, 2007 (PSSA)</span>
            </div>
            <div className="text-xs text-slate-300 leading-relaxed space-y-3">
              <p>
                The <strong>Payment and Settlement Systems Act, 2007 (Act 51 of 2007)</strong> is the statutory cornerstone regulating digital clearing houses, card payment networks, and Unified Payments Interface (UPI) operations in India.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2">
                <div className="bg-slate-950 border border-slate-800 p-3 space-y-1">
                  <div className="font-semibold text-cyan-400">Section 4 — Mandatory Authorization</div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Prohibits any entity from operating a payment system in India without obtaining prior authorization from the Reserve Bank of India. Ensures security audits, technical architecture review, and financial viability.
                  </p>
                </div>
                <div className="bg-slate-950 border border-slate-800 p-3 space-y-1">
                  <div className="font-semibold text-cyan-400">Section 18 — Directives on Systemic Risk</div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">
                    Empowers RBI to issue binding standards regarding payment instrumentation, transaction data localization, encryption requirements, and mandatory multi-factor authentication (MFA/2FA) for electronic transactions.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: BUILT-IN VERIFICATION TESTS */}
      {activeTab === 'TEST_SUITE' && (
        <div className="bg-slate-900 border border-slate-800 p-5 space-y-5">
          <div>
            <h3 className="text-sm font-semibold text-slate-200">Interactive Verification Test Cases</h3>
            <p className="text-xs text-slate-400">
              Run automated test assertions directly against the payment risk engine to verify compliance with engineering guidelines
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Test 1 */}
            <div className="bg-slate-950 border border-slate-800 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-slate-200">Test Case 1: Standard Domestic Baseline</span>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 border border-emerald-500/30">
                  Expected: Low Risk (0–29)
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Single $45 grocery purchase with routine spacing and successful authorization.
              </p>
              <button
                onClick={async () => {
                  try {
                    const res = await api.addPaymentTransaction({
                      transactionId: `TEST-CLEAN-${Date.now()}`,
                      accountRef: 'acc_test_priya',
                      amount: 45.00,
                      timestamp: new Date().toISOString(),
                      paymentMethod: 'UPI',
                      transactionResult: 'SUCCESS',
                      merchantCategory: 'GROCERY',
                    });
                    setSelectedTxn(res);
                    setActiveTab('TRANSACTIONS');
                    await loadTransactions();
                  } catch (e: any) {
                    alert(e.message);
                  }
                }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-cyan-300 py-1.5 text-xs font-medium transition-colors"
              >
                Execute Test 1
              </button>
            </div>

            {/* Test 2 */}
            <div className="bg-slate-950 border border-slate-800 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-slate-200">Test Case 2: High Amount Spike Anomaly</span>
                <span className="text-[10px] font-mono text-rose-400 bg-rose-500/10 px-2 py-0.5 border border-rose-500/30">
                  Expected: High Risk (70–100)
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                $3,500 electronics transaction exceeding the $500 baseline threshold by 700%.
              </p>
              <button
                onClick={async () => {
                  try {
                    const res = await api.addPaymentTransaction({
                      transactionId: `TEST-SPIKE-${Date.now()}`,
                      accountRef: 'acc_test_anomaly',
                      amount: 3500.00,
                      timestamp: new Date().toISOString(),
                      paymentMethod: 'CREDIT_CARD',
                      transactionResult: 'SUCCESS',
                      merchantCategory: 'ELECTRONICS',
                    });
                    setSelectedTxn(res);
                    setActiveTab('TRANSACTIONS');
                    await loadTransactions();
                  } catch (e: any) {
                    alert(e.message);
                  }
                }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-rose-300 py-1.5 text-xs font-medium transition-colors"
              >
                Execute Test 2
              </button>
            </div>

            {/* Test 3 */}
            <div className="bg-slate-950 border border-slate-800 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-slate-200">Test Case 3: Duplicate Transaction ID Collision</span>
                <span className="text-[10px] font-mono text-rose-400 bg-rose-500/10 px-2 py-0.5 border border-rose-500/30">
                  Expected: Duplicate ID Flag (+40 pts)
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Submits an existing transaction ID to trigger replay attack / inconsistent record detection.
              </p>
              <button
                onClick={async () => {
                  try {
                    const dupId = transactions[0]?.transactionId || 'TXN-DUP-TEST';
                    const res = await api.addPaymentTransaction({
                      transactionId: dupId,
                      accountRef: 'acc_test_replay',
                      amount: 250.00,
                      timestamp: new Date().toISOString(),
                      paymentMethod: 'NET_BANKING',
                      transactionResult: 'SUCCESS',
                      merchantCategory: 'TRAVEL',
                    });
                    setSelectedTxn(res);
                    setActiveTab('TRANSACTIONS');
                    await loadTransactions();
                  } catch (e: any) {
                    alert(e.message);
                  }
                }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-amber-300 py-1.5 text-xs font-medium transition-colors"
              >
                Execute Test 3
              </button>
            </div>

            {/* Test 4 */}
            <div className="bg-slate-950 border border-slate-800 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-xs text-slate-200">Test Case 4: Rapid 5-Min Duplicate Burst</span>
                <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-2 py-0.5 border border-amber-500/30">
                  Expected: Medium/High Risk
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Successive identical transactions for the same account within a 2-minute window.
              </p>
              <button
                onClick={async () => {
                  try {
                    const acct = 'acc_burst_test';
                    await api.addPaymentTransaction({
                      transactionId: `TEST-RAPID-A-${Date.now()}`,
                      accountRef: acct,
                      amount: 180.00,
                      timestamp: new Date(Date.now() - 60000).toISOString(),
                      paymentMethod: 'UPI',
                      transactionResult: 'SUCCESS',
                      merchantCategory: 'GAMING',
                    });
                    const res2 = await api.addPaymentTransaction({
                      transactionId: `TEST-RAPID-B-${Date.now()}`,
                      accountRef: acct,
                      amount: 180.00,
                      timestamp: new Date().toISOString(),
                      paymentMethod: 'UPI',
                      transactionResult: 'SUCCESS',
                      merchantCategory: 'GAMING',
                    });
                    setSelectedTxn(res2);
                    setActiveTab('TRANSACTIONS');
                    await loadTransactions();
                  } catch (e: any) {
                    alert(e.message);
                  }
                }}
                className="w-full bg-slate-800 hover:bg-slate-700 text-cyan-300 py-1.5 text-xs font-medium transition-colors"
              >
                Execute Test 4
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
