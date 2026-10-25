import React, { useState } from 'react';
import {
  Activity,
  Search,
  Filter,
  Download,
  Shield,
  Eye,
  X,
  FileJson,
  FileSpreadsheet,
} from 'lucide-react';
import { SecurityEvent } from '../../types/security';
import { RiskBadge } from '../common/RiskBadge';

interface SecurityEventsViewProps {
  events: SecurityEvent[];
  isLoading: boolean;
  onRefresh: () => Promise<void>;
}

export const SecurityEventsView: React.FC<SecurityEventsViewProps> = ({ events, isLoading }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [inspectingEvent, setInspectingEvent] = useState<SecurityEvent | null>(null);

  const filteredEvents = events.filter((e) => {
    if (selectedSeverity !== 'ALL' && e.severity !== selectedSeverity) return false;
    if (selectedType !== 'ALL' && e.type !== selectedType) return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return (
        e.userEmail.toLowerCase().includes(q) ||
        e.ip.toLowerCase().includes(q) ||
        e.location.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        e.type.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const exportToJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(filteredEvents, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `authshield-audit-log-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportToCsv = () => {
    const headers = ['Timestamp', 'Type', 'User Email', 'IP Address', 'Location', 'Severity', 'Status', 'Description'];
    const rows = filteredEvents.map((e) => [
      `"${e.timestamp}"`,
      `"${e.type}"`,
      `"${e.userEmail}"`,
      `"${e.ip}"`,
      `"${e.location}"`,
      `"${e.severity}"`,
      `"${e.status}"`,
      `"${e.description.replace(/"/g, '""')}"`,
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', encodeURI(csvContent));
    downloadAnchor.setAttribute('download', `authshield-audit-log-${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            <span>Security Events Forensic Audit Log</span>
          </h2>
          <p className="text-xs text-slate-400">
            Immutable system activity log recording authentication, access anomalies, and threat mitigations
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={exportToCsv}
            className="flex items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-300 hover:border-slate-700 hover:text-white transition-colors"
          >
            <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" />
            <span>Export CSV</span>
          </button>
          <button
            onClick={exportToJson}
            className="flex items-center gap-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20 transition-colors"
          >
            <FileJson className="h-3.5 w-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-4 space-y-3">
        <div className="flex flex-col sm:flex-row gap-3">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input
              type="text"
              placeholder="Search by user email, IP address, location, or anomaly description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full rounded-lg border border-slate-800 bg-[#090e1a] pl-9 pr-3 py-2 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-none"
            />
          </div>

          {/* Severity Segmented Filter */}
          <div className="flex items-center gap-1 bg-slate-950/70 p-1 rounded-lg border border-slate-800 shrink-0 overflow-x-auto">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSelectedSeverity(lvl)}
                className={`px-3 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
                  selectedSeverity === lvl
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-semibold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        {/* Event Type Filter */}
        <div className="flex items-center gap-2 overflow-x-auto pt-1 text-xs text-slate-400">
          <span className="font-semibold uppercase text-[10px] tracking-wider text-slate-500 shrink-0">Type:</span>
          {[
            { id: 'ALL', label: 'All Types' },
            { id: 'IMPOSSIBLE_TRAVEL', label: 'Impossible Travel' },
            { id: 'BRUTE_FORCE_BURST', label: 'Brute Force' },
            { id: 'TOR_ACCESS', label: 'Tor Access' },
            { id: 'LOGIN_FAILED', label: 'Failed Login' },
            { id: 'PHISHING_BLOCKED', label: 'Phishing' },
            { id: 'PAYMENT_FLAGGED', label: 'Payment Risk' },
            { id: 'FILE_INTEGRITY_TAMPER', label: 'FIM Tamper' },
          ].map((item) => (
            <button
              key={item.id}
              onClick={() => setSelectedType(item.id)}
              className={`rounded-md px-2.5 py-1 text-xs transition-colors whitespace-nowrap ${
                selectedType === item.id
                  ? 'bg-slate-800 text-slate-100 font-semibold border border-slate-700'
                  : 'text-slate-400 hover:text-slate-300'
              }`}
            >
              {item.label}
            </button>
          ))}
        </div>
      </div>

      {/* Events Table */}
      <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 overflow-hidden backdrop-blur-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-[#090f1d] text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <th className="py-3 pl-4">Timestamp</th>
                <th className="py-3">Severity</th>
                <th className="py-3">Event Type</th>
                <th className="py-3">User & IP</th>
                <th className="py-3">Location</th>
                <th className="py-3">Status</th>
                <th className="py-3 text-right pr-4">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredEvents.map((event) => (
                <tr key={event.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 pl-4 font-mono text-[11px] text-slate-400 whitespace-nowrap">
                    {event.timestamp}
                  </td>
                  <td className="py-3 whitespace-nowrap">
                    <RiskBadge severity={event.severity} />
                  </td>
                  <td className="py-3 font-mono text-[11px] text-slate-300 whitespace-nowrap">
                    {event.type}
                  </td>
                  <td className="py-3 font-mono text-[11px]">
                    <div className="text-slate-200">{event.userEmail}</div>
                    <div className="text-slate-500">{event.ip}</div>
                  </td>
                  <td className="py-3 text-slate-400 whitespace-nowrap">
                    {event.location}
                  </td>
                  <td className="py-3 whitespace-nowrap">
                    <span
                      className={`font-mono text-[10px] font-semibold ${
                        event.status === 'BLOCKED'
                          ? 'text-rose-400'
                          : event.status === 'ACTION_TAKEN'
                          ? 'text-amber-400'
                          : 'text-slate-400'
                      }`}
                    >
                      {event.status}
                    </span>
                  </td>
                  <td className="py-3 text-right pr-4 whitespace-nowrap">
                    <button
                      onClick={() => setInspectingEvent(event)}
                      className="rounded border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] font-medium text-slate-300 hover:border-slate-600 hover:text-white transition-colors"
                    >
                      <Eye className="h-3 w-3 inline mr-1" />
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}

              {filteredEvents.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-xs text-slate-500">
                    No security events matched the selected filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Forensic Inspection Modal */}
      {inspectingEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div className="relative w-full max-w-2xl rounded-xl border border-slate-800 bg-[#0e1626] p-6 shadow-2xl">
            <button
              onClick={() => setInspectingEvent(null)}
              className="absolute right-4 top-4 text-slate-400 hover:text-white"
            >
              <X className="h-5 w-5" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <Shield className="h-5 w-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-slate-100">Event Forensic Drill-Down</h3>
                  <RiskBadge severity={inspectingEvent.severity} />
                </div>
                <p className="font-mono text-xs text-slate-400">ID: {inspectingEvent.id}</p>
              </div>
            </div>

            <div className="space-y-3.5 text-xs">
              <div className="rounded-lg border border-slate-800 bg-slate-900/80 p-3 space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
                  Incident Narrative
                </div>
                <p className="text-slate-200 leading-relaxed">{inspectingEvent.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-1">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500">User Subject</span>
                  <div className="font-mono text-slate-200">{inspectingEvent.userEmail}</div>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 space-y-1">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500">Origin IP & Location</span>
                  <div className="font-mono text-slate-200">{inspectingEvent.ip} ({inspectingEvent.location})</div>
                </div>
              </div>

              {inspectingEvent.details && (
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 space-y-2">
                  <span className="text-[10px] uppercase tracking-wider text-slate-500">Raw Technical Telemetry</span>
                  <pre className="font-mono text-[11px] text-cyan-300/90 overflow-x-auto p-2 bg-black/40 rounded border border-slate-900 max-h-48">
                    {JSON.stringify(inspectingEvent.details, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setInspectingEvent(null)}
                className="rounded-lg bg-slate-800 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-700"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
