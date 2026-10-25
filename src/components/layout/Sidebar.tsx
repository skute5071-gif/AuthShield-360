import React from 'react';
import {
  LayoutDashboard,
  ShieldCheck,
  Activity,
  Globe,
  CreditCard,
  FileCheck2,
  FileSpreadsheet,
  Settings,
  Shield,
  ExternalLink,
} from 'lucide-react';

interface SidebarProps {
  activeTab: string;
  onSelectTab: (tab: string) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  mobileOpen,
  onCloseMobile,
}) => {
  const navItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      description: 'Threat overview & telemetry',
    },
    {
      id: 'login-security',
      label: 'Login Security',
      icon: ShieldCheck,
      description: 'Suspicious login detection & simulator',
    },
    {
      id: 'security-events',
      label: 'Security Events',
      icon: Activity,
      description: 'Audit log & forensic trail',
    },
    {
      id: 'phishing-checker',
      label: 'Phishing Checker',
      icon: Globe,
      description: 'URL heuristics & homograph engine',
    },
    {
      id: 'payment-risk',
      label: 'Payment Risk Analyzer',
      icon: CreditCard,
      description: 'Fraud & triangulation detection',
    },
    {
      id: 'file-integrity',
      label: 'File Integrity',
      icon: FileCheck2,
      description: 'FIM & entropy ransomware scanner',
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: FileSpreadsheet,
      description: 'Academic mini-project report & export',
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
      description: 'Thresholds, firewall & Firebase setup',
    },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          onClick={onCloseMobile}
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm lg:hidden"
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 border-r border-slate-800/80 bg-[#070b16] pt-16 transition-transform duration-200 lg:static lg:w-64 lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <div className="flex h-full flex-col justify-between p-3">
          {/* Nav Links */}
          <div className="space-y-1">
            <div className="px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Core Modules
            </div>

            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    onSelectTab(item.id);
                    onCloseMobile();
                  }}
                  className={`group flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 font-semibold border-l-2 border-cyan-400 shadow-sm'
                      : 'text-slate-400 hover:bg-slate-900/60 hover:text-slate-200'
                  }`}
                >
                  <Icon
                    className={`h-4 w-4 shrink-0 transition-colors ${
                      isActive ? 'text-cyan-400' : 'text-slate-500 group-hover:text-slate-300'
                    }`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-xs">{item.label}</div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Student Mini-Project Footer Info Card */}
          <div className="rounded-xl border border-slate-800/90 bg-slate-900/40 p-3 text-xs text-slate-400">
            <div className="flex items-center gap-2 font-mono text-[11px] font-semibold text-slate-300">
              <Shield className="h-3.5 w-3.5 text-cyan-400" />
              <span>COLLEGE CAPSTONE</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-500 leading-relaxed">
              Computer Engineering Mini-Project: Real-time Account Protection & Threat Mitigation.
            </p>
            <div className="mt-2.5 flex items-center justify-between border-t border-slate-800/80 pt-2 text-[10px] text-slate-400">
              <span>Eng. Dept · 2026</span>
              <span className="font-mono text-cyan-400">v3.2 Final</span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
