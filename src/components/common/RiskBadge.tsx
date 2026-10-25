import React from 'react';
import { SeverityLevel } from '../../types/security';

interface RiskBadgeProps {
  severity: SeverityLevel | string;
  className?: string;
  showDot?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ severity, className = '', showDot = true }) => {
  const norm = (severity || 'LOW').toUpperCase();

  const config = {
    LOW: {
      color: 'text-emerald-400',
      dotColor: 'bg-emerald-400',
      label: 'LOW RISK (0–29)',
    },
    MEDIUM: {
      color: 'text-amber-400',
      dotColor: 'bg-amber-400',
      label: 'MEDIUM RISK (30–69)',
    },
    HIGH: {
      color: 'text-rose-400',
      dotColor: 'bg-rose-400',
      label: 'HIGH RISK (70–100)',
    },
    CRITICAL: {
      color: 'text-rose-400',
      dotColor: 'bg-rose-400',
      label: 'HIGH RISK (70–100)',
    },
  }[norm] || {
    color: 'text-slate-400',
    dotColor: 'bg-slate-400',
    label: norm,
  };

  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-xs font-semibold tracking-wider ${config.color} ${className}`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${config.dotColor}`} />}
      {config.label}
    </span>
  );
};
