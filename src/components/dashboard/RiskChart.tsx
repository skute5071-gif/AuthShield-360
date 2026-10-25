import React from 'react';

interface RiskChartProps {
  severityCount: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  total: number;
}

export const RiskChart: React.FC<RiskChartProps> = ({ severityCount, total }) => {
  const safeTotal = total > 0 ? total : 1;
  const lowPercent = Math.round((severityCount.LOW / safeTotal) * 100);
  const medPercent = Math.round((severityCount.MEDIUM / safeTotal) * 100);
  const highPercent = Math.round((severityCount.HIGH / safeTotal) * 100);
  const critPercent = Math.round((severityCount.CRITICAL / safeTotal) * 100);

  // SVG Donut calculation
  const radius = 64;
  const stroke = 18;
  const circumference = 2 * Math.PI * radius;

  const lowOffset = 0;
  const lowDash = (severityCount.LOW / safeTotal) * circumference;

  const medOffset = -lowDash;
  const medDash = (severityCount.MEDIUM / safeTotal) * circumference;

  const highOffset = -(lowDash + medDash);
  const highDash = (severityCount.HIGH / safeTotal) * circumference;

  const critOffset = -(lowDash + medDash + highDash);
  const critDash = (severityCount.CRITICAL / safeTotal) * circumference;

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-6">
      {/* SVG Donut */}
      <div className="relative flex h-44 w-44 shrink-0 items-center justify-center">
        <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 160 160">
          <circle
            cx="80"
            cy="80"
            r={radius}
            fill="transparent"
            stroke="#1e293b"
            strokeWidth={stroke}
          />
          {severityCount.LOW > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="transparent"
              stroke="#10b981"
              strokeWidth={stroke}
              strokeDasharray={`${lowDash} ${circumference}`}
              strokeDashoffset={lowOffset}
              className="transition-all duration-500"
            />
          )}
          {severityCount.MEDIUM > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="transparent"
              stroke="#f59e0b"
              strokeWidth={stroke}
              strokeDasharray={`${medDash} ${circumference}`}
              strokeDashoffset={medOffset}
              className="transition-all duration-500"
            />
          )}
          {severityCount.HIGH > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="transparent"
              stroke="#f97316"
              strokeWidth={stroke}
              strokeDasharray={`${highDash} ${circumference}`}
              strokeDashoffset={highOffset}
              className="transition-all duration-500"
            />
          )}
          {severityCount.CRITICAL > 0 && (
            <circle
              cx="80"
              cy="80"
              r={radius}
              fill="transparent"
              stroke="#f43f5e"
              strokeWidth={stroke}
              strokeDasharray={`${critDash} ${circumference}`}
              strokeDashoffset={critOffset}
              className="transition-all duration-500"
            />
          )}
        </svg>

        {/* Center Text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="font-mono text-2xl font-extrabold text-slate-100">{total}</span>
          <span className="text-[10px] uppercase tracking-wider text-slate-400">Total Events</span>
        </div>
      </div>

      {/* Legend & Breakdown */}
      <div className="w-full flex-1 space-y-2.5">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-rose-500" />
            <span className="text-slate-300 font-medium">Critical Risk</span>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-100 font-bold">{severityCount.CRITICAL}</span>
            <span className="text-slate-500">({critPercent}%)</span>
          </div>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div className="h-full bg-rose-500" style={{ width: `${critPercent}%` }} />
        </div>

        <div className="flex items-center justify-between text-xs pt-1">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-orange-500" />
            <span className="text-slate-300 font-medium">High Risk</span>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-100 font-bold">{severityCount.HIGH}</span>
            <span className="text-slate-500">({highPercent}%)</span>
          </div>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div className="h-full bg-orange-500" style={{ width: `${highPercent}%` }} />
        </div>

        <div className="flex items-center justify-between text-xs pt-1">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-amber-500" />
            <span className="text-slate-300 font-medium">Medium Risk</span>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-100 font-bold">{severityCount.MEDIUM}</span>
            <span className="text-slate-500">({medPercent}%)</span>
          </div>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div className="h-full bg-amber-500" style={{ width: `${medPercent}%` }} />
        </div>

        <div className="flex items-center justify-between text-xs pt-1">
          <div className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            <span className="text-slate-300 font-medium">Low / Legitimate</span>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-100 font-bold">{severityCount.LOW}</span>
            <span className="text-slate-500">({lowPercent}%)</span>
          </div>
        </div>
        <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-800">
          <div className="h-full bg-emerald-500" style={{ width: `${lowPercent}%` }} />
        </div>
      </div>
    </div>
  );
};
