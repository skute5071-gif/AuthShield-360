import React from 'react';
import { UserRole } from '../../types/security';

interface UserRoleBadgeProps {
  role: UserRole;
  className?: string;
}

export const UserRoleBadge: React.FC<UserRoleBadgeProps> = ({ role, className = '' }) => {
  const isAdm = role === 'admin';
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono text-xs font-bold uppercase tracking-wider ${
        isAdm ? 'text-cyan-400' : 'text-emerald-400'
      } ${className}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${isAdm ? 'bg-cyan-400 animate-pulse' : 'bg-emerald-400'}`} />
      {isAdm ? 'SecOps Administrator' : 'Standard User'}
    </span>
  );
};
