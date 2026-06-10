/**
 * AlertCard — Individual alert display card.
 * Shows severity badge, entity, score, MITRE techniques, and reasons.
 */
import React from 'react';
import { AlertTriangle, AlertCircle, Info, Shield, ShieldAlert } from 'lucide-react';
import { format } from 'date-fns';
import type { ThreatScore } from '../../types';

export interface AlertCardProps {
  alert: ThreatScore;
  onClick?: (alert: ThreatScore) => void;
  compact?: boolean;
}

const SEVERITY_CONFIG: Record<
  string,
  { color: string; bg: string; border: string; icon: React.ReactNode }
> = {
  critical: {
    color: 'text-red-400',
    bg: 'bg-red-500/10',
    border: 'border-red-500/30',
    icon: <ShieldAlert size={16} />,
  },
  high: {
    color: 'text-orange-400',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    icon: <AlertTriangle size={16} />,
  },
  medium: {
    color: 'text-amber-400',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/30',
    icon: <AlertCircle size={16} />,
  },
  low: {
    color: 'text-blue-400',
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/30',
    icon: <Shield size={16} />,
  },
  info: {
    color: 'text-gray-400',
    bg: 'bg-gray-500/10',
    border: 'border-gray-500/30',
    icon: <Info size={16} />,
  },
};

export const AlertCard: React.FC<AlertCardProps> = ({ alert, onClick, compact = false }) => {
  const sev = SEVERITY_CONFIG[alert.level] || SEVERITY_CONFIG.info;
  const lastSeen = format(new Date(alert.last_seen * 1000), 'MMM d, HH:mm');

  return (
    <div
      className={`rounded-lg border ${sev.border} ${sev.bg} p-4 transition-all ${
        onClick ? 'cursor-pointer hover:brightness-110' : ''
      }`}
      onClick={() => onClick?.(alert)}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className={sev.color}>{sev.icon}</span>
          <span className={`text-xs font-semibold uppercase ${sev.color}`}>
            {alert.level}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-500">{lastSeen}</span>
          <span
            className={`text-sm font-mono font-bold ${sev.color}`}
          >
            {alert.score}
          </span>
        </div>
      </div>

      {/* Entity */}
      <p className="mt-2 font-mono text-sm text-gray-200 truncate">{alert.entity}</p>

      {!compact && (
        <>
          {/* Reasons */}
          <ul className="mt-2 space-y-0.5">
            {alert.reasons.slice(0, 3).map((r, i) => (
              <li key={i} className="text-xs text-gray-400 truncate">
                • {r}
              </li>
            ))}
          </ul>

          {/* MITRE techniques */}
          {alert.mitre_techniques.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1">
              {alert.mitre_techniques.map((t) => (
                <span
                  key={t}
                  className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20"
                >
                  {t}
                </span>
              ))}
            </div>
          )}

          {/* Footer */}
          <div className="mt-2 flex items-center justify-between text-[10px] text-gray-500">
            <span>{alert.occurrence_count} occurrences</span>
            <span>
              Confidence: {(alert.confidence * 100).toFixed(0)}%
            </span>
          </div>
        </>
      )}
    </div>
  );
};

export default AlertCard;
