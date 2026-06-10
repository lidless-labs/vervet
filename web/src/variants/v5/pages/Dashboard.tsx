/**
 * V5 Dashboard — Threat Overview
 * Large serif headline, oversized metric numbers, thin-line timeline,
 * horizontal dot severity strip, editorial threat list.
 */
import React, { useMemo } from 'react';
import { format, parseISO } from 'date-fns';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import {
  mockDashboardStats,
  mockTimeline,
  mockSeverityDistribution,
  mockAlerts,
} from '../../../data/mockData';

const stats = mockDashboardStats;

const severityLevel = (score: number): string => {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  if (score >= 15) return 'low';
  return 'info';
};

/* Custom tooltip for the thin timeline */
const TimelineTooltip: React.FC<{ active?: boolean; payload?: any[]; label?: string }> = ({
  active,
  payload,
  label,
}) => {
  if (!active || !payload?.length) return null;
  return (
    <div
      style={{
        background: '#FAFAF8',
        border: '1px solid #E7E5E4',
        padding: '10px 14px',
        fontFamily: 'DM Sans, sans-serif',
        fontSize: 12,
        color: '#1C1917',
        lineHeight: 1.6,
      }}
    >
      <div style={{ fontWeight: 600, marginBottom: 4 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.dataKey} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span
            style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              background: p.color,
              display: 'inline-block',
            }}
          />
          <span style={{ color: '#78716C', textTransform: 'capitalize' }}>{p.dataKey}:</span>
          <span style={{ fontFamily: 'IBM Plex Mono, monospace', fontWeight: 500 }}>{p.value}</span>
        </div>
      ))}
    </div>
  );
};

const Dashboard: React.FC = () => {
  const topAlerts = useMemo(
    () => [...mockAlerts].sort((a, b) => b.score - a.score).slice(0, 10),
    [],
  );

  const timelineData = useMemo(
    () =>
      mockTimeline.map((d) => ({
        ...d,
        label: format(parseISO(d.timestamp), 'MMM d HH:mm'),
      })),
    [],
  );

  return (
    <div>
      {/* Headline */}
      <header style={{ marginBottom: 8 }}>
        <h1 className="v5-headline v5-headline-xl">Threat Overview</h1>
        <p className="v5-subhead">
          72-hour network analysis · {stats.uniqueSourceIPs} source IPs ·{' '}
          {format(new Date(stats.lastUpdated), 'MMMM d, yyyy HH:mm')}
        </p>
      </header>

      <hr className="v5-rule" />

      {/* Oversized Metrics */}
      <div className="v5-grid-4" style={{ marginBottom: 8 }}>
        <div className="v5-metric">
          <div className="v5-metric-number vermillion">{stats.criticalAlerts}</div>
          <div className="v5-metric-label">Critical Threats</div>
        </div>
        <div className="v5-metric">
          <div className="v5-metric-number">{stats.totalAlerts}</div>
          <div className="v5-metric-label">Total Detections</div>
        </div>
        <div className="v5-metric">
          <div className="v5-metric-number teal">{stats.totalBeacons}</div>
          <div className="v5-metric-label">Active Beacons</div>
        </div>
        <div className="v5-metric">
          <div className="v5-metric-number indigo">{stats.totalDnsThreats}</div>
          <div className="v5-metric-label">DNS Threats</div>
        </div>
      </div>

      <hr className="v5-rule" />

      {/* Severity Dot Strip */}
      <div className="v5-severity-strip">
        {mockSeverityDistribution.map((s) => (
          <div className="v5-severity-item" key={s.severity as string}>
            <span className={`v5-severity-dot ${s.severity}`} />
            <span className="v5-severity-text">
              <span className="v5-severity-count">{s.count}</span>{' '}
              <span style={{ textTransform: 'capitalize' }}>{s.severity as string}</span>
            </span>
          </div>
        ))}
      </div>

      <hr className="v5-rule-thin" />

      {/* Thin-line Timeline */}
      <div style={{ marginBottom: 8 }}>
        <h2 className="v5-headline v5-headline-sm" style={{ marginBottom: 16 }}>
          Activity Timeline
        </h2>
        <div className="v5-chart-container">
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timelineData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#E7E5E4"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                tick={{ fill: '#78716C', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }}
                tickLine={false}
                axisLine={{ stroke: '#E7E5E4' }}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: '#78716C', fontSize: 11, fontFamily: 'IBM Plex Mono, monospace' }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip content={<TimelineTooltip />} />
              <Area
                type="monotone"
                dataKey="critical"
                stackId="1"
                stroke="#E54D2E"
                fill="#E54D2E"
                fillOpacity={0.15}
                strokeWidth={1.5}
              />
              <Area
                type="monotone"
                dataKey="high"
                stackId="1"
                stroke="#F97316"
                fill="#F97316"
                fillOpacity={0.1}
                strokeWidth={1}
              />
              <Area
                type="monotone"
                dataKey="medium"
                stackId="1"
                stroke="#EAB308"
                fill="#EAB308"
                fillOpacity={0.08}
                strokeWidth={1}
              />
              <Area
                type="monotone"
                dataKey="low"
                stackId="1"
                stroke="#4F46E5"
                fill="#4F46E5"
                fillOpacity={0.06}
                strokeWidth={1}
              />
              <Area
                type="monotone"
                dataKey="info"
                stackId="1"
                stroke="#A8A29E"
                fill="#A8A29E"
                fillOpacity={0.04}
                strokeWidth={0.5}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <hr className="v5-rule" />

      {/* Editorial Threat List */}
      <section>
        <h2 className="v5-headline v5-headline-md" style={{ marginBottom: 4 }}>
          Top Detections
        </h2>
        <p className="v5-subhead" style={{ marginBottom: 16 }}>
          Ranked by composite threat score
        </p>

        <div>
          {topAlerts.map((alert, i) => {
            const level = severityLevel(alert.score);
            return (
              <div className="v5-threat-item" key={i}>
                <div className={`v5-threat-score ${level}`}>{alert.score}</div>
                <div>
                  <div className="v5-threat-entity">{alert.entity}</div>
                  <div className="v5-threat-reason">{alert.reasons[0]}</div>
                  {alert.mitre_techniques.length > 0 && (
                    <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {alert.mitre_techniques.slice(0, 3).map((t) => (
                        <span key={t} className="v5-tag">{t}</span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="v5-threat-meta">
                  {format(new Date(alert.last_seen * 1000), 'MMM d, HH:mm')}
                  <br />
                  <span style={{ fontSize: 11 }}>{alert.occurrence_count} events</span>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
};

export default Dashboard;
