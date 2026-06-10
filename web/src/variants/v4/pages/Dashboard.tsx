/**
 * V4 Dashboard — Cyberpunk Neon Command Center
 * Oversized hero metrics with glow, asymmetric grid, neon gradient charts,
 * glow score bars, neon heatmap.
 */
import React, { useMemo } from 'react';
import {
  AlertTriangle,
  Radio,
  Globe,
  Target,
  Activity,
  Skull,
  Crosshair,
} from 'lucide-react';
import { format, parseISO, getHours } from 'date-fns';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  BarChart, Bar, Cell,
} from 'recharts';
import {
  mockDashboardStats,
  mockTimeline,
  mockSeverityDistribution,
  mockAlerts,
} from '../../../data/mockData';
import type { ThreatTimelinePoint } from '../../../types';

const stats = mockDashboardStats;

const severityNeonColor = (level: string): string => {
  const map: Record<string, string> = {
    critical: '#FF00FF', high: '#FF6600', medium: '#FFFF00',
    low: '#00FFFF', info: '#8878A8',
  };
  return map[level] || '#8878A8';
};

const scoreBarClass = (score: number): string => {
  if (score >= 85) return 'v4-score-bar-critical';
  if (score >= 65) return 'v4-score-bar-high';
  if (score >= 40) return 'v4-score-bar-medium';
  return 'v4-score-bar-low';
};

/* Custom neon tooltip */
const NeonTooltip: React.FC<{ active?: boolean; payload?: any[]; label?: string }> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(15, 10, 26, 0.95)', border: '1px solid rgba(0, 255, 255, 0.3)',
      padding: 12, fontFamily: 'Fira Code, monospace', fontSize: 11,
      boxShadow: '0 0 20px rgba(0, 255, 255, 0.15)',
      color: '#E0D8F0',
    }}>
      <p style={{ margin: '0 0 6px', color: '#00FFFF', fontFamily: 'Orbitron, sans-serif', fontSize: 10, letterSpacing: '0.1em' }}>
        {label}
      </p>
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ margin: '2px 0', color: p.color }}>
          {p.name}: {p.value}
        </p>
      ))}
    </div>
  );
};

/* Neon Heatmap */
const NeonHeatmap: React.FC<{ data: ThreatTimelinePoint[] }> = ({ data }) => {
  const { grid, maxVal, days } = useMemo(() => {
    const cells: { day: string; hour: number; value: number }[] = [];
    let max = 0;
    const daySet = new Set<string>();
    data.forEach((p) => {
      const d = parseISO(p.timestamp);
      const day = format(d, 'EEE');
      const hour = getHours(d);
      daySet.add(day);
      cells.push({ day, hour, value: p.total });
      if (p.total > max) max = p.total;
    });
    return { grid: cells, maxVal: max || 1, days: Array.from(daySet) };
  }, [data]);

  const cellColor = (value: number): string => {
    const t = value / maxVal;
    if (t > 0.8) return 'rgba(255, 0, 255, 0.9)';
    if (t > 0.6) return 'rgba(255, 102, 0, 0.8)';
    if (t > 0.4) return 'rgba(255, 255, 0, 0.6)';
    if (t > 0.2) return 'rgba(0, 255, 255, 0.4)';
    if (t > 0) return 'rgba(0, 255, 255, 0.15)';
    return 'rgba(255, 255, 255, 0.03)';
  };

  const cellGlow = (value: number): string => {
    const t = value / maxVal;
    if (t > 0.8) return '0 0 8px rgba(255, 0, 255, 0.6)';
    if (t > 0.6) return '0 0 6px rgba(255, 102, 0, 0.4)';
    if (t > 0.4) return '0 0 4px rgba(255, 255, 0, 0.3)';
    return 'none';
  };

  return (
    <div>
      <div style={{ display: 'flex', gap: 2 }}>
        {/* Hour labels */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, justifyContent: 'flex-start', paddingTop: 20 }}>
          {Array.from({ length: 24 }, (_, i) => (
            <div key={i} style={{
              height: 14, display: 'flex', alignItems: 'center',
              fontFamily: 'Fira Code, monospace', fontSize: 9, color: '#8878A8',
              paddingRight: 6, width: 26, justifyContent: 'flex-end',
            }}>
              {String(i).padStart(2, '0')}
            </div>
          ))}
        </div>
        {/* Grid */}
        <div>
          {/* Day headers */}
          <div style={{ display: 'flex', gap: 2, marginBottom: 4 }}>
            {days.map((d) => (
              <div key={d} style={{
                width: 14, textAlign: 'center',
                fontFamily: 'Orbitron, sans-serif', fontSize: 8, color: '#00FFFF',
                letterSpacing: '0.05em', textShadow: '0 0 4px rgba(0, 255, 255, 0.3)',
              }}>
                {d.charAt(0)}
              </div>
            ))}
          </div>
          {/* Cells */}
          {Array.from({ length: 24 }, (_, hour) => (
            <div key={hour} style={{ display: 'flex', gap: 2, marginBottom: 2 }}>
              {days.map((day) => {
                const cell = grid.find((c) => c.day === day && c.hour === hour);
                const val = cell?.value || 0;
                return (
                  <div
                    key={`${day}-${hour}`}
                    title={`${day} ${String(hour).padStart(2, '0')}:00 — ${val} threats`}
                    style={{
                      width: 14, height: 14, borderRadius: 1,
                      background: cellColor(val),
                      boxShadow: cellGlow(val),
                      transition: 'all 0.15s',
                      cursor: 'default',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.transform = 'scale(1.4)'; e.currentTarget.style.zIndex = '2'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.transform = 'scale(1)'; e.currentTarget.style.zIndex = '0'; }}
                  />
                );
              })}
            </div>
          ))}
        </div>
      </div>
      {/* Legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 12 }}>
        <span style={{ fontFamily: 'Fira Code, monospace', fontSize: 9, color: '#8878A8' }}>LOW</span>
        {[0.1, 0.3, 0.5, 0.7, 0.9].map((t) => (
          <div key={t} style={{
            width: 14, height: 14, borderRadius: 1,
            background: t > 0.8 ? 'rgba(255, 0, 255, 0.9)' : t > 0.6 ? 'rgba(255, 102, 0, 0.8)' : t > 0.4 ? 'rgba(255, 255, 0, 0.6)' : t > 0.2 ? 'rgba(0, 255, 255, 0.4)' : 'rgba(0, 255, 255, 0.15)',
          }} />
        ))}
        <span style={{ fontFamily: 'Fira Code, monospace', fontSize: 9, color: '#8878A8' }}>HIGH</span>
      </div>
    </div>
  );
};

const Dashboard: React.FC = () => {
  const topAlerts = useMemo(() =>
    [...mockAlerts].sort((a, b) => b.score - a.score).slice(0, 6),
    []
  );

  const timelineFormatted = useMemo(() =>
    mockTimeline.map((p) => ({
      ...p,
      label: format(parseISO(p.timestamp), 'HH:mm'),
    })),
    []
  );

  return (
    <div>
      {/* Page Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="v4-heading v4-heading-glow" style={{ fontSize: 26, margin: 0, display: 'flex', alignItems: 'center', gap: 12 }}>
          <Crosshair size={24} style={{ color: '#00FFFF', filter: 'drop-shadow(0 0 6px rgba(0, 255, 255, 0.5))' }} />
          THREAT COMMAND CENTER
        </h1>
        <p style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#8878A8', marginTop: 6 }}>
          SYSTEM.STATUS: <span style={{ color: '#39FF14', textShadow: '0 0 6px rgba(57, 255, 20, 0.4)' }}>ONLINE</span>
          {' · '}LAST_SYNC: {format(new Date(stats.lastUpdated), 'yyyy-MM-dd HH:mm:ss')}
        </p>
      </div>

      {/* Hero Metrics Row */}
      <div className="v4-grid v4-grid-hero" style={{ marginBottom: 24 }}>
        <div className="v4-card v4-card-glow-magenta">
          <div className="v4-hero-metric">
            <div className="v4-hero-value v4-hero-value-magenta">{stats.criticalAlerts}</div>
            <div className="v4-hero-label">
              <Skull size={12} style={{ verticalAlign: -1, marginRight: 4 }} />
              Critical Threats
            </div>
          </div>
        </div>
        <div className="v4-card v4-card-glow-cyan">
          <div className="v4-hero-metric">
            <div className="v4-hero-value v4-hero-value-cyan">{stats.totalAlerts}</div>
            <div className="v4-hero-label">
              <AlertTriangle size={12} style={{ verticalAlign: -1, marginRight: 4 }} />
              Total Detections
            </div>
          </div>
        </div>
        <div className="v4-card">
          <div className="v4-hero-metric">
            <div className="v4-hero-value v4-hero-value-orange">{stats.totalBeacons}</div>
            <div className="v4-hero-label">
              <Radio size={12} style={{ verticalAlign: -1, marginRight: 4 }} />
              Active Beacons
            </div>
          </div>
        </div>
        <div className="v4-card">
          <div className="v4-hero-metric">
            <div className="v4-hero-value v4-hero-value-green">{stats.totalDnsThreats}</div>
            <div className="v4-hero-label">
              <Globe size={12} style={{ verticalAlign: -1, marginRight: 4 }} />
              DNS Threats
            </div>
          </div>
        </div>
        <div className="v4-card">
          <div className="v4-hero-metric">
            <div className="v4-hero-value v4-hero-value-yellow">{stats.averageThreatScore.toFixed(0)}</div>
            <div className="v4-hero-label">
              <Activity size={12} style={{ verticalAlign: -1, marginRight: 4 }} />
              Avg Score
            </div>
          </div>
        </div>
      </div>

      {/* Asymmetric Grid: Timeline + Heatmap */}
      <div className="v4-grid v4-grid-asym" style={{ marginBottom: 20 }}>
        {/* Timeline Chart */}
        <div className="v4-card v4-card-glow-cyan">
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title">Threat Activity Stream</div>
              <div className="v4-card-subtitle">72-hour neon intensity map by severity</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={timelineFormatted} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="v4GradCritical" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FF00FF" stopOpacity={0.6} />
                  <stop offset="100%" stopColor="#FF00FF" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="v4GradHigh" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FF6600" stopOpacity={0.5} />
                  <stop offset="100%" stopColor="#FF6600" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="v4GradMedium" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FFFF00" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="#FFFF00" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="v4GradLow" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00FFFF" stopOpacity={0.3} />
                  <stop offset="100%" stopColor="#00FFFF" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="v4GradInfo" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#8878A8" stopOpacity={0.2} />
                  <stop offset="100%" stopColor="#8878A8" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 0, 255, 0.06)" />
              <XAxis dataKey="label" tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 9 }} axisLine={{ stroke: 'rgba(255, 0, 255, 0.15)' }} tickLine={false} interval={5} />
              <YAxis tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 9 }} axisLine={{ stroke: 'rgba(255, 0, 255, 0.15)' }} tickLine={false} />
              <Tooltip content={<NeonTooltip />} />
              <Area type="monotone" dataKey="critical" stackId="1" stroke="#FF00FF" fill="url(#v4GradCritical)" strokeWidth={2} name="Critical" />
              <Area type="monotone" dataKey="high" stackId="1" stroke="#FF6600" fill="url(#v4GradHigh)" strokeWidth={1.5} name="High" />
              <Area type="monotone" dataKey="medium" stackId="1" stroke="#FFFF00" fill="url(#v4GradMedium)" strokeWidth={1} name="Medium" />
              <Area type="monotone" dataKey="low" stackId="1" stroke="#00FFFF" fill="url(#v4GradLow)" strokeWidth={1} name="Low" />
              <Area type="monotone" dataKey="info" stackId="1" stroke="#8878A8" fill="url(#v4GradInfo)" strokeWidth={1} name="Info" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Heatmap */}
        <div className="v4-card v4-card-glow-magenta">
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title" style={{ color: '#FF00FF', textShadow: '0 0 8px rgba(255, 0, 255, 0.3)' }}>
                Threat Heatmap
              </div>
              <div className="v4-card-subtitle">Activity by hour × day</div>
            </div>
          </div>
          <NeonHeatmap data={mockTimeline} />
        </div>
      </div>

      {/* Severity Distribution + Score Bars */}
      <div className="v4-grid v4-grid-asym-reverse" style={{ marginBottom: 20 }}>
        {/* Severity Bars */}
        <div className="v4-card">
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title">Severity Distribution</div>
              <div className="v4-card-subtitle">Neon intensity by threat level</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart
              data={mockSeverityDistribution.map((d) => ({
                name: d.severity,
                count: d.count,
                color: severityNeonColor(d.severity as string),
              }))}
              margin={{ top: 10, right: 10, left: -10, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 0, 255, 0.06)" />
              <XAxis dataKey="name" tick={{ fill: '#8878A8', fontFamily: 'Orbitron', fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 9 }} axisLine={false} tickLine={false} />
              <Tooltip content={<NeonTooltip />} />
              <Bar dataKey="count" name="Count" radius={[2, 2, 0, 0]}>
                {mockSeverityDistribution.map((d, i) => (
                  <Cell key={i} fill={severityNeonColor(d.severity as string)} fillOpacity={0.8} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Score Bars for top alerts */}
        <div className="v4-card v4-card-glow-cyan">
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title">Top Threat Scores</div>
              <div className="v4-card-subtitle">Neon glow intensity = danger level</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {topAlerts.map((a, i) => (
              <div key={i}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span className="v4-data" style={{ fontSize: 12, color: '#E0D8F0' }}>{a.entity}</span>
                  <span className="v4-data" style={{ fontSize: 12, fontWeight: 700, color: severityNeonColor(a.level as string), textShadow: `0 0 6px ${severityNeonColor(a.level as string)}60` }}>
                    {a.score}
                  </span>
                </div>
                <div className={`v4-score-bar ${scoreBarClass(a.score)}`}>
                  <div className="v4-score-bar-fill" style={{ width: `${a.score}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bottom Row: MITRE Techniques + Recent Critical */}
      <div className="v4-grid v4-grid-asym" style={{ marginBottom: 20 }}>
        {/* MITRE Techniques */}
        <div className="v4-card">
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title">
                <Target size={14} style={{ verticalAlign: -2, marginRight: 6 }} />
                MITRE ATT&CK Coverage
              </div>
              <div className="v4-card-subtitle">Detected technique frequency</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {stats.topMitreTechniques.map((t) => (
              <div
                key={t.technique}
                style={{
                  padding: '8px 14px',
                  background: 'rgba(255, 0, 255, 0.06)',
                  border: '1px solid rgba(255, 0, 255, 0.2)',
                  borderRadius: 2,
                  fontFamily: "'Fira Code', monospace",
                  fontSize: 11,
                  transition: 'all 0.2s',
                  cursor: 'default',
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(255, 0, 255, 0.5)';
                  e.currentTarget.style.boxShadow = '0 0 15px rgba(255, 0, 255, 0.2)';
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.borderColor = 'rgba(255, 0, 255, 0.2)';
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <span style={{ color: '#FF00FF', textShadow: '0 0 4px rgba(255, 0, 255, 0.4)' }}>{t.technique}</span>
                <span style={{ color: '#8878A8', marginLeft: 8 }}>×{t.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Critical Alerts */}
        <div className="v4-card v4-card-glow-magenta">
          <div className="v4-card-header">
            <div>
              <div className="v4-card-title" style={{ color: '#FF00FF', textShadow: '0 0 8px rgba(255, 0, 255, 0.3)' }}>
                <Skull size={14} style={{ verticalAlign: -2, marginRight: 6 }} />
                Critical Signals
              </div>
              <div className="v4-card-subtitle">Immediate action required</div>
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {mockAlerts
              .filter((a) => a.level === ('critical' as any))
              .slice(0, 4)
              .map((a, i) => (
                <div
                  key={i}
                  className="v4-angular-card"
                  style={{
                    padding: 14,
                    borderColor: 'rgba(255, 0, 255, 0.25)',
                    borderLeft: '3px solid #FF00FF',
                    boxShadow: 'inset 0 0 20px rgba(255, 0, 255, 0.05)',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span className="v4-data" style={{ fontSize: 13, fontWeight: 600, color: '#E0D8F0' }}>
                      {a.entity}
                    </span>
                    <span className="v4-data" style={{
                      fontSize: 14, fontWeight: 700, color: '#FF00FF',
                      textShadow: '0 0 10px rgba(255, 0, 255, 0.6)',
                    }}>
                      {a.score}
                    </span>
                  </div>
                  <p style={{ fontSize: 12, color: '#8878A8', margin: 0, lineHeight: 1.4 }}>
                    {a.reasons[0]}
                  </p>
                  <div style={{ marginTop: 8, display: 'flex', gap: 4 }}>
                    {a.mitre_techniques.slice(0, 2).map((t) => (
                      <span key={t} className="v4-tag">{t}</span>
                    ))}
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
