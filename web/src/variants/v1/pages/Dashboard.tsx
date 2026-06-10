/**
 * V1 Dashboard — Dense, data-first NOC overview.
 * 4-column stat cards, ThreatTimeline, SeverityDonut, top threats, recent alerts.
 */
import React, { useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Radio,
  Globe,
  Activity,
  Target,
  TrendingUp,
  Eye,
} from 'lucide-react';
import { format } from 'date-fns';
import { StatCard, PcapUpload } from '../../../components/data';
import { ThreatTimeline, SeverityDonut, ThreatHeatmap } from '../../../components/charts';
import { AlertCard } from '../../../components/data';
import {
  mockDashboardStats,
  mockAlerts,
  mockTimeline,
  mockSeverityDistribution,
} from '../../../data/mockData';
import type { ChartTheme } from '../../../types';

/** V1 chart theme tuned for the NOC palette */
const v1Theme: ChartTheme = {
  colors: {
    primary: '#06B6D4',
    secondary: '#8B5CF6',
    accent: '#F59E0B',
    danger: '#EF4444',
    warning: '#F59E0B',
    success: '#22C55E',
    info: '#3B82F6',
    background: '#0B1426',
    surface: '#162035',
    text: '#E2E8F0',
    textSecondary: '#94A3B8',
    gridLine: '#1E293B',
    series: ['#06B6D4', '#8B5CF6', '#F59E0B', '#EF4444', '#22C55E', '#3B82F6', '#EC4899', '#14B8A6'],
  },
  fonts: {
    family: "'Barlow Condensed', sans-serif",
    monoFamily: "'JetBrains Mono', monospace",
    sizeSmall: 10,
    sizeBase: 12,
    sizeLarge: 14,
  },
  spacing: {
    chartPadding: 16,
    legendGap: 10,
    tooltipPadding: 8,
  },
};

function scoreClass(score: number): string {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

const Dashboard: React.FC = () => {
  const stats = mockDashboardStats;

  const topThreats = useMemo(
    () =>
      [...mockAlerts]
        .sort((a, b) => b.score - a.score)
        .slice(0, 8),
    [],
  );

  const recentAlerts = useMemo(
    () =>
      [...mockAlerts]
        .sort((a, b) => b.last_seen - a.last_seen)
        .slice(0, 5),
    [],
  );

  const topMitre = useMemo(
    () => stats.topMitreTechniques.slice(0, 8),
    [stats],
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Stat Cards Row */}
      <div className="v1-stat-grid">
        <StatCard
          icon={<ShieldAlert size={20} />}
          label="Critical Alerts"
          value={stats.criticalAlerts}
          trend={stats.alertsTrend}
          trendLabel="24h"
          color="text-red-400"
        />
        <StatCard
          icon={<AlertTriangle size={20} />}
          label="Total Threats"
          value={stats.totalAlerts}
          trend={8.2}
          trendLabel="24h"
          color="text-amber-400"
        />
        <StatCard
          icon={<Radio size={20} />}
          label="Active Beacons"
          value={stats.totalBeacons}
          color="text-orange-400"
        />
        <StatCard
          icon={<Globe size={20} />}
          label="DNS Threats"
          value={stats.totalDnsThreats}
          color="text-cyan-400"
        />
      </div>

      {/* Main Grid */}
      <div className="v1-dashboard-grid">
        {/* Threat Timeline — spans 3 cols */}
        <div className="v1-panel span-3">
          <div className="v1-panel-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Activity size={14} />
              Threat Timeline (72h)
            </span>
          </div>
          <div className="v1-panel-body">
            <ThreatTimeline
              data={mockTimeline}
              theme={v1Theme}
              height={220}
              showLegend={true}
            />
          </div>
        </div>

        {/* Recent Alerts — right column, row-span 2 */}
        <div className="v1-panel row-span-2">
          <div className="v1-panel-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Eye size={14} />
              Recent Alerts
            </span>
          </div>
          <div className="v1-panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 520, overflowY: 'auto' }}>
            {recentAlerts.map((alert) => (
              <AlertCard key={`${alert.entity}-${alert.last_seen}`} alert={alert} compact />
            ))}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="v1-panel">
          <div className="v1-panel-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={14} />
              Severity Distribution
            </span>
          </div>
          <div className="v1-panel-body">
            <SeverityDonut
              data={mockSeverityDistribution}
              theme={v1Theme}
              height={200}
              innerRadius={45}
              outerRadius={80}
              showLegend={false}
            />
          </div>
        </div>

        {/* Top MITRE Techniques */}
        <div className="v1-panel span-2">
          <div className="v1-panel-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={14} />
              Top MITRE ATT&CK Techniques
            </span>
          </div>
          <div className="v1-panel-body" style={{ padding: '8px 14px' }}>
            {topMitre.map((t) => {
              const maxCount = topMitre[0]?.count || 1;
              const pct = (t.count / maxCount) * 100;
              return (
                <div key={t.technique} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span className="v1-mitre-tag" style={{ minWidth: 72, justifyContent: 'center' }}>{t.technique}</span>
                  <div style={{ flex: 1, height: 6, background: 'rgba(6,182,212,0.08)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: '#06B6D4', borderRadius: 3, transition: 'width 0.3s ease' }} />
                  </div>
                  <span style={{ fontSize: 11, fontWeight: 600, color: '#94A3B8', minWidth: 24, textAlign: 'right' }}>{t.count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Threat Heatmap — full width span 3 */}
        <div className="v1-panel span-3">
          <div className="v1-panel-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <TrendingUp size={14} />
              Activity Heatmap
            </span>
          </div>
          <div className="v1-panel-body" style={{ overflowX: 'auto' }}>
            <ThreatHeatmap data={mockTimeline} theme={v1Theme} cellSize={24} />
          </div>
        </div>

        {/* Top Threats Table — right column */}
        <div className="v1-panel">
          <div className="v1-panel-header">
            <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <ShieldAlert size={14} />
              Top Scores
            </span>
          </div>
          <div className="v1-panel-body-flush">
            <table style={{ width: '100%', fontSize: 11 }}>
              <tbody>
                {topThreats.map((t, i) => (
                  <tr
                    key={`${t.entity}-${i}`}
                    style={{ borderBottom: '1px solid rgba(6,182,212,0.08)' }}
                  >
                    <td style={{ padding: '6px 12px', fontFamily: "'JetBrains Mono', monospace", color: '#94A3B8', whiteSpace: 'nowrap' }}>
                      {t.entity}
                    </td>
                    <td style={{ padding: '6px 8px', textAlign: 'right' }}>
                      <span className={`v1-sev-pill ${t.level}`}>
                        {t.level}
                      </span>
                    </td>
                    <td style={{ padding: '6px 12px', textAlign: 'right' }}>
                      <span className={`v1-score-inline ${scoreClass(t.score)}`}>
                        {t.score}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="v1-panel">
        <div className="v1-panel-header">PCAP Ingestion</div>
        <div className="v1-panel-body">
          <PcapUpload />
        </div>
      </div>

      {/* Footer stats */}
      <div style={{ display: 'flex', gap: 24, fontSize: 11, color: '#64748B', padding: '4px 0' }}>
        <span>Unique Source IPs: <strong style={{ color: '#94A3B8' }}>{stats.uniqueSourceIPs}</strong></span>
        <span>Unique Dest IPs: <strong style={{ color: '#94A3B8' }}>{stats.uniqueDestIPs}</strong></span>
        <span>Avg Score: <strong style={{ color: '#94A3B8' }}>{stats.averageThreatScore.toFixed(1)}</strong></span>
        <span>Updated: <strong style={{ color: '#94A3B8' }}>{format(new Date(stats.lastUpdated), 'HH:mm:ss')}</strong></span>
      </div>
    </div>
  );
};

export default Dashboard;
