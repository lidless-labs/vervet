/**
 * V2 Dashboard — System report style terminal output.
 * key=value stats, green line chart, log-style alert ticker.
 */
import React, { useMemo } from 'react';
import { format } from 'date-fns';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
} from 'recharts';
import { useDashboardStats, useTimeline, useAlerts } from '../../../hooks/useApi';
import {
  mockDashboardStats,
  mockTimeline,
  mockAlerts,
} from '../../../data/mockData';
import type { ThreatScore } from '../../../types';

/* ═══ Panel wrapper ═══ */
const Panel: React.FC<{ title: string; pid?: number; children: React.ReactNode }> = ({
  title,
  pid,
  children,
}) => (
  <div className="v2-panel">
    <div className="v2-panel-header">
      <span>
        [{title} - pid:{pid ?? Math.floor(Math.random() * 9000 + 1000)}]
      </span>
      <div className="v2-panel-dots">
        <span className="v2-panel-dot red" />
        <span className="v2-panel-dot amber" />
        <span className="v2-panel-dot green" />
      </div>
    </div>
    <div className="v2-panel-body">{children}</div>
  </div>
);

/* ═══ Stat line ═══ */
const Stat: React.FC<{ k: string; v: string | number; cls?: string }> = ({ k, v, cls }) => (
  <div className="v2-stat-line">
    <span className="v2-stat-key">{k}</span>
    <span className="v2-stat-eq">=</span>
    <span className={`v2-stat-value ${cls ?? ''}`}>{v}</span>
  </div>
);

/* ═══ Log line for alert ticker ═══ */
const AlertLogLine: React.FC<{ alert: ThreatScore }> = ({ alert }) => {
  const ts = format(new Date(alert.last_seen * 1000), 'HH:mm:ss');
  return (
    <div className="v2-log-line">
      <span className="v2-log-ts">{ts}</span>
      <span className={`v2-log-level ${alert.level}`}>{alert.level}</span>
      <span className="v2-log-msg">
        <span className="v2-log-entity">{alert.entity}</span>
        {' → '}
        {alert.reasons[0]}
        <span className="v2-dim"> [{alert.mitre_techniques.join(', ')}]</span>
      </span>
    </div>
  );
};

const Dashboard: React.FC = () => {
  const { data: stats } = useDashboardStats();
  const { data: timeline } = useTimeline();
  const { data: alerts } = useAlerts();

  const s = stats ?? mockDashboardStats;
  const tl = timeline ?? mockTimeline;
  const al = alerts ?? mockAlerts;

  /* prepare chart data */
  const chartData = useMemo(
    () =>
      tl.map((p) => ({
        label: format(new Date(p.timestamp), 'HH:mm'),
        total: p.total,
        critical: p.critical,
      })),
    [tl],
  );

  /* recent alerts sorted by last_seen desc */
  const recentAlerts = useMemo(
    () => [...al].sort((a, b) => b.last_seen - a.last_seen).slice(0, 20),
    [al],
  );

  return (
    <>
      {/* SYSTEM REPORT HEADER */}
      <div className="v2-heading">
        ╔═ SYSTEM REPORT ═══════════════════════════════════════╗
      </div>

      {/* KEY=VALUE STATS */}
      <Panel title="THREAT_STATS" pid={4201}>
        <div className="v2-stats-grid">
          <Stat k="total_alerts" v={s.totalAlerts} />
          <Stat k="critical" v={s.criticalAlerts} cls="critical" />
          <Stat k="high" v={s.highAlerts} cls="critical" />
          <Stat k="medium" v={s.mediumAlerts} cls="amber" />
          <Stat k="low" v={s.lowAlerts} cls="green" />
          <Stat k="info" v={s.infoAlerts} />
          <Stat k="total_beacons" v={s.totalBeacons} cls={s.totalBeacons > 20 ? 'critical' : 'amber'} />
          <Stat k="dns_threats" v={s.totalDnsThreats} cls={s.totalDnsThreats > 25 ? 'critical' : 'amber'} />
          <Stat k="unique_src_ips" v={s.uniqueSourceIPs} />
          <Stat k="unique_dst_ips" v={s.uniqueDestIPs} />
          <Stat k="avg_threat_score" v={s.averageThreatScore.toFixed(1)} cls="amber" />
          <Stat k="trend" v={`${s.alertsTrend > 0 ? '+' : ''}${s.alertsTrend}%`} cls={s.alertsTrend > 0 ? 'critical' : 'green'} />
        </div>

        <div className="v2-divider" />

        <div className="v2-heading-section">top mitre techniques</div>
        {s.topMitreTechniques.slice(0, 6).map((t) => (
          <div key={t.technique} className="v2-stat-line">
            <span className="v2-amber" style={{ minWidth: 90 }}>{t.technique}</span>
            <span className="v2-dim" style={{ margin: '0 6px' }}>│</span>
            <span className="v2-green v2-bold">{t.count}</span>
            <span className="v2-dim" style={{ marginLeft: 8 }}>
              {'█'.repeat(Math.min(t.count, 20))}
            </span>
          </div>
        ))}
      </Panel>

      {/* THREAT TIMELINE — green line chart */}
      <Panel title="THREAT_TIMELINE" pid={4202}>
        <div className="v2-chart-container">
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={chartData} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="#0A3D0A"
                strokeOpacity={0.4}
                vertical={false}
              />
              <XAxis
                dataKey="label"
                tick={{ fill: '#0A3D0A', fontSize: 10, fontFamily: 'Fira Code' }}
                tickLine={false}
                axisLine={{ stroke: '#0A3D0A' }}
                interval="preserveStartEnd"
              />
              <YAxis
                tick={{ fill: '#0A3D0A', fontSize: 10, fontFamily: 'Fira Code' }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#000',
                  border: '1px solid #0A3D0A',
                  color: '#00FF41',
                  fontFamily: 'Fira Code',
                  fontSize: 11,
                }}
                labelStyle={{ color: '#FFB000' }}
              />
              <Line
                type="monotone"
                dataKey="total"
                stroke="#00FF41"
                strokeWidth={1.5}
                dot={false}
                activeDot={{ r: 3, fill: '#00FF41', stroke: '#000' }}
              />
              <Line
                type="monotone"
                dataKey="critical"
                stroke="#FF0040"
                strokeWidth={1}
                dot={false}
                strokeDasharray="4 3"
                activeDot={{ r: 3, fill: '#FF0040', stroke: '#000' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      {/* ALERT TICKER — log-style */}
      <Panel title="ALERT_FEED" pid={4203}>
        <div style={{ maxHeight: 400, overflowY: 'auto' }}>
          {recentAlerts.map((a, i) => (
            <AlertLogLine key={`${a.entity}-${i}`} alert={a} />
          ))}
        </div>
      </Panel>

      <div className="v2-dim" style={{ fontSize: 10, textAlign: 'right', paddingTop: 4 }}>
        last_updated={s.lastUpdated ? format(new Date(s.lastUpdated), 'yyyy-MM-dd HH:mm:ss') : 'N/A'} | render=v2_terminal
      </div>
    </>
  );
};

export default Dashboard;
