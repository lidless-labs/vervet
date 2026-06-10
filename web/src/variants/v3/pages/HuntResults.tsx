/**
 * V3 Hunt Results — Professional report with collapsible sections, print-friendly.
 */
import React, { useState } from 'react';
import {
  ChevronDown,
  ChevronRight,
  Printer,
  FileText,
  Shield,
  Target,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Info,
  ExternalLink,
} from 'lucide-react';
import { format } from 'date-fns';
import {
  mockAlerts,
  mockIndicators,
  mockMitreMappings,
  mockDashboardStats,
  mockBeacons,
  mockDnsThreats,
} from '../../../data/mockData';
import type { ThreatIndicator } from '../../../types';
import AddToCase from '../../../components/AddToCase';

interface CollapsibleProps {
  title: string;
  icon: React.ReactNode;
  defaultOpen?: boolean;
  badge?: string | number;
  children: React.ReactNode;
}

const Collapsible: React.FC<CollapsibleProps> = ({ title, icon, defaultOpen = true, badge, children }) => {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ marginBottom: 16 }}>
      <div
        className="v3-collapsible-header"
        onClick={() => setOpen(!open)}
      >
        <h3>
          {icon} {title}
          {badge !== undefined && (
            <span style={{
              background: 'rgba(37, 99, 235, 0.1)', color: '#2563EB',
              padding: '2px 8px', borderRadius: 9999, fontSize: 11, fontWeight: 600, marginLeft: 8,
            }}>
              {badge}
            </span>
          )}
        </h3>
        {open ? <ChevronDown size={16} style={{ color: '#64748B' }} /> : <ChevronRight size={16} style={{ color: '#64748B' }} />}
      </div>
      {open && <div className="v3-collapsible-body">{children}</div>}
    </div>
  );
};

const IndicatorRow: React.FC<{ indicator: ThreatIndicator }> = ({ indicator }) => (
  <tr>
    <td>
      <span className={`v3-badge ${indicator.severity}`}>{indicator.severity}</span>
    </td>
    <td>
      <span style={{
        display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11,
        background: '#F1F5F9', color: '#475569', fontWeight: 500,
      }}>
        {indicator.indicator_type}
      </span>
    </td>
    <td className="mono" style={{ fontWeight: 500 }}>{indicator.value}</td>
    <td style={{ color: '#64748B', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
      {indicator.description}
    </td>
    <td style={{ color: '#64748B', fontSize: 12 }}>{indicator.source}</td>
  </tr>
);

const HuntResults: React.FC = () => {
  const stats = mockDashboardStats;
  const criticalAlerts = mockAlerts.filter((a) => a.level === ('critical' as any));
  const topBeacons = [...mockBeacons].sort((a, b) => b.beacon_score - a.beacon_score).slice(0, 5);
  const topDns = [...mockDnsThreats].sort((a, b) => b.score - a.score).slice(0, 5);

  const recommendations = [
    'Immediately isolate hosts 198.19.1.15 and 198.19.2.5 — confirmed C2 beacon and DNS exfiltration activity.',
    'Block outbound connections to 185.220.101.34 and 91.219.236.222 at the firewall level.',
    'Investigate DGA patterns from 198.18.160.10 — possible Emotet variant infection.',
    'Review SSL certificates on port 443 connections to 198.98.56.78 — certificate CN mismatch detected.',
    'Deploy additional monitoring for DNS TXT record queries from the 198.19.2.0/24 subnet.',
    'Escalate Tor exit node communications from 198.19.3.8 to incident response team.',
    'Update threat intelligence feeds to include newly discovered C2 domains.',
    'Schedule full forensic analysis of hosts with beacon scores ≥ 90.',
  ];

  return (
    <div>
      {/* Report Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 24 }}>
        <div>
          <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Threat Hunt Report</h1>
          <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
            Comprehensive analysis results · Generated {format(new Date(), 'MMMM d, yyyy HH:mm')}
          </p>
        </div>
        <button className="v3-btn v3-btn-outline" onClick={() => window.print()}>
          <Printer size={14} />
          Print Report
        </button>
      </div>

      {/* Executive Summary */}
      <Collapsible title="Executive Summary" icon={<FileText size={16} />} defaultOpen={true}>
        <div style={{ marginBottom: 16 }}>
          <p style={{ fontSize: 14, color: '#1E293B', lineHeight: 1.6, margin: 0 }}>
            This hunt analyzed network traffic over a 72-hour period, examining{' '}
            <strong>{stats.totalAlerts} threat detections</strong> across{' '}
            <strong>{stats.uniqueSourceIPs} unique source IPs</strong> communicating with{' '}
            <strong>{stats.uniqueDestIPs} external destinations</strong>. The analysis identified{' '}
            <strong style={{ color: '#DC2626' }}>{stats.criticalAlerts} critical</strong> and{' '}
            <strong style={{ color: '#EA580C' }}>{stats.highAlerts} high-severity</strong> threats
            requiring immediate attention, with an average threat score of{' '}
            <strong>{stats.averageThreatScore.toFixed(1)}</strong>.
          </p>
        </div>

        {/* Quick stats grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
          {[
            { label: 'Total Alerts', value: stats.totalAlerts, color: '#2563EB' },
            { label: 'Critical', value: stats.criticalAlerts, color: '#DC2626' },
            { label: 'High', value: stats.highAlerts, color: '#EA580C' },
            { label: 'Beacons', value: stats.totalBeacons, color: '#7C3AED' },
            { label: 'DNS Threats', value: stats.totalDnsThreats, color: '#0891B2' },
            { label: 'MITRE Techniques', value: stats.topMitreTechniques.length, color: '#16A34A' },
          ].map((s) => (
            <div key={s.label} style={{
              padding: '12px 14px', background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0',
              textAlign: 'center',
            }}>
              <div style={{ fontFamily: 'Outfit, sans-serif', fontWeight: 700, fontSize: 22, color: s.color }}>{s.value}</div>
              <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>{s.label}</div>
            </div>
          ))}
        </div>
      </Collapsible>

      {/* Critical Findings */}
      <Collapsible title="Critical Findings" icon={<AlertTriangle size={16} />} badge={criticalAlerts.length}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {criticalAlerts.map((a, i) => (
            <div key={i} style={{
              padding: '14px 16px', border: '1px solid rgba(220, 38, 38, 0.15)', borderRadius: 6,
              background: 'rgba(220, 38, 38, 0.03)', borderLeft: '3px solid #DC2626',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span className="v3-data" style={{ fontSize: 14, fontWeight: 600, color: '#1E293B' }}>{a.entity}</span>
                <span className="v3-data" style={{ fontSize: 14, fontWeight: 700, color: '#DC2626' }}>{a.score}</span>
              </div>
              <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                {a.reasons.map((r, j) => (
                  <li key={j} style={{ fontSize: 13, color: '#475569', marginBottom: 3 }}>• {r}</li>
                ))}
              </ul>
              <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                {a.mitre_techniques.map((t) => (
                  <span key={t} className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>{t}</span>
                ))}
                <AddToCase
                  findingType="rule_match"
                  summary={`Hunt result finding: ${a.entity}`}
                  severity={a.level as string}
                  data={{ entity: a.entity, score: a.score, mitre_techniques: a.mitre_techniques, reasons: a.reasons }}
                />
              </div>
            </div>
          ))}
        </div>
      </Collapsible>

      {/* Indicators of Compromise */}
      <Collapsible title="Indicators of Compromise" icon={<Shield size={16} />} badge={mockIndicators.length}>
        <div className="v3-table-wrapper">
          <table className="v3-table">
            <thead>
              <tr>
                <th style={{ width: 80 }}>Severity</th>
                <th style={{ width: 100 }}>Type</th>
                <th>Value</th>
                <th>Description</th>
                <th style={{ width: 120 }}>Source</th>
              </tr>
            </thead>
            <tbody>
              {mockIndicators.map((ind, i) => (
                <IndicatorRow key={i} indicator={ind} />
              ))}
            </tbody>
          </table>
        </div>
      </Collapsible>

      {/* Top Beacons */}
      <Collapsible title="Top Beacon Detections" icon={<Target size={16} />} badge={topBeacons.length} defaultOpen={false}>
        <div className="v3-table-wrapper">
          <table className="v3-table">
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Destination</th>
                <th style={{ width: 70 }}>Score</th>
                <th style={{ width: 90 }}>Interval</th>
                <th style={{ width: 80 }}>Jitter</th>
                <th style={{ width: 90 }}>Connections</th>
              </tr>
            </thead>
            <tbody>
              {topBeacons.map((b) => (
                <tr key={b.id}>
                  <td className="mono">{b.src_ip}</td>
                  <td className="mono">{b.dst_ip}:{b.dst_port}</td>
                  <td>
                    <span className="v3-score-badge" style={{
                      background: b.beacon_score >= 85 ? 'rgba(220, 38, 38, 0.08)' : b.beacon_score >= 65 ? 'rgba(234, 88, 12, 0.08)' : 'rgba(22, 163, 74, 0.08)',
                      color: b.beacon_score >= 85 ? '#DC2626' : b.beacon_score >= 65 ? '#EA580C' : '#16A34A',
                    }}>
                      {b.beacon_score}
                    </span>
                  </td>
                  <td className="mono" style={{ color: '#64748B' }}>{b.avg_interval_seconds}s</td>
                  <td className="mono" style={{ color: '#64748B' }}>{b.jitter_pct.toFixed(1)}%</td>
                  <td className="mono" style={{ color: '#64748B' }}>{b.connection_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Collapsible>

      {/* Top DNS Threats */}
      <Collapsible title="Top DNS Threats" icon={<Info size={16} />} badge={topDns.length} defaultOpen={false}>
        <div className="v3-table-wrapper">
          <table className="v3-table">
            <thead>
              <tr>
                <th>Type</th>
                <th>Domain</th>
                <th>Source IP</th>
                <th style={{ width: 70 }}>Score</th>
                <th style={{ width: 90 }}>Queries</th>
              </tr>
            </thead>
            <tbody>
              {topDns.map((t) => (
                <tr key={t.id}>
                  <td>
                    <span style={{
                      display: 'inline-block', fontSize: 11, fontWeight: 600, padding: '2px 8px',
                      borderRadius: 9999,
                      background: t.threat_type === 'tunneling' ? 'rgba(220, 38, 38, 0.08)' : t.threat_type === 'dga' ? 'rgba(234, 88, 12, 0.08)' : 'rgba(37, 99, 235, 0.08)',
                      color: t.threat_type === 'tunneling' ? '#DC2626' : t.threat_type === 'dga' ? '#EA580C' : '#2563EB',
                    }}>
                      {t.threat_type.replace('_', ' ')}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{t.domain}</td>
                  <td className="mono" style={{ color: '#64748B' }}>{t.src_ip}</td>
                  <td>
                    <span className="v3-score-badge" style={{
                      background: t.score >= 85 ? 'rgba(220, 38, 38, 0.08)' : t.score >= 65 ? 'rgba(234, 88, 12, 0.08)' : 'rgba(22, 163, 74, 0.08)',
                      color: t.score >= 85 ? '#DC2626' : t.score >= 65 ? '#EA580C' : '#16A34A',
                    }}>
                      {t.score}
                    </span>
                  </td>
                  <td className="mono" style={{ color: '#64748B' }}>{t.query_count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Collapsible>

      {/* MITRE ATT&CK Coverage */}
      <Collapsible title="MITRE ATT&CK Coverage" icon={<Target size={16} />} badge={mockMitreMappings.length} defaultOpen={false}>
        <div className="v3-mitre-grid">
          {mockMitreMappings.map((m) => (
            <div key={m.technique_id} className="v3-mitre-cell">
              <div className="v3-mitre-cell-id">
                <a
                  href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`}
                  target="_blank" rel="noopener noreferrer"
                  style={{ color: '#2563EB', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 3 }}
                >
                  {m.technique_id} <ExternalLink size={9} />
                </a>
              </div>
              <div className="v3-mitre-cell-name">{m.technique_name}</div>
              <div className="v3-mitre-cell-meta">
                {m.tactic.replace(/-/g, ' ')} · {m.detection_count} detections
              </div>
              <div className="v3-mitre-cell-meta">
                Confidence: {(m.confidence * 100).toFixed(0)}% · {m.affected_hosts.length} hosts
              </div>
            </div>
          ))}
        </div>
      </Collapsible>

      {/* Recommendations */}
      <Collapsible title="Recommendations" icon={<CheckCircle2 size={16} />} badge={recommendations.length}>
        <ol style={{ margin: 0, padding: '0 0 0 20px' }}>
          {recommendations.map((r, i) => (
            <li key={i} style={{
              fontSize: 13, color: '#1E293B', lineHeight: 1.6, marginBottom: 8,
              paddingLeft: 4,
            }}>
              {r}
            </li>
          ))}
        </ol>
      </Collapsible>

      {/* Report Footer */}
      <div style={{
        marginTop: 24, padding: '16px 20px', background: '#F8FAFC', borderRadius: 8,
        border: '1px solid #E2E8F0', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <div>
          <div style={{ fontSize: 12, color: '#64748B' }}>
            <Clock size={12} style={{ verticalAlign: -1, marginRight: 4 }} />
            Report generated {format(new Date(), 'MMMM d, yyyy HH:mm:ss')}
          </div>
          <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 4 }}>
            Vervet — Corporate SOC Edition · Automated Threat Hunt Analysis
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="v3-btn v3-btn-outline" onClick={() => window.print()}>
            <Printer size={14} /> Print
          </button>
        </div>
      </div>
    </div>
  );
};

export default HuntResults;
