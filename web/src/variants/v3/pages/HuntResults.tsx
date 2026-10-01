/**
 * V3 Hunt Results — Professional report with collapsible sections, print-friendly.
 */
import React, { useEffect, useMemo, useState } from 'react';
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
import LoadingSkeleton from '../../../components/LoadingSkeleton';
import AddToCase from '../../../components/AddToCase';

const API_BASE = import.meta.env.VITE_API_BASE || '';

// --- Local response shapes for the real backend ---------------------------

interface StatsResponse {
  total_hosts: number;
  threat_level_distribution: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  detections: {
    beacons: number;
    dns_threats: number;
    ids_alerts: number;
    long_connections: number;
    total: number;
  };
  mitre: {
    techniques_observed: number;
    tactics_observed: number;
  };
}

interface Threat {
  entity: string;
  score: number; // 0..1
  level: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number; // 0..1
  reasons: string[];
  indicators_count: number;
  mitre_techniques_count: number;
  first_seen: number;
  last_seen: number;
}

interface Indicator {
  severity: string;
  indicator_type: string;
  value: string;
  description?: string;
  source?: string;
}

interface Beacon {
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  connection_count: number;
  avg_interval_seconds: number;
  jitter_pct: number;
  beacon_score: number; // 0..100
}

interface DnsDetection {
  domain: string | null;
  src_ip: string;
  query_count: number;
  tunneling_score?: number; // 0..100
  dga_score?: number; // 0..100
  fast_flux_score?: number; // 0..100
}

interface DnsThreatsResponse {
  summary?: {
    top_tunneling?: DnsDetection[];
    top_dga?: DnsDetection[];
    top_fast_flux?: DnsDetection[];
  };
}

interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number; // 0..1
  detection_count: number;
  affected_hosts: string[];
}

// Row shape used by the DNS table (normalised across the three detection kinds).
interface DnsRow {
  threat_type: 'tunneling' | 'dga' | 'fast_flux';
  domain: string;
  src_ip: string;
  score: number; // 0..100
  query_count: number;
}

const HuntResults: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');

  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [beacons, setBeacons] = useState<Beacon[]>([]);
  const [dnsThreats, setDnsThreats] = useState<DnsThreatsResponse | null>(null);
  const [mitreMappings, setMitreMappings] = useState<MitreMapping[]>([]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError('');
      try {
        const safeFetch = async (url: string) => {
          const res = await fetch(url);
          if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
          return res.json();
        };

        const [statsRes, threatsRes, beaconsRes, dnsRes, mitreRes] = await Promise.all([
          safeFetch(`${API_BASE}/api/v1/analysis/stats`),
          safeFetch(`${API_BASE}/api/v1/analysis/threats`),
          safeFetch(`${API_BASE}/api/v1/hunt/beacons`),
          safeFetch(`${API_BASE}/api/v1/hunt/dns/threats`),
          safeFetch(`${API_BASE}/api/v1/analysis/mitre`),
        ]);

        setStats(statsRes || null);
        setThreats(Array.isArray(threatsRes?.threats) ? threatsRes.threats : []);
        setBeacons(Array.isArray(beaconsRes?.beacons) ? beaconsRes.beacons : []);
        setDnsThreats(dnsRes || null);
        setMitreMappings(Array.isArray(mitreRes?.mappings) ? mitreRes.mappings : []);

        // Indicators can be unavailable in demo (500 / empty). Fetch it
        // independently so a failure hides the IOC section rather than
        // failing the whole report or fabricating rows.
        try {
          const indRes = await fetch(`${API_BASE}/api/v1/analysis/indicators`);
          if (indRes.ok) {
            const indJson = await indRes.json();
            const list = Array.isArray(indJson)
              ? indJson
              : Array.isArray(indJson?.indicators)
                ? indJson.indicators
                : [];
            setIndicators(list);
          } else {
            setIndicators([]);
          }
        } catch {
          setIndicators([]);
        }
      } catch (e) {
        setError(e instanceof Error ? e.message : 'Failed to load hunt results');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const criticalThreats = useMemo(() => threats.filter((t) => t.level === 'critical'), [threats]);
  const highCount = stats?.threat_level_distribution?.high ?? 0;
  const criticalCount = stats?.threat_level_distribution?.critical ?? criticalThreats.length;

  const avgThreatScore = useMemo(() => {
    if (threats.length === 0) return 0;
    const sum = threats.reduce((acc, t) => acc + (t.score || 0), 0);
    return Math.round((sum / threats.length) * 100);
  }, [threats]);

  const topBeacons = useMemo(
    () => [...beacons].sort((a, b) => (b.beacon_score || 0) - (a.beacon_score || 0)).slice(0, 5),
    [beacons],
  );

  const dnsRows = useMemo<DnsRow[]>(() => {
    const s = dnsThreats?.summary;
    if (!s) return [];
    const rows: DnsRow[] = [];
    for (const d of s.top_tunneling || []) {
      rows.push({
        threat_type: 'tunneling',
        domain: d.domain || '—',
        src_ip: d.src_ip,
        score: d.tunneling_score ?? 0,
        query_count: d.query_count,
      });
    }
    for (const d of s.top_dga || []) {
      rows.push({
        threat_type: 'dga',
        domain: d.domain || '—',
        src_ip: d.src_ip,
        score: d.dga_score ?? 0,
        query_count: d.query_count,
      });
    }
    for (const d of s.top_fast_flux || []) {
      rows.push({
        threat_type: 'fast_flux',
        domain: d.domain || '—',
        src_ip: d.src_ip,
        score: d.fast_flux_score ?? 0,
        query_count: d.query_count,
      });
    }
    return rows.sort((a, b) => b.score - a.score).slice(0, 5);
  }, [dnsThreats]);

  // Recommendations derived from the real findings — no fabricated hosts,
  // domains, or malware attributions.
  const recommendations = useMemo<string[]>(() => {
    const recs: string[] = [];
    const topCritical = criticalThreats[0];
    if (topCritical) {
      recs.push(`Isolate and forensically review ${topCritical.entity} — highest-scoring critical host in this hunt.`);
    }
    const topBeacon = topBeacons[0];
    if (topBeacon) {
      recs.push(`Block outbound traffic from ${topBeacon.src_ip} to ${topBeacon.dst_ip}:${topBeacon.dst_port} — regular beaconing pattern consistent with C2.`);
    }
    const topTunnel = dnsThreats?.summary?.top_tunneling?.[0];
    if (topTunnel?.domain) {
      recs.push(`Investigate DNS activity to ${topTunnel.domain} from ${topTunnel.src_ip} — indicators of DNS tunneling / exfiltration.`);
    }
    if (criticalCount > 0 || highCount > 0) {
      recs.push(`Triage the ${criticalCount} critical and ${highCount} high-severity host(s) flagged in this report before lower-priority items.`);
    }
    if (mitreMappings.length > 0) {
      recs.push(`Map detection coverage against the ${mitreMappings.length} observed MITRE ATT&CK technique(s) and confirm alerting exists for each.`);
    }
    recs.push('Preserve relevant Zeek/Suricata logs for the affected hosts to support any follow-up investigation.');
    return recs;
  }, [criticalThreats, topBeacons, dnsThreats, criticalCount, highCount, mitreMappings]);

  const scorePillStyle = (s: number): React.CSSProperties => ({
    background: s >= 85 ? 'rgba(220, 38, 38, 0.08)' : s >= 65 ? 'rgba(234, 88, 12, 0.08)' : 'rgba(22, 163, 74, 0.08)',
    color: s >= 85 ? '#DC2626' : s >= 65 ? '#EA580C' : '#16A34A',
  });

  const dnsTypeStyle = (t: DnsRow['threat_type']): React.CSSProperties => ({
    display: 'inline-block',
    fontSize: 11,
    fontWeight: 600,
    padding: '2px 8px',
    borderRadius: 9999,
    background: t === 'tunneling' ? 'rgba(220, 38, 38, 0.08)' : t === 'dga' ? 'rgba(234, 88, 12, 0.08)' : 'rgba(37, 99, 235, 0.08)',
    color: t === 'tunneling' ? '#DC2626' : t === 'dga' ? '#EA580C' : '#2563EB',
  });

  if (loading) {
    return <LoadingSkeleton rows={8} />;
  }

  if (error) {
    return (
      <div style={{
        margin: 16, padding: '12px 16px', borderRadius: 8,
        background: 'rgba(220, 38, 38, 0.06)', border: '1px solid rgba(220, 38, 38, 0.3)',
        color: '#B91C1C', fontSize: 13,
      }}>
        Failed to load hunt results: {error}
      </div>
    );
  }

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
            This hunt analyzed network telemetry across{' '}
            <strong>{stats?.total_hosts ?? 0} host{(stats?.total_hosts ?? 0) === 1 ? '' : 's'}</strong>, producing{' '}
            <strong>{stats?.detections?.total ?? 0} threat detection{(stats?.detections?.total ?? 0) === 1 ? '' : 's'}</strong>. The analysis identified{' '}
            <strong style={{ color: '#DC2626' }}>{criticalCount} critical</strong> and{' '}
            <strong style={{ color: '#EA580C' }}>{highCount} high-severity</strong> threat(s)
            requiring attention, with an average threat score of{' '}
            <strong>{avgThreatScore}</strong>.
          </p>
        </div>

        {/* Quick stats grid */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12 }}>
          {[
            { label: 'Total Detections', value: stats?.detections?.total ?? 0, color: '#2563EB' },
            { label: 'Critical', value: criticalCount, color: '#DC2626' },
            { label: 'High', value: highCount, color: '#EA580C' },
            { label: 'Beacons', value: stats?.detections?.beacons ?? 0, color: '#7C3AED' },
            { label: 'DNS Threats', value: stats?.detections?.dns_threats ?? 0, color: '#0891B2' },
            { label: 'MITRE Techniques', value: stats?.mitre?.techniques_observed ?? 0, color: '#16A34A' },
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
      <Collapsible title="Critical Findings" icon={<AlertTriangle size={16} />} badge={criticalThreats.length}>
        {criticalThreats.length === 0 ? (
          <p style={{ fontSize: 13, color: '#64748B', margin: 0 }}>No critical findings in this hunt.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {criticalThreats.map((a, i) => (
              <div key={i} style={{
                padding: '14px 16px', border: '1px solid rgba(220, 38, 38, 0.15)', borderRadius: 6,
                background: 'rgba(220, 38, 38, 0.03)', borderLeft: '3px solid #DC2626',
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span className="v3-data" style={{ fontSize: 14, fontWeight: 600, color: '#1E293B' }}>{a.entity}</span>
                  <span className="v3-data" style={{ fontSize: 14, fontWeight: 700, color: '#DC2626' }}>{Math.round(a.score * 100)}</span>
                </div>
                <ul style={{ margin: 0, padding: 0, listStyle: 'none' }}>
                  {a.reasons.map((r, j) => (
                    <li key={j} style={{ fontSize: 13, color: '#475569', marginBottom: 3 }}>• {r}</li>
                  ))}
                </ul>
                <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                  {a.mitre_techniques_count > 0 && (
                    <span className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>
                      {a.mitre_techniques_count} MITRE technique{a.mitre_techniques_count === 1 ? '' : 's'}
                    </span>
                  )}
                  <span className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>
                    confidence {Math.round(a.confidence * 100)}%
                  </span>
                  <AddToCase
                    findingType="rule_match"
                    summary={`Hunt result finding: ${a.entity}`}
                    severity={a.level}
                    data={{ entity: a.entity, score: a.score, mitre_techniques_count: a.mitre_techniques_count, reasons: a.reasons }}
                  />
                </div>
              </div>
            ))}
          </div>
        )}
      </Collapsible>

      {/* Indicators of Compromise — hidden entirely when none are available. */}
      {indicators.length > 0 && (
        <Collapsible title="Indicators of Compromise" icon={<Shield size={16} />} badge={indicators.length}>
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
                {indicators.map((ind, i) => (
                  <tr key={i}>
                    <td>
                      <span className={`v3-badge ${ind.severity}`}>{ind.severity}</span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-block', padding: '2px 8px', borderRadius: 4, fontSize: 11,
                        background: '#F1F5F9', color: '#475569', fontWeight: 500,
                      }}>
                        {ind.indicator_type}
                      </span>
                    </td>
                    <td className="mono" style={{ fontWeight: 500 }}>{ind.value}</td>
                    <td style={{ color: '#64748B', maxWidth: 260, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ind.description}
                    </td>
                    <td style={{ color: '#64748B', fontSize: 12 }}>{ind.source}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Collapsible>
      )}

      {/* Top Beacons */}
      <Collapsible title="Top Beacon Detections" icon={<Target size={16} />} badge={topBeacons.length} defaultOpen={false}>
        {topBeacons.length === 0 ? (
          <p style={{ fontSize: 13, color: '#64748B', margin: 0 }}>No beaconing patterns detected.</p>
        ) : (
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
                {topBeacons.map((b, i) => (
                  <tr key={`${b.src_ip}-${b.dst_ip}-${b.dst_port}-${i}`}>
                    <td className="mono">{b.src_ip}</td>
                    <td className="mono">{b.dst_ip}:{b.dst_port}</td>
                    <td>
                      <span className="v3-score-badge" style={scorePillStyle(b.beacon_score)}>
                        {Math.round(b.beacon_score)}
                      </span>
                    </td>
                    <td className="mono" style={{ color: '#64748B' }}>{b.avg_interval_seconds.toFixed(1)}s</td>
                    <td className="mono" style={{ color: '#64748B' }}>{b.jitter_pct.toFixed(1)}%</td>
                    <td className="mono" style={{ color: '#64748B' }}>{b.connection_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Collapsible>

      {/* Top DNS Threats */}
      <Collapsible title="Top DNS Threats" icon={<Info size={16} />} badge={dnsRows.length} defaultOpen={false}>
        {dnsRows.length === 0 ? (
          <p style={{ fontSize: 13, color: '#64748B', margin: 0 }}>No DNS threats detected.</p>
        ) : (
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
                {dnsRows.map((t, i) => (
                  <tr key={`${t.threat_type}-${t.domain}-${t.src_ip}-${i}`}>
                    <td>
                      <span style={dnsTypeStyle(t.threat_type)}>
                        {t.threat_type.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{t.domain}</td>
                    <td className="mono" style={{ color: '#64748B' }}>{t.src_ip}</td>
                    <td>
                      <span className="v3-score-badge" style={scorePillStyle(t.score)}>
                        {Math.round(t.score)}
                      </span>
                    </td>
                    <td className="mono" style={{ color: '#64748B' }}>{t.query_count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Collapsible>

      {/* MITRE ATT&CK Coverage */}
      <Collapsible title="MITRE ATT&CK Coverage" icon={<Target size={16} />} badge={mitreMappings.length} defaultOpen={false}>
        {mitreMappings.length === 0 ? (
          <p style={{ fontSize: 13, color: '#64748B', margin: 0 }}>No MITRE ATT&CK techniques observed.</p>
        ) : (
          <div className="v3-mitre-grid">
            {mitreMappings.map((m) => (
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
                  {m.tactic.replace(/-/g, ' ')} · {m.detection_count} detection{m.detection_count === 1 ? '' : 's'}
                </div>
                <div className="v3-mitre-cell-meta">
                  Confidence: {(m.confidence * 100).toFixed(0)}% · {m.affected_hosts.length} host{m.affected_hosts.length === 1 ? '' : 's'}
                </div>
              </div>
            ))}
          </div>
        )}
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

export default HuntResults;
