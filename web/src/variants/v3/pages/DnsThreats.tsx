/**
 * V3 DNS Threats — Underline tabs, card layout per category, DGA entropy scatter, summary stats.
 */
import React, { useEffect, useMemo, useState } from 'react';
import {
  ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { format } from 'date-fns';
import { Globe, Activity, AlertTriangle, Zap, Radio } from 'lucide-react';
import LoadingSkeleton from '../../../components/LoadingSkeleton';

const API_BASE = import.meta.env.VITE_API_BASE || '';

type TabKey = 'all' | 'tunneling' | 'dga' | 'fast_flux' | 'suspicious_pattern';

/** Displayed threat row, combined across the API's per-category arrays. */
interface DnsThreat {
  id: string;
  threat_type: TabKey;
  domain: string;
  src_ip: string;
  query_count: number;
  score: number;
  confidence: number;
  reasons: string[];
  mitre_techniques: string[];
  first_seen: number;
  last_seen: number;
  unique_subdomains?: number;
  avg_subdomain_entropy?: number;
  estimated_bytes_exfiltrated?: number;
  domain_entropy?: number;
  unique_ips?: number;
}

/* Raw API shapes (subset of fields consumed here). */
interface TunnelingRow {
  domain: string;
  src_ip: string;
  query_count: number;
  unique_subdomains?: number;
  avg_subdomain_entropy?: number;
  estimated_bytes_exfiltrated?: number;
  tunneling_score: number;
  confidence: number;
  reasons?: string[];
  mitre_techniques?: string[];
  first_seen: number;
  last_seen: number;
}

interface DgaRow {
  domain: string;
  src_ip: string;
  query_count: number;
  domain_entropy?: number;
  dga_score: number;
  confidence: number;
  reasons?: string[];
  mitre_techniques?: string[];
  first_seen: number;
  last_seen: number;
}

interface FastFluxRow {
  domain: string;
  src_ip?: string;
  query_count: number;
  unique_ips?: number;
  fast_flux_score: number;
  confidence: number;
  reasons?: string[];
  mitre_techniques?: string[];
  first_seen: number;
  last_seen: number;
}

interface PatternRow {
  pattern_type: string;
  domain: string | null;
  src_ip: string;
  query_count: number;
  suspicion_score: number;
  confidence: number;
  reasons?: string[];
  mitre_techniques?: string[];
  first_seen: number;
  last_seen: number;
}

interface DnsThreatsSummary {
  total_queries_analyzed?: number;
  tunneling_detections?: number;
  dga_detections?: number;
  fast_flux_detections?: number;
  other_patterns?: number;
  top_tunneling?: TunnelingRow[];
  top_dga?: DgaRow[];
  top_fast_flux?: FastFluxRow[];
  top_patterns?: PatternRow[];
}

interface DnsThreatsResponse {
  summary?: DnsThreatsSummary;
}

const TABS: { key: TabKey; label: string; icon: React.ReactNode }[] = [
  { key: 'all', label: 'All Threats', icon: <Globe size={14} /> },
  { key: 'tunneling', label: 'Tunneling', icon: <Activity size={14} /> },
  { key: 'dga', label: 'DGA', icon: <AlertTriangle size={14} /> },
  { key: 'fast_flux', label: 'Fast Flux', icon: <Zap size={14} /> },
  { key: 'suspicious_pattern', label: 'Suspicious', icon: <Radio size={14} /> },
];

const scoreColor = (score: number): string => {
  if (score >= 85) return '#DC2626';
  if (score >= 65) return '#EA580C';
  if (score >= 40) return '#D97706';
  return '#16A34A';
};

const scoreBg = (score: number): string => {
  if (score >= 85) return 'rgba(220, 38, 38, 0.08)';
  if (score >= 65) return 'rgba(234, 88, 12, 0.08)';
  if (score >= 40) return 'rgba(217, 119, 6, 0.08)';
  return 'rgba(22, 163, 74, 0.08)';
};

const typeLabel = (t: string): string => {
  const map: Record<string, string> = {
    tunneling: 'Tunneling', dga: 'DGA', fast_flux: 'Fast Flux', suspicious_pattern: 'Suspicious',
  };
  return map[t] || t;
};

const typeBadgeColor = (t: string): { bg: string; color: string } => {
  const map: Record<string, { bg: string; color: string }> = {
    tunneling: { bg: 'rgba(220, 38, 38, 0.08)', color: '#DC2626' },
    dga: { bg: 'rgba(234, 88, 12, 0.08)', color: '#EA580C' },
    fast_flux: { bg: 'rgba(37, 99, 235, 0.08)', color: '#2563EB' },
    suspicious_pattern: { bg: 'rgba(100, 116, 139, 0.08)', color: '#64748B' },
  };
  return map[t] || { bg: 'rgba(100, 116, 139, 0.08)', color: '#64748B' };
};

interface ScatterPoint {
  entropy: number;
  score: number;
  queryCount: number;
  domain: string;
  src_ip: string;
}

/* DGA Entropy Scatter tooltip */
const EntropyTooltip: React.FC<{ active?: boolean; payload?: Array<{ payload: ScatterPoint }> }> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{
      background: '#FFFFFF', border: '1px solid #E2E8F0', borderRadius: 6, padding: 10,
      fontSize: 12, color: '#1E293B', boxShadow: '0 4px 6px rgba(0,0,0,0.05)',
    }}>
      <p style={{ fontWeight: 600, marginBottom: 4 }}>{d.domain}</p>
      <p>Entropy: {d.entropy.toFixed(2)}</p>
      <p>Score: {d.score}</p>
      <p>Source: {d.src_ip}</p>
    </div>
  );
};

const ThreatCard: React.FC<{ threat: DnsThreat }> = ({ threat }) => {
  const tb = typeBadgeColor(threat.threat_type);
  return (
    <div className="v3-card" style={{ padding: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div>
          <span
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 4, padding: '2px 8px',
              borderRadius: 9999, fontSize: 11, fontWeight: 600, background: tb.bg, color: tb.color,
              border: `1px solid ${tb.color}20`,
            }}
          >
            {typeLabel(threat.threat_type)}
          </span>
        </div>
        <span
          className="v3-score-badge"
          style={{ background: scoreBg(threat.score), color: scoreColor(threat.score), fontWeight: 700 }}
        >
          {threat.score}
        </span>
      </div>

      <div style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 13, fontWeight: 600, color: '#1E293B', marginBottom: 4, wordBreak: 'break-all' }}>
        {threat.domain}
      </div>
      <div style={{ fontSize: 12, color: '#64748B', marginBottom: 10 }}>
        Source: <span className="v3-data">{threat.src_ip}</span>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6, marginBottom: 10 }}>
        <div style={{ fontSize: 11, color: '#94A3B8' }}>
          Queries: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.query_count.toLocaleString()}</span>
        </div>
        <div style={{ fontSize: 11, color: '#94A3B8' }}>
          Confidence: <span style={{ color: '#1E293B', fontWeight: 500 }}>{Math.round(threat.confidence * 100)}%</span>
        </div>
        {threat.unique_subdomains !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Subdomains: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.unique_subdomains}</span>
          </div>
        )}
        {threat.domain_entropy !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Entropy: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.domain_entropy.toFixed(2)}</span>
          </div>
        )}
        {threat.unique_ips !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Unique IPs: <span style={{ color: '#1E293B', fontWeight: 500 }}>{threat.unique_ips}</span>
          </div>
        )}
        {threat.estimated_bytes_exfiltrated !== undefined && (
          <div style={{ fontSize: 11, color: '#94A3B8' }}>
            Exfiltrated: <span style={{ color: '#1E293B', fontWeight: 500 }}>
              {(threat.estimated_bytes_exfiltrated / 1024).toFixed(0)} KB
            </span>
          </div>
        )}
      </div>

      {/* Reasons */}
      <div style={{ borderTop: '1px solid #E2E8F0', paddingTop: 8, marginTop: 4 }}>
        {threat.reasons.slice(0, 2).map((r, i) => (
          <div key={i} style={{ fontSize: 12, color: '#64748B', marginBottom: 2 }}>• {r}</div>
        ))}
      </div>

      {/* MITRE */}
      {threat.mitre_techniques.length > 0 && (
        <div style={{ marginTop: 8, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {threat.mitre_techniques.map((t) => (
            <span key={t} className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>{t}</span>
          ))}
        </div>
      )}

      <div style={{ fontSize: 11, color: '#94A3B8', marginTop: 8 }}>
        {format(new Date(threat.first_seen * 1000), 'MMM d HH:mm')} — {format(new Date(threat.last_seen * 1000), 'MMM d HH:mm')}
      </div>
    </div>
  );
};

/* Map each per-category API array into the unified displayed shape. */
function mapTunneling(rows: TunnelingRow[]): DnsThreat[] {
  return rows.map((r, i) => ({
    id: `tunneling-${r.domain}-${r.src_ip}-${i}`,
    threat_type: 'tunneling',
    domain: r.domain,
    src_ip: r.src_ip,
    query_count: r.query_count,
    score: Math.round(r.tunneling_score),
    confidence: r.confidence,
    reasons: r.reasons ?? [],
    mitre_techniques: r.mitre_techniques ?? [],
    first_seen: r.first_seen,
    last_seen: r.last_seen,
    unique_subdomains: r.unique_subdomains,
    avg_subdomain_entropy: r.avg_subdomain_entropy,
    estimated_bytes_exfiltrated: r.estimated_bytes_exfiltrated,
  }));
}

function mapDga(rows: DgaRow[]): DnsThreat[] {
  return rows.map((r, i) => ({
    id: `dga-${r.domain}-${r.src_ip}-${i}`,
    threat_type: 'dga',
    domain: r.domain,
    src_ip: r.src_ip,
    query_count: r.query_count,
    score: Math.round(r.dga_score),
    confidence: r.confidence,
    reasons: r.reasons ?? [],
    mitre_techniques: r.mitre_techniques ?? [],
    first_seen: r.first_seen,
    last_seen: r.last_seen,
    domain_entropy: r.domain_entropy,
  }));
}

function mapFastFlux(rows: FastFluxRow[]): DnsThreat[] {
  return rows.map((r, i) => ({
    id: `fast_flux-${r.domain}-${i}`,
    threat_type: 'fast_flux',
    domain: r.domain,
    src_ip: r.src_ip ?? '',
    query_count: r.query_count,
    score: Math.round(r.fast_flux_score),
    confidence: r.confidence,
    reasons: r.reasons ?? [],
    mitre_techniques: r.mitre_techniques ?? [],
    first_seen: r.first_seen,
    last_seen: r.last_seen,
    unique_ips: r.unique_ips,
  }));
}

function mapPatterns(rows: PatternRow[]): DnsThreat[] {
  return rows.map((r, i) => ({
    id: `pattern-${r.src_ip}-${r.pattern_type}-${i}`,
    threat_type: 'suspicious_pattern',
    domain: r.domain ?? r.pattern_type,
    src_ip: r.src_ip,
    query_count: r.query_count,
    score: Math.round(r.suspicion_score),
    confidence: r.confidence,
    reasons: r.reasons ?? [],
    mitre_techniques: r.mitre_techniques ?? [],
    first_seen: r.first_seen,
    last_seen: r.last_seen,
  }));
}

const DnsThreats: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('all');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [threats, setThreats] = useState<DnsThreat[]>([]);
  const [summary, setSummary] = useState<DnsThreatsSummary | null>(null);

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

        const [data] = await Promise.all([
          safeFetch(`${API_BASE}/api/v1/hunt/dns/threats`) as Promise<DnsThreatsResponse>,
        ]);

        const s = data?.summary ?? null;
        setSummary(s);
        setThreats([
          ...mapTunneling(s?.top_tunneling ?? []),
          ...mapDga(s?.top_dga ?? []),
          ...mapFastFlux(s?.top_fast_flux ?? []),
          ...mapPatterns(s?.top_patterns ?? []),
        ]);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load DNS threats');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = useMemo(() => {
    if (activeTab === 'all') return threats;
    return threats.filter((t) => t.threat_type === activeTab);
  }, [activeTab, threats]);

  /* Summary stats — prefer API summary counts, fall back to combined list. */
  const summaryStats = useMemo(() => {
    return {
      total: threats.length,
      tunneling: summary?.tunneling_detections ?? threats.filter((t) => t.threat_type === 'tunneling').length,
      dga: summary?.dga_detections ?? threats.filter((t) => t.threat_type === 'dga').length,
      fast_flux: summary?.fast_flux_detections ?? threats.filter((t) => t.threat_type === 'fast_flux').length,
    };
  }, [threats, summary]);

  /* DGA entropy scatter data */
  const dgaScatterData = useMemo<ScatterPoint[]>(() => {
    return threats
      .filter((t) => t.threat_type === 'dga' && t.domain_entropy !== undefined)
      .map((t) => ({
        entropy: t.domain_entropy!,
        score: t.score,
        queryCount: t.query_count,
        domain: t.domain,
        src_ip: t.src_ip,
      }));
  }, [threats]);

  if (loading) {
    return <LoadingSkeleton rows={8} />;
  }

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>DNS Threat Intelligence</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          DNS-based threat detection · {threats.length} threats identified
        </p>
      </div>

      {error && (
        <div style={{
          background: 'rgba(220, 38, 38, 0.08)', border: '1px solid rgba(220, 38, 38, 0.3)',
          color: '#DC2626', fontSize: 13, borderRadius: 8, padding: '10px 14px', marginBottom: 20,
        }}>
          {error}
        </div>
      )}

      {/* Summary Stats */}
      <div className="v3-grid-12" style={{ marginBottom: 20 }}>
        {[
          { label: 'Total DNS Threats', value: summaryStats.total, color: 'blue' as const },
          { label: 'Tunneling', value: summaryStats.tunneling, color: 'red' as const },
          { label: 'DGA Detected', value: summaryStats.dga, color: 'orange' as const },
          { label: 'Fast Flux', value: summaryStats.fast_flux, color: 'blue' as const },
        ].map((s) => (
          <div key={s.label} className="v3-col-3">
            <div className="v3-kpi" style={{ padding: '14px 16px' }}>
              <div className="v3-kpi-value" style={{ fontSize: 24 }}>{s.value}</div>
              <div className="v3-kpi-label">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* DGA Entropy Scatter (visible when 'all' or 'dga' tab is active) */}
      {(activeTab === 'all' || activeTab === 'dga') && dgaScatterData.length > 0 && (
        <div className="v3-card" style={{ marginBottom: 20 }}>
          <div className="v3-card-header">
            <div>
              <div className="v3-card-title">DGA Entropy Analysis</div>
              <div className="v3-card-subtitle">Domain entropy vs. threat score — bubble size = query count</div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#E2E8F0" />
              <XAxis
                type="number" dataKey="entropy" name="Entropy"
                tick={{ fill: '#64748B', fontSize: 11 }}
                label={{ value: 'Domain Entropy', position: 'insideBottom', offset: -5, fill: '#64748B', fontSize: 11 }}
              />
              <YAxis
                type="number" dataKey="score" name="Score" domain={[0, 100]}
                tick={{ fill: '#64748B', fontSize: 11 }}
                label={{ value: 'Threat Score', angle: -90, position: 'insideLeft', fill: '#64748B', fontSize: 11 }}
              />
              <ZAxis type="number" dataKey="queryCount" range={[40, 300]} name="Queries" />
              <Tooltip content={<EntropyTooltip />} />
              <Scatter data={dgaScatterData} fill="#EA580C" fillOpacity={0.7} />
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Tabs */}
      <div className="v3-tabs">
        {TABS.map((tab) => (
          <button
            key={tab.key}
            className={`v3-tab${activeTab === tab.key ? ' active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              {tab.icon} {tab.label}
              <span style={{
                background: activeTab === tab.key ? 'rgba(37, 99, 235, 0.1)' : '#F1F5F9',
                color: activeTab === tab.key ? '#2563EB' : '#94A3B8',
                padding: '1px 6px', borderRadius: 9999, fontSize: 11, fontWeight: 600,
              }}>
                {tab.key === 'all' ? threats.length : threats.filter((t) => t.threat_type === tab.key).length}
              </span>
            </span>
          </button>
        ))}
      </div>

      {/* Threat Cards */}
      {filtered.length === 0 ? (
        <div className="v3-card" style={{ padding: 32, textAlign: 'center', color: '#94A3B8', fontSize: 13 }}>
          No DNS threats detected for this category.
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
          {[...filtered].sort((a, b) => b.score - a.score).map((t) => (
            <ThreatCard key={t.id} threat={t} />
          ))}
        </div>
      )}
    </div>
  );
};

export default DnsThreats;
