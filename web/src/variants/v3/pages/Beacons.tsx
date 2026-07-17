/**
 * V3 Beacons — Beacon analysis with scatter plot, cards, and slide-over detail.
 * Score badges, expandable detail panel, BeaconScatter at top.
 */
import React, { useEffect, useState, useMemo } from 'react';
import { X, Clock, ExternalLink, Radio, Search } from 'lucide-react';
import { format } from 'date-fns';
import LoadingSkeleton from '../../../components/LoadingSkeleton';
import { BeaconScatter } from '../../../components/charts/BeaconScatter';
import type { ChartTheme } from '../../../types';

const API_BASE = import.meta.env.VITE_API_BASE || '';

/** Real /api/v1/hunt/beacons row. No `id` in the API — we synthesize one from src/dst/port. */
interface Beacon {
  id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  proto: string;
  connection_count: number;
  time_span_seconds: number;
  avg_interval_seconds: number;
  median_interval_seconds: number;
  min_interval_seconds: number;
  max_interval_seconds: number;
  interval_std_dev: number;
  jitter_pct: number;
  data_size_avg: number | null;
  data_size_variance: number | null;
  beacon_score: number;
  confidence: number;
  reasons: string[];
  mitre_techniques: string[];
  first_seen: number;
  last_seen: number;
}

interface BeaconsResponse {
  beacons: Beacon[];
  total: number;
}

const v3ChartTheme: ChartTheme = {
  colors: {
    primary: '#2563EB',
    secondary: '#7C3AED',
    accent: '#EA580C',
    danger: '#DC2626',
    warning: '#EA580C',
    success: '#16A34A',
    info: '#2563EB',
    background: '#FFFFFF',
    surface: '#F8FAFC',
    text: '#1E293B',
    textSecondary: '#64748B',
    gridLine: '#E2E8F0',
    series: ['#DC2626', '#EA580C', '#16A34A', '#2563EB', '#7C3AED',
      '#0891B2', '#DB2777', '#059669', '#D97706', '#6D28D9'],
  },
  fonts: { family: 'Source Sans 3, system-ui, sans-serif', monoFamily: 'Source Code Pro, monospace', sizeSmall: 11, sizeBase: 12, sizeLarge: 14 },
  spacing: { chartPadding: 20, legendGap: 12, tooltipPadding: 10 },
};

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

const scoreLabel = (score: number): string => {
  if (score >= 85) return 'Critical';
  if (score >= 65) return 'High';
  if (score >= 40) return 'Medium';
  return 'Low';
};

const BeaconCard: React.FC<{ beacon: Beacon; onClick: () => void }> = ({ beacon, onClick }) => (
  <div
    className="v3-card"
    style={{ cursor: 'pointer', padding: 16, transition: 'box-shadow 0.15s' }}
    onClick={onClick}
    onMouseEnter={(e) => (e.currentTarget.style.boxShadow = '0 4px 6px rgba(0,0,0,0.05), 0 2px 4px rgba(0,0,0,0.04)')}
    onMouseLeave={(e) => (e.currentTarget.style.boxShadow = '0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04)')}
  >
    {/* Top row: score badge + IPs */}
    <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
      <div>
        <div style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 13, fontWeight: 600, color: '#1E293B' }}>
          {beacon.src_ip}
        </div>
        <div style={{ fontSize: 12, color: '#64748B', marginTop: 2 }}>
          → {beacon.dst_ip}:{beacon.dst_port}
        </div>
      </div>
      <span
        className="v3-score-badge"
        style={{ background: scoreBg(beacon.beacon_score), color: scoreColor(beacon.beacon_score), fontWeight: 700, fontSize: 14 }}
      >
        {beacon.beacon_score.toFixed(1)}
      </span>
    </div>

    {/* Stats row */}
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginTop: 12, fontSize: 12 }}>
      <div>
        <div style={{ color: '#94A3B8', fontSize: 11 }}>Interval</div>
        <div style={{ fontFamily: 'Source Code Pro, monospace', fontWeight: 500, color: '#1E293B' }}>
          {beacon.avg_interval_seconds.toFixed(1)}s
        </div>
      </div>
      <div>
        <div style={{ color: '#94A3B8', fontSize: 11 }}>Jitter</div>
        <div style={{ fontFamily: 'Source Code Pro, monospace', fontWeight: 500, color: '#1E293B' }}>
          {beacon.jitter_pct.toFixed(1)}%
        </div>
      </div>
      <div>
        <div style={{ color: '#94A3B8', fontSize: 11 }}>Connections</div>
        <div style={{ fontFamily: 'Source Code Pro, monospace', fontWeight: 500, color: '#1E293B' }}>
          {beacon.connection_count}
        </div>
      </div>
    </div>

    {/* Badge */}
    <div style={{ marginTop: 10 }}>
      <span
        className="v3-badge"
        style={{ background: scoreBg(beacon.beacon_score), color: scoreColor(beacon.beacon_score), border: `1px solid ${scoreColor(beacon.beacon_score)}20` }}
      >
        {scoreLabel(beacon.beacon_score)}
      </span>
    </div>
  </div>
);

const DetailSlideOver: React.FC<{ beacon: Beacon; onClose: () => void }> = ({ beacon, onClose }) => (
  <>
    <div className="v3-slide-over-backdrop" onClick={onClose} />
    <div className="v3-slide-over">
      <div className="v3-slide-over-header">
        <div>
          <div className="v3-slide-over-title">Beacon Detail</div>
          <div style={{ fontSize: 12, color: '#64748B', marginTop: 2, fontFamily: 'Source Code Pro, monospace' }}>
            {beacon.src_ip} → {beacon.dst_ip}:{beacon.dst_port}
          </div>
        </div>
        <button className="v3-slide-over-close" onClick={onClose}><X size={18} /></button>
      </div>
      <div className="v3-slide-over-body">
        {/* Score */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
          <div style={{
            width: 64, height: 64, borderRadius: 12,
            background: scoreBg(beacon.beacon_score),
            color: scoreColor(beacon.beacon_score),
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'Outfit, sans-serif', fontWeight: 700, fontSize: 24,
          }}>
            {Math.round(beacon.beacon_score)}
          </div>
          <div>
            <span
              className="v3-badge"
              style={{ background: scoreBg(beacon.beacon_score), color: scoreColor(beacon.beacon_score), border: `1px solid ${scoreColor(beacon.beacon_score)}20`, marginBottom: 4 }}
            >
              {scoreLabel(beacon.beacon_score)} Risk
            </span>
            <div style={{ fontSize: 12, color: '#64748B', marginTop: 4 }}>
              Confidence: {Math.round(beacon.confidence * 100)}%
            </div>
          </div>
        </div>

        <div className="v3-divider" />

        {/* Timeline */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} style={{ color: '#64748B' }} />
            <div>
              <div style={{ fontSize: 11, color: '#94A3B8' }}>First Seen</div>
              <div style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 12, color: '#1E293B' }}>
                {format(new Date(beacon.first_seen * 1000), 'MMM d, yyyy HH:mm')}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} style={{ color: '#64748B' }} />
            <div>
              <div style={{ fontSize: 11, color: '#94A3B8' }}>Last Seen</div>
              <div style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 12, color: '#1E293B' }}>
                {format(new Date(beacon.last_seen * 1000), 'MMM d, yyyy HH:mm')}
              </div>
            </div>
          </div>
        </div>

        {/* Metrics */}
        <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 12 }}>Beacon Metrics</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
          {[
            { label: 'Avg Interval', value: `${beacon.avg_interval_seconds.toFixed(1)}s` },
            { label: 'Median Interval', value: `${beacon.median_interval_seconds.toFixed(1)}s` },
            { label: 'Min Interval', value: `${beacon.min_interval_seconds.toFixed(1)}s` },
            { label: 'Max Interval', value: `${beacon.max_interval_seconds.toFixed(1)}s` },
            { label: 'Std Dev', value: `${beacon.interval_std_dev.toFixed(2)}` },
            { label: 'Jitter', value: `${beacon.jitter_pct.toFixed(1)}%` },
            { label: 'Connections', value: `${beacon.connection_count}` },
            { label: 'Avg Data Size', value: beacon.data_size_avg ? `${beacon.data_size_avg.toFixed(0)}B` : 'N/A' },
          ].map((m) => (
            <div key={m.label} style={{ padding: '8px 12px', background: '#F8FAFC', borderRadius: 6, border: '1px solid #E2E8F0' }}>
              <div style={{ fontSize: 11, color: '#94A3B8' }}>{m.label}</div>
              <div style={{ fontFamily: 'Source Code Pro, monospace', fontSize: 14, fontWeight: 600, color: '#1E293B', marginTop: 2 }}>{m.value}</div>
            </div>
          ))}
        </div>

        <div className="v3-divider" />

        {/* Reasons */}
        <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 8 }}>Detection Reasons</h3>
        <ul style={{ margin: 0, padding: 0, listStyle: 'none', marginBottom: 20 }}>
          {beacon.reasons.map((r, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6, fontSize: 13, color: '#475569' }}>
              <span style={{ marginTop: 6, width: 5, height: 5, borderRadius: '50%', background: '#2563EB', flexShrink: 0 }} />
              {r}
            </li>
          ))}
        </ul>

        {/* MITRE */}
        {beacon.mitre_techniques.length > 0 && (
          <>
            <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 8 }}>MITRE ATT&CK</h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {beacon.mitre_techniques.map((t) => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="v3-tag"
                  style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}
                >
                  {t} <ExternalLink size={10} />
                </a>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  </>
);

const Beacons: React.FC = () => {
  const [beacons, setBeacons] = useState<Beacon[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [selected, setSelected] = useState<Beacon | null>(null);
  const [search, setSearch] = useState('');
  const [minScore, setMinScore] = useState(0);

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
          safeFetch(`${API_BASE}/api/v1/hunt/beacons`) as Promise<BeaconsResponse>,
        ]);

        const rows = (data?.beacons || []).map((b) => ({
          ...b,
          id: `${b.src_ip}-${b.dst_ip}-${b.dst_port}`,
        }));
        setBeacons(rows);
      } catch (err) {
        console.error('Failed to load beacons', err);
        setError(err instanceof Error ? err.message : 'Failed to load beacons');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = useMemo(() => {
    let data = [...beacons].sort((a, b) => b.beacon_score - a.beacon_score);
    if (minScore > 0) data = data.filter((b) => b.beacon_score >= minScore);
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (b) => b.src_ip.includes(q) || b.dst_ip.includes(q) || String(b.dst_port).includes(q)
      );
    }
    return data;
  }, [beacons, search, minScore]);

  if (loading) {
    return <LoadingSkeleton rows={8} />;
  }

  return (
    <div>
      {error && (
        <div
          style={{
            marginBottom: 16,
            padding: '10px 14px',
            borderRadius: 6,
            background: 'rgba(220, 38, 38, 0.08)',
            border: '1px solid rgba(220, 38, 38, 0.3)',
            color: '#DC2626',
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Beacon Analysis</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          Periodic communication detection · {filtered.length} beacons identified
        </p>
      </div>

      {/* Scatter Plot */}
      <div className="v3-card" style={{ marginBottom: 20 }}>
        <div className="v3-card-header">
          <div>
            <div className="v3-card-title">Beacon Scatter Plot</div>
            <div className="v3-card-subtitle">Score vs. interval — bubble size = connection count</div>
          </div>
        </div>
        <BeaconScatter data={filtered} theme={v3ChartTheme} height={320} />
      </div>

      {/* Filters */}
      <div className="v3-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 240px', maxWidth: 320 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#94A3B8' }} />
            <input
              className="v3-input"
              style={{ width: '100%', paddingLeft: 32 }}
              placeholder="Search IP, port…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            className="v3-select"
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
          >
            <option value={0}>All Scores</option>
            <option value={85}>Critical (≥85)</option>
            <option value={65}>High+ (≥65)</option>
            <option value={40}>Medium+ (≥40)</option>
          </select>
          <span style={{ fontSize: 12, color: '#94A3B8' }}>
            <Radio size={14} style={{ verticalAlign: -2 }} /> {filtered.length} beacons
          </span>
        </div>
      </div>

      {/* Beacon Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 14 }}>
        {filtered.map((b) => (
          <BeaconCard key={b.id} beacon={b} onClick={() => setSelected(b)} />
        ))}
      </div>

      {/* Detail Slide-Over */}
      {selected && <DetailSlideOver beacon={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

export default Beacons;
