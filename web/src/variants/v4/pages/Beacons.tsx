/**
 * V4 Beacons — Glowing scatter dots with halos, angular clip-path cards,
 * neon histogram bars, glowing detail panels.
 */
import React, { useState, useMemo } from 'react';
import {
  X, Clock, ExternalLink, Radio, Search,
  Activity, Wifi,
} from 'lucide-react';
import { format } from 'date-fns';
import {
  ScatterChart, Scatter, XAxis, YAxis, ZAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, BarChart, Bar, Cell,
} from 'recharts';
import { mockBeacons } from '../../../data/mockData';
import type { BeaconResult } from '../../../types';

const scoreNeon = (score: number): string => {
  if (score >= 85) return '#FF00FF';
  if (score >= 65) return '#FF6600';
  if (score >= 40) return '#FFFF00';
  return '#39FF14';
};

const scoreLabel = (score: number): string => {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
};

/* Neon tooltip */
const NeonTooltip: React.FC<{ active?: boolean; payload?: any[] }> = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload;
  if (!d) return null;
  return (
    <div style={{
      background: 'rgba(15, 10, 26, 0.95)', border: '1px solid rgba(0, 255, 255, 0.3)',
      padding: 12, fontFamily: 'Fira Code, monospace', fontSize: 11,
      boxShadow: '0 0 20px rgba(0, 255, 255, 0.15)', color: '#E0D8F0',
    }}>
      <p style={{ margin: '0 0 4px', color: '#00FFFF', fontFamily: 'Orbitron, sans-serif', fontSize: 10 }}>
        {d.src} → {d.dst}
      </p>
      <p style={{ margin: '2px 0', color: '#FF00FF' }}>Score: {d.y}</p>
      <p style={{ margin: '2px 0' }}>Interval: {d.x}s</p>
      <p style={{ margin: '2px 0' }}>Connections: {d.z}</p>
    </div>
  );
};

/* Beacon Card */
const BeaconCard: React.FC<{ beacon: BeaconResult; onClick: () => void }> = ({ beacon, onClick }) => {
  const neon = scoreNeon(beacon.beacon_score);
  return (
    <div
      className="v4-angular-card"
      style={{
        cursor: 'pointer',
        borderColor: `${neon}30`,
        borderLeft: `3px solid ${neon}`,
        boxShadow: `inset 0 0 20px ${neon}08`,
        transition: 'all 0.2s',
      }}
      onClick={onClick}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = `${neon}60`;
        e.currentTarget.style.boxShadow = `0 0 20px ${neon}20, inset 0 0 20px ${neon}10`;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = `${neon}30`;
        e.currentTarget.style.boxShadow = `inset 0 0 20px ${neon}08`;
      }}
    >
      {/* Top row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <div className="v4-data" style={{ fontSize: 13, fontWeight: 600, color: '#E0D8F0' }}>
            {beacon.src_ip}
          </div>
          <div className="v4-data" style={{ fontSize: 11, color: '#8878A8', marginTop: 2 }}>
            → {beacon.dst_ip}:{beacon.dst_port}
          </div>
        </div>
        <div style={{
          fontFamily: "'Orbitron', sans-serif", fontSize: 18, fontWeight: 800,
          color: neon, textShadow: `0 0 12px ${neon}80`,
        }}>
          {beacon.beacon_score}
        </div>
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8, marginTop: 14 }}>
        {[
          { label: 'INTERVAL', value: `${beacon.avg_interval_seconds}s` },
          { label: 'JITTER', value: `${beacon.jitter_pct.toFixed(1)}%` },
          { label: 'CONNS', value: `${beacon.connection_count}` },
        ].map((s) => (
          <div key={s.label}>
            <div className="v4-label" style={{ fontSize: 9 }}>{s.label}</div>
            <div className="v4-data" style={{ fontSize: 12, fontWeight: 600, color: '#E0D8F0', marginTop: 2 }}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* Badge */}
      <div style={{ marginTop: 12 }}>
        <span style={{
          display: 'inline-block', padding: '3px 10px',
          fontFamily: "'Orbitron', sans-serif", fontSize: 9, fontWeight: 700,
          letterSpacing: '0.1em', textTransform: 'uppercase' as const,
          color: neon, background: `${neon}15`,
          border: `1px solid ${neon}30`,
          clipPath: 'polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%)',
          textShadow: `0 0 6px ${neon}60`,
        }}>
          {scoreLabel(beacon.beacon_score)}
        </span>
      </div>
    </div>
  );
};

/* Detail Slide-Over */
const DetailPanel: React.FC<{ beacon: BeaconResult; onClose: () => void }> = ({ beacon, onClose }) => {
  const neon = scoreNeon(beacon.beacon_score);

  /* Histogram data: simulate interval distribution */
  const histData = useMemo(() => {
    const avg = beacon.avg_interval_seconds;
    const bins = 10;
    const range = avg * 0.4;
    return Array.from({ length: bins }, (_, i) => {
      const center = avg - range + (2 * range * i) / (bins - 1);
      const dist = Math.abs(center - avg) / range;
      const count = Math.max(1, Math.round(beacon.connection_count * 0.3 * Math.exp(-dist * dist * 3)));
      return { interval: center.toFixed(1), count };
    });
  }, [beacon]);

  return (
    <>
      <div className="v4-slide-backdrop" onClick={onClose} />
      <div className="v4-slide-panel">
        <div className="v4-slide-header">
          <div>
            <div className="v4-heading" style={{ fontSize: 14, color: '#00FFFF', textShadow: '0 0 8px rgba(0, 255, 255, 0.4)' }}>
              BEACON ANALYSIS
            </div>
            <div className="v4-data" style={{ fontSize: 12, color: '#8878A8', marginTop: 4 }}>
              {beacon.src_ip} → {beacon.dst_ip}:{beacon.dst_port}
            </div>
          </div>
          <button className="v4-slide-close" onClick={onClose}><X size={18} /></button>
        </div>
        <div className="v4-slide-body">
          {/* Score */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
            <div style={{
              width: 72, height: 72,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: "'Orbitron', sans-serif", fontWeight: 900, fontSize: 28,
              color: neon, textShadow: `0 0 20px ${neon}80`,
              border: `2px solid ${neon}40`,
              boxShadow: `0 0 20px ${neon}30, inset 0 0 20px ${neon}10`,
              background: `${neon}08`,
            }}>
              {beacon.beacon_score}
            </div>
            <div>
              <span style={{
                display: 'inline-block', padding: '3px 10px',
                fontFamily: "'Orbitron', sans-serif", fontSize: 10, fontWeight: 700,
                color: neon, background: `${neon}15`, border: `1px solid ${neon}30`,
                clipPath: 'polygon(4px 0, 100% 0, calc(100% - 4px) 100%, 0 100%)',
                textShadow: `0 0 6px ${neon}60`, letterSpacing: '0.08em',
              }}>
                {scoreLabel(beacon.beacon_score)} RISK
              </span>
              <div style={{ fontSize: 12, color: '#8878A8', marginTop: 6 }}>
                Confidence: <span style={{ color: '#00FFFF' }}>{(beacon.confidence * 100).toFixed(0)}%</span>
              </div>
            </div>
          </div>

          <div className="v4-divider" />

          {/* Timeline */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
            {[
              { label: 'FIRST SEEN', value: format(new Date(beacon.first_seen * 1000), 'MMM d, yyyy HH:mm'), icon: <Clock size={14} /> },
              { label: 'LAST SEEN', value: format(new Date(beacon.last_seen * 1000), 'MMM d, yyyy HH:mm'), icon: <Clock size={14} /> },
            ].map((item) => (
              <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ color: '#00FFFF' }}>{item.icon}</span>
                <div>
                  <div className="v4-label" style={{ fontSize: 9 }}>{item.label}</div>
                  <div className="v4-data" style={{ fontSize: 11, color: '#E0D8F0', marginTop: 2 }}>{item.value}</div>
                </div>
              </div>
            ))}
          </div>

          {/* Interval Histogram */}
          <h3 className="v4-heading" style={{ fontSize: 12, color: '#FF00FF', textShadow: '0 0 6px rgba(255, 0, 255, 0.3)', marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Activity size={14} /> INTERVAL DISTRIBUTION
          </h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={histData} margin={{ top: 5, right: 5, left: -15, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 0, 255, 0.06)" />
              <XAxis dataKey="interval" tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 9 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 9 }} axisLine={false} tickLine={false} />
              <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                {histData.map((_, i) => (
                  <Cell key={i} fill={neon} fillOpacity={0.6 + (i / histData.length) * 0.3} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>

          <div className="v4-divider" />

          {/* Metrics Grid */}
          <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 12 }}>BEACON METRICS</h3>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 20 }}>
            {[
              { label: 'Avg Interval', value: `${beacon.avg_interval_seconds}s` },
              { label: 'Median Interval', value: `${beacon.median_interval_seconds.toFixed(1)}s` },
              { label: 'Min Interval', value: `${beacon.min_interval_seconds.toFixed(1)}s` },
              { label: 'Max Interval', value: `${beacon.max_interval_seconds.toFixed(1)}s` },
              { label: 'Std Dev', value: `${beacon.interval_std_dev.toFixed(2)}` },
              { label: 'Jitter', value: `${beacon.jitter_pct.toFixed(1)}%` },
              { label: 'Connections', value: `${beacon.connection_count}` },
              { label: 'Avg Data Size', value: beacon.data_size_avg ? `${beacon.data_size_avg}B` : 'N/A' },
            ].map((m) => (
              <div key={m.label} style={{
                padding: '8px 12px',
                background: 'rgba(15, 10, 26, 0.6)',
                border: '1px solid rgba(255, 0, 255, 0.1)',
              }}>
                <div className="v4-label" style={{ fontSize: 9 }}>{m.label}</div>
                <div className="v4-data" style={{ fontSize: 13, fontWeight: 600, color: '#E0D8F0', marginTop: 2 }}>{m.value}</div>
              </div>
            ))}
          </div>

          <div className="v4-divider" />

          {/* Reasons */}
          <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 8 }}>DETECTION REASONS</h3>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none', marginBottom: 20 }}>
            {beacon.reasons.map((r, i) => (
              <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6, fontSize: 13, color: '#E0D8F0' }}>
                <span style={{
                  marginTop: 6, width: 6, height: 6, flexShrink: 0,
                  background: neon, boxShadow: `0 0 6px ${neon}`,
                  clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)',
                }} />
                {r}
              </li>
            ))}
          </ul>

          {/* MITRE */}
          {beacon.mitre_techniques.length > 0 && (
            <>
              <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 8 }}>MITRE ATT&CK</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {beacon.mitre_techniques.map((t) => (
                  <a
                    key={t}
                    href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                    target="_blank" rel="noopener noreferrer"
                    className="v4-tag"
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
};

const Beacons: React.FC = () => {
  const [selected, setSelected] = useState<BeaconResult | null>(null);
  const [search, setSearch] = useState('');
  const [minScore, setMinScore] = useState(0);

  const filtered = useMemo(() => {
    let data = [...mockBeacons].sort((a, b) => b.beacon_score - a.beacon_score);
    if (minScore > 0) data = data.filter((b) => b.beacon_score >= minScore);
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (b) => b.src_ip.includes(q) || b.dst_ip.includes(q) || String(b.dst_port).includes(q)
      );
    }
    return data;
  }, [search, minScore]);

  /* Scatter data with glow-coloring */
  const scatterData = useMemo(() =>
    filtered.map((b) => ({
      x: b.avg_interval_seconds,
      y: b.beacon_score,
      z: b.connection_count,
      src: b.src_ip,
      dst: b.dst_ip,
      fill: scoreNeon(b.beacon_score),
    })),
    [filtered]
  );

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="v4-heading v4-heading-glow" style={{ fontSize: 22, margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Wifi size={22} style={{ color: '#FF00FF', filter: 'drop-shadow(0 0 6px rgba(255, 0, 255, 0.5))' }} />
          BEACON SCANNER
        </h1>
        <p style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#8878A8', marginTop: 6 }}>
          C2_SIGNALS: {filtered.length} · SCAN.MODE: ACTIVE
        </p>
      </div>

      {/* Scatter Plot */}
      <div className="v4-card v4-card-glow-magenta" style={{ marginBottom: 20 }}>
        <div className="v4-card-header">
          <div>
            <div className="v4-card-title" style={{ color: '#FF00FF', textShadow: '0 0 8px rgba(255, 0, 255, 0.3)' }}>
              Beacon Signal Map
            </div>
            <div className="v4-card-subtitle">Score × Interval — dot size = connection count</div>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={320}>
          <ScatterChart margin={{ top: 10, right: 20, left: 0, bottom: 10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 0, 255, 0.06)" />
            <XAxis
              type="number" dataKey="x" name="Interval (s)"
              tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 10 }}
              axisLine={{ stroke: 'rgba(255, 0, 255, 0.15)' }} tickLine={false}
              label={{ value: 'Interval (s)', position: 'insideBottom', offset: -5, fill: '#8878A8', fontFamily: 'Orbitron', fontSize: 9 }}
            />
            <YAxis
              type="number" dataKey="y" name="Score" domain={[0, 100]}
              tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 10 }}
              axisLine={{ stroke: 'rgba(255, 0, 255, 0.15)' }} tickLine={false}
              label={{ value: 'Score', angle: -90, position: 'insideLeft', fill: '#8878A8', fontFamily: 'Orbitron', fontSize: 9 }}
            />
            <ZAxis type="number" dataKey="z" range={[60, 400]} name="Connections" />
            <Tooltip content={<NeonTooltip />} />
            <Scatter data={scatterData} fillOpacity={0.7}>
              {scatterData.map((d, i) => (
                <Cell key={i} fill={d.fill} />
              ))}
            </Scatter>
          </ScatterChart>
        </ResponsiveContainer>
      </div>

      {/* Filters */}
      <div className="v4-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 240px', maxWidth: 320 }}>
            <Search size={14} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: '#8878A8' }} />
            <input
              className="v4-input"
              style={{ width: '100%', paddingLeft: 36 }}
              placeholder="SEARCH IP, PORT..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <select
            className="v4-select"
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
          >
            <option value={0}>ALL SCORES</option>
            <option value={85}>CRITICAL (≥85)</option>
            <option value={65}>HIGH+ (≥65)</option>
            <option value={40}>MEDIUM+ (≥40)</option>
          </select>
          <span className="v4-data" style={{ fontSize: 11, color: '#FF00FF', display: 'flex', alignItems: 'center', gap: 4, textShadow: '0 0 4px rgba(255, 0, 255, 0.3)' }}>
            <Radio size={14} /> {filtered.length} SIGNALS
          </span>
        </div>
      </div>

      {/* Beacon Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 14 }}>
        {filtered.map((b) => (
          <BeaconCard key={b.id} beacon={b} onClick={() => setSelected(b)} />
        ))}
      </div>

      {/* Detail Slide-Over */}
      {selected && <DetailPanel beacon={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

export default Beacons;
