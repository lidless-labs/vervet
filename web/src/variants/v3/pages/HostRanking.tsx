import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AlertTriangle, ShieldAlert, Radar, Search, Server, Globe2 } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || '';

type HostRow = {
  ip: string;
  score: number;
  threat_level: string;
  confidence: number;
  beacon_count: number;
  dns_threat_count: number;
  alert_count: number;
  long_connection_count: number;
  mitre_techniques: string[];
  attack_summary: string;
};

const scoreColor = (score: number) => {
  if (score > 0.75) return '#EF4444';
  if (score > 0.5) return '#F59E0B';
  if (score > 0.25) return '#D97706';
  return '#10B981';
};

const HostRanking: React.FC = () => {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState<HostRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState('all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<'score' | 'beacons' | 'alerts'>('score');

  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        const sevParam = severity !== 'all' ? `?severity=${severity}&limit=200` : '?limit=200';
        const res = await fetch(`${API_BASE}/api/v1/hosts/ranking${sevParam}`);
        const data = await res.json();
        setHosts(data?.hosts || []);
      } catch (err) {
        console.error('Failed to load host rankings', err);
        setHosts([]);
      } finally {
        setLoading(false);
      }
    })();
  }, [severity]);

  const sortedFiltered = useMemo(() => {
    const q = search.trim();
    let data = hosts.filter((h) => !q || h.ip.includes(q));

    if (sortBy === 'beacons') data = [...data].sort((a, b) => b.beacon_count - a.beacon_count || b.score - a.score);
    else if (sortBy === 'alerts') data = [...data].sort((a, b) => b.alert_count - a.alert_count || b.score - a.score);
    else data = [...data].sort((a, b) => b.score - a.score);

    return data;
  }, [hosts, search, sortBy]);

  const counts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0 };
    hosts.forEach((h) => {
      const lvl = h.threat_level?.toLowerCase();
      if (lvl in c) (c as any)[lvl] += 1;
    });
    return c;
  }, [hosts]);

  return (
    <div>
      <h1 className="v3-page-title">Host Ranking</h1>
      <p className="v3-page-subtitle">Hosts ranked by composite threat severity, highest risk first</p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 12, marginBottom: 16 }}>
        <div className="v3-kpi"><div>Total Hosts</div><strong>{hosts.length}</strong></div>
        <div className="v3-kpi"><div>Critical</div><strong style={{ color: '#EF4444' }}>{counts.critical}</strong></div>
        <div className="v3-kpi"><div>High</div><strong style={{ color: '#F59E0B' }}>{counts.high}</strong></div>
        <div className="v3-kpi"><div>Medium</div><strong style={{ color: '#D97706' }}>{counts.medium}</strong></div>
        <div className="v3-kpi"><div>Low</div><strong style={{ color: '#10B981' }}>{counts.low}</strong></div>
      </div>

      <div className="v3-card" style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((s) => (
              <button key={s} className={`v3-btn ${severity === s ? 'v3-btn-primary' : 'v3-btn-outline'}`} onClick={() => setSeverity(s)}>
                {s.toUpperCase()}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', top: 9, left: 8, color: '#94A3B8' }} />
              <input className="v3-input" style={{ paddingLeft: 28 }} value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search IP..." />
            </div>
            <select className="v3-select" value={sortBy} onChange={(e) => setSortBy(e.target.value as any)}>
              <option value="score">Sort: Threat Score</option>
              <option value="beacons">Sort: Beacon Count</option>
              <option value="alerts">Sort: Alert Count</option>
            </select>
          </div>
        </div>
      </div>

      <div className="v3-card" style={{ padding: 0 }}>
        {loading ? (
          <div style={{ padding: 24, color: '#64748B' }}>Loading host ranking...</div>
        ) : (
          <div className="v3-table-wrapper">
            <table className="v3-table">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Threat Score</th>
                  <th>Threat Level</th>
                  <th>Indicators</th>
                  <th>MITRE</th>
                  <th>Attack Summary</th>
                </tr>
              </thead>
              <tbody>
                {sortedFiltered.map((host) => (
                  <tr key={host.ip} style={{ cursor: 'pointer' }} onClick={() => navigate(`../host/${encodeURIComponent(host.ip)}`)}>
                    <td style={{ fontFamily: 'Source Code Pro, monospace' }}>{host.ip}</td>
                    <td>
                      <span style={{ fontSize: 24, fontWeight: 700, color: scoreColor(host.score) }}>{(host.score * 100).toFixed(0)}</span>
                    </td>
                    <td><span className={`v3-badge ${host.threat_level}`}>{host.threat_level.toUpperCase()}</span></td>
                    <td>
                      <div style={{ display: 'flex', gap: 10 }}>
                        <span title="Beacons" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><Radar size={14} />{host.beacon_count}</span>
                        <span title="DNS" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><Globe2 size={14} />{host.dns_threat_count}</span>
                        <span title="Alerts" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><ShieldAlert size={14} />{host.alert_count}</span>
                      </div>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {host.mitre_techniques.slice(0, 3).map((m) => <span key={m} className="v3-tag">{m}</span>)}
                      </div>
                    </td>
                    <td style={{ maxWidth: 460, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{host.attack_summary || '—'}</td>
                  </tr>
                ))}
                {sortedFiltered.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: '#94A3B8', padding: 24 }}><Server size={16} style={{ marginRight: 8 }} />No hosts found</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default HostRanking;
