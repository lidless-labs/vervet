/**
 * V4 Connections — Neon header table, hover glow rows,
 * angular/slanted filter inputs, neon gradient protocol chart.
 */
import React, { useState, useMemo } from 'react';
import {
  Download, Search, X, ChevronUp, ChevronDown,
  ChevronsUpDown, ChevronLeft, ChevronRight, Network, Filter,
} from 'lucide-react';
import { format } from 'date-fns';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { mockAlerts } from '../../../data/mockData';

type SortDir = 'asc' | 'desc';
const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'] as const;

const severityNeon = (level: string): string => {
  const map: Record<string, string> = {
    critical: '#FF00FF', high: '#FF6600', medium: '#FFFF00', low: '#00FFFF', info: '#8878A8',
  };
  return map[level] || '#8878A8';
};

/* Neon tooltip for charts */
const NeonTooltip: React.FC<{ active?: boolean; payload?: any[]; label?: string }> = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: 'rgba(15, 10, 26, 0.95)', border: '1px solid rgba(0, 255, 255, 0.3)',
      padding: 10, fontFamily: 'Fira Code, monospace', fontSize: 11,
      boxShadow: '0 0 20px rgba(0, 255, 255, 0.15)', color: '#E0D8F0',
    }}>
      <p style={{ margin: '0 0 4px', color: '#00FFFF', fontFamily: 'Orbitron, sans-serif', fontSize: 10 }}>{label}</p>
      {payload.map((p: any, i: number) => (
        <p key={i} style={{ margin: '2px 0', color: p.color || '#00FFFF' }}>{p.name}: {p.value}</p>
      ))}
    </div>
  );
};

const Connections: React.FC = () => {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState<string>('all');
  const [sortKey, setSortKey] = useState<string>('score');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 12;

  const filtered = useMemo(() => {
    let data = [...mockAlerts];
    if (severity !== 'all') data = data.filter((a) => a.level === severity);
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (a) =>
          a.entity.toLowerCase().includes(q) ||
          a.indicators.some((ind) => ind.toLowerCase().includes(q)) ||
          a.mitre_techniques.some((t) => t.toLowerCase().includes(q))
      );
    }
    return data;
  }, [search, severity]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: any, vb: any;
      switch (sortKey) {
        case 'entity': va = a.entity; vb = b.entity; break;
        case 'level': {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          va = order[a.level as keyof typeof order] ?? 5;
          vb = order[b.level as keyof typeof order] ?? 5;
          break;
        }
        case 'score': va = a.score; vb = b.score; break;
        case 'occurrences': va = a.occurrence_count; vb = b.occurrence_count; break;
        case 'last_seen': va = a.last_seen; vb = b.last_seen; break;
        default: va = a.score; vb = b.score;
      }
      if (typeof va === 'number' && typeof vb === 'number') return sortDir === 'asc' ? va - vb : vb - va;
      return sortDir === 'asc' ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paged = sorted.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleSort = (key: string) => {
    if (sortKey === key) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else { setSortKey(key); setSortDir('desc'); }
  };

  const SortIcon: React.FC<{ col: string }> = ({ col }) => {
    if (sortKey !== col) return <ChevronsUpDown size={12} style={{ opacity: 0.3 }} />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} style={{ color: '#00FFFF' }} />
      : <ChevronDown size={12} style={{ color: '#00FFFF' }} />;
  };

  /* Protocol distribution data */
  const protocolData = useMemo(() => {
    const counts: Record<string, number> = {};
    mockAlerts.forEach((a) => {
      a.mitre_techniques.forEach((t) => {
        const base = t.split('.')[0];
        counts[base] = (counts[base] || 0) + 1;
      });
    });
    return Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 8)
      .map(([name, count], i) => ({
        name, count,
        color: ['#FF00FF', '#00FFFF', '#FF6600', '#FFFF00', '#39FF14', '#FF0040', '#8B5CF6', '#14B8A6'][i % 8],
      }));
  }, []);

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="v4-heading v4-heading-glow" style={{ fontSize: 22, margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Network size={22} style={{ color: '#00FFFF', filter: 'drop-shadow(0 0 6px rgba(0, 255, 255, 0.5))' }} />
          CONNECTION MATRIX
        </h1>
        <p style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#8878A8', marginTop: 6 }}>
          NODES: {sorted.length} · FILTER.ACTIVE: {severity !== 'all' || search ? 'TRUE' : 'FALSE'}
        </p>
      </div>

      {/* Protocol Chart */}
      <div className="v4-card v4-card-glow-cyan" style={{ marginBottom: 20 }}>
        <div className="v4-card-header">
          <div>
            <div className="v4-card-title">Technique Distribution</div>
            <div className="v4-card-subtitle">Neon gradient protocol breakdown</div>
          </div>
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={protocolData} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 0, 255, 0.06)" />
            <XAxis dataKey="name" tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#8878A8', fontFamily: 'Fira Code', fontSize: 9 }} axisLine={false} tickLine={false} />
            <Tooltip content={<NeonTooltip />} />
            <Bar dataKey="count" name="Detections" radius={[2, 2, 0, 0]}>
              {protocolData.map((d, i) => (
                <Cell key={i} fill={d.color} fillOpacity={0.8} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Filters */}
      <div className="v4-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: 360 }}>
            <Search size={14} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: '#8878A8' }} />
            <input
              className="v4-input"
              style={{ width: '100%', paddingLeft: 36, paddingRight: search ? 28 : 12 }}
              placeholder="SEARCH_QUERY..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#FF00FF', padding: 0 }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: '#FF00FF' }} />
            <select
              className="v4-select"
              value={severity}
              onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
            >
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s === 'all' ? 'ALL LEVELS' : s.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          <button className="v4-btn" style={{ marginLeft: 'auto' }}>
            <Download size={14} />
            EXPORT
          </button>
        </div>
      </div>

      {/* Data Table */}
      <div className="v4-card" style={{ padding: 0 }}>
        <div className="v4-table-wrapper" style={{ maxHeight: 560, overflowY: 'auto' }}>
          <table className="v4-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('level')} style={{ width: 100 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>SEVERITY <SortIcon col="level" /></span>
                </th>
                <th className="sortable" onClick={() => handleSort('entity')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>ENTITY <SortIcon col="entity" /></span>
                </th>
                <th className="sortable" onClick={() => handleSort('score')} style={{ width: 80 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>SCORE <SortIcon col="score" /></span>
                </th>
                <th>INDICATORS</th>
                <th>MITRE</th>
                <th className="sortable" onClick={() => handleSort('occurrences')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>COUNT <SortIcon col="occurrences" /></span>
                </th>
                <th className="sortable" onClick={() => handleSort('last_seen')} style={{ width: 130 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>LAST SEEN <SortIcon col="last_seen" /></span>
                </th>
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '32px 16px', color: '#8878A8' }}>
                    NO MATCHING CONNECTIONS FOUND
                  </td>
                </tr>
              ) : (
                paged.map((a, i) => (
                  <tr key={i}>
                    <td><span className={`v4-badge ${a.level}`}>{a.level}</span></td>
                    <td className="v4-data" style={{ fontSize: 12 }}>{a.entity}</td>
                    <td>
                      <span className="v4-score-badge" style={{
                        background: `${severityNeon(a.level as string)}15`,
                        color: severityNeon(a.level as string),
                        textShadow: `0 0 6px ${severityNeon(a.level as string)}60`,
                      }}>
                        {a.score}
                      </span>
                    </td>
                    <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span className="v4-data" style={{ fontSize: 11, color: '#8878A8' }}>
                        {a.indicators.slice(0, 2).join(', ') || '—'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {a.mitre_techniques.slice(0, 2).map((t) => (
                          <span key={t} className="v4-tag">{t}</span>
                        ))}
                      </div>
                    </td>
                    <td className="v4-data" style={{ color: '#8878A8' }}>{a.occurrence_count}</td>
                    <td style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#8878A8' }}>
                      {format(new Date(a.last_seen * 1000), 'MMM d, HH:mm')}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="v4-pagination">
            <span className="v4-data" style={{ fontSize: 11 }}>
              {sorted.length} RECORDS · PAGE {currentPage}/{totalPages}
            </span>
            <div style={{ display: 'flex', gap: 4 }}>
              <button className="v4-pagination-btn" disabled={currentPage <= 1} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft size={14} />
              </button>
              <button className="v4-pagination-btn" disabled={currentPage >= totalPages} onClick={() => setPage((p) => p + 1)}>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Connections;
