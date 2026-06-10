/**
 * V4 Threats — Neon severity indicators, intense MITRE cell glow,
 * sliding neon border detail panel.
 */
import React, { useState, useMemo } from 'react';
import {
  X, ExternalLink, Clock, Target, Search, Filter,
  ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight,
  Skull, Crosshair,
} from 'lucide-react';
import { format } from 'date-fns';
import { mockAlerts, mockMitreMappings } from '../../../data/mockData';
import type { ThreatScore, MitreMapping } from '../../../types';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const severityNeon = (level: string): string => {
  const map: Record<string, string> = {
    critical: '#FF00FF', high: '#FF6600', medium: '#FFFF00', low: '#00FFFF', info: '#8878A8',
  };
  return map[level] || '#8878A8';
};

/* MITRE Grid with intense glow */
const MitreGrid: React.FC = () => {
  const tactics = useMemo(() => {
    const grouped: Record<string, MitreMapping[]> = {};
    mockMitreMappings.forEach((m) => {
      if (!grouped[m.tactic]) grouped[m.tactic] = [];
      grouped[m.tactic].push(m);
    });
    return grouped;
  }, []);

  return (
    <div>
      {Object.entries(tactics).map(([tactic, techniques]) => (
        <div key={tactic} style={{ marginBottom: 16 }}>
          <h4 className="v4-label" style={{ fontSize: 10, marginBottom: 8, color: '#FF00FF', textShadow: '0 0 4px rgba(255, 0, 255, 0.3)' }}>
            {tactic.replace(/-/g, ' ').toUpperCase()}
          </h4>
          <div className="v4-mitre-grid">
            {techniques.map((t) => {
              const intensity = Math.min(t.detection_count / 25, 1);
              const glowColor = intensity > 0.6 ? '#FF00FF' : intensity > 0.3 ? '#FF6600' : '#00FFFF';
              return (
                <div
                  key={t.technique_id}
                  className="v4-mitre-cell"
                  style={{
                    borderColor: `${glowColor}30`,
                    boxShadow: `0 0 ${10 + intensity * 20}px ${glowColor}${Math.round(intensity * 30).toString(16).padStart(2, '0')}, inset 0 0 ${5 + intensity * 10}px ${glowColor}${Math.round(intensity * 15).toString(16).padStart(2, '0')}`,
                  }}
                >
                  <div className="v4-mitre-cell-id">{t.technique_id}</div>
                  <div className="v4-mitre-cell-name">{t.technique_name}</div>
                  <div className="v4-mitre-cell-meta">
                    {t.detection_count} detections · {(t.confidence * 100).toFixed(0)}% conf
                  </div>
                  <div style={{ marginTop: 4 }}>
                    {t.affected_hosts.slice(0, 2).map((h) => (
                      <span key={h} style={{
                        display: 'inline-block', fontSize: 9, fontFamily: "'Fira Code', monospace",
                        color: '#00FFFF', background: 'rgba(0, 255, 255, 0.08)',
                        padding: '1px 5px', marginRight: 3,
                        border: '1px solid rgba(0, 255, 255, 0.15)',
                      }}>
                        {h}
                      </span>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
};

/* Detail Panel — sliding neon border */
const DetailPanel: React.FC<{ threat: ThreatScore; onClose: () => void }> = ({ threat, onClose }) => {
  const neon = severityNeon(threat.level as string);

  return (
    <>
      <div className="v4-slide-backdrop" onClick={onClose} />
      <div className="v4-slide-panel">
        <div className="v4-slide-header">
          <div>
            <div className="v4-heading" style={{ fontSize: 14, color: '#00FFFF', textShadow: '0 0 8px rgba(0, 255, 255, 0.4)' }}>
              THREAT ANALYSIS
            </div>
            <div className="v4-data" style={{ fontSize: 12, color: '#8878A8', marginTop: 4 }}>
              {threat.entity}
            </div>
          </div>
          <button className="v4-slide-close" onClick={onClose}><X size={18} /></button>
        </div>
        <div className="v4-slide-body">
          {/* Score + Severity */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
            <div style={{
              width: 64, height: 64,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: "'Orbitron', sans-serif", fontWeight: 900, fontSize: 24,
              color: neon, textShadow: `0 0 20px ${neon}80`,
              border: `2px solid ${neon}40`,
              boxShadow: `0 0 20px ${neon}30, inset 0 0 20px ${neon}10`,
              background: `${neon}08`,
            }}>
              {threat.score}
            </div>
            <div>
              <span className={`v4-badge ${threat.level}`}>{threat.level}</span>
              <div style={{ fontSize: 12, color: '#8878A8', marginTop: 6 }}>
                Confidence: <span style={{ color: '#00FFFF' }}>{(threat.confidence * 100).toFixed(0)}%</span>
                {' · '}{threat.occurrence_count} occurrences
              </div>
            </div>
          </div>

          <div className="v4-divider" />

          {/* Timeline */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
            {[
              { label: 'FIRST SEEN', value: format(new Date(threat.first_seen * 1000), 'MMM d, yyyy HH:mm:ss') },
              { label: 'LAST SEEN', value: format(new Date(threat.last_seen * 1000), 'MMM d, yyyy HH:mm:ss') },
            ].map((item) => (
              <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Clock size={14} style={{ color: '#00FFFF' }} />
                <div>
                  <div className="v4-label" style={{ fontSize: 9 }}>{item.label}</div>
                  <div className="v4-data" style={{ fontSize: 11, color: '#E0D8F0', marginTop: 2 }}>{item.value}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="v4-divider" />

          {/* Reasons */}
          <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
            <Crosshair size={14} style={{ color: '#FF00FF' }} /> DETECTION REASONS
          </h3>
          <ul style={{ margin: 0, padding: 0, listStyle: 'none', marginBottom: 20 }}>
            {threat.reasons.map((r, i) => (
              <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6, fontSize: 13, color: '#E0D8F0' }}>
                <span style={{
                  marginTop: 6, width: 6, height: 6, flexShrink: 0,
                  background: '#FF00FF', boxShadow: '0 0 6px #FF00FF',
                  clipPath: 'polygon(50% 0%, 100% 50%, 50% 100%, 0% 50%)',
                }} />
                {r}
              </li>
            ))}
          </ul>

          {/* MITRE */}
          {threat.mitre_techniques.length > 0 && (
            <>
              <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Target size={14} style={{ color: '#00FFFF' }} /> MITRE ATT&CK
              </h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 20 }}>
                {threat.mitre_techniques.map((t) => (
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

          {/* Indicators */}
          {threat.indicators.length > 0 && (
            <>
              <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 8 }}>INDICATORS</h3>
              <div style={{ marginBottom: 20 }}>
                {threat.indicators.map((ind, i) => (
                  <div key={i} className="v4-data" style={{
                    fontSize: 11, color: '#E0D8F0',
                    background: 'rgba(15, 10, 26, 0.6)',
                    padding: '6px 10px', marginBottom: 4,
                    border: '1px solid rgba(0, 255, 255, 0.1)',
                  }}>
                    {ind}
                  </div>
                ))}
              </div>
            </>
          )}

          {/* Related */}
          {(threat.related_ips.length > 0 || threat.related_domains.length > 0) && (
            <>
              <h3 className="v4-heading" style={{ fontSize: 12, marginBottom: 8 }}>RELATED ENTITIES</h3>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {threat.related_ips.map((ip) => (
                  <span key={ip} className="v4-data" style={{
                    fontSize: 10, background: 'rgba(255, 0, 255, 0.08)',
                    padding: '3px 8px', color: '#FF00FF',
                    border: '1px solid rgba(255, 0, 255, 0.15)',
                  }}>{ip}</span>
                ))}
                {threat.related_domains.map((d) => (
                  <span key={d} className="v4-data" style={{
                    fontSize: 10, background: 'rgba(0, 255, 255, 0.08)',
                    padding: '3px 8px', color: '#00FFFF',
                    border: '1px solid rgba(0, 255, 255, 0.15)',
                  }}>{d}</span>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </>
  );
};

type SortDir = 'asc' | 'desc';

const Threats: React.FC = () => {
  const [selected, setSelected] = useState<ThreatScore | null>(null);
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('all');
  const [sortKey, setSortKey] = useState('score');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const filtered = useMemo(() => {
    let data = [...mockAlerts];
    if (severity !== 'all') data = data.filter((a) => a.level === severity);
    if (search) {
      const q = search.toLowerCase();
      data = data.filter((a) =>
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
        case 'level': va = SEVERITY_ORDER[a.level as string] ?? 5; vb = SEVERITY_ORDER[b.level as string] ?? 5; break;
        case 'score': va = a.score; vb = b.score; break;
        case 'confidence': va = a.confidence; vb = b.confidence; break;
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
    if (sortKey === key) setSortDir((d) => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
  };

  const SortIcon: React.FC<{ col: string }> = ({ col }) => {
    if (sortKey !== col) return <ChevronsUpDown size={12} style={{ opacity: 0.3 }} />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} style={{ color: '#00FFFF' }} />
      : <ChevronDown size={12} style={{ color: '#00FFFF' }} />;
  };

  return (
    <div>
      {/* Header */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="v4-heading v4-heading-magenta" style={{ fontSize: 22, margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Skull size={22} style={{ filter: 'drop-shadow(0 0 6px rgba(255, 0, 255, 0.5))' }} />
          THREAT ANALYSIS
        </h1>
        <p style={{ fontFamily: "'Fira Code', monospace", fontSize: 11, color: '#8878A8', marginTop: 6 }}>
          THREATS.TOTAL: {sorted.length} · MITRE_COVERAGE: {mockMitreMappings.length} TECHNIQUES
        </p>
      </div>

      {/* MITRE Grid */}
      <div className="v4-card v4-card-glow-magenta" style={{ marginBottom: 20 }}>
        <div className="v4-card-header">
          <div>
            <div className="v4-card-title" style={{ color: '#FF00FF', textShadow: '0 0 8px rgba(255, 0, 255, 0.3)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={14} /> MITRE ATT&CK COVERAGE
            </div>
            <div className="v4-card-subtitle">Detected techniques grouped by tactic — glow = intensity</div>
          </div>
        </div>
        <MitreGrid />
      </div>

      {/* Filters */}
      <div className="v4-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: 360 }}>
            <Search size={14} style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', color: '#8878A8' }} />
            <input
              className="v4-input" style={{ width: '100%', paddingLeft: 36 }}
              placeholder="SEARCH ENTITY, TECHNIQUE..."
              value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: '#FF00FF' }} />
            <select className="v4-select" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
              <option value="all">ALL LEVELS</option>
              <option value="critical">CRITICAL</option>
              <option value="high">HIGH</option>
              <option value="medium">MEDIUM</option>
              <option value="low">LOW</option>
              <option value="info">INFO</option>
            </select>
          </div>
        </div>
      </div>

      {/* Threat Table */}
      <div className="v4-card" style={{ padding: 0 }}>
        <div className="v4-table-wrapper" style={{ maxHeight: 500, overflowY: 'auto' }}>
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
                <th className="sortable" onClick={() => handleSort('confidence')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>CONF. <SortIcon col="confidence" /></span>
                </th>
                <th>MITRE</th>
                <th className="sortable" onClick={() => handleSort('last_seen')} style={{ width: 130 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>LAST SEEN <SortIcon col="last_seen" /></span>
                </th>
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '32px 16px', color: '#8878A8' }}>
                    NO MATCHING THREATS FOUND
                  </td>
                </tr>
              ) : (
                paged.map((a, i) => {
                  const neon = severityNeon(a.level as string);
                  return (
                    <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setSelected(a)}>
                      <td>
                        {/* Neon severity indicator dot + badge */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div style={{
                            width: 8, height: 8, borderRadius: '50%',
                            background: neon, boxShadow: `0 0 8px ${neon}`,
                          }} />
                          <span className={`v4-badge ${a.level}`}>{a.level}</span>
                        </div>
                      </td>
                      <td className="v4-data" style={{ fontSize: 12 }}>{a.entity}</td>
                      <td>
                        <span className="v4-score-badge" style={{
                          background: `${neon}15`, color: neon,
                          textShadow: `0 0 6px ${neon}60`,
                          fontWeight: 700,
                        }}>
                          {a.score}
                        </span>
                      </td>
                      <td className="v4-data" style={{ fontSize: 11, color: '#8878A8' }}>
                        {(a.confidence * 100).toFixed(0)}%
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {a.mitre_techniques.slice(0, 2).map((t) => (
                            <span key={t} className="v4-tag">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td className="v4-data" style={{ fontSize: 11, color: '#8878A8' }}>
                        {format(new Date(a.last_seen * 1000), 'MMM d, HH:mm')}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="v4-pagination">
            <span className="v4-data" style={{ fontSize: 11 }}>
              {sorted.length} THREATS · PAGE {currentPage}/{totalPages}
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

      {/* Detail Panel */}
      {selected && <DetailPanel threat={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

export default Threats;
