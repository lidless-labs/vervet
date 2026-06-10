/**
 * V3 Threats — Threat table with severity badges, unified scores, MITRE grid, detail modal.
 */
import React, { useState, useMemo } from 'react';
import { X, ExternalLink, Clock, Target, Search, Filter, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { format } from 'date-fns';
import { mockAlerts, mockMitreMappings } from '../../../data/mockData';
import type { ThreatScore, MitreMapping } from '../../../types';
import AddToCase from '../../../components/AddToCase';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const severityColor = (level: string): string => {
  const map: Record<string, string> = {
    critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#64748B',
  };
  return map[level] || '#64748B';
};

const severityBg = (level: string): string => {
  const map: Record<string, string> = {
    critical: 'rgba(220, 38, 38, 0.08)', high: 'rgba(234, 88, 12, 0.08)',
    medium: 'rgba(217, 119, 6, 0.08)', low: 'rgba(37, 99, 235, 0.08)', info: 'rgba(100, 116, 139, 0.08)',
  };
  return map[level] || 'rgba(100, 116, 139, 0.08)';
};

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
          <h4 className="v3-heading" style={{ fontSize: 12, textTransform: 'uppercase', color: '#64748B', letterSpacing: '0.04em', marginBottom: 8 }}>
            {tactic.replace(/-/g, ' ')}
          </h4>
          <div className="v3-mitre-grid">
            {techniques.map((t) => (
              <div key={t.technique_id} className="v3-mitre-cell">
                <div className="v3-mitre-cell-id">{t.technique_id}</div>
                <div className="v3-mitre-cell-name">{t.technique_name}</div>
                <div className="v3-mitre-cell-meta">
                  {t.detection_count} detections · {(t.confidence * 100).toFixed(0)}% conf
                </div>
                <div style={{ marginTop: 4 }}>
                  {t.affected_hosts.slice(0, 2).map((h) => (
                    <span key={h} style={{
                      display: 'inline-block', fontSize: 10, fontFamily: 'Source Code Pro, monospace',
                      color: '#64748B', background: '#F1F5F9', padding: '1px 5px', borderRadius: 3, marginRight: 3,
                    }}>
                      {h}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

const DetailModal: React.FC<{ threat: ThreatScore; onClose: () => void }> = ({ threat, onClose }) => (
  <div className="v3-modal-backdrop" onClick={onClose}>
    <div className="v3-modal" onClick={(e) => e.stopPropagation()}>
      <div className="v3-modal-header">
        <div>
          <h2 className="v3-heading" style={{ fontSize: 18, margin: 0 }}>Threat Detail</h2>
          <p style={{ fontSize: 12, color: '#64748B', fontFamily: 'Source Code Pro, monospace', margin: '4px 0 0' }}>
            {threat.entity}
          </p>
        </div>
        <button className="v3-slide-over-close" onClick={onClose}><X size={18} /></button>
      </div>
      <div className="v3-modal-body">
        {/* Score + Severity */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
          <div style={{
            width: 56, height: 56, borderRadius: 10,
            background: severityBg(threat.level as string), color: severityColor(threat.level as string),
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'Outfit, sans-serif', fontWeight: 700, fontSize: 22,
          }}>
            {threat.score}
          </div>
          <div>
            <span className={`v3-badge ${threat.level}`}>{threat.level}</span>
            <div style={{ fontSize: 12, color: '#64748B', marginTop: 4 }}>
              Confidence: {(threat.confidence * 100).toFixed(0)}% · {threat.occurrence_count} occurrences
            </div>
          </div>
        </div>

        {/* Timeline */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} style={{ color: '#64748B' }} />
            <div>
              <div style={{ fontSize: 11, color: '#94A3B8' }}>First Seen</div>
              <div className="v3-data" style={{ fontSize: 12, color: '#1E293B' }}>
                {format(new Date(threat.first_seen * 1000), 'MMM d, yyyy HH:mm:ss')}
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={14} style={{ color: '#64748B' }} />
            <div>
              <div style={{ fontSize: 11, color: '#94A3B8' }}>Last Seen</div>
              <div className="v3-data" style={{ fontSize: 12, color: '#1E293B' }}>
                {format(new Date(threat.last_seen * 1000), 'MMM d, yyyy HH:mm:ss')}
              </div>
            </div>
          </div>
        </div>

        <div className="v3-divider" />

        {/* Reasons */}
        <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 8 }}>Detection Reasons</h3>
        <ul style={{ margin: 0, padding: 0, listStyle: 'none', marginBottom: 20 }}>
          {threat.reasons.map((r, i) => (
            <li key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 6, fontSize: 13, color: '#475569' }}>
              <span style={{ marginTop: 6, width: 5, height: 5, borderRadius: '50%', background: '#2563EB', flexShrink: 0 }} />
              {r}
            </li>
          ))}
        </ul>

        {/* MITRE */}
        {threat.mitre_techniques.length > 0 && (
          <>
            <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={14} /> MITRE ATT&CK
            </h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 20 }}>
              {threat.mitre_techniques.map((t) => (
                <a
                  key={t}
                  href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                  target="_blank" rel="noopener noreferrer"
                  className="v3-tag" style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 4 }}
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
            <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 8 }}>Indicators</h3>
            <div style={{ marginBottom: 20 }}>
              {threat.indicators.map((ind, i) => (
                <div key={i} className="v3-data" style={{ fontSize: 12, color: '#475569', background: '#F8FAFC', padding: '6px 10px', borderRadius: 4, marginBottom: 4, border: '1px solid #E2E8F0' }}>
                  {ind}
                </div>
              ))}
            </div>
          </>
        )}

        {/* Related */}
        {(threat.related_ips.length > 0 || threat.related_domains.length > 0) && (
          <>
            <h3 className="v3-heading" style={{ fontSize: 14, marginBottom: 8 }}>Related Entities</h3>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {threat.related_ips.map((ip) => (
                <span key={ip} className="v3-data" style={{ fontSize: 11, background: '#F1F5F9', padding: '3px 8px', borderRadius: 4, color: '#475569' }}>{ip}</span>
              ))}
              {threat.related_domains.map((d) => (
                <span key={d} className="v3-data" style={{ fontSize: 11, background: '#F1F5F9', padding: '3px 8px', borderRadius: 4, color: '#475569' }}>{d}</span>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  </div>
);

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
    return sortDir === 'asc' ? <ChevronUp size={12} style={{ color: '#2563EB' }} /> : <ChevronDown size={12} style={{ color: '#2563EB' }} />;
  };

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Threat Analysis</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          Unified threat scores with MITRE ATT&CK mapping · {sorted.length} threats
        </p>
      </div>

      {/* MITRE Grid */}
      <div className="v3-card" style={{ marginBottom: 20 }}>
        <div className="v3-card-header">
          <div>
            <div className="v3-card-title" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Target size={16} /> MITRE ATT&CK Coverage
            </div>
            <div className="v3-card-subtitle">Detected techniques grouped by tactic</div>
          </div>
        </div>
        <MitreGrid />
      </div>

      {/* Filters */}
      <div className="v3-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: 360 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#94A3B8' }} />
            <input
              className="v3-input" style={{ width: '100%', paddingLeft: 32 }}
              placeholder="Search entity, indicator, technique…"
              value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: '#64748B' }} />
            <select className="v3-select" value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
      </div>

      {/* Threat Table */}
      <div className="v3-card" style={{ padding: 0 }}>
        <div className="v3-table-wrapper" style={{ maxHeight: 500, overflowY: 'auto' }}>
          <table className="v3-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('level')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>Severity <SortIcon col="level" /></span>
                </th>
                <th className="sortable" onClick={() => handleSort('entity')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>Entity <SortIcon col="entity" /></span>
                </th>
                <th className="sortable" onClick={() => handleSort('score')} style={{ width: 70 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>Score <SortIcon col="score" /></span>
                </th>
                <th className="sortable" onClick={() => handleSort('confidence')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>Conf. <SortIcon col="confidence" /></span>
                </th>
                <th>MITRE</th>
                <th className="sortable" onClick={() => handleSort('last_seen')} style={{ width: 130 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>Last Seen <SortIcon col="last_seen" /></span>
                </th>
                <th style={{ width: 120 }}>Case</th>
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '32px 16px', color: '#94A3B8' }}>
                    No threats match your filters.
                  </td>
                </tr>
              ) : (
                paged.map((a, i) => (
                  <tr key={i} style={{ cursor: 'pointer' }} onClick={() => setSelected(a)}>
                    <td><span className={`v3-badge ${a.level}`}>{a.level}</span></td>
                    <td className="mono">{a.entity}</td>
                    <td>
                      <span className="v3-score-badge" style={{ background: severityBg(a.level as string), color: severityColor(a.level as string) }}>
                        {a.score}
                      </span>
                    </td>
                    <td style={{ color: '#64748B', fontSize: 12 }}>{(a.confidence * 100).toFixed(0)}%</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                        {a.mitre_techniques.slice(0, 2).map((t) => (
                          <span key={t} className="v3-tag" style={{ fontSize: 10, padding: '1px 6px' }}>{t}</span>
                        ))}
                      </div>
                    </td>
                    <td style={{ color: '#64748B', fontSize: 12 }}>
                      {format(new Date(a.last_seen * 1000), 'MMM d, HH:mm')}
                    </td>
                    <td onClick={(e) => e.stopPropagation()}>
                      <AddToCase
                        findingType="alert"
                        summary={`Threat detected: ${a.entity}`}
                        severity={a.level as string}
                        data={{ entity: a.entity, reasons: a.reasons, mitre_techniques: a.mitre_techniques }}
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 16px', borderTop: '1px solid #E2E8F0', fontSize: 12, color: '#64748B',
          }}>
            <span>{sorted.length} threats · Page {currentPage} of {totalPages}</span>
            <div style={{ display: 'flex', gap: 4 }}>
              <button className="v3-btn v3-btn-outline" style={{ padding: '4px 8px' }} disabled={currentPage <= 1} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft size={14} />
              </button>
              <button className="v3-btn v3-btn-outline" style={{ padding: '4px 8px' }} disabled={currentPage >= totalPages} onClick={() => setPage((p) => p + 1)}>
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {selected && <DetailModal threat={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

export default Threats;
