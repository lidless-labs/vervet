/**
 * V2 Threats — > severity indicators, MITRE text-grid, indented log evidence.
 */
import React, { useState, useMemo } from 'react';
import { format } from 'date-fns';
import { useAlerts, useMitreMappings } from '../../../hooks/useApi';
import { mockAlerts, mockMitreMappings } from '../../../data/mockData';
import type { MitreMapping } from '../../../types';

/* ═══ Panel ═══ */
const Panel: React.FC<{ title: string; pid?: number; children: React.ReactNode }> = ({
  title, pid, children,
}) => (
  <div className="v2-panel">
    <div className="v2-panel-header">
      <span>[{title} - pid:{pid ?? Math.floor(Math.random() * 9000 + 1000)}]</span>
      <div className="v2-panel-dots">
        <span className="v2-panel-dot red" />
        <span className="v2-panel-dot amber" />
        <span className="v2-panel-dot green" />
      </div>
    </div>
    <div className="v2-panel-body">{children}</div>
  </div>
);

/* ═══ Severity indicator with > prefix ═══ */
const SeverityIndicator: React.FC<{ level: string }> = ({ level }) => {
  const arrows = level === 'critical' ? '>>>' : level === 'high' ? '>>' : '>';
  return (
    <span className={`v2-severity ${level}`}>
      <span className="v2-severity-prefix">{arrows}</span>
      {level.toUpperCase()}
    </span>
  );
};

/* ═══ Score bar ═══ */
const ScoreBar: React.FC<{ score: number; width?: number }> = ({ score, width = 10 }) => {
  const filled = Math.round((score / 100) * width);
  const empty = width - filled;
  const cls = score >= 85 ? 'critical' : score >= 65 ? 'amber' : '';
  return (
    <span className={`v2-progress-bar ${cls}`}>
      <span className="v2-progress-filled">{'█'.repeat(filled)}</span>
      <span className="v2-progress-empty">{'░'.repeat(empty)}</span>
      <span className="v2-dim" style={{ marginLeft: 4 }}>{score}</span>
    </span>
  );
};

/* ═══ MITRE cell ═══ */
const MitreCell: React.FC<{ mapping: MitreMapping }> = ({ mapping }) => (
  <div className="v2-mitre-cell">
    <div>
      <span className="v2-mitre-id">{mapping.technique_id}</span>
      <span className="v2-mitre-name">{mapping.technique_name}</span>
      <span className="v2-mitre-count">×{mapping.detection_count}</span>
    </div>
    <div className="v2-mitre-tactic">{mapping.tactic.replace(/-/g, ' ')}</div>
    <div style={{ marginTop: 4 }}>
      <span className="v2-dim" style={{ fontSize: 10 }}>
        conf={((mapping.confidence) * 100).toFixed(0)}% │ hosts=[{mapping.affected_hosts.slice(0, 2).join(', ')}]
      </span>
    </div>
  </div>
);

const Threats: React.FC = () => {
  const { data: alerts } = useAlerts();
  const { data: mitre } = useMitreMappings();
  const al = alerts ?? mockAlerts;
  const mm = mitre ?? mockMitreMappings;

  const [selectedLevel, setSelectedLevel] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  /* severity counts */
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    al.forEach((a) => { c[a.level] = (c[a.level] || 0) + 1; });
    return c;
  }, [al]);

  /* filter by severity */
  const filtered = useMemo(
    () => selectedLevel ? al.filter((a) => a.level === selectedLevel) : al,
    [al, selectedLevel],
  );

  const sorted = useMemo(
    () => [...filtered].sort((a, b) => b.score - a.score),
    [filtered],
  );

  const levels = ['critical', 'high', 'medium', 'low', 'info'];

  return (
    <>
      <div className="v2-heading">
        ╔═ THREAT MAP ══════════════════════════════════════════╗
      </div>

      {/* Severity selector */}
      <Panel title="SEVERITY_FILTER" pid={8101}>
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          <button
            className={`v2-tab ${!selectedLevel ? 'active' : ''}`}
            onClick={() => setSelectedLevel(null)}
            style={{ fontSize: 11 }}
          >
            [ALL] {al.length}
          </button>
          {levels.map((lev) => (
            <button
              key={lev}
              className={`v2-tab ${selectedLevel === lev ? 'active' : ''}`}
              onClick={() => setSelectedLevel(selectedLevel === lev ? null : lev)}
              style={{ fontSize: 11 }}
            >
              <span className={`v2-severity ${lev}`} style={{ marginRight: 4 }}>
                {lev === 'critical' ? '>>>' : lev === 'high' ? '>>' : '>'}
              </span>
              [{lev.toUpperCase()}] {counts[lev] ?? 0}
            </button>
          ))}
        </div>
      </Panel>

      {/* MITRE ATT&CK text grid */}
      <Panel title="MITRE_MATRIX" pid={8102}>
        <div className="v2-heading-section">MITRE ATT&CK Technique Coverage</div>
        <div className="v2-mitre-grid">
          {mm.map((m) => (
            <MitreCell key={m.technique_id} mapping={m} />
          ))}
        </div>
      </Panel>

      {/* Threat listing with indented evidence */}
      <Panel title="THREAT_LOG" pid={8103}>
        <div className="v2-dim" style={{ fontSize: 11, marginBottom: 8 }}>
          showing {sorted.length} threats | sorted by score desc
        </div>

        <div style={{ maxHeight: 600, overflowY: 'auto' }}>
          {sorted.map((a, i) => {
            const isExpanded = expanded === `${a.entity}-${i}`;
            return (
              <div key={`${a.entity}-${i}`} style={{ marginBottom: 8 }}>
                {/* Main threat line */}
                <div
                  style={{
                    display: 'flex',
                    gap: 8,
                    alignItems: 'center',
                    fontSize: 12,
                    cursor: 'pointer',
                    padding: '4px 0',
                    borderBottom: '1px solid rgba(10,61,10,0.2)',
                  }}
                  onClick={() => setExpanded(isExpanded ? null : `${a.entity}-${i}`)}
                >
                  <SeverityIndicator level={a.level} />
                  <span className="v2-amber v2-bold" style={{ minWidth: 130 }}>
                    {a.entity}
                  </span>
                  <span className="v2-dim">│</span>
                  <ScoreBar score={a.score} />
                  <span className="v2-dim">│</span>
                  <span className="v2-dim">
                    {a.mitre_techniques.join(', ') || '—'}
                  </span>
                  <span style={{ marginLeft: 'auto' }} className="v2-dim">
                    {format(new Date(a.last_seen * 1000), 'MM-dd HH:mm')}
                  </span>
                </div>

                {/* Expanded evidence */}
                {isExpanded && (
                  <div className="v2-evidence" style={{ marginLeft: 24 }}>
                    <div className="v2-evidence-line">
                      <span className="highlight">entity_type</span> = {a.entity_type}
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">score</span> = {a.score}
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">confidence</span> = {(a.confidence * 100).toFixed(0)}%
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">occurrences</span> = {a.occurrence_count}
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">first_seen</span> = {format(new Date(a.first_seen * 1000), 'yyyy-MM-dd HH:mm:ss')}
                    </div>
                    <div className="v2-evidence-line">
                      <span className="highlight">last_seen</span> = {format(new Date(a.last_seen * 1000), 'yyyy-MM-dd HH:mm:ss')}
                    </div>

                    {/* Indicators */}
                    {a.indicators.length > 0 && (
                      <div className="v2-evidence-line">
                        <span className="highlight">indicators</span> = [{a.indicators.join(', ')}]
                      </div>
                    )}

                    {/* Related */}
                    {a.related_ips.length > 0 && (
                      <div className="v2-evidence-line">
                        <span className="highlight">related_ips</span> = [{a.related_ips.join(', ')}]
                      </div>
                    )}
                    {a.related_domains.length > 0 && (
                      <div className="v2-evidence-line">
                        <span className="highlight">related_domains</span> = [{a.related_domains.join(', ')}]
                      </div>
                    )}

                    {/* MITRE */}
                    {a.mitre_techniques.length > 0 && (
                      <div className="v2-evidence-line">
                        <span className="highlight">mitre</span> ={' '}
                        {a.mitre_techniques.map((t) => (
                          <span key={t} className="v2-tag amber" style={{ marginLeft: 2 }}>{t}</span>
                        ))}
                      </div>
                    )}

                    <div className="v2-divider" />

                    {/* Reasons as log evidence */}
                    <div style={{ fontSize: 11 }} className="v2-dim">
                      detection_reasons:
                    </div>
                    {a.reasons.map((r, ri) => (
                      <div key={ri} className="v2-evidence-line">
                        <span style={{ color: '#00FF41' }}>  [{String(ri + 1).padStart(2, '0')}]</span> {r}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>
    </>
  );
};

export default Threats;
