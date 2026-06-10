/**
 * V5 Threats — Typographic hierarchy.
 * Oversized score number, bold entity, body-text reasons.
 * Minimal MITRE grid with thin borders.
 */
import React, { useState, useMemo } from 'react';
import { Search, X, ExternalLink } from 'lucide-react';
import { format } from 'date-fns';
import { mockAlerts, mockMitreMappings } from '../../../data/mockData';
import type { ThreatScore, MitreMapping } from '../../../types';

const scoreColor = (score: number): string => {
  if (score >= 85) return '#E54D2E';
  if (score >= 65) return '#F97316';
  if (score >= 40) return '#EAB308';
  return '#0D9488';
};

const severityLabel = (score: number): string => {
  if (score >= 85) return 'Critical';
  if (score >= 65) return 'High';
  if (score >= 40) return 'Medium';
  if (score >= 15) return 'Low';
  return 'Info';
};

/* MITRE Grid */
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
        <div key={tactic} style={{ marginBottom: 24 }}>
          <div className="v5-small-caps" style={{ marginBottom: 10 }}>
            {tactic.replace(/-/g, ' ')}
          </div>
          <div className="v5-mitre-grid">
            {techniques.map((t) => (
              <div key={t.technique_id} className="v5-mitre-cell">
                <div className="v5-mitre-cell-id">
                  <a
                    href={`https://attack.mitre.org/techniques/${t.technique_id.replace('.', '/')}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {t.technique_id} <ExternalLink size={9} style={{ display: 'inline', verticalAlign: 0 }} />
                  </a>
                </div>
                <div className="v5-mitre-cell-name">{t.technique_name}</div>
                <div className="v5-mitre-cell-meta">
                  {t.detection_count} detections · {(t.confidence * 100).toFixed(0)}% confidence
                </div>
                <div className="v5-mitre-cell-meta">
                  {t.affected_hosts.length} affected host{t.affected_hosts.length !== 1 ? 's' : ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

/* Threat card with typographic hierarchy */
const ThreatCard: React.FC<{ alert: ThreatScore; index: number }> = ({ alert }) => {
  const color = scoreColor(alert.score);
  const level = severityLabel(alert.score);

  return (
    <article
      style={{
        padding: '28px 0',
        borderBottom: '1px solid #E7E5E4',
      }}
    >
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '100px 1fr',
          gap: 20,
          alignItems: 'start',
        }}
      >
        {/* Oversized score */}
        <div style={{ textAlign: 'center' }}>
          <div
            style={{
              fontFamily: 'Playfair Display, Georgia, serif',
              fontWeight: 700,
              fontSize: 52,
              lineHeight: 1,
              color,
              letterSpacing: '-0.02em',
            }}
          >
            {alert.score}
          </div>
          <div
            style={{
              fontFamily: 'DM Sans, sans-serif',
              fontSize: 11,
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '0.06em',
              color,
              marginTop: 4,
            }}
          >
            {level}
          </div>
        </div>

        {/* Entity + reasons */}
        <div>
          <h3
            style={{
              fontFamily: 'IBM Plex Mono, monospace',
              fontSize: 17,
              fontWeight: 700,
              color: '#1C1917',
              margin: '0 0 8px',
            }}
          >
            {alert.entity}
          </h3>

          {/* Reasons as body text */}
          <div style={{ marginBottom: 10 }}>
            {alert.reasons.map((r, j) => (
              <p
                key={j}
                className="v5-body"
                style={{ margin: '0 0 3px', fontSize: 14, color: '#44403C' }}
              >
                {r}
              </p>
            ))}
          </div>

          {/* Indicators */}
          {alert.indicators.length > 0 && (
            <div
              style={{
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: 12,
                color: '#78716C',
                marginBottom: 8,
              }}
            >
              {alert.indicators.slice(0, 3).join(' · ')}
            </div>
          )}

          {/* MITRE tags + meta */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'flex-end',
              flexWrap: 'wrap',
              gap: 8,
            }}
          >
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
              {alert.mitre_techniques.map((t) => (
                <span key={t} className="v5-tag">
                  {t}
                </span>
              ))}
            </div>
            <span
              style={{
                fontFamily: 'IBM Plex Mono, monospace',
                fontSize: 12,
                color: '#A8A29E',
              }}
            >
              {alert.occurrence_count} events ·{' '}
              {format(new Date(alert.last_seen * 1000), 'MMM d, HH:mm')}
            </span>
          </div>
        </div>
      </div>
    </article>
  );
};

const Threats: React.FC = () => {
  const [search, setSearch] = useState('');

  const sorted = useMemo(() => {
    let data = [...mockAlerts].sort((a, b) => b.score - a.score);
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (a) =>
          a.entity.toLowerCase().includes(q) ||
          a.indicators.some((ind) => ind.toLowerCase().includes(q)) ||
          a.mitre_techniques.some((t) => t.toLowerCase().includes(q)) ||
          a.reasons.some((r) => r.toLowerCase().includes(q)),
      );
    }
    return data;
  }, [search]);

  const critical = sorted.filter((a) => a.score >= 85);
  const high = sorted.filter((a) => a.score >= 65 && a.score < 85);
  const rest = sorted.filter((a) => a.score < 65);

  return (
    <div>
      {/* Headline */}
      <header style={{ marginBottom: 8 }}>
        <h1 className="v5-headline v5-headline-lg">Threat Assessment</h1>
        <p className="v5-subhead">
          {mockAlerts.length} threats scored and mapped to MITRE ATT&CK framework
        </p>
      </header>

      <hr className="v5-rule" />

      {/* Search */}
      <div style={{ marginBottom: 32 }}>
        <div className="v5-search">
          <Search size={14} className="v5-search-icon" />
          <input
            placeholder="Search entities, techniques, or indicators…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="v5-search-clear" onClick={() => setSearch('')}>
              <X size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Critical threats */}
      {critical.length > 0 && (
        <section style={{ marginBottom: 0 }}>
          <div className="v5-small-caps" style={{ marginBottom: 8, color: '#E54D2E' }}>
            Critical · {critical.length}
          </div>
          {critical.map((a, i) => (
            <ThreatCard key={i} alert={a} index={i} />
          ))}
        </section>
      )}

      {/* High threats */}
      {high.length > 0 && (
        <section style={{ marginTop: 32, marginBottom: 0 }}>
          <div className="v5-small-caps" style={{ marginBottom: 8, color: '#F97316' }}>
            High · {high.length}
          </div>
          {high.map((a, i) => (
            <ThreatCard key={i} alert={a} index={i} />
          ))}
        </section>
      )}

      {/* Others */}
      {rest.length > 0 && (
        <section style={{ marginTop: 32, marginBottom: 0 }}>
          <div className="v5-small-caps" style={{ marginBottom: 8 }}>
            Medium & Below · {rest.length}
          </div>
          {rest.slice(0, 15).map((a, i) => (
            <ThreatCard key={i} alert={a} index={i} />
          ))}
          {rest.length > 15 && (
            <div className="v5-empty">
              + {rest.length - 15} additional lower-priority threats
            </div>
          )}
        </section>
      )}

      {/* MITRE ATT&CK Grid */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">MITRE ATT&CK Coverage</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          {mockMitreMappings.length} techniques observed across multiple tactical categories
        </p>
        <MitreGrid />
      </section>
    </div>
  );
};

export default Threats;
