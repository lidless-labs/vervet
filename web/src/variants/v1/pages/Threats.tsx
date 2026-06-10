/**
 * V1 Threats — Unified threat scores with ScoreGauge per row, detail panel on click.
 */
import React, { useState, useMemo } from 'react';
import { Shield } from 'lucide-react';
import { ScoreGauge } from '../../../components/charts';
import { ThreatDetailPanel, FilterBar, defaultFilterState } from '../../../components/data';
import type { ThreatScore, FilterState, ChartTheme } from '../../../types';
import { mockAlerts } from '../../../data/mockData';

const v1Theme: ChartTheme = {
  colors: {
    primary: '#06B6D4',
    secondary: '#8B5CF6',
    accent: '#F59E0B',
    danger: '#EF4444',
    warning: '#F59E0B',
    success: '#22C55E',
    info: '#3B82F6',
    background: '#0B1426',
    surface: '#162035',
    text: '#E2E8F0',
    textSecondary: '#94A3B8',
    gridLine: '#1E293B',
    series: ['#06B6D4'],
  },
  fonts: {
    family: "'Barlow Condensed', sans-serif",
    monoFamily: "'JetBrains Mono', monospace",
    sizeSmall: 10,
    sizeBase: 12,
    sizeLarge: 14,
  },
  spacing: { chartPadding: 16, legendGap: 10, tooltipPadding: 8 },
};

const PAGE_SIZE = 12;

const Threats: React.FC = () => {
  const [filters, setFilters] = useState<FilterState>(defaultFilterState);
  const [selectedThreat, setSelectedThreat] = useState<ThreatScore | null>(null);
  const [page, setPage] = useState(1);

  const sorted = useMemo(
    () => [...mockAlerts].sort((a, b) => b.score - a.score),
    [],
  );

  const filtered = useMemo(() => {
    let data = sorted;

    if (filters.search) {
      const q = filters.search.toLowerCase();
      data = data.filter(
        (t) =>
          t.entity.toLowerCase().includes(q) ||
          t.indicators.some((i) => i.toLowerCase().includes(q)) ||
          t.mitre_techniques.some((m) => m.toLowerCase().includes(q)) ||
          t.reasons.some((r) => r.toLowerCase().includes(q)),
      );
    }

    if (filters.severity.length > 0) {
      data = data.filter((t) => filters.severity.includes(t.level));
    }

    if (filters.minScore > 0 || filters.maxScore < 100) {
      data = data.filter((t) => t.score >= filters.minScore && t.score <= filters.maxScore);
    }

    return data;
  }, [sorted, filters]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const paged = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  // Severity summary
  const sevCounts = useMemo(() => {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    filtered.forEach((t) => { c[t.level as keyof typeof c]++; });
    return c;
  }, [filtered]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="v1-section-title">
        <Shield size={22} />
        Unified Threat Scores
        <span style={{ fontSize: 12, fontWeight: 400, color: '#64748B', marginLeft: 8 }}>
          {filtered.length} entities
        </span>
      </div>

      {/* Severity summary bar */}
      <div style={{ display: 'flex', gap: 12 }}>
        {Object.entries(sevCounts).map(([sev, count]) => (
          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
            <span className={`v1-sev-pill ${sev}`}>{sev}</span>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 700, color: '#E2E8F0' }}>{count}</span>
          </div>
        ))}
      </div>

      {/* Filter Bar */}
      <FilterBar
        filters={filters}
        onChange={(f) => { setFilters(f); setPage(1); }}
        showSeverity={true}
        showScoreRange={true}
        placeholder="Search by entity, indicator, MITRE technique…"
      />

      {/* Threat Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 10 }}>
        {paged.map((threat) => (
          <ThreatRow
            key={`${threat.entity}-${threat.first_seen}`}
            threat={threat}
            theme={v1Theme}
            onClick={() => setSelectedThreat(threat)}
          />
        ))}
      </div>

      {paged.length === 0 && (
        <div style={{ textAlign: 'center', padding: 40, color: '#64748B' }}>
          No threats match current filters.
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, color: '#64748B', padding: '4px 0' }}>
          <span>{filtered.length} threats · Page {currentPage} of {totalPages}</span>
          <div style={{ display: 'flex', gap: 4 }}>
            <button
              disabled={currentPage <= 1}
              onClick={() => setPage((p) => p - 1)}
              style={{
                padding: '4px 10px',
                fontSize: 11,
                background: 'rgba(6,182,212,0.08)',
                border: '1px solid rgba(6,182,212,0.15)',
                borderRadius: 3,
                color: currentPage <= 1 ? '#334155' : '#94A3B8',
                cursor: currentPage <= 1 ? 'not-allowed' : 'pointer',
              }}
            >
              Prev
            </button>
            <button
              disabled={currentPage >= totalPages}
              onClick={() => setPage((p) => p + 1)}
              style={{
                padding: '4px 10px',
                fontSize: 11,
                background: 'rgba(6,182,212,0.08)',
                border: '1px solid rgba(6,182,212,0.15)',
                borderRadius: 3,
                color: currentPage >= totalPages ? '#334155' : '#94A3B8',
                cursor: currentPage >= totalPages ? 'not-allowed' : 'pointer',
              }}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {/* Detail Panel */}
      <ThreatDetailPanel
        threat={selectedThreat}
        onClose={() => setSelectedThreat(null)}
      />
    </div>
  );
};

const ThreatRow: React.FC<{
  threat: ThreatScore;
  theme: ChartTheme;
  onClick: () => void;
}> = ({ threat, theme, onClick }) => {
  const t = threat;
  return (
    <div
      className="v1-panel"
      style={{ cursor: 'pointer', transition: 'border-color 0.15s' }}
      onClick={onClick}
      onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'rgba(6,182,212,0.35)')}
      onMouseLeave={(e) => (e.currentTarget.style.borderColor = '')}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px' }}>
        {/* Score Gauge */}
        <div style={{ flexShrink: 0 }}>
          <ScoreGauge score={t.score} theme={theme} size={80} showValue={true} />
        </div>

        {/* Info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: '#E2E8F0', fontWeight: 600 }}>
              {t.entity}
            </span>
            <span className={`v1-sev-pill ${t.level}`}>{t.level}</span>
          </div>

          <div style={{ fontSize: 11, color: '#94A3B8', marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {t.reasons[0]}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            {t.mitre_techniques.slice(0, 3).map((m) => (
              <span key={m} className="v1-mitre-tag">{m}</span>
            ))}
            <span style={{ fontSize: 10, color: '#64748B' }}>
              {t.occurrence_count} occ · {(t.confidence * 100).toFixed(0)}% conf
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Threats;
