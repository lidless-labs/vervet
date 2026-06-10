/**
 * V5 Hunt Results — Intelligence Brief
 * Serif headlines, justified body, blockquote evidence,
 * numbered recommendations, clean MITRE tags.
 */
import React from 'react';
import { format } from 'date-fns';
import { ExternalLink } from 'lucide-react';
import {
  mockAlerts,
  mockIndicators,
  mockMitreMappings,
  mockDashboardStats,
  mockBeacons,
  mockDnsThreats,
} from '../../../data/mockData';

const stats = mockDashboardStats;

const severityColor = (level: string): string => {
  const map: Record<string, string> = {
    critical: '#E54D2E',
    high: '#F97316',
    medium: '#EAB308',
    low: '#4F46E5',
    info: '#A8A29E',
  };
  return map[level] || '#A8A29E';
};

const HuntResults: React.FC = () => {
  const criticalAlerts = mockAlerts.filter((a) => a.level === ('critical' as any));
  const topBeacons = [...mockBeacons]
    .sort((a, b) => b.beacon_score - a.beacon_score)
    .slice(0, 5);
  const topDns = [...mockDnsThreats]
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const recommendations = [
    'Immediately isolate hosts 198.19.1.15 and 198.19.2.5 — confirmed C2 beacon and DNS exfiltration activity.',
    'Block outbound connections to 203.0.113.105 and 203.0.113.118 at the perimeter firewall.',
    'Investigate DGA patterns from 198.18.160.10 — possible Emotet variant infection requiring forensic disk imaging.',
    'Review SSL certificates on port 443 connections to 203.0.113.109 — certificate common name mismatch detected.',
    'Deploy additional monitoring for DNS TXT record queries originating from the 198.19.2.0/24 subnet.',
    'Escalate Tor exit node communications from 198.19.3.8 to the incident response team for containment.',
    'Update threat intelligence feeds to include the newly discovered C2 domains and associated infrastructure.',
    'Schedule full forensic analysis of all hosts with beacon scores at or above 90.',
  ];

  return (
    <div>
      {/* Report masthead */}
      <header style={{ marginBottom: 8, textAlign: 'center' }}>
        <div
          className="v5-small-caps"
          style={{ marginBottom: 12, color: '#E54D2E', letterSpacing: '0.12em' }}
        >
          Intelligence Brief
        </div>
        <h1 className="v5-headline v5-headline-xl" style={{ marginBottom: 8 }}>
          Network Threat Hunt Report
        </h1>
        <p className="v5-subhead" style={{ maxWidth: 640, margin: '0 auto' }}>
          Comprehensive analysis of 72-hour network traffic patterns,
          beacon activity, and DNS-based threats
        </p>
        <div
          style={{
            fontFamily: 'IBM Plex Mono, monospace',
            fontSize: 12,
            color: '#A8A29E',
            marginTop: 12,
          }}
        >
          {format(new Date(), 'MMMM d, yyyy · HH:mm z')}
        </div>
      </header>

      <hr className="v5-rule" />

      {/* Key figures */}
      <div className="v5-grid-3" style={{ marginBottom: 0 }}>
        <div className="v5-metric" style={{ textAlign: 'center' }}>
          <div className="v5-metric-number vermillion">{stats.criticalAlerts}</div>
          <div className="v5-metric-label">Critical Findings</div>
        </div>
        <div className="v5-metric" style={{ textAlign: 'center' }}>
          <div className="v5-metric-number">{stats.totalAlerts}</div>
          <div className="v5-metric-label">Total Detections</div>
        </div>
        <div className="v5-metric" style={{ textAlign: 'center' }}>
          <div className="v5-metric-number indigo">{stats.topMitreTechniques.length}</div>
          <div className="v5-metric-label">MITRE Techniques</div>
        </div>
      </div>

      {/* Executive Summary */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">Executive Summary</h2>
        <div className="v5-body v5-justified" style={{ maxWidth: 780 }}>
          <p style={{ marginBottom: 16 }}>
            This intelligence brief presents findings from an automated threat hunt conducted
            over a 72-hour observation window. The analysis examined{' '}
            <strong>{stats.totalAlerts} threat detections</strong> across{' '}
            <strong>{stats.uniqueSourceIPs} unique internal hosts</strong> communicating with{' '}
            <strong>{stats.uniqueDestIPs} external destinations</strong>.
          </p>
          <p style={{ marginBottom: 16 }}>
            The investigation identified{' '}
            <strong style={{ color: '#E54D2E' }}>
              {stats.criticalAlerts} critical-severity
            </strong>{' '}
            and{' '}
            <strong style={{ color: '#F97316' }}>{stats.highAlerts} high-severity</strong>{' '}
            threats requiring immediate operational response. The mean composite threat score
            across all detections is{' '}
            <strong>{stats.averageThreatScore.toFixed(1)}</strong>, with an upward trend of{' '}
            <strong>{stats.alertsTrend}%</strong> compared to the previous analysis period.
          </p>
          <p>
            Beacon analysis identified <strong>{stats.totalBeacons} periodic communication
            patterns</strong>, while DNS threat detection surfaced{' '}
            <strong>{stats.totalDnsThreats} suspicious DNS behaviors</strong> including
            tunneling, domain generation algorithms, and fast-flux networks.
          </p>
        </div>
      </section>

      {/* Critical Findings */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">Critical Findings</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          {criticalAlerts.length} detections requiring immediate response
        </p>

        {criticalAlerts.map((alert, i) => (
          <article
            key={i}
            style={{
              padding: '20px 0',
              borderBottom: '1px solid #E7E5E4',
            }}
          >
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: '72px 1fr',
                gap: 16,
                alignItems: 'start',
              }}
            >
              <div
                style={{
                  fontFamily: 'Playfair Display, Georgia, serif',
                  fontWeight: 700,
                  fontSize: 36,
                  lineHeight: 1,
                  color: '#E54D2E',
                }}
              >
                {alert.score}
              </div>
              <div>
                <h3
                  style={{
                    fontFamily: 'IBM Plex Mono, monospace',
                    fontSize: 16,
                    fontWeight: 700,
                    color: '#1C1917',
                    margin: '0 0 8px',
                  }}
                >
                  {alert.entity}
                </h3>

                {/* Evidence as blockquote */}
                <div className="v5-blockquote">
                  {alert.reasons.map((r, j) => (
                    <span key={j}>
                      {r}
                      {j < alert.reasons.length - 1 ? '. ' : '.'}
                    </span>
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
                    Associated: {alert.indicators.join(' · ')}
                  </div>
                )}

                {/* MITRE tags */}
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {alert.mitre_techniques.map((t) => (
                    <span key={t} className="v5-tag">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </article>
        ))}
      </section>

      {/* Indicators of Compromise */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">Indicators of Compromise</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          Key indicators extracted from the analysis
        </p>

        <table className="v5-table">
          <thead>
            <tr>
              <th style={{ width: 80 }}>Severity</th>
              <th style={{ width: 90 }}>Type</th>
              <th>Value</th>
              <th>Description</th>
              <th style={{ width: 100 }}>Source</th>
            </tr>
          </thead>
          <tbody>
            {mockIndicators.map((ind, i) => (
              <tr key={i}>
                <td>
                  <span
                    style={{
                      fontSize: 12,
                      fontWeight: 600,
                      color: severityColor(ind.severity as string),
                      textTransform: 'capitalize',
                    }}
                  >
                    {ind.severity as string}
                  </span>
                </td>
                <td>
                  <span
                    style={{
                      fontFamily: 'IBM Plex Mono, monospace',
                      fontSize: 11,
                      color: '#78716C',
                    }}
                  >
                    {ind.indicator_type as string}
                  </span>
                </td>
                <td
                  className="mono"
                  style={{ fontWeight: 500, fontSize: 13, wordBreak: 'break-all' }}
                >
                  {ind.value}
                </td>
                <td
                  style={{
                    fontSize: 13,
                    color: '#78716C',
                    maxWidth: 260,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {ind.description}
                </td>
                <td style={{ fontSize: 12, color: '#A8A29E' }}>{ind.source}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Top Beacons */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">High-Confidence Beacons</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          Top {topBeacons.length} periodic communication patterns ranked by score
        </p>

        <table className="v5-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Destination</th>
              <th style={{ width: 64 }}>Score</th>
              <th style={{ width: 80 }}>Interval</th>
              <th style={{ width: 72 }}>Jitter</th>
              <th style={{ width: 80 }}>Conns</th>
            </tr>
          </thead>
          <tbody>
            {topBeacons.map((b) => (
              <tr key={b.id}>
                <td className="mono">{b.src_ip}</td>
                <td className="mono">
                  {b.dst_ip}:{b.dst_port}
                </td>
                <td>
                  <span className="v5-data-value" style={{ color: b.beacon_score >= 85 ? '#E54D2E' : b.beacon_score >= 65 ? '#F97316' : '#0D9488' }}>
                    {b.beacon_score}
                  </span>
                </td>
                <td className="mono" style={{ color: '#78716C' }}>
                  {b.avg_interval_seconds}s
                </td>
                <td className="mono" style={{ color: '#78716C' }}>
                  {b.jitter_pct.toFixed(1)}%
                </td>
                <td className="mono" style={{ color: '#78716C' }}>
                  {b.connection_count}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* Top DNS Threats */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">DNS Threat Summary</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          Highest-scored DNS-based detections
        </p>

        {topDns.map((t) => (
          <div
            key={t.id}
            style={{
              padding: '14px 0',
              borderBottom: '1px solid #E7E5E4',
              display: 'grid',
              gridTemplateColumns: '50px 1fr auto',
              gap: 14,
              alignItems: 'start',
            }}
          >
            <span
              style={{
                fontFamily: 'Playfair Display, Georgia, serif',
                fontWeight: 700,
                fontSize: 24,
                lineHeight: 1,
                color:
                  t.score >= 85
                    ? '#E54D2E'
                    : t.score >= 65
                    ? '#F97316'
                    : '#0D9488',
              }}
            >
              {t.score}
            </span>
            <div>
              <div
                style={{
                  fontFamily: 'IBM Plex Mono, monospace',
                  fontSize: 14,
                  fontWeight: 600,
                  color: '#1C1917',
                  wordBreak: 'break-all',
                  marginBottom: 2,
                }}
              >
                {t.domain}
              </div>
              <div style={{ fontSize: 13, color: '#78716C' }}>
                {t.threat_type.replace('_', ' ')} · {t.src_ip} ·{' '}
                {t.query_count.toLocaleString()} queries
              </div>
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              {t.mitre_techniques.map((tech) => (
                <span key={tech} className="v5-tag">
                  {tech}
                </span>
              ))}
            </div>
          </div>
        ))}
      </section>

      {/* MITRE ATT&CK Coverage */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">MITRE ATT&CK Coverage</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          {mockMitreMappings.length} techniques mapped across tactical categories
        </p>

        <div className="v5-mitre-grid">
          {mockMitreMappings.map((m) => (
            <div key={m.technique_id} className="v5-mitre-cell">
              <div className="v5-mitre-cell-id">
                <a
                  href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {m.technique_id}{' '}
                  <ExternalLink
                    size={9}
                    style={{ display: 'inline', verticalAlign: 0 }}
                  />
                </a>
              </div>
              <div className="v5-mitre-cell-name">{m.technique_name}</div>
              <div className="v5-mitre-cell-meta">
                {m.tactic.replace(/-/g, ' ')} · {m.detection_count} detections
              </div>
              <div className="v5-mitre-cell-meta">
                {(m.confidence * 100).toFixed(0)}% confidence · {m.affected_hosts.length} hosts
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Recommendations */}
      <section className="v5-section">
        <h2 className="v5-headline v5-headline-md">Recommendations</h2>
        <p className="v5-subhead" style={{ marginBottom: 24 }}>
          Prioritized response actions based on threat severity and operational impact
        </p>

        <ol className="v5-numbered-list">
          {recommendations.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ol>
      </section>

      {/* Report footer */}
      <footer
        style={{
          borderTop: '2px solid #1C1917',
          padding: '20px 0 40px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div>
          <div
            style={{
              fontFamily: 'Playfair Display, Georgia, serif',
              fontWeight: 700,
              fontSize: 14,
              color: '#1C1917',
              marginBottom: 4,
            }}
          >
            Vervet — Minimal Analyst
          </div>
          <div style={{ fontSize: 12, color: '#A8A29E' }}>
            Automated Threat Hunt Intelligence Brief ·{' '}
            {format(new Date(), 'MMMM d, yyyy HH:mm:ss')}
          </div>
        </div>
        <button
          onClick={() => window.print()}
          style={{
            fontFamily: 'DM Sans, sans-serif',
            fontSize: 13,
            color: '#78716C',
            background: 'none',
            border: '1px solid #E7E5E4',
            padding: '6px 16px',
            cursor: 'pointer',
            transition: 'color 0.15s, border-color 0.15s',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = '#1C1917';
            e.currentTarget.style.borderColor = '#1C1917';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = '#78716C';
            e.currentTarget.style.borderColor = '#E7E5E4';
          }}
        >
          Print Report
        </button>
      </footer>
    </div>
  );
};

export default HuntResults;
