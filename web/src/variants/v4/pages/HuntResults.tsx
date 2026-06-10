/**
 * V4 Hunt Results — Cyberpunk dossier, geometric accent headers, neon bullets, urgency glow.
 */
import React, { useMemo, useState } from 'react';
import { Search, Target, ExternalLink, ChevronDown, ChevronRight, FileText, AlertTriangle, CheckCircle2, Crosshair } from 'lucide-react';
import { format } from 'date-fns';
import type { HuntResult } from '../../../types';
import {
  mockAlerts,
  mockIndicators,
  mockMitreMappings,
} from '../../../data/mockData';

function generateHunts(): HuntResult[] {
  const BASE_TS = new Date('2026-01-15T08:00:00Z').getTime() / 1000;

  return [
    {
      hunt_id: 'HUNT-Σ-001',
      hunt_name: 'C2 Beacon Infrastructure Mapping',
      hunt_description: 'Systematic identification of command-and-control beacon patterns across all monitored subnets.',
      hypothesis: 'Adversaries are using periodic HTTPS beacons to maintain persistent C2 channels with external infrastructure.',
      total_events_analyzed: 284500,
      suspicious_events: 1247,
      threat_scores: mockAlerts.filter((a) => a.level === 'critical').slice(0, 4),
      indicators: mockIndicators.filter((i) => i.tags.includes('c2') || i.tags.includes('beacon')),
      mitre_mappings: mockMitreMappings.filter((m) => m.tactic === 'command-and-control').slice(0, 4),
      analysis_start: BASE_TS,
      analysis_end: BASE_TS + 72 * 3600,
      time_range_start: BASE_TS - 168 * 3600,
      time_range_end: BASE_TS + 72 * 3600,
      summary: 'Identified 8 high-confidence C2 beacon patterns across 6 internal hosts. Primary beacon targets include known Tor exit nodes and bulletproof hosting infrastructure.',
      recommendations: [
        'Immediately isolate 198.19.1.15 and 198.18.10.22',
        'Block outbound traffic to 185.220.101.34, 198.98.56.78, 162.247.74.27',
        'Deploy SSL inspection on port 443/8443 for affected subnets',
        'Conduct memory forensics on identified hosts',
        'Review DNS logs for DGA patterns correlated with beacon sources',
      ],
      false_positive_likelihood: 'Low',
      analyst: 'CYBER-AUTO',
      tags: ['c2', 'beacon', 'cobalt-strike', 'persistence', 'critical'],
      references: ['https://attack.mitre.org/techniques/T1071/001/', 'https://attack.mitre.org/techniques/T1573/'],
    },
    {
      hunt_id: 'HUNT-Σ-002',
      hunt_name: 'DNS Exfiltration Campaign',
      hunt_description: 'Detection and quantification of data exfiltration via DNS tunneling techniques.',
      hypothesis: 'Threat actors are leveraging DNS queries with encoded payloads to exfiltrate sensitive data.',
      total_events_analyzed: 1856000,
      suspicious_events: 4230,
      threat_scores: mockAlerts.filter((a) => a.reasons.some((r) => r.toLowerCase().includes('dns'))).slice(0, 3),
      indicators: mockIndicators.filter((i) => i.tags.includes('dns-tunnel') || i.tags.includes('exfiltration')),
      mitre_mappings: mockMitreMappings.filter((m) => m.tactic === 'exfiltration').slice(0, 3),
      analysis_start: BASE_TS + 2 * 3600,
      analysis_end: BASE_TS + 74 * 3600,
      time_range_start: BASE_TS - 336 * 3600,
      time_range_end: BASE_TS + 74 * 3600,
      summary: 'Confirmed DNS tunneling activity from 198.19.2.5 to multiple external resolvers. Estimated 7.2MB exfiltrated via high-entropy subdomain queries.',
      recommendations: [
        'Enforce DNS-over-HTTPS policy to internal resolvers only',
        'Implement DNS query length and entropy monitoring',
        'Block identified tunneling domains at DNS sinkhole',
        'Investigate 198.19.2.5 for installed exfiltration tooling',
      ],
      false_positive_likelihood: 'Very Low',
      analyst: 'CYBER-AUTO',
      tags: ['dns-tunnel', 'exfiltration', 'data-loss', 'high-entropy'],
      references: ['https://attack.mitre.org/techniques/T1048/003/', 'https://attack.mitre.org/techniques/T1071/004/'],
    },
    {
      hunt_id: 'HUNT-Σ-003',
      hunt_name: 'DGA Domain Resolution Activity',
      hunt_description: 'Identification of algorithmically generated domain name resolution attempts.',
      hypothesis: 'Compromised hosts are resolving DGA domains to establish fallback C2 channels.',
      total_events_analyzed: 923000,
      suspicious_events: 890,
      threat_scores: mockAlerts.filter((a) => a.mitre_techniques.includes('T1568.002')).slice(0, 3),
      indicators: mockIndicators.filter((i) => i.tags.includes('dga')),
      mitre_mappings: mockMitreMappings.filter((m) => m.technique_id === 'T1568.002'),
      analysis_start: BASE_TS + 4 * 3600,
      analysis_end: BASE_TS + 76 * 3600,
      time_range_start: BASE_TS - 168 * 3600,
      time_range_end: BASE_TS + 76 * 3600,
      summary: 'Detected 12 unique DGA domain patterns from 5 internal hosts. Domains exhibit high entropy (>3.8), elevated consonant ratios.',
      recommendations: [
        'Deploy real-time DGA detection at DNS resolver with ML-based classifier',
        'Quarantine 198.18.160.10',
        'Cross-reference DGA domains with threat intel feeds',
        'Implement DNS response policy zones for known DGA TLDs',
      ],
      false_positive_likelihood: 'Low',
      analyst: 'CYBER-AUTO',
      tags: ['dga', 'malware', 'emotet', 'domain-generation'],
      references: ['https://attack.mitre.org/techniques/T1568/002/'],
    },
    {
      hunt_id: 'HUNT-Σ-004',
      hunt_name: 'Lateral Movement & Internal Recon',
      hunt_description: 'Proactive hunt for internal network scanning and lateral movement indicators.',
      hypothesis: 'Post-compromise lateral movement is occurring via internal service scanning.',
      total_events_analyzed: 450000,
      suspicious_events: 312,
      threat_scores: mockAlerts.filter((a) => a.score >= 60 && a.score < 85).slice(0, 4),
      indicators: [],
      mitre_mappings: mockMitreMappings.filter((m) => m.tactic === 'discovery' || m.tactic === 'reconnaissance'),
      analysis_start: BASE_TS + 8 * 3600,
      analysis_end: BASE_TS + 80 * 3600,
      time_range_start: BASE_TS - 72 * 3600,
      time_range_end: BASE_TS + 80 * 3600,
      summary: 'Identified port scanning from 3 internal hosts targeting management ports (22, 3389, 5985). Correlates with C2 beacons from Hunt-001.',
      recommendations: [
        'Enable enhanced logging on targeted management services',
        'Implement network segmentation for affected subnets',
        'Review authentication logs for anomalous access patterns',
        'Deploy honeypots on unused IP space',
      ],
      false_positive_likelihood: 'Medium',
      analyst: 'CYBER-AUTO',
      tags: ['lateral-movement', 'recon', 'port-scan', 'post-exploitation'],
      references: ['https://attack.mitre.org/techniques/T1046/', 'https://attack.mitre.org/techniques/T1018/'],
    },
  ];
}

function urgencyColor(fp: string): string {
  switch (fp) {
    case 'Very Low': return '#FF00FF';
    case 'Low': return '#39FF14';
    case 'Medium': return '#FFFF00';
    case 'High': return '#FF6600';
    default: return '#00FFFF';
  }
}

function urgencyGlow(fp: string): string {
  const c = urgencyColor(fp);
  return `0 0 8px ${c}66, 0 0 20px ${c}22`;
}

function scoreColor(score: number): string {
  if (score >= 85) return '#FF00FF';
  if (score >= 65) return '#FF6600';
  if (score >= 40) return '#FFFF00';
  return '#39FF14';
}

const HuntResults: React.FC = () => {
  const hunts = useMemo(() => generateHunts(), []);
  const [expandedId, setExpandedId] = useState<string | null>(hunts[0]?.hunt_id || null);

  return (
    <div className="v4-hunt-container">
      {/* Page Header */}
      <div className="v4-dossier-header">
        <div className="v4-dossier-header-accent" />
        <Crosshair size={20} style={{ color: '#FF00FF', filter: 'drop-shadow(0 0 6px #FF00FF88)' }} />
        <h2 className="v4-dossier-title">HUNT DOSSIERS</h2>
        <span className="v4-dossier-count">{hunts.length} OPERATIONS COMPLETE</span>
      </div>

      {/* Stats Bar */}
      <div className="v4-hunt-stats-bar">
        <div className="v4-hunt-stat">
          <span className="v4-hunt-stat-value" style={{ color: '#00FFFF' }}>
            {hunts.reduce((s, h) => s + h.total_events_analyzed, 0).toLocaleString()}
          </span>
          <span className="v4-hunt-stat-label">EVENTS ANALYZED</span>
        </div>
        <div className="v4-hunt-stat">
          <span className="v4-hunt-stat-value" style={{ color: '#FF00FF' }}>
            {hunts.reduce((s, h) => s + h.suspicious_events, 0).toLocaleString()}
          </span>
          <span className="v4-hunt-stat-label">SUSPICIOUS</span>
        </div>
        <div className="v4-hunt-stat">
          <span className="v4-hunt-stat-value" style={{ color: '#39FF14' }}>
            {hunts.filter((h) => h.false_positive_likelihood === 'Low' || h.false_positive_likelihood === 'Very Low').length}/{hunts.length}
          </span>
          <span className="v4-hunt-stat-label">HIGH CONFIDENCE</span>
        </div>
      </div>

      {/* Hunt Cards */}
      {hunts.map((hunt) => {
        const isExpanded = expandedId === hunt.hunt_id;
        const uc = urgencyColor(hunt.false_positive_likelihood || 'Medium');

        return (
          <div
            key={hunt.hunt_id}
            className="v4-hunt-card"
            style={{
              borderColor: isExpanded ? uc + '44' : '#FF00FF11',
              boxShadow: isExpanded ? urgencyGlow(hunt.false_positive_likelihood || 'Medium') : 'none',
            }}
          >
            {/* Card Header */}
            <div
              className="v4-hunt-card-header"
              onClick={() => setExpandedId(isExpanded ? null : hunt.hunt_id)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                {isExpanded
                  ? <ChevronDown size={16} style={{ color: '#00FFFF', filter: 'drop-shadow(0 0 4px #00FFFF)' }} />
                  : <ChevronRight size={16} style={{ color: '#FF00FF66' }} />
                }
                <div>
                  <div className="v4-hunt-card-id">{hunt.hunt_id}</div>
                  <div className="v4-hunt-card-name">{hunt.hunt_name.toUpperCase()}</div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span className="v4-fp-badge" style={{ color: uc, borderColor: uc + '44', boxShadow: `0 0 6px ${uc}22` }}>
                  FP: {hunt.false_positive_likelihood}
                </span>
                <span className="v4-suspicious-count" style={{ color: '#FF00FF', textShadow: '0 0 8px #FF00FF66' }}>
                  {hunt.suspicious_events.toLocaleString()}
                </span>
              </div>
            </div>

            {/* Time + Tags */}
            <div className="v4-hunt-card-meta">
              <span style={{ color: '#00FFFF88' }}>
                {format(new Date(hunt.analysis_start * 1000), 'MMM d HH:mm')} → {format(new Date(hunt.analysis_end * 1000), 'MMM d HH:mm')}
              </span>
              <span style={{ color: '#ffffff22' }}>|</span>
              <span style={{ color: '#FF00FF88' }}>{hunt.total_events_analyzed.toLocaleString()} events</span>
            </div>

            <div className="v4-hunt-tags">
              {hunt.tags.map((tag) => (
                <span key={tag} className="v4-neon-tag">{tag}</span>
              ))}
            </div>

            {/* Summary */}
            <div className="v4-hunt-summary">{hunt.summary}</div>

            {/* Hypothesis */}
            <div className="v4-hunt-hypothesis">
              <span style={{ color: '#FFFF00', fontFamily: "'Orbitron', sans-serif", fontSize: 9, letterSpacing: 2 }}>HYPOTHESIS:</span>{' '}
              {hunt.hypothesis}
            </div>

            {/* Expanded */}
            {isExpanded && (
              <div className="v4-hunt-expanded">
                {/* Recommendations */}
                <div className="v4-hunt-section">
                  <div className="v4-hunt-section-header">
                    <div className="v4-section-accent-line" style={{ background: '#39FF14' }} />
                    <CheckCircle2 size={14} style={{ color: '#39FF14', filter: 'drop-shadow(0 0 4px #39FF14)' }} />
                    <span>RECOMMENDATIONS</span>
                  </div>
                  <ol className="v4-hunt-rec-list">
                    {hunt.recommendations.map((r, i) => (
                      <li key={i}>
                        <span className="v4-rec-bullet" style={{ color: '#39FF14', textShadow: '0 0 4px #39FF14' }}>▸</span>
                        {r}
                      </li>
                    ))}
                  </ol>
                </div>

                {/* Threat Entities */}
                {hunt.threat_scores.length > 0 && (
                  <div className="v4-hunt-section">
                    <div className="v4-hunt-section-header">
                      <div className="v4-section-accent-line" style={{ background: '#FF00FF' }} />
                      <AlertTriangle size={14} style={{ color: '#FF00FF', filter: 'drop-shadow(0 0 4px #FF00FF)' }} />
                      <span>THREAT ENTITIES</span>
                    </div>
                    <div className="v4-threat-entity-grid">
                      {hunt.threat_scores.map((ts, i) => (
                        <div key={`${ts.entity}-${i}`} className="v4-threat-entity-card">
                          <span className="v4-entity-score" style={{ color: scoreColor(ts.score), textShadow: `0 0 8px ${scoreColor(ts.score)}66` }}>
                            {ts.score}
                          </span>
                          <div>
                            <div className="v4-entity-name">{ts.entity}</div>
                            <div className="v4-entity-meta">{ts.level} · {ts.occurrence_count} occurrences</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* MITRE */}
                {hunt.mitre_mappings.length > 0 && (
                  <div className="v4-hunt-section">
                    <div className="v4-hunt-section-header">
                      <div className="v4-section-accent-line" style={{ background: '#00FFFF' }} />
                      <Target size={14} style={{ color: '#00FFFF', filter: 'drop-shadow(0 0 4px #00FFFF)' }} />
                      <span>MITRE ATT&CK COVERAGE</span>
                    </div>
                    <div className="v4-mitre-chips">
                      {hunt.mitre_mappings.map((m) => (
                        <a
                          key={m.technique_id}
                          href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="v4-mitre-chip"
                        >
                          {m.technique_id} — {m.technique_name}
                          <ExternalLink size={9} />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* References */}
                {hunt.references.length > 0 && (
                  <div className="v4-hunt-section">
                    <div className="v4-hunt-section-header">
                      <div className="v4-section-accent-line" style={{ background: '#FFFF00' }} />
                      <FileText size={14} style={{ color: '#FFFF00' }} />
                      <span>REFERENCES</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      {hunt.references.map((ref) => (
                        <a key={ref} href={ref} target="_blank" rel="noopener noreferrer" className="v4-ref-link">
                          {ref} <ExternalLink size={9} />
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};

export default HuntResults;
