/**
 * V1 Hunt Results — Hunt result cards with evidence, recommendations, MITRE tags.
 * Generates mock HuntResult data from existing alerts/indicators/MITRE mappings.
 */
import React, { useMemo, useState } from 'react';
import { Search, Target, ExternalLink, ChevronDown, ChevronRight, FileText, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { format } from 'date-fns';
import type { HuntResult } from '../../../types';
import {
  mockAlerts,
  mockIndicators,
  mockMitreMappings,
} from '../../../data/mockData';

/** Synthesize hunt results from existing mock data */
function generateHunts(): HuntResult[] {
  const BASE_TS = new Date('2026-01-15T08:00:00Z').getTime() / 1000;

  const hunts: HuntResult[] = [
    {
      hunt_id: 'hunt-001',
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
      summary: 'Identified 8 high-confidence C2 beacon patterns across 6 internal hosts. Primary beacon targets include known Tor exit nodes and bulletproof hosting infrastructure. Beacon intervals range from 30s to 600s with jitter patterns consistent with Cobalt Strike and custom implants.',
      recommendations: [
        'Immediately isolate 198.19.1.15 and 198.18.10.22 — highest confidence C2 activity',
        'Block outbound traffic to 185.220.101.34, 198.98.56.78, 162.247.74.27 at perimeter',
        'Deploy SSL inspection on port 443/8443 for affected subnets',
        'Conduct memory forensics on identified hosts for implant artifacts',
        'Review DNS logs for DGA patterns correlated with beacon sources',
      ],
      false_positive_likelihood: 'Low',
      analyst: 'NOC-AUTO',
      tags: ['c2', 'beacon', 'cobalt-strike', 'persistence', 'critical'],
      references: [
        'https://attack.mitre.org/techniques/T1071/001/',
        'https://attack.mitre.org/techniques/T1573/',
      ],
    },
    {
      hunt_id: 'hunt-002',
      hunt_name: 'DNS Exfiltration Campaign',
      hunt_description: 'Detection and quantification of data exfiltration via DNS tunneling techniques.',
      hypothesis: 'Threat actors are leveraging DNS queries with encoded payloads to exfiltrate sensitive data, bypassing traditional DLP controls.',
      total_events_analyzed: 1856000,
      suspicious_events: 4230,
      threat_scores: mockAlerts.filter((a) => a.reasons.some((r) => r.toLowerCase().includes('dns'))).slice(0, 3),
      indicators: mockIndicators.filter((i) => i.tags.includes('dns-tunnel') || i.tags.includes('exfiltration')),
      mitre_mappings: mockMitreMappings.filter((m) => m.tactic === 'exfiltration').slice(0, 3),
      analysis_start: BASE_TS + 2 * 3600,
      analysis_end: BASE_TS + 74 * 3600,
      time_range_start: BASE_TS - 336 * 3600,
      time_range_end: BASE_TS + 74 * 3600,
      summary: 'Confirmed DNS tunneling activity from 198.19.2.5 to multiple external resolvers. Estimated 7.2MB exfiltrated via high-entropy subdomain queries to data.exfil.tunnel.example.com. Query patterns indicate automated tooling with base64-encoded payloads fragmented across TXT record requests.',
      recommendations: [
        'Enforce DNS-over-HTTPS (DoH) policy to internal resolvers only',
        'Implement DNS query length and entropy monitoring at resolver level',
        'Block identified tunneling domains at DNS sinkhole',
        'Investigate 198.19.2.5 for installed exfiltration tooling',
        'Review outbound TXT record queries exceeding 100 chars',
      ],
      false_positive_likelihood: 'Very Low',
      analyst: 'NOC-AUTO',
      tags: ['dns-tunnel', 'exfiltration', 'data-loss', 'high-entropy'],
      references: [
        'https://attack.mitre.org/techniques/T1048/003/',
        'https://attack.mitre.org/techniques/T1071/004/',
      ],
    },
    {
      hunt_id: 'hunt-003',
      hunt_name: 'DGA Domain Resolution Activity',
      hunt_description: 'Identification of algorithmically generated domain name resolution attempts indicative of malware C2 rendezvous.',
      hypothesis: 'Compromised hosts are resolving DGA domains to establish fallback C2 channels when primary infrastructure is blocked.',
      total_events_analyzed: 923000,
      suspicious_events: 890,
      threat_scores: mockAlerts.filter((a) => a.mitre_techniques.includes('T1568.002')).slice(0, 3),
      indicators: mockIndicators.filter((i) => i.tags.includes('dga')),
      mitre_mappings: mockMitreMappings.filter((m) => m.technique_id === 'T1568.002'),
      analysis_start: BASE_TS + 4 * 3600,
      analysis_end: BASE_TS + 76 * 3600,
      time_range_start: BASE_TS - 168 * 3600,
      time_range_end: BASE_TS + 76 * 3600,
      summary: 'Detected 12 unique DGA domain patterns from 5 internal hosts. Domains exhibit high entropy (>3.8), elevated consonant ratios, and cluster across .ru, .cn, .biz, and .info TLDs. Multiple NXDOMAIN responses followed by successful resolution suggest active domain cycling consistent with Emotet/Trickbot DGA families.',
      recommendations: [
        'Deploy real-time DGA detection at DNS resolver with ML-based classifier',
        'Quarantine 198.18.160.10 — highest DGA query volume',
        'Cross-reference DGA domains with threat intel feeds for malware family attribution',
        'Implement DNS response policy zones (RPZ) for known DGA TLDs',
      ],
      false_positive_likelihood: 'Low',
      analyst: 'NOC-AUTO',
      tags: ['dga', 'malware', 'emotet', 'domain-generation'],
      references: [
        'https://attack.mitre.org/techniques/T1568/002/',
      ],
    },
    {
      hunt_id: 'hunt-004',
      hunt_name: 'Lateral Movement & Internal Reconnaissance',
      hunt_description: 'Proactive hunt for internal network scanning, service discovery, and lateral movement indicators.',
      hypothesis: 'Post-compromise lateral movement is occurring via internal network service scanning and remote access tool deployment.',
      total_events_analyzed: 450000,
      suspicious_events: 312,
      threat_scores: mockAlerts.filter((a) => a.score >= 60 && a.score < 85).slice(0, 4),
      indicators: [],
      mitre_mappings: mockMitreMappings.filter((m) => m.tactic === 'discovery' || m.tactic === 'reconnaissance'),
      analysis_start: BASE_TS + 8 * 3600,
      analysis_end: BASE_TS + 80 * 3600,
      time_range_start: BASE_TS - 72 * 3600,
      time_range_end: BASE_TS + 80 * 3600,
      summary: 'Identified port scanning patterns from 3 internal hosts targeting common management ports (22, 3389, 5985). Activity correlates with C2 beacon sources identified in Hunt-001, suggesting post-exploitation enumeration phase. No confirmed credential abuse detected yet.',
      recommendations: [
        'Enable enhanced logging on targeted management services',
        'Implement network segmentation between identified scanner hosts and sensitive subnets',
        'Review authentication logs for anomalous RDP/SSH access patterns',
        'Deploy honeypots on unused IP space to detect lateral movement attempts',
      ],
      false_positive_likelihood: 'Medium',
      analyst: 'NOC-AUTO',
      tags: ['lateral-movement', 'recon', 'port-scan', 'post-exploitation'],
      references: [
        'https://attack.mitre.org/techniques/T1046/',
        'https://attack.mitre.org/techniques/T1018/',
      ],
    },
  ];

  return hunts;
}

function scoreClass(score: number): string {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

const HuntResults: React.FC = () => {
  const hunts = useMemo(() => generateHunts(), []);
  const [expandedId, setExpandedId] = useState<string | null>(hunts[0]?.hunt_id || null);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="v1-section-title">
        <Search size={22} />
        Hunt Results
        <span style={{ fontSize: 12, fontWeight: 400, color: '#64748B', marginLeft: 8 }}>
          {hunts.length} completed hunts
        </span>
      </div>

      {/* Hunt Cards */}
      {hunts.map((hunt) => {
        const isExpanded = expandedId === hunt.hunt_id;
        return (
          <div key={hunt.hunt_id} className="v1-hunt-card">
            {/* Header */}
            <div
              className="v1-hunt-card-header"
              style={{ cursor: 'pointer' }}
              onClick={() => setExpandedId(isExpanded ? null : hunt.hunt_id)}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {isExpanded ? <ChevronDown size={16} style={{ color: '#06B6D4' }} /> : <ChevronRight size={16} style={{ color: '#64748B' }} />}
                <div>
                  <div className="v1-hunt-card-title">{hunt.hunt_name}</div>
                  <div style={{ fontSize: 11, color: '#64748B', marginTop: 2 }}>
                    {hunt.hunt_id.toUpperCase()} · {hunt.analyst}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {hunt.false_positive_likelihood && (
                  <span style={{
                    fontSize: 10,
                    padding: '2px 8px',
                    borderRadius: 3,
                    background: hunt.false_positive_likelihood === 'Very Low' || hunt.false_positive_likelihood === 'Low'
                      ? 'rgba(34,197,94,0.1)' : 'rgba(245,158,11,0.1)',
                    color: hunt.false_positive_likelihood === 'Very Low' || hunt.false_positive_likelihood === 'Low'
                      ? '#22C55E' : '#F59E0B',
                    border: `1px solid ${hunt.false_positive_likelihood === 'Very Low' || hunt.false_positive_likelihood === 'Low'
                      ? 'rgba(34,197,94,0.2)' : 'rgba(245,158,11,0.2)'}`,
                    fontWeight: 600,
                    textTransform: 'uppercase',
                  }}>
                    FP: {hunt.false_positive_likelihood}
                  </span>
                )}
                <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, fontWeight: 700, color: '#EF4444' }}>
                  {hunt.suspicious_events.toLocaleString()}
                </span>
                <span style={{ fontSize: 10, color: '#64748B' }}>suspicious</span>
              </div>
            </div>

            {/* Meta row */}
            <div className="v1-hunt-card-meta">
              <span>{hunt.total_events_analyzed.toLocaleString()} events analyzed</span>
              <span>|</span>
              <span>{format(new Date(hunt.analysis_start * 1000), 'MMM d HH:mm')} – {format(new Date(hunt.analysis_end * 1000), 'MMM d HH:mm')}</span>
            </div>

            {/* Tags */}
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 8 }}>
              {hunt.tags.map((tag) => (
                <span key={tag} className="v1-mitre-tag">{tag}</span>
              ))}
            </div>

            {/* Summary (always visible) */}
            <div className="v1-hunt-card-summary">{hunt.summary}</div>

            {/* Expanded Content */}
            {isExpanded && (
              <div style={{ borderTop: '1px solid rgba(6,182,212,0.12)', paddingTop: 12 }}>
                {/* Recommendations */}
                <div style={{ marginBottom: 16 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#E2E8F0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, fontFamily: "'Barlow Condensed', sans-serif", textTransform: 'uppercase', letterSpacing: 0.5 }}>
                    <CheckCircle2 size={14} style={{ color: '#22C55E' }} />
                    Recommendations
                  </div>
                  <ol style={{ margin: 0, paddingLeft: 20, fontSize: 11, color: '#94A3B8', lineHeight: 1.8 }}>
                    {hunt.recommendations.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ol>
                </div>

                {/* Evidence: Threat Scores */}
                {hunt.threat_scores.length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#E2E8F0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, fontFamily: "'Barlow Condensed', sans-serif", textTransform: 'uppercase', letterSpacing: 0.5 }}>
                      <AlertTriangle size={14} style={{ color: '#EF4444' }} />
                      Key Threat Entities
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: 8 }}>
                      {hunt.threat_scores.map((ts, i) => (
                        <div key={`${ts.entity}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 10, background: 'rgba(6,182,212,0.03)', borderRadius: 4, padding: '8px 10px', border: '1px solid rgba(6,182,212,0.08)' }}>
                          <span className={`v1-score-inline ${scoreClass(ts.score)}`} style={{ fontSize: 18 }}>{ts.score}</span>
                          <div>
                            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#E2E8F0' }}>{ts.entity}</div>
                            <div style={{ fontSize: 10, color: '#64748B' }}>{ts.level} · {ts.occurrence_count} occ</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* MITRE Mappings */}
                {hunt.mitre_mappings.length > 0 && (
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#E2E8F0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, fontFamily: "'Barlow Condensed', sans-serif", textTransform: 'uppercase', letterSpacing: 0.5 }}>
                      <Target size={14} style={{ color: '#06B6D4' }} />
                      MITRE ATT&CK Coverage
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {hunt.mitre_mappings.map((m) => (
                        <a
                          key={m.technique_id}
                          href={`https://attack.mitre.org/techniques/${m.technique_id.replace('.', '/')}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="v1-mitre-tag"
                          style={{ textDecoration: 'none', padding: '4px 8px' }}
                        >
                          {m.technique_id} — {m.technique_name}
                          <ExternalLink size={9} style={{ marginLeft: 4 }} />
                        </a>
                      ))}
                    </div>
                  </div>
                )}

                {/* References */}
                {hunt.references.length > 0 && (
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 600, color: '#E2E8F0', marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6, fontFamily: "'Barlow Condensed', sans-serif", textTransform: 'uppercase', letterSpacing: 0.5 }}>
                      <FileText size={14} style={{ color: '#64748B' }} />
                      References
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                      {hunt.references.map((ref) => (
                        <a
                          key={ref}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          style={{ fontSize: 11, color: '#06B6D4', textDecoration: 'none', fontFamily: "'JetBrains Mono', monospace" }}
                        >
                          {ref} <ExternalLink size={9} style={{ display: 'inline' }} />
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
