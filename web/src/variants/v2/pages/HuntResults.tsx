/**
 * V2 Hunt Results — Terminal document, === HEADERS ===, numbered recommendations.
 */
import React, { useMemo } from 'react';
import { format } from 'date-fns';
import {
  useAlerts,
  useBeacons,
  useDnsThreats,
  useMitreMappings,
  useDashboardStats,
  useIndicators,
} from '../../../hooks/useApi';
import {
  mockAlerts,
  mockBeacons,
  mockDnsThreats,
  mockMitreMappings,
  mockDashboardStats,
  mockIndicators,
} from '../../../data/mockData';

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

/* ═══ Section header ═══ */
const SectionHeader: React.FC<{ text: string }> = ({ text }) => (
  <div className="v2-doc-section-header">
    ═══ {text} ═══════════════════════════════════════
  </div>
);

const HuntResults: React.FC = () => {
  const { data: alerts } = useAlerts();
  const { data: beacons } = useBeacons();
  const { data: dnsThreats } = useDnsThreats();
  const { data: mitre } = useMitreMappings();
  const { data: stats } = useDashboardStats();
  const { data: indicators } = useIndicators();

  const al = alerts ?? mockAlerts;
  const bc = beacons ?? mockBeacons;
  const dns = dnsThreats ?? mockDnsThreats;
  const mm = mitre ?? mockMitreMappings;
  const s = stats ?? mockDashboardStats;
  const ind = indicators ?? mockIndicators;

  /* derived data */
  const criticalThreats = useMemo(() => al.filter((a) => a.level === 'critical'), [al]);
  const highBeacons = useMemo(() => bc.filter((b) => b.beacon_score >= 85), [bc]);
  const highDns = useMemo(() => dns.filter((d) => d.score >= 75), [dns]);

  const recommendations = useMemo(() => [
    `Isolate high-confidence C2 beacons: ${highBeacons.slice(0, 3).map((b) => `${b.src_ip}→${b.dst_ip}`).join(', ')}. These show strong periodic communication patterns with known threat infrastructure.`,
    `Block DNS tunneling domains at perimeter resolver: ${dns.filter((d) => d.threat_type === 'tunneling').slice(0, 3).map((d) => d.domain).join(', ')}. Estimated data exfiltration exceeds acceptable threshold.`,
    `Blackhole DGA domains and deploy sinkholing for: ${dns.filter((d) => d.threat_type === 'dga').slice(0, 3).map((d) => d.domain).join(', ')}. Pattern matches known malware family signatures.`,
    `Investigate internal host ${criticalThreats[0]?.entity ?? '198.19.1.15'} for compromise indicators. Multiple detection vectors converge on this endpoint.`,
    `Deploy enhanced monitoring on ports 443, 8443, 4443 for encrypted C2 traffic. ${highBeacons.filter((b) => [443, 8443, 4443].includes(b.dst_port)).length} beacons detected on these ports.`,
    `Review SSL certificate validation across proxy infrastructure. Certificate mismatches detected in ${criticalThreats.filter((a) => a.reasons.some((r) => r.toLowerCase().includes('cert'))).length} critical alerts.`,
    `Implement DNS response policy zones (RPZ) for fast-flux domains. ${dns.filter((d) => d.threat_type === 'fast_flux').length} fast-flux networks identified with rapidly rotating A records.`,
    `Escalate MITRE technique ${mm[0]?.technique_id ?? 'T1071.001'} (${mm[0]?.technique_name ?? 'Web Protocols'}) — ${mm[0]?.detection_count ?? 0} detections across ${mm[0]?.affected_hosts.length ?? 0} hosts indicates active C2 campaign.`,
    `Schedule threat hunting sweep for Tor exit node communication. ${al.filter((a) => a.reasons.some((r) => r.toLowerCase().includes('tor'))).length} alerts reference Tor infrastructure.`,
    `Update threat intelligence feeds and validate IOC correlation. Current hunt identified ${ind.length} indicators requiring feed integration.`,
  ], [al, bc, dns, mm, criticalThreats, highBeacons, highDns, ind]);

  const now = format(new Date(), 'yyyy-MM-dd HH:mm:ss');
  const huntId = 'HNT-2026-0115-001';

  return (
    <>
      <div className="v2-heading">
        ╔═ HUNT REPORT ═════════════════════════════════════════╗
      </div>

      <Panel title="HUNT_DOCUMENT" pid={9101}>
        {/* Document header */}
        <div className="v2-doc-header">
          ╔══════════════════════════════════════════════════════════════╗
        </div>
        <div className="v2-doc-header" style={{ textAlign: 'center' }}>
          THREAT HUNTING REPORT
        </div>
        <div className="v2-doc-header">
          ╚══════════════════════════════════════════════════════════════╝
        </div>

        <div className="v2-divider" />

        {/* Metadata */}
        <div className="v2-stats-grid" style={{ marginBottom: 16 }}>
          <div className="v2-stat-line">
            <span className="v2-stat-key">hunt_id</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value amber">{huntId}</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">analyst</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value">root@vervet</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">generated</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value">{now}</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">classification</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value critical">TLP:RED</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">hypothesis</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value">"Active C2 infrastructure present in network"</span>
          </div>
          <div className="v2-stat-line">
            <span className="v2-stat-key">verdict</span>
            <span className="v2-stat-eq">=</span>
            <span className="v2-stat-value critical">CONFIRMED</span>
          </div>
        </div>

        <div className="v2-divider" />

        {/* Executive Summary */}
        <SectionHeader text="EXECUTIVE SUMMARY" />
        <div className="v2-doc-text" style={{ marginBottom: 12 }}>
          Threat hunting analysis of network traffic spanning 72 hours identified{' '}
          <span className="v2-bold v2-red">{s.criticalAlerts} critical</span> and{' '}
          <span className="v2-bold v2-amber">{s.highAlerts} high</span> severity threats
          across {s.uniqueSourceIPs} internal hosts communicating with {s.uniqueDestIPs} external
          threat endpoints. Analysis reveals active command-and-control infrastructure with
          confirmed data exfiltration via DNS tunneling.
        </div>

        <div className="v2-divider" />

        {/* Key Findings */}
        <SectionHeader text="KEY FINDINGS" />

        <div className="v2-heading-section" style={{ marginTop: 8 }}>
          1. C2 Beacon Activity
        </div>
        <div className="v2-doc-text">
          Detected <span className="v2-bold v2-red">{highBeacons.length}</span> high-confidence
          beacons (score ≥85). Top beacons:
        </div>
        <div className="v2-evidence" style={{ marginTop: 4 }}>
          {highBeacons.slice(0, 5).map((b) => (
            <div key={b.id} className="v2-evidence-line">
              <span className="highlight">{b.src_ip}</span>
              {' → '}
              <span className="highlight">{b.dst_ip}</span>
              :{b.dst_port}
              {' │ score='}
              <span className={b.beacon_score >= 85 ? 'v2-red' : 'v2-amber'}>{b.beacon_score}</span>
              {' │ int='}
              {b.avg_interval_seconds}s{' │ jitter='}
              {b.jitter_pct}%
            </div>
          ))}
        </div>

        <div className="v2-heading-section">
          2. DNS Exfiltration
        </div>
        <div className="v2-doc-text">
          Identified <span className="v2-bold v2-red">
            {dns.filter((d) => d.threat_type === 'tunneling').length}
          </span> DNS tunneling operations and{' '}
          <span className="v2-bold v2-amber">
            {dns.filter((d) => d.threat_type === 'dga').length}
          </span> DGA domain clusters.
        </div>
        <div className="v2-evidence" style={{ marginTop: 4 }}>
          {highDns.slice(0, 4).map((d) => (
            <div key={d.id} className="v2-evidence-line">
              [{d.threat_type.toUpperCase()}]{' '}
              <span className="highlight">{d.domain}</span>
              {' │ score='}
              <span className={d.score >= 80 ? 'v2-red' : 'v2-amber'}>{d.score}</span>
              {' │ queries='}
              {d.query_count}
            </div>
          ))}
        </div>

        <div className="v2-heading-section">
          3. MITRE ATT&CK Coverage
        </div>
        <div className="v2-doc-text">
          Threat activity maps to <span className="v2-bold">{mm.length}</span> MITRE ATT&CK
          techniques spanning {new Set(mm.map((m) => m.tactic)).size} tactics.
        </div>
        <div className="v2-evidence" style={{ marginTop: 4 }}>
          {mm.slice(0, 6).map((m) => (
            <div key={m.technique_id} className="v2-evidence-line">
              <span className="v2-amber">{m.technique_id}</span>
              {' '}
              {m.technique_name}
              {' │ '}
              <span className="v2-dim">{m.tactic}</span>
              {' │ detections='}
              <span className="v2-red">{m.detection_count}</span>
            </div>
          ))}
        </div>

        <div className="v2-divider" />

        {/* Indicators of Compromise */}
        <SectionHeader text="INDICATORS OF COMPROMISE" />
        <div className="v2-evidence">
          {ind.map((indicator, i) => (
            <div key={i} className="v2-evidence-line" style={{ marginBottom: 4 }}>
              <span className={`v2-severity ${indicator.severity}`} style={{ marginRight: 8, fontSize: 10 }}>
                {indicator.severity === 'critical' ? '>>>' : indicator.severity === 'high' ? '>>' : '>'}
                {indicator.severity.toUpperCase()}
              </span>
              [{indicator.indicator_type}]{' '}
              <span className="highlight">{indicator.value}</span>
              <br />
              <span className="v2-dim" style={{ marginLeft: 24 }}>
                └─ {indicator.description}
              </span>
            </div>
          ))}
        </div>

        <div className="v2-divider" />

        {/* Recommendations */}
        <SectionHeader text="RECOMMENDATIONS" />
        <ol className="v2-doc-numbered">
          {recommendations.map((rec, i) => (
            <li key={i}>{rec}</li>
          ))}
        </ol>

        <div className="v2-divider" />

        {/* Footer */}
        <div className="v2-dim" style={{ fontSize: 10, textAlign: 'center', paddingTop: 8 }}>
          ═══════════════════════════════════════════════════════════════
          <br />
          END OF REPORT │ {huntId} │ Classification: TLP:RED │ {now}
          <br />
          Generated by bro_hunter v2.0 │ render=terminal
          <br />
          ═══════════════════════════════════════════════════════════════
        </div>
      </Panel>
    </>
  );
};

export default HuntResults;
