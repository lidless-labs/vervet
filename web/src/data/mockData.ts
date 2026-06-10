/**
 * Comprehensive mock data for Vervet frontend development.
 * Uses realistic network threat hunting data:
 * - RFC 1918 internal IPs, realistic external threat IPs
 * - Plausible domains, actual MITRE ATT&CK technique IDs
 * - Real-looking timestamps (based around Jan 2026)
 */
import type {
  ThreatScore,
  ThreatIndicator,
  ThreatLevel,
  IndicatorType,
  MitreMapping,
  BeaconResult,
  DnsThreatResult,
  ThreatTimelinePoint,
  ThreatSeverityDistribution,
  DashboardStats,
  ChartTheme,
} from '../types';

// ============================================================================
// Helper utilities
// ============================================================================

const BASE_TS = new Date('2026-01-15T08:00:00Z').getTime() / 1000;

function ts(hoursOffset: number): number {
  return BASE_TS + hoursOffset * 3600;
}

function isoTs(hoursOffset: number): string {
  return new Date((BASE_TS + hoursOffset * 3600) * 1000).toISOString();
}

let _idCounter = 0;
function nextId(prefix = 'mock'): string {
  _idCounter += 1;
  return `${prefix}-${_idCounter.toString(16).padStart(6, '0')}`;
}

// ============================================================================
// Internal IPs (RFC 1918)
// ============================================================================
const INTERNAL_IPS = [
  '198.19.1.15', '198.19.1.22', '198.19.1.47', '198.19.1.88', '198.19.1.112',
  '198.19.2.5', '198.19.2.19', '198.19.2.34', '198.19.2.71', '198.19.2.99',
  '198.19.3.8', '198.19.3.41', '198.19.3.66', '198.19.3.103', '198.19.3.200',
  '192.0.2.10', '192.0.2.25', '192.0.2.50', '192.0.2.101', '192.0.2.150',
  '198.18.10.5', '198.18.10.22', '198.18.10.44', '198.18.10.80', '198.18.10.133',
  '198.18.160.10', '198.18.160.25', '198.18.161.5', '198.18.161.30', '198.18.162.15',
];

// ============================================================================
// External / Threat IPs (realistic-looking public IPs)
// ============================================================================
const EXTERNAL_THREAT_IPS = [
  '185.220.101.34', '91.219.236.222', '45.155.205.108', '23.129.64.210',
  '103.75.201.4', '198.98.56.78', '162.247.74.27', '209.141.47.65',
  '185.56.80.65', '37.120.198.219', '193.239.147.51', '94.232.46.202',
  '195.176.3.24', '176.10.104.240', '51.15.43.205', '80.67.172.162',
  '185.100.87.174', '199.195.250.77', '104.244.76.13', '46.166.139.111',
];

// ============================================================================
// Suspicious domains
// ============================================================================
const SUSPICIOUS_DOMAINS = [
  'cdn-update.xyz', 'api-metrics-v2.top', 'secure-login-verify.tk',
  'cloud-sync-node.cc', 'telemetry-edge.pw', 'xjkf8823mxvp.ru',
  'qwz7721nbd.cn', 'asd89xnm3k.biz', 'n4k8jx2pqm.info', 'zxc9v8b7n.ws',
  'microsft-update.com', 'gooogle-analytics.net', 'amazn-support.org',
  'paypa1-secure.com', 'app1e-verify.net', 'cloudflare-cdn-edge.co',
  'free-vpn-download.xyz', 'crypto-wallet-update.cc', 'banking-secure-login.tk',
  'fast-dns-resolver.top', 'office365-auth.pw', 'dropbox-share-link.ru',
  'linkedin-jobs-alert.biz', 'windows-update-kb.info', 'chrome-extension-update.ws',
  'a1b2c3d4e5f6.onion.ly', 'data.exfil.tunnel.example.com',
  'cmd.c2.beacon.example.net', 'stage2.payload.example.org',
  'proxy.tor2web.example.cc',
];

// ============================================================================
// MITRE ATT&CK techniques
// ============================================================================
const MITRE_TECHNIQUES: { id: string; name: string; tactic: string }[] = [
  { id: 'T1071.001', name: 'Web Protocols', tactic: 'command-and-control' },
  { id: 'T1071.004', name: 'DNS', tactic: 'command-and-control' },
  { id: 'T1573.001', name: 'Symmetric Cryptography', tactic: 'command-and-control' },
  { id: 'T1573.002', name: 'Asymmetric Cryptography', tactic: 'command-and-control' },
  { id: 'T1572', name: 'Protocol Tunneling', tactic: 'command-and-control' },
  { id: 'T1568.002', name: 'Domain Generation Algorithms', tactic: 'command-and-control' },
  { id: 'T1568.001', name: 'Fast Flux DNS', tactic: 'command-and-control' },
  { id: 'T1090.003', name: 'Multi-hop Proxy', tactic: 'command-and-control' },
  { id: 'T1048.001', name: 'Exfiltration Over Symmetric Encrypted Non-C2 Protocol', tactic: 'exfiltration' },
  { id: 'T1048.003', name: 'Exfiltration Over Unencrypted Non-C2 Protocol', tactic: 'exfiltration' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'exfiltration' },
  { id: 'T1595.002', name: 'Vulnerability Scanning', tactic: 'reconnaissance' },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'discovery' },
  { id: 'T1018', name: 'Remote System Discovery', tactic: 'discovery' },
  { id: 'T1059.001', name: 'PowerShell', tactic: 'execution' },
  { id: 'T1053.005', name: 'Scheduled Task', tactic: 'persistence' },
  { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'command-and-control' },
  { id: 'T1219', name: 'Remote Access Software', tactic: 'command-and-control' },
  { id: 'T1102', name: 'Web Service', tactic: 'command-and-control' },
  { id: 'T1001.003', name: 'Protocol Impersonation', tactic: 'command-and-control' },
];

// ============================================================================
// Mock Alerts (ThreatScore[]) — 55 entries
// ============================================================================

function generateAlerts(): ThreatScore[] {
  const alerts: ThreatScore[] = [];

  // --- Critical alerts (8) ---
  const criticals = [
    { ip: '198.19.1.15', ext: '185.220.101.34', domain: 'cmd.c2.beacon.example.net', score: 97, reasons: ['Regular 60s beacon interval', 'Known C2 infrastructure IP', 'Encrypted payload with fixed size'], techniques: ['T1071.001', 'T1573.001'] },
    { ip: '198.19.2.5', ext: '91.219.236.222', domain: 'data.exfil.tunnel.example.com', score: 95, reasons: ['High-entropy DNS subdomain queries', 'Estimated 2.4MB exfiltrated via DNS', 'TXT record abuse'], techniques: ['T1071.004', 'T1048.003'] },
    { ip: '192.0.2.10', ext: '45.155.205.108', domain: 'stage2.payload.example.org', score: 93, reasons: ['Binary download over HTTP', 'Known malware staging server', 'PowerShell execution after download'], techniques: ['T1105', 'T1059.001'] },
    { ip: '198.19.3.8', ext: '23.129.64.210', domain: 'proxy.tor2web.example.cc', score: 91, reasons: ['Tor exit node communication', 'Multi-hop proxy chain detected', 'Data exfiltration over encrypted channel'], techniques: ['T1090.003', 'T1041'] },
    { ip: '198.18.160.10', ext: '103.75.201.4', domain: 'xjkf8823mxvp.ru', score: 90, reasons: ['DGA domain pattern detected', 'High consonant-to-vowel ratio', 'Multiple NXDOMAIN followed by successful resolution'], techniques: ['T1568.002'] },
    { ip: '198.19.1.47', ext: '198.98.56.78', domain: 'cdn-update.xyz', score: 89, reasons: ['Beacon interval 120s ± 3s jitter', 'Consistent 512-byte payloads', 'SSL certificate mismatch'], techniques: ['T1071.001', 'T1573.002'] },
    { ip: '198.18.10.5', ext: '162.247.74.27', domain: 'crypto-wallet-update.cc', score: 88, reasons: ['Credential harvesting page detected', 'SSL cert CN mismatch', 'Known phishing infrastructure'], techniques: ['T1071.001'] },
    { ip: '198.19.2.19', ext: '209.141.47.65', domain: 'free-vpn-download.xyz', score: 87, reasons: ['Malware dropper URL pattern', 'Obfuscated JavaScript payload', 'Post-exploitation framework beacon'], techniques: ['T1105', 'T1219'] },
  ];

  criticals.forEach((c, i) => {
    alerts.push({
      entity: c.ip,
      entity_type: 'ip_address',
      score: c.score,
      level: 'critical' as ThreatLevel,
      confidence: 0.92 + Math.random() * 0.07,
      reasons: c.reasons,
      indicators: [c.domain, c.ext],
      mitre_techniques: c.techniques,
      first_seen: ts(i * 2),
      last_seen: ts(i * 2 + 12),
      occurrence_count: 40 + Math.floor(Math.random() * 200),
      related_ips: [c.ext],
      related_domains: [c.domain],
      related_files: [],
    });
  });

  // --- High alerts (12) ---
  for (let i = 0; i < 12; i++) {
    const srcIp = INTERNAL_IPS[8 + (i % INTERNAL_IPS.length)];
    const dstIp = EXTERNAL_THREAT_IPS[(i + 4) % EXTERNAL_THREAT_IPS.length];
    const domain = SUSPICIOUS_DOMAINS[(i + 5) % SUSPICIOUS_DOMAINS.length];
    const tech = MITRE_TECHNIQUES[(i + 2) % MITRE_TECHNIQUES.length];
    alerts.push({
      entity: srcIp,
      entity_type: 'ip_address',
      score: 70 + Math.floor(Math.random() * 16),
      level: 'high' as ThreatLevel,
      confidence: 0.75 + Math.random() * 0.15,
      reasons: [
        'Unusual outbound connection frequency',
        `Connection to known threat IP ${dstIp}`,
        'Non-standard port usage detected',
      ],
      indicators: [domain, dstIp],
      mitre_techniques: [tech.id],
      first_seen: ts(i * 3 + 1),
      last_seen: ts(i * 3 + 20),
      occurrence_count: 15 + Math.floor(Math.random() * 80),
      related_ips: [dstIp],
      related_domains: [domain],
      related_files: [],
    });
  }

  // --- Medium alerts (15) ---
  for (let i = 0; i < 15; i++) {
    const srcIp = INTERNAL_IPS[(i + 3) % INTERNAL_IPS.length];
    const dstIp = EXTERNAL_THREAT_IPS[(i + 8) % EXTERNAL_THREAT_IPS.length];
    const domain = SUSPICIOUS_DOMAINS[(i + 12) % SUSPICIOUS_DOMAINS.length];
    const tech = MITRE_TECHNIQUES[(i + 5) % MITRE_TECHNIQUES.length];
    alerts.push({
      entity: srcIp,
      entity_type: i % 3 === 0 ? 'domain' : 'ip_address',
      score: 40 + Math.floor(Math.random() * 26),
      level: 'medium' as ThreatLevel,
      confidence: 0.55 + Math.random() * 0.2,
      reasons: [
        'Moderate frequency anomaly',
        'Potentially suspicious TLD',
      ],
      indicators: [domain],
      mitre_techniques: [tech.id],
      first_seen: ts(i * 4 + 2),
      last_seen: ts(i * 4 + 36),
      occurrence_count: 5 + Math.floor(Math.random() * 30),
      related_ips: [dstIp],
      related_domains: [domain],
      related_files: [],
    });
  }

  // --- Low alerts (12) ---
  for (let i = 0; i < 12; i++) {
    const srcIp = INTERNAL_IPS[(i + 15) % INTERNAL_IPS.length];
    alerts.push({
      entity: srcIp,
      entity_type: 'ip_address',
      score: 15 + Math.floor(Math.random() * 20),
      level: 'low' as ThreatLevel,
      confidence: 0.35 + Math.random() * 0.2,
      reasons: ['Minor traffic anomaly', 'Low-confidence pattern match'],
      indicators: [SUSPICIOUS_DOMAINS[(i + 20) % SUSPICIOUS_DOMAINS.length]],
      mitre_techniques: [MITRE_TECHNIQUES[(i + 10) % MITRE_TECHNIQUES.length].id],
      first_seen: ts(i * 5),
      last_seen: ts(i * 5 + 48),
      occurrence_count: 2 + Math.floor(Math.random() * 10),
      related_ips: [],
      related_domains: [],
      related_files: [],
    });
  }

  // --- Info alerts (8) ---
  for (let i = 0; i < 8; i++) {
    const srcIp = INTERNAL_IPS[(i + 20) % INTERNAL_IPS.length];
    alerts.push({
      entity: srcIp,
      entity_type: 'ip_address',
      score: 1 + Math.floor(Math.random() * 12),
      level: 'info' as ThreatLevel,
      confidence: 0.2 + Math.random() * 0.15,
      reasons: ['Informational traffic pattern noted'],
      indicators: [],
      mitre_techniques: [],
      first_seen: ts(i * 6),
      last_seen: ts(i * 6 + 72),
      occurrence_count: 1 + Math.floor(Math.random() * 5),
      related_ips: [],
      related_domains: [],
      related_files: [],
    });
  }

  return alerts;
}

export const mockAlerts: ThreatScore[] = generateAlerts();

// ============================================================================
// Mock Beacon Results — 25 entries
// ============================================================================

function generateBeacons(): BeaconResult[] {
  const beacons: BeaconResult[] = [];
  const beaconConfigs = [
    { src: '198.19.1.15', dst: '185.220.101.34', port: 443, avgInt: 60, jitter: 2.1, score: 97 },
    { src: '198.19.1.47', dst: '198.98.56.78', port: 443, avgInt: 120, jitter: 3.5, score: 89 },
    { src: '198.19.2.34', dst: '91.219.236.222', port: 8443, avgInt: 300, jitter: 5.2, score: 82 },
    { src: '192.0.2.25', dst: '45.155.205.108', port: 80, avgInt: 1800, jitter: 8.0, score: 74 },
    { src: '198.19.3.41', dst: '23.129.64.210', port: 443, avgInt: 90, jitter: 1.8, score: 95 },
    { src: '198.18.160.25', dst: '103.75.201.4', port: 8080, avgInt: 600, jitter: 4.5, score: 78 },
    { src: '198.19.1.88', dst: '162.247.74.27', port: 443, avgInt: 45, jitter: 6.2, score: 71 },
    { src: '198.18.10.22', dst: '209.141.47.65', port: 4443, avgInt: 30, jitter: 1.2, score: 96 },
    { src: '198.19.2.71', dst: '185.56.80.65', port: 443, avgInt: 180, jitter: 3.8, score: 85 },
    { src: '198.19.3.66', dst: '37.120.198.219', port: 80, avgInt: 3600, jitter: 12.0, score: 62 },
    { src: '192.0.2.50', dst: '193.239.147.51', port: 443, avgInt: 240, jitter: 2.5, score: 88 },
    { src: '198.19.1.112', dst: '94.232.46.202', port: 8443, avgInt: 150, jitter: 4.0, score: 80 },
    { src: '198.18.161.5', dst: '195.176.3.24', port: 443, avgInt: 60, jitter: 7.5, score: 68 },
    { src: '198.19.2.99', dst: '176.10.104.240', port: 80, avgInt: 900, jitter: 6.0, score: 72 },
    { src: '198.18.10.44', dst: '51.15.43.205', port: 443, avgInt: 75, jitter: 2.0, score: 92 },
    { src: '198.19.3.103', dst: '80.67.172.162', port: 8080, avgInt: 200, jitter: 3.2, score: 83 },
    { src: '198.19.1.22', dst: '185.100.87.174', port: 443, avgInt: 120, jitter: 1.5, score: 94 },
    { src: '192.0.2.101', dst: '199.195.250.77', port: 4443, avgInt: 600, jitter: 9.0, score: 65 },
    { src: '198.18.161.30', dst: '104.244.76.13', port: 443, avgInt: 30, jitter: 1.0, score: 98 },
    { src: '198.19.2.5', dst: '46.166.139.111', port: 80, avgInt: 1200, jitter: 7.8, score: 67 },
    { src: '198.19.3.200', dst: '185.220.101.34', port: 443, avgInt: 90, jitter: 2.8, score: 86 },
    { src: '198.18.10.80', dst: '91.219.236.222', port: 8443, avgInt: 45, jitter: 3.0, score: 90 },
    { src: '198.19.1.15', dst: '45.155.205.108', port: 80, avgInt: 360, jitter: 5.5, score: 76 },
    { src: '198.18.162.15', dst: '23.129.64.210', port: 443, avgInt: 60, jitter: 1.6, score: 93 },
    { src: '192.0.2.150', dst: '103.75.201.4', port: 8080, avgInt: 180, jitter: 4.2, score: 79 },
  ];

  beaconConfigs.forEach((b, i) => {
    const connCount = Math.floor((24 * 3600) / b.avgInt);
    const stdDev = (b.jitter / 100) * b.avgInt;
    beacons.push({
      id: nextId('bcn'),
      src_ip: b.src,
      dst_ip: b.dst,
      dst_port: b.port,
      proto: 'tcp',
      connection_count: connCount,
      time_span_seconds: 24 * 3600,
      avg_interval_seconds: b.avgInt,
      median_interval_seconds: b.avgInt * (0.98 + Math.random() * 0.04),
      min_interval_seconds: b.avgInt * 0.85,
      max_interval_seconds: b.avgInt * 1.15,
      interval_std_dev: stdDev,
      jitter_pct: b.jitter,
      data_size_avg: 256 + Math.floor(Math.random() * 1024),
      data_size_variance: 100 + Math.floor(Math.random() * 500),
      beacon_score: b.score,
      confidence: b.score > 85 ? 0.9 + Math.random() * 0.09 : 0.6 + Math.random() * 0.25,
      reasons: [
        `Regular ${b.avgInt}s interval with ${b.jitter}% jitter`,
        b.score > 85 ? 'Strong C2 beacon signature' : 'Moderate periodicity detected',
        'Consistent payload sizes',
      ],
      mitre_techniques: ['T1071.001', ...(b.port === 443 ? ['T1573.002'] : [])],
      first_seen: ts(i * 0.5),
      last_seen: ts(i * 0.5 + 24),
    });
  });

  return beacons;
}

export const mockBeacons: BeaconResult[] = generateBeacons();

// ============================================================================
// Mock DNS Threats — 32 entries
// ============================================================================

function generateDnsThreats(): DnsThreatResult[] {
  const threats: DnsThreatResult[] = [];

  // Tunneling threats (10)
  const tunnelingDomains = [
    'data.exfil.tunnel.example.com', 'dns-proxy.covert-channel.xyz',
    'c2.encoded-payload.top', 'sub.long-query-strings.cc',
    'exfil.base64-encoded.pw', 'tunnel.hex-data.biz',
    'stream.dns-over-https.info', 'payload.fragment-reassemble.ws',
    'chunk.dns-streamer.ru', 'pipe.covert-dns-pipe.cn',
  ];
  tunnelingDomains.forEach((domain, i) => {
    threats.push({
      id: nextId('dns'),
      threat_type: 'tunneling',
      domain,
      src_ip: INTERNAL_IPS[i % INTERNAL_IPS.length],
      query_count: 200 + Math.floor(Math.random() * 2000),
      score: 75 + Math.floor(Math.random() * 25),
      confidence: 0.7 + Math.random() * 0.25,
      reasons: [
        'High-entropy subdomain queries',
        'Abnormal query volume to single domain',
        `Estimated ${Math.floor(50 + Math.random() * 5000)}KB exfiltrated`,
      ],
      mitre_techniques: ['T1071.004', 'T1572'],
      first_seen: ts(i * 1.5),
      last_seen: ts(i * 1.5 + 18),
      unique_subdomains: 100 + Math.floor(Math.random() * 900),
      avg_subdomain_entropy: 3.5 + Math.random() * 1.2,
      estimated_bytes_exfiltrated: 50000 + Math.floor(Math.random() * 5000000),
    });
  });

  // DGA threats (12)
  const dgaDomains = [
    'xjkf8823mxvp.ru', 'qwz7721nbd.cn', 'asd89xnm3k.biz', 'n4k8jx2pqm.info',
    'zxc9v8b7n.ws', 'plk3mnb8xz.cc', 'wrt7yui2op.top', 'ghj5fds1aq.xyz',
    'bnm6vck4ze.pw', 'tyui9olp3k.tk', 'rfv5tgb2hy.co', 'mju7nhb4zx.net',
  ];
  dgaDomains.forEach((domain, i) => {
    threats.push({
      id: nextId('dns'),
      threat_type: 'dga',
      domain,
      src_ip: INTERNAL_IPS[(i + 5) % INTERNAL_IPS.length],
      query_count: 10 + Math.floor(Math.random() * 100),
      score: 60 + Math.floor(Math.random() * 38),
      confidence: 0.6 + Math.random() * 0.35,
      reasons: [
        'Domain name has high entropy',
        'High consonant-to-vowel ratio',
        'Multiple NXDOMAIN responses',
      ],
      mitre_techniques: ['T1568.002'],
      first_seen: ts(i * 2 + 0.5),
      last_seen: ts(i * 2 + 12),
      domain_entropy: 3.8 + Math.random() * 0.8,
      consonant_ratio: 0.7 + Math.random() * 0.25,
      nxdomain_count: 5 + Math.floor(Math.random() * 40),
    });
  });

  // Fast-flux threats (6)
  const fastFluxDomains = [
    'fast-dns-resolver.top', 'dynamic-cdn-edge.xyz', 'load-balance-global.cc',
    'rapid-rotate.pw', 'flux-network.biz', 'shifting-ips.info',
  ];
  fastFluxDomains.forEach((domain, i) => {
    threats.push({
      id: nextId('dns'),
      threat_type: 'fast_flux',
      domain,
      src_ip: INTERNAL_IPS[(i + 12) % INTERNAL_IPS.length],
      query_count: 50 + Math.floor(Math.random() * 300),
      score: 65 + Math.floor(Math.random() * 30),
      confidence: 0.6 + Math.random() * 0.3,
      reasons: [
        'Rapidly rotating A records',
        'Very low TTL values',
        'IPs span multiple ASNs and countries',
      ],
      mitre_techniques: ['T1568.001'],
      first_seen: ts(i * 3),
      last_seen: ts(i * 3 + 24),
      unique_ips: 8 + Math.floor(Math.random() * 50),
      ip_changes_per_hour: 4 + Math.random() * 20,
      avg_ttl: 30 + Math.random() * 120,
    });
  });

  // Suspicious patterns (4)
  const patternSources = ['198.19.1.22', '198.19.2.71', '192.0.2.50', '198.18.160.25'];
  patternSources.forEach((src, i) => {
    threats.push({
      id: nextId('dns'),
      threat_type: 'suspicious_pattern',
      domain: SUSPICIOUS_DOMAINS[(i + 15) % SUSPICIOUS_DOMAINS.length],
      src_ip: src,
      query_count: 30 + Math.floor(Math.random() * 150),
      score: 40 + Math.floor(Math.random() * 35),
      confidence: 0.4 + Math.random() * 0.3,
      reasons: [
        'Unusual query timing pattern',
        'Queries to uncommon TLD',
      ],
      mitre_techniques: ['T1071.004'],
      first_seen: ts(i * 4),
      last_seen: ts(i * 4 + 36),
    });
  });

  return threats;
}

export const mockDnsThreats: DnsThreatResult[] = generateDnsThreats();

// ============================================================================
// Mock Timeline Data — 72 hourly data points (3 days)
// ============================================================================

function generateTimeline(): ThreatTimelinePoint[] {
  const points: ThreatTimelinePoint[] = [];
  for (let h = 0; h < 72; h++) {
    // Simulate diurnal pattern: more activity during business hours
    const hourOfDay = h % 24;
    const isBusinessHours = hourOfDay >= 8 && hourOfDay <= 18;
    const multiplier = isBusinessHours ? 1.5 + Math.random() * 0.5 : 0.3 + Math.random() * 0.4;

    const critical = Math.floor((0 + Math.random() * 3) * multiplier);
    const high = Math.floor((1 + Math.random() * 5) * multiplier);
    const medium = Math.floor((3 + Math.random() * 8) * multiplier);
    const low = Math.floor((5 + Math.random() * 10) * multiplier);
    const info = Math.floor((2 + Math.random() * 6) * multiplier);

    points.push({
      timestamp: isoTs(h),
      total: critical + high + medium + low + info,
      critical,
      high,
      medium,
      low,
      info,
    });
  }
  return points;
}

export const mockTimeline: ThreatTimelinePoint[] = generateTimeline();

// ============================================================================
// Mock Severity Distribution
// ============================================================================

export const mockSeverityDistribution: ThreatSeverityDistribution[] = [
  { severity: 'critical' as ThreatLevel, count: 8, percentage: 14.5 },
  { severity: 'high' as ThreatLevel, count: 12, percentage: 21.8 },
  { severity: 'medium' as ThreatLevel, count: 15, percentage: 27.3 },
  { severity: 'low' as ThreatLevel, count: 12, percentage: 21.8 },
  { severity: 'info' as ThreatLevel, count: 8, percentage: 14.5 },
];

// ============================================================================
// Mock Dashboard Stats
// ============================================================================

export const mockDashboardStats: DashboardStats = {
  totalAlerts: 55,
  criticalAlerts: 8,
  highAlerts: 12,
  mediumAlerts: 15,
  lowAlerts: 12,
  infoAlerts: 8,
  totalBeacons: 25,
  totalDnsThreats: 32,
  uniqueSourceIPs: 24,
  uniqueDestIPs: 20,
  topMitreTechniques: [
    { technique: 'T1071.001', count: 18 },
    { technique: 'T1071.004', count: 14 },
    { technique: 'T1568.002', count: 12 },
    { technique: 'T1573.002', count: 9 },
    { technique: 'T1572', count: 8 },
    { technique: 'T1105', count: 6 },
    { technique: 'T1568.001', count: 6 },
    { technique: 'T1090.003', count: 4 },
    { technique: 'T1041', count: 4 },
    { technique: 'T1219', count: 3 },
  ],
  averageThreatScore: 56.3,
  alertsTrend: 12.5,
  lastUpdated: isoTs(71),
};

// ============================================================================
// Mock Threat Indicators
// ============================================================================

export const mockIndicators: ThreatIndicator[] = [
  {
    indicator_type: 'ip_address' as IndicatorType,
    value: '185.220.101.34',
    description: 'Known Tor exit node and C2 relay infrastructure',
    severity: 'critical' as ThreatLevel,
    source: 'Threat Intel Feed',
    detection_time: ts(0),
    log_source: 'zeek_conn',
    context: { country: 'DE', asn: 'AS205100', hosting: 'Flokinet Ltd' },
    tags: ['tor', 'c2', 'relay'],
    mitre_technique: 'T1090.003',
    mitre_tactic: 'command-and-control',
  },
  {
    indicator_type: 'domain' as IndicatorType,
    value: 'cmd.c2.beacon.example.net',
    description: 'C2 beacon domain used in targeted intrusion campaign',
    severity: 'critical' as ThreatLevel,
    source: 'Internal Hunt',
    detection_time: ts(1),
    log_source: 'zeek_dns',
    context: { registrar: 'Namecheap', age_days: '3' },
    tags: ['c2', 'beacon', 'apt'],
    mitre_technique: 'T1071.001',
    mitre_tactic: 'command-and-control',
  },
  {
    indicator_type: 'ip_address' as IndicatorType,
    value: '91.219.236.222',
    description: 'DNS tunneling endpoint for data exfiltration',
    severity: 'critical' as ThreatLevel,
    source: 'Beacon Analysis',
    detection_time: ts(2),
    log_source: 'zeek_dns',
    context: { country: 'RO', asn: 'AS9009' },
    tags: ['exfiltration', 'dns-tunnel'],
    mitre_technique: 'T1048.003',
    mitre_tactic: 'exfiltration',
  },
  {
    indicator_type: 'domain' as IndicatorType,
    value: 'xjkf8823mxvp.ru',
    description: 'Algorithmically generated domain (DGA) - possible Emotet variant',
    severity: 'high' as ThreatLevel,
    source: 'DGA Detection',
    detection_time: ts(3),
    log_source: 'zeek_dns',
    context: { entropy: '4.2', tld: 'ru' },
    tags: ['dga', 'malware', 'emotet'],
    mitre_technique: 'T1568.002',
    mitre_tactic: 'command-and-control',
  },
  {
    indicator_type: 'url' as IndicatorType,
    value: 'http://stage2.payload.example.org/dl/update.exe',
    description: 'Malware staging URL delivering second-stage payload',
    severity: 'critical' as ThreatLevel,
    source: 'HTTP Analysis',
    detection_time: ts(4),
    log_source: 'zeek_http',
    context: { content_type: 'application/octet-stream', size: '2.1MB' },
    tags: ['malware', 'dropper', 'stage2'],
    mitre_technique: 'T1105',
    mitre_tactic: 'command-and-control',
  },
];

// ============================================================================
// Mock MITRE Mappings
// ============================================================================

export const mockMitreMappings: MitreMapping[] = MITRE_TECHNIQUES.slice(0, 12).map((t, i) => ({
  technique_id: t.id,
  technique_name: t.name,
  tactic: t.tactic,
  tactic_id: `TA00${40 + Math.floor(i / 3)}`,
  confidence: 0.7 + Math.random() * 0.28,
  evidence: [`${2 + Math.floor(Math.random() * 8)} log entries match pattern`],
  observed_behaviors: [`Behavior consistent with ${t.name}`],
  detection_count: 3 + Math.floor(Math.random() * 25),
  first_detected: ts(i),
  last_detected: ts(i + 48),
  affected_hosts: INTERNAL_IPS.slice(i % 5, i % 5 + 3),
}));

// ============================================================================
// Default Chart Theme (matches Tailwind config)
// ============================================================================

export const defaultChartTheme: ChartTheme = {
  colors: {
    primary: '#06b6d4',
    secondary: '#8b5cf6',
    accent: '#f59e0b',
    danger: '#ef4444',
    warning: '#f59e0b',
    success: '#22c55e',
    info: '#3b82f6',
    background: '#0a0e17',
    surface: '#111827',
    text: '#f3f4f6',
    textSecondary: '#9ca3af',
    gridLine: '#1f2937',
    series: [
      '#06b6d4', '#8b5cf6', '#f59e0b', '#ef4444', '#22c55e',
      '#3b82f6', '#ec4899', '#14b8a6', '#f97316', '#a855f7',
    ],
  },
  fonts: {
    family: 'Inter, system-ui, sans-serif',
    monoFamily: 'Fira Code, Consolas, Monaco, Courier New, monospace',
    sizeSmall: 10,
    sizeBase: 12,
    sizeLarge: 14,
  },
  spacing: {
    chartPadding: 20,
    legendGap: 12,
    tooltipPadding: 8,
  },
};
