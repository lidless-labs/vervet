/**
 * TypeScript type definitions for Vervet frontend.
 * Mirrors backend Pydantic models for type safety.
 */

// ============================================================================
// Zeek Log Types
// ============================================================================

export interface ConnLog {
  ts: number;
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  proto: string;
  service?: string;
  duration?: number;
  orig_bytes?: number;
  resp_bytes?: number;
  conn_state?: string;
  local_orig?: boolean;
  local_resp?: boolean;
  missed_bytes?: number;
  history?: string;
  orig_pkts?: number;
  orig_ip_bytes?: number;
  resp_pkts?: number;
  resp_ip_bytes?: number;
  tunnel_parents?: string[];
}

export interface DnsLog {
  ts: number;
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  proto: string;
  trans_id?: number;
  query?: string;
  qclass?: number;
  qclass_name?: string;
  qtype?: number;
  qtype_name?: string;
  rcode?: number;
  rcode_name?: string;
  AA?: boolean;
  TC?: boolean;
  RD?: boolean;
  RA?: boolean;
  Z?: number;
  answers?: string[];
  TTLs?: number[];
  rejected?: boolean;
}

export interface HttpLog {
  ts: number;
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  trans_depth?: number;
  method?: string;
  host?: string;
  uri?: string;
  referrer?: string;
  version?: string;
  user_agent?: string;
  request_body_len?: number;
  response_body_len?: number;
  status_code?: number;
  status_msg?: string;
  info_code?: number;
  info_msg?: string;
  tags?: string[];
  username?: string;
  password?: string;
  proxied?: string[];
  orig_fuids?: string[];
  orig_filenames?: string[];
  orig_mime_types?: string[];
  resp_fuids?: string[];
  resp_filenames?: string[];
  resp_mime_types?: string[];
}

export interface SslLog {
  ts: number;
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  version?: string;
  cipher?: string;
  curve?: string;
  server_name?: string;
  resumed?: boolean;
  last_alert?: string;
  next_protocol?: string;
  established?: boolean;
  cert_chain_fuids?: string[];
  client_cert_chain_fuids?: string[];
  subject?: string;
  issuer?: string;
  client_subject?: string;
  client_issuer?: string;
  validation_status?: string;
}

export interface X509Log {
  ts: number;
  fingerprint: string;
  certificate_version?: number;
  certificate_serial?: string;
  certificate_subject?: string;
  certificate_issuer?: string;
  certificate_not_valid_before?: number;
  certificate_not_valid_after?: number;
  certificate_key_alg?: string;
  certificate_sig_alg?: string;
  certificate_key_type?: string;
  certificate_key_length?: number;
  certificate_exponent?: string;
  certificate_curve?: string;
  san_dns?: string[];
  san_uri?: string[];
  san_email?: string[];
  san_ip?: string[];
  basic_constraints_ca?: boolean;
  basic_constraints_path_len?: number;
}

export interface FilesLog {
  ts: number;
  fuid: string;
  tx_hosts?: string[];
  rx_hosts?: string[];
  conn_uids?: string[];
  source?: string;
  depth?: number;
  analyzers?: string[];
  mime_type?: string;
  filename?: string;
  duration?: number;
  local_orig?: boolean;
  is_orig?: boolean;
  seen_bytes?: number;
  total_bytes?: number;
  missing_bytes?: number;
  overflow_bytes?: number;
  timedout?: boolean;
  parent_fuid?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  extracted?: string;
}

export interface NoticeLog {
  ts: number;
  uid?: string;
  id_orig_h?: string;
  id_orig_p?: number;
  id_resp_h?: string;
  id_resp_p?: number;
  fuid?: string;
  file_mime_type?: string;
  file_desc?: string;
  proto?: string;
  note: string;
  msg?: string;
  sub?: string;
  src?: string;
  dst?: string;
  p?: number;
  n?: number;
  peer_descr?: string;
  actions?: string[];
  suppress_for?: number;
  remote_location_country_code?: string;
  remote_location_region?: string;
  remote_location_city?: string;
  remote_location_latitude?: number;
  remote_location_longitude?: number;
}

export interface WeirdLog {
  ts: number;
  uid?: string;
  id_orig_h?: string;
  id_orig_p?: number;
  id_resp_h?: string;
  id_resp_p?: number;
  name: string;
  addl?: string;
  notice?: boolean;
  peer?: string;
}

export interface DpdLog {
  ts: number;
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  proto: string;
  analyzer: string;
  failure_reason?: string;
}

export interface SmtpLog {
  ts: number;
  uid: string;
  id_orig_h: string;
  id_orig_p: number;
  id_resp_h: string;
  id_resp_p: number;
  trans_depth?: number;
  helo?: string;
  mailfrom?: string;
  rcptto?: string[];
  date?: string;
  from?: string;
  to?: string[];
  cc?: string[];
  reply_to?: string;
  msg_id?: string;
  in_reply_to?: string;
  subject?: string;
  x_originating_ip?: string;
  first_received?: string;
  second_received?: string;
  last_reply?: string;
  path?: string[];
  user_agent?: string;
  tls?: boolean;
  fuids?: string[];
  is_webmail?: boolean;
}

// ============================================================================
// Suricata Sub-Object Types
// ============================================================================

/** Suricata alert rule metadata. */
export interface SuricataAlertInfo {
  action?: string;
  gid?: number;
  signature_id?: number;
  rev?: number;
  signature?: string;
  category?: string;
  severity?: number;
  metadata?: Record<string, string[]>;
}

/** Suricata packet metadata. */
export interface SuricataPacketInfo {
  linktype?: number;
}

/** Suricata HTTP sub-object. */
export interface SuricataHttpInfo {
  hostname?: string;
  url?: string;
  http_user_agent?: string;
  http_content_type?: string;
  http_method?: string;
  http_refer?: string;
  protocol?: string;
  status?: number;
  length?: number;
  redirect?: string;
}

/** Suricata DNS sub-object. */
export interface SuricataDnsInfo {
  type?: string;
  id?: number;
  flags?: string;
  qr?: boolean;
  rd?: boolean;
  ra?: boolean;
  rrname?: string;
  rrtype?: string;
  rcode?: string;
  rdata?: string;
  ttl?: number;
  tx_id?: number;
}

/** Suricata TLS sub-object. */
export interface SuricataTlsInfo {
  subject?: string;
  issuerdn?: string;
  serial?: string;
  fingerprint?: string;
  sni?: string;
  version?: string;
  notbefore?: string;
  notafter?: string;
  ja3?: { hash?: string; string?: string };
  ja3s?: { hash?: string; string?: string };
}

/** Suricata SSH sub-object. */
export interface SuricataSshInfo {
  client?: { proto_version?: string; software_version?: string };
  server?: { proto_version?: string; software_version?: string };
}

/** Suricata SMTP sub-object. */
export interface SuricataSmtpInfo {
  helo?: string;
  mail_from?: string;
  rcpt_to?: string[];
}

/** Suricata file info sub-object. */
export interface SuricataFileInfo {
  filename?: string;
  magic?: string;
  gaps?: boolean;
  state?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  stored?: boolean;
  file_id?: number;
  size?: number;
  tx_id?: number;
}

/** Suricata flow sub-object (used in flow events and as sub-object in other events). */
export interface SuricataFlowInfo {
  pkts_toserver?: number;
  pkts_toclient?: number;
  bytes_toserver?: number;
  bytes_toclient?: number;
  start?: string;
  end?: string;
  age?: number;
  state?: string;
  reason?: string;
  alerted?: boolean;
}

/** Suricata TCP sub-object. */
export interface SuricataTcpInfo {
  tcp_flags?: string;
  tcp_flags_ts?: string;
  tcp_flags_tc?: string;
  syn?: boolean;
  rst?: boolean;
  psh?: boolean;
  ack?: boolean;
  state?: string;
}

// ============================================================================
// Suricata Log Types
// ============================================================================

export interface SuricataAlert {
  timestamp: string;
  flow_id?: number;
  in_iface?: string;
  event_type: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  tx_id?: number;
  alert: SuricataAlertInfo;
  payload?: string;
  payload_printable?: string;
  stream?: number;
  packet?: string;
  packet_info?: SuricataPacketInfo;
  app_proto?: string;
  http?: SuricataHttpInfo;
  dns?: SuricataDnsInfo;
  tls?: SuricataTlsInfo;
  ssh?: SuricataSshInfo;
  smtp?: SuricataSmtpInfo;
  fileinfo?: SuricataFileInfo;
  flow?: SuricataFlowInfo;
}

export interface SuricataFlow {
  timestamp: string;
  flow_id: number;
  in_iface?: string;
  event_type: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  app_proto?: string;
  app_proto_tc?: string;
  app_proto_ts?: string;
  flow: SuricataFlowInfo;
  tcp?: SuricataTcpInfo;
  community_id?: string;
}

export interface SuricataDns {
  timestamp: string;
  flow_id?: number;
  in_iface?: string;
  event_type: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  dns: SuricataDnsInfo;
  community_id?: string;
}

export interface SuricataHttp {
  timestamp: string;
  flow_id: number;
  in_iface?: string;
  event_type: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  tx_id: number;
  http: SuricataHttpInfo;
  fileinfo?: SuricataFileInfo;
  community_id?: string;
}

export interface SuricataTls {
  timestamp: string;
  flow_id: number;
  in_iface?: string;
  event_type: string;
  src_ip: string;
  src_port: number;
  dest_ip: string;
  dest_port: number;
  proto: string;
  tls: SuricataTlsInfo;
  community_id?: string;
}

// ============================================================================
// Threat Intelligence Types
// ============================================================================

export enum ThreatLevel {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

export enum IndicatorType {
  IP_ADDRESS = "ip_address",
  DOMAIN = "domain",
  URL = "url",
  FILE_HASH = "file_hash",
  EMAIL = "email",
  USER_AGENT = "user_agent",
  CERTIFICATE = "certificate",
  BEHAVIOR = "behavior",
}

export interface ThreatScore {
  entity: string;
  entity_type: string;
  score: number;
  level: ThreatLevel;
  confidence: number;
  reasons: string[];
  indicators: string[];
  mitre_techniques: string[];
  first_seen: number;
  last_seen: number;
  occurrence_count: number;
  related_ips: string[];
  related_domains: string[];
  related_files: string[];
}

export interface ThreatIndicator {
  indicator_type: IndicatorType;
  value: string;
  description: string;
  severity: ThreatLevel;
  source: string;
  detection_time: number;
  log_source: string;
  context: Record<string, string>;
  tags: string[];
  mitre_technique?: string;
  mitre_tactic?: string;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  confidence: number;
  evidence: string[];
  observed_behaviors: string[];
  detection_count: number;
  first_detected: number;
  last_detected: number;
  affected_hosts: string[];
}

export interface HuntResult {
  hunt_id: string;
  hunt_name: string;
  hunt_description: string;
  hypothesis: string;
  total_events_analyzed: number;
  suspicious_events: number;
  threat_scores: ThreatScore[];
  indicators: ThreatIndicator[];
  mitre_mappings: MitreMapping[];
  analysis_start: number;
  analysis_end: number;
  time_range_start: number;
  time_range_end: number;
  summary: string;
  recommendations: string[];
  false_positive_likelihood?: string;
  analyst?: string;
  tags: string[];
  references: string[];
}

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiResponse<T> {
  status: string;
  data?: T;
  message?: string;
  error?: string;
}

export interface LogStats {
  zeek_logs: {
    count: number;
    types: string[];
  };
  suricata_logs: {
    count: number;
    types: string[];
  };
}

export interface ThreatsResponse {
  threats: ThreatScore[];
  total: number;
}

export interface IndicatorsResponse {
  indicators: ThreatIndicator[];
  total: number;
}

export interface MitreResponse {
  mappings: MitreMapping[];
  total: number;
}

// ============================================================================
// Frontend-Specific Types (Beacon, DNS Threats, Charts, UI State)
// ============================================================================

/**
 * Frontend representation of beacon detection results.
 * Mirrors backend BeaconResult but optimized for UI consumption.
 */
export interface BeaconResult {
  id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number;
  proto: string;
  connection_count: number;
  time_span_seconds: number;
  avg_interval_seconds: number;
  median_interval_seconds: number;
  min_interval_seconds: number;
  max_interval_seconds: number;
  interval_std_dev: number;
  jitter_pct: number;
  data_size_avg: number | null;
  data_size_variance: number | null;
  beacon_score: number;
  confidence: number;
  reasons: string[];
  mitre_techniques: string[];
  first_seen: number;
  last_seen: number;
}

/**
 * Extended beacon result with histogram / detailed interval data.
 */
export interface BeaconDetailedResult extends BeaconResult {
  interval_histogram: {
    bin_edges: number[];
    bin_counts: number[];
    bin_centers: number[];
  };
  all_intervals: number[];
  all_timestamps: number[];
  all_data_sizes: number[];
}

/**
 * Unified DNS threat result encompassing tunneling, DGA, fast-flux, etc.
 */
export interface DnsThreatResult {
  id: string;
  threat_type: 'tunneling' | 'dga' | 'fast_flux' | 'suspicious_pattern';
  domain: string;
  src_ip: string;
  query_count: number;
  score: number;
  confidence: number;
  reasons: string[];
  mitre_techniques: string[];
  first_seen: number;
  last_seen: number;
  /** Tunneling-specific */
  unique_subdomains?: number;
  avg_subdomain_entropy?: number;
  estimated_bytes_exfiltrated?: number;
  /** DGA-specific */
  domain_entropy?: number;
  consonant_ratio?: number;
  nxdomain_count?: number;
  /** Fast-flux-specific */
  unique_ips?: number;
  ip_changes_per_hour?: number;
  avg_ttl?: number;
}

/**
 * Single point on a threat timeline chart.
 */
export interface ThreatTimelinePoint {
  timestamp: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Severity distribution for donut/pie charts.
 */
export interface ThreatSeverityDistribution {
  severity: ThreatLevel;
  count: number;
  percentage: number;
}

/**
 * Model score comparison for multi-model analysis views.
 */
export interface ModelScoreComparison {
  entity: string;
  entity_type: string;
  scores: Record<string, number>;
  consensus_score: number;
  variance: number;
}

/**
 * Theme configuration for chart components.
 * Each variant supplies its own ChartTheme.
 */
export interface ChartTheme {
  colors: {
    primary: string;
    secondary: string;
    accent: string;
    danger: string;
    warning: string;
    success: string;
    info: string;
    background: string;
    surface: string;
    text: string;
    textSecondary: string;
    gridLine: string;
    series: string[];
  };
  fonts: {
    family: string;
    monoFamily: string;
    sizeSmall: number;
    sizeBase: number;
    sizeLarge: number;
  };
  spacing: {
    chartPadding: number;
    legendGap: number;
    tooltipPadding: number;
  };
}

/**
 * Per-variant theme wrapper. Contains chart theme plus UI-level overrides.
 */
export interface VariantTheme {
  id: number;
  name: string;
  description: string;
  chart: ChartTheme;
  ui: {
    borderRadius: string;
    cardBg: string;
    headerBg: string;
    accentGradient?: string;
  };
}

/**
 * Aggregate dashboard statistics.
 */
export interface DashboardStats {
  totalAlerts: number;
  criticalAlerts: number;
  highAlerts: number;
  mediumAlerts: number;
  lowAlerts: number;
  infoAlerts: number;
  totalBeacons: number;
  totalDnsThreats: number;
  uniqueSourceIPs: number;
  uniqueDestIPs: number;
  topMitreTechniques: { technique: string; count: number }[];
  averageThreatScore: number;
  alertsTrend: number;
  lastUpdated: string;
}

/**
 * Generic filter state for data views.
 */
export interface FilterState {
  search: string;
  severity: ThreatLevel[];
  dateRange: { start: string | null; end: string | null };
  sourceIPs: string[];
  destIPs: string[];
  mitreTechniques: string[];
  minScore: number;
  maxScore: number;
}

/**
 * Sort configuration for data tables.
 */
export interface SortConfig {
  key: string;
  direction: 'asc' | 'desc';
}

/**
 * Pagination state for data tables.
 */
export interface PaginationState {
  page: number;
  pageSize: number;
  totalItems: number;
  totalPages: number;
}
