/**
 * V1 DNS Threats — Tabbed view (Tunneling / DGA / Fast-Flux / Patterns).
 * Each tab shows filtered threat list with scores and details.
 */
import React, { useState, useMemo } from 'react';
import { Globe, ArrowUpDown } from 'lucide-react';
import type { DnsThreatResult } from '../../../types';
import { mockDnsThreats } from '../../../data/mockData';

type TabKey = 'tunneling' | 'dga' | 'fast_flux' | 'suspicious_pattern';

interface TabDef {
  key: TabKey;
  label: string;
  count: number;
}

function scoreClass(score: number): string {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / 1048576).toFixed(1)}MB`;
}

const DnsThreats: React.FC = () => {
  const [activeTab, setActiveTab] = useState<TabKey>('tunneling');
  const [sortKey, setSortKey] = useState<'score' | 'query_count' | 'first_seen'>('score');
  const [sortDir, setSortDir] = useState<'desc' | 'asc'>('desc');

  const byType = useMemo(() => {
    const map: Record<TabKey, DnsThreatResult[]> = {
      tunneling: [],
      dga: [],
      fast_flux: [],
      suspicious_pattern: [],
    };
    mockDnsThreats.forEach((t) => map[t.threat_type]?.push(t));
    return map;
  }, []);

  const tabs: TabDef[] = [
    { key: 'tunneling', label: 'Tunneling', count: byType.tunneling.length },
    { key: 'dga', label: 'DGA', count: byType.dga.length },
    { key: 'fast_flux', label: 'Fast-Flux', count: byType.fast_flux.length },
    { key: 'suspicious_pattern', label: 'Patterns', count: byType.suspicious_pattern.length },
  ];

  const currentData = useMemo(() => {
    const data = [...(byType[activeTab] || [])];
    data.sort((a, b) => {
      const va = a[sortKey] as number;
      const vb = b[sortKey] as number;
      return sortDir === 'desc' ? vb - va : va - vb;
    });
    return data;
  }, [byType, activeTab, sortKey, sortDir]);

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const totalThreats = mockDnsThreats.length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div className="v1-section-title">
        <Globe size={22} />
        DNS Threat Analysis
        <span style={{ fontSize: 12, fontWeight: 400, color: '#64748B', marginLeft: 8 }}>
          {totalThreats} threats detected
        </span>
      </div>

      {/* Summary row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        {tabs.map((tab) => (
          <div
            key={tab.key}
            className="v1-panel"
            style={{ cursor: 'pointer', borderColor: activeTab === tab.key ? 'rgba(6,182,212,0.35)' : undefined }}
            onClick={() => setActiveTab(tab.key)}
          >
            <div className="v1-panel-body" style={{ textAlign: 'center', padding: '12px' }}>
              <div style={{ fontSize: 24, fontWeight: 700, color: activeTab === tab.key ? '#06B6D4' : '#E2E8F0', fontFamily: "'JetBrains Mono', monospace" }}>
                {tab.count}
              </div>
              <div style={{ fontSize: 11, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: 0.5 }}>{tab.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="v1-tabs">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            className={`v1-tab${activeTab === tab.key ? ' active' : ''}`}
            onClick={() => setActiveTab(tab.key)}
          >
            {tab.label}
            <span style={{ marginLeft: 6, fontSize: 10, opacity: 0.6 }}>({tab.count})</span>
          </button>
        ))}
      </div>

      {/* Threat List */}
      <div className="v1-panel">
        <div className="v1-panel-body-flush">
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(6,182,212,0.12)' }}>
                <ThCol>Domain</ThCol>
                <ThCol>Source IP</ThCol>
                <ThCol align="right" sortable onClick={() => toggleSort('query_count')} active={sortKey === 'query_count'}>
                  Queries
                </ThCol>
                {activeTab === 'tunneling' && <ThCol align="right">Subdomains</ThCol>}
                {activeTab === 'tunneling' && <ThCol align="right">Exfiltrated</ThCol>}
                {activeTab === 'dga' && <ThCol align="right">Entropy</ThCol>}
                {activeTab === 'dga' && <ThCol align="right">NXDOMAIN</ThCol>}
                {activeTab === 'fast_flux' && <ThCol align="right">Unique IPs</ThCol>}
                {activeTab === 'fast_flux' && <ThCol align="right">Avg TTL</ThCol>}
                <ThCol align="right">Confidence</ThCol>
                <ThCol align="center">MITRE</ThCol>
                <ThCol align="right" sortable onClick={() => toggleSort('score')} active={sortKey === 'score'}>
                  Score
                </ThCol>
              </tr>
            </thead>
            <tbody>
              {currentData.map((t) => (
                <DnsRow key={t.id} threat={t} tab={activeTab} />
              ))}
              {currentData.length === 0 && (
                <tr>
                  <td colSpan={10} style={{ padding: 24, textAlign: 'center', color: '#64748B' }}>
                    No threats in this category.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

const ThCol: React.FC<{
  children: React.ReactNode;
  align?: 'left' | 'center' | 'right';
  sortable?: boolean;
  onClick?: () => void;
  active?: boolean;
}> = ({ children, align = 'left', sortable, onClick, active }) => (
  <th
    style={{
      padding: '8px 10px',
      textAlign: align,
      color: active ? '#06B6D4' : '#64748B',
      fontFamily: "'Barlow Condensed', sans-serif",
      fontWeight: 600,
      fontSize: 11,
      textTransform: 'uppercase',
      letterSpacing: 0.5,
      cursor: sortable ? 'pointer' : 'default',
      userSelect: 'none',
    }}
    onClick={onClick}
  >
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      {children}
      {sortable && <ArrowUpDown size={11} style={{ opacity: active ? 1 : 0.3 }} />}
    </span>
  </th>
);

const DnsRow: React.FC<{ threat: DnsThreatResult; tab: TabKey }> = ({ threat, tab }) => {
  const t = threat;
  return (
    <tr style={{ borderBottom: '1px solid rgba(6,182,212,0.06)' }} className="v1-expandable-row">
      <td style={{ padding: '6px 10px' }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#E2E8F0', wordBreak: 'break-all' }}>
          {t.domain}
        </span>
      </td>
      <td style={{ padding: '6px 10px', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
        {t.src_ip}
      </td>
      <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#94A3B8' }}>
        {t.query_count.toLocaleString()}
      </td>

      {tab === 'tunneling' && (
        <>
          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#E2E8F0' }}>
            {t.unique_subdomains?.toLocaleString() ?? '-'}
          </td>
          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: t.estimated_bytes_exfiltrated && t.estimated_bytes_exfiltrated > 1000000 ? '#EF4444' : '#94A3B8' }}>
            {t.estimated_bytes_exfiltrated ? formatBytes(t.estimated_bytes_exfiltrated) : '-'}
          </td>
        </>
      )}

      {tab === 'dga' && (
        <>
          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: (t.domain_entropy ?? 0) > 4 ? '#EF4444' : '#94A3B8' }}>
            {t.domain_entropy?.toFixed(2) ?? '-'}
          </td>
          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#F59E0B' }}>
            {t.nxdomain_count ?? '-'}
          </td>
        </>
      )}

      {tab === 'fast_flux' && (
        <>
          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#E2E8F0' }}>
            {t.unique_ips ?? '-'}
          </td>
          <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: (t.avg_ttl ?? 999) < 60 ? '#EF4444' : '#94A3B8' }}>
            {t.avg_ttl ? `${t.avg_ttl.toFixed(0)}s` : '-'}
          </td>
        </>
      )}

      <td style={{ padding: '6px 10px', textAlign: 'right', fontFamily: "'JetBrains Mono', monospace", fontSize: 11, color: '#06B6D4' }}>
        {(t.confidence * 100).toFixed(0)}%
      </td>
      <td style={{ padding: '6px 10px', textAlign: 'center' }}>
        <div style={{ display: 'flex', gap: 3, justifyContent: 'center', flexWrap: 'wrap' }}>
          {t.mitre_techniques.map((m) => (
            <span key={m} className="v1-mitre-tag">{m}</span>
          ))}
        </div>
      </td>
      <td style={{ padding: '6px 10px', textAlign: 'right' }}>
        <span className={`v1-score-inline ${scoreClass(t.score)}`}>
          {t.score}
        </span>
      </td>
    </tr>
  );
};

export default DnsThreats;
