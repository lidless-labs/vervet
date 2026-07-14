/**
 * V3 Connections — Enterprise DataTable with filters, search, export.
 * Clean alternating rows, sticky header, filter dropdowns.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Download, Filter, Search, X, ChevronUp, ChevronDown, ChevronsUpDown, ChevronLeft, ChevronRight } from 'lucide-react';
import { format } from 'date-fns';
import LoadingSkeleton from '../../../components/LoadingSkeleton';
import AddToCase from '../../../components/AddToCase';

const API_BASE = import.meta.env.VITE_API_BASE || '';

type SortDir = 'asc' | 'desc';

interface ConnectionRow {
  uid: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  proto: string;
  service: string | null;
  duration: number;
  bytes_sent: number;
  bytes_recv: number;
  timestamp: string;
  tags: string[];
  source: string;
  conn_state: string;
  pkts_sent: number;
  pkts_recv: number;
}

interface ConnectionsResponse {
  total: number;
  limit: number;
  offset: number;
  connections: ConnectionRow[];
}

const PROTO_OPTIONS = ['all', 'tcp', 'udp', 'icmp'] as const;

const formatBytes = (bytes: number): string => {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  const val = bytes / Math.pow(1024, i);
  return `${val.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
};

const formatDuration = (seconds: number): string => {
  if (seconds < 1) return `${(seconds * 1000).toFixed(0)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  if (seconds < 3600) return `${(seconds / 60).toFixed(1)}m`;
  return `${(seconds / 3600).toFixed(1)}h`;
};

const protoColor = (proto: string) => {
  const map: Record<string, string> = {
    tcp: '#2563EB', udp: '#7C3AED', icmp: '#D97706',
  };
  return map[proto?.toLowerCase()] || '#64748B';
};

const Connections: React.FC = () => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [rows, setRows] = useState<ConnectionRow[]>([]);
  const [total, setTotal] = useState(0);

  const [search, setSearch] = useState('');
  const [proto, setProto] = useState<string>('all');
  const [sortKey, setSortKey] = useState<string>('bytes');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [page, setPage] = useState(1);
  const pageSize = 12;

  useEffect(() => {
    (async () => {
      setLoading(true);
      setError('');
      try {
        const safeFetch = async (url: string) => {
          const res = await fetch(url);
          if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
          return res.json();
        };

        const [data] = await Promise.all([
          safeFetch(`${API_BASE}/api/v1/data/connections?limit=500&offset=0`) as Promise<ConnectionsResponse>,
        ]);

        setRows(data.connections || []);
        setTotal(data.total || 0);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load connections');
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const filtered = useMemo(() => {
    let data = [...rows];
    if (proto !== 'all') {
      data = data.filter((c) => c.proto?.toLowerCase() === proto);
    }
    if (search) {
      const q = search.toLowerCase();
      data = data.filter(
        (c) =>
          c.src_ip.toLowerCase().includes(q) ||
          c.dst_ip.toLowerCase().includes(q) ||
          String(c.src_port).includes(q) ||
          String(c.dst_port).includes(q) ||
          (c.service || '').toLowerCase().includes(q) ||
          (c.conn_state || '').toLowerCase().includes(q) ||
          c.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return data;
  }, [rows, search, proto]);

  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      let va: string | number;
      let vb: string | number;
      switch (sortKey) {
        case 'src': va = a.src_ip; vb = b.src_ip; break;
        case 'dst': va = a.dst_ip; vb = b.dst_ip; break;
        case 'proto': va = a.proto; vb = b.proto; break;
        case 'bytes': va = a.bytes_sent + a.bytes_recv; vb = b.bytes_sent + b.bytes_recv; break;
        case 'duration': va = a.duration; vb = b.duration; break;
        case 'timestamp': va = new Date(a.timestamp).getTime(); vb = new Date(b.timestamp).getTime(); break;
        default: va = a.bytes_sent + a.bytes_recv; vb = b.bytes_sent + b.bytes_recv;
      }
      if (typeof va === 'number' && typeof vb === 'number') {
        return sortDir === 'asc' ? va - vb : vb - va;
      }
      return sortDir === 'asc'
        ? String(va).localeCompare(String(vb))
        : String(vb).localeCompare(String(va));
    });
    return arr;
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sorted.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paged = sorted.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(key);
      setSortDir('desc');
    }
  };

  const SortIcon: React.FC<{ col: string }> = ({ col }) => {
    if (sortKey !== col) return <ChevronsUpDown size={12} style={{ opacity: 0.3 }} />;
    return sortDir === 'asc'
      ? <ChevronUp size={12} style={{ color: '#2563EB' }} />
      : <ChevronDown size={12} style={{ color: '#2563EB' }} />;
  };

  if (loading) {
    return <LoadingSkeleton rows={8} />;
  }

  return (
    <div>
      <div style={{ marginBottom: 24 }}>
        <h1 className="v3-heading" style={{ fontSize: 22, margin: 0 }}>Connections</h1>
        <p className="v3-text-secondary" style={{ fontSize: 13, marginTop: 4 }}>
          Network connection log with threat correlation · {rows.length < total
            ? `showing first ${rows.length.toLocaleString()} of ${total.toLocaleString()}`
            : total.toLocaleString()} records
        </p>
      </div>

      {error && (
        <div style={{
          marginBottom: 16, padding: '10px 14px', borderRadius: 8,
          background: '#FEF2F2', border: '1px solid #FECACA', color: '#B91C1C', fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* Toolbar */}
      <div className="v3-card" style={{ marginBottom: 16, padding: '12px 16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {/* Search */}
          <div style={{ position: 'relative', flex: '1 1 260px', maxWidth: 360 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: '#94A3B8' }} />
            <input
              className="v3-input"
              style={{ width: '100%', paddingLeft: 32, paddingRight: search ? 28 : 12 }}
              placeholder="Search IP, port, service…"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: '#94A3B8', padding: 0 }}
              >
                <X size={14} />
              </button>
            )}
          </div>

          {/* Protocol filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Filter size={14} style={{ color: '#64748B' }} />
            <select
              className="v3-select"
              value={proto}
              onChange={(e) => { setProto(e.target.value); setPage(1); }}
            >
              {PROTO_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s === 'all' ? 'All Protocols' : s.toUpperCase()}
                </option>
              ))}
            </select>
          </div>

          {/* Export button (UI only) */}
          <button className="v3-btn v3-btn-outline" style={{ marginLeft: 'auto' }}>
            <Download size={14} />
            Export CSV
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="v3-card" style={{ padding: 0 }}>
        <div className="v3-table-wrapper" style={{ maxHeight: 560, overflowY: 'auto' }}>
          <table className="v3-table">
            <thead>
              <tr>
                <th className="sortable" onClick={() => handleSort('src')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Source <SortIcon col="src" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('dst')}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Destination <SortIcon col="dst" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('proto')} style={{ width: 80 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Proto <SortIcon col="proto" />
                  </span>
                </th>
                <th style={{ width: 90 }}>Service</th>
                <th style={{ width: 80 }}>State</th>
                <th className="sortable" onClick={() => handleSort('bytes')} style={{ width: 100 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Bytes <SortIcon col="bytes" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('duration')} style={{ width: 90 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Duration <SortIcon col="duration" />
                  </span>
                </th>
                <th className="sortable" onClick={() => handleSort('timestamp')} style={{ width: 130 }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                    Time <SortIcon col="timestamp" />
                  </span>
                </th>
                <th style={{ width: 120 }}>Case</th>
              </tr>
            </thead>
            <tbody>
              {paged.length === 0 ? (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', padding: '32px 16px', color: '#94A3B8' }}>
                    No connections match your filters.
                  </td>
                </tr>
              ) : (
                paged.map((c) => (
                  <tr key={c.uid}>
                    <td className="mono">{c.src_ip}:{c.src_port}</td>
                    <td className="mono">{c.dst_ip}:{c.dst_port}</td>
                    <td>
                      <span
                        className="v3-score-badge"
                        style={{
                          background: `${protoColor(c.proto)}10`,
                          color: protoColor(c.proto),
                        }}
                      >
                        {c.proto?.toUpperCase()}
                      </span>
                    </td>
                    <td className="mono" style={{ fontSize: 12, color: '#64748B' }}>
                      {c.service || '—'}
                    </td>
                    <td className="mono" style={{ fontSize: 12, color: '#64748B' }}>
                      {c.conn_state || '—'}
                    </td>
                    <td className="mono" style={{ color: '#64748B' }}>{formatBytes(c.bytes_sent + c.bytes_recv)}</td>
                    <td className="mono" style={{ color: '#64748B', fontSize: 12 }}>{formatDuration(c.duration)}</td>
                    <td style={{ color: '#64748B', fontSize: 12 }}>
                      {format(new Date(c.timestamp), 'MMM d, HH:mm')}
                    </td>
                    <td>
                      <AddToCase
                        findingType="connection"
                        summary={`Connection: ${c.src_ip}:${c.src_port} → ${c.dst_ip}:${c.dst_port}`}
                        data={{
                          uid: c.uid,
                          src_ip: c.src_ip,
                          src_port: c.src_port,
                          dst_ip: c.dst_ip,
                          dst_port: c.dst_port,
                          proto: c.proto,
                          service: c.service,
                          conn_state: c.conn_state,
                        }}
                      />
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 16px', borderTop: '1px solid #E2E8F0', fontSize: 12, color: '#64748B',
          }}>
            <span>{sorted.length} results · Page {currentPage} of {totalPages}</span>
            <div style={{ display: 'flex', gap: 4 }}>
              <button
                className="v3-btn v3-btn-outline"
                style={{ padding: '4px 8px' }}
                disabled={currentPage <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                <ChevronLeft size={14} />
              </button>
              <button
                className="v3-btn v3-btn-outline"
                style={{ padding: '4px 8px' }}
                disabled={currentPage >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Connections;
