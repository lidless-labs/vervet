/**
 * GlobalSearch: Ctrl+K searchbar with dropdown results.
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Search, X, Globe, Network, Shield, Wifi } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_BASE || '';

interface SearchResults {
  query: string;
  ips: Array<{ ip: string; type: string; connection_count: number }>;
  domains: Array<{ domain: string; query_type: string; src_ip: string }>;
  alerts: Array<{ signature: string; src_ip: string; dst_ip: string; severity: number }>;
  connections: Array<{ src_ip: string; dst_ip: string; dst_port: number; proto: string }>;
  total: number;
}

interface GlobalSearchProps {
  onNavigate?: (path: string) => void;
}

const GlobalSearch: React.FC<GlobalSearchProps> = () => {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const latestRequestIdRef = useRef(0);

  // Ctrl+K handler
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setOpen(true);
        setTimeout(() => inputRef.current?.focus(), 50);
      }
      if (e.key === 'Escape') {
        setOpen(false);
        setQuery('');
        setResults(null);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const search = useCallback(async (q: string, requestId: number) => {
    if (!q.trim() || q.length < 2) {
      setResults(null);
      return;
    }
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/search?q=${encodeURIComponent(q)}`);
      if (requestId !== latestRequestIdRef.current) return;
      if (res.ok) {
        setResults(await res.json());
      } else {
        setResults(null);
      }
    } catch {
      if (requestId === latestRequestIdRef.current) setResults(null);
    } finally {
      if (requestId === latestRequestIdRef.current) setLoading(false);
    }
  }, []);

  const handleInput = (val: string) => {
    setQuery(val);
    const id = ++latestRequestIdRef.current;
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => search(val, id), 300);
  };

  const close = () => {
    setOpen(false);
    setQuery('');
    setResults(null);
  };

  if (!open) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-50"
        onClick={close}
        style={{ backdropFilter: 'blur(2px)' }}
      />

      {/* Search modal */}
      <div className="fixed top-[15%] left-1/2 -translate-x-1/2 w-full max-w-xl z-50">
        <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
          {/* Input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-gray-800">
            <Search size={18} className="text-gray-500" />
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => handleInput(e.target.value)}
              placeholder="Search IPs, domains, alerts..."
              className="flex-1 bg-transparent text-gray-200 placeholder-gray-600 outline-none text-sm"
              autoFocus
            />
            {loading && <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />}
            <button onClick={close} className="text-gray-500 hover:text-gray-300">
              <X size={16} />
            </button>
          </div>

          {/* Results */}
          {results && results.total > 0 && (
            <div className="max-h-80 overflow-y-auto">
              {results.ips.length > 0 && (
                <div className="px-3 py-2">
                  <div className="text-xs text-gray-500 uppercase tracking-wider px-2 py-1">IPs ({results.ips.length})</div>
                  {results.ips.slice(0, 5).map((ip) => (
                    <div key={ip.ip} className="flex items-center gap-3 px-2 py-2 rounded hover:bg-gray-800/50 cursor-pointer text-sm">
                      <Network size={14} className="text-cyan-500" />
                      <span className="text-gray-200 font-mono">{ip.ip}</span>
                      <span className="text-gray-600 text-xs">{ip.type} ({ip.connection_count} conns)</span>
                    </div>
                  ))}
                </div>
              )}

              {results.domains.length > 0 && (
                <div className="px-3 py-2 border-t border-gray-800/50">
                  <div className="text-xs text-gray-500 uppercase tracking-wider px-2 py-1">Domains ({results.domains.length})</div>
                  {results.domains.slice(0, 5).map((d, i) => (
                    <div key={`${d.domain}-${i}`} className="flex items-center gap-3 px-2 py-2 rounded hover:bg-gray-800/50 cursor-pointer text-sm">
                      <Globe size={14} className="text-purple-400" />
                      <span className="text-gray-200">{d.domain}</span>
                      <span className="text-gray-600 text-xs">{d.query_type}</span>
                    </div>
                  ))}
                </div>
              )}

              {results.alerts.length > 0 && (
                <div className="px-3 py-2 border-t border-gray-800/50">
                  <div className="text-xs text-gray-500 uppercase tracking-wider px-2 py-1">Alerts ({results.alerts.length})</div>
                  {results.alerts.slice(0, 5).map((a, i) => (
                    <div key={`${a.signature}-${i}`} className="flex items-center gap-3 px-2 py-2 rounded hover:bg-gray-800/50 cursor-pointer text-sm">
                      <Shield size={14} className="text-red-400" />
                      <span className="text-gray-200 truncate">{a.signature}</span>
                      <span className="text-gray-600 text-xs">sev {a.severity}</span>
                    </div>
                  ))}
                </div>
              )}

              {results.connections.length > 0 && (
                <div className="px-3 py-2 border-t border-gray-800/50">
                  <div className="text-xs text-gray-500 uppercase tracking-wider px-2 py-1">Connections ({results.connections.length})</div>
                  {results.connections.slice(0, 5).map((c, i) => (
                    <div key={`${c.src_ip}-${c.dst_ip}-${i}`} className="flex items-center gap-3 px-2 py-2 rounded hover:bg-gray-800/50 cursor-pointer text-sm">
                      <Wifi size={14} className="text-green-400" />
                      <span className="text-gray-200 font-mono text-xs">{c.src_ip} &rarr; {c.dst_ip}:{c.dst_port}</span>
                      <span className="text-gray-600 text-xs">{c.proto}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {results && results.total === 0 && (
            <div className="px-4 py-8 text-center text-gray-500 text-sm">
              No results found for "{query}"
            </div>
          )}

          {/* Footer hint */}
          <div className="px-4 py-2 border-t border-gray-800 text-xs text-gray-600 flex gap-4">
            <span><kbd className="px-1.5 py-0.5 bg-gray-800 rounded text-gray-500">Esc</kbd> to close</span>
            <span><kbd className="px-1.5 py-0.5 bg-gray-800 rounded text-gray-500">Ctrl+K</kbd> to search</span>
          </div>
        </div>
      </div>
    </>
  );
};

export default GlobalSearch;
