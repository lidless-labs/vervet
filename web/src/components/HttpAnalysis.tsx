import React, { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || '';

interface HttpSession {
  uid: string; ts: string; src_ip: string; dst_ip: string; dst_port: number;
  method: string; uri: string; user_agent: string; status_code: number;
  request_body_len: number; response_body_len: number;
  anomalies: string[]; score: string; mitre: string[];
}

const ScoreBadge: React.FC<{score: string}> = ({ score }) => {
  const c: Record<string, string> = { malicious: 'bg-red-500/20 text-red-400', suspicious: 'bg-amber-500/20 text-amber-400', clean: 'bg-emerald-500/20 text-emerald-400' };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${c[score] || c.clean}`}>{score}</span>;
};

const MethodBadge: React.FC<{method: string}> = ({ method }) => {
  const c: Record<string, string> = { GET: 'text-cyan-400', POST: 'text-amber-400', PUT: 'text-orange-400', DELETE: 'text-red-400' };
  return <span className={`font-mono text-xs font-bold ${c[method] || 'text-gray-400'}`}>{method}</span>;
};

const HttpAnalysis: React.FC = () => {
  const [sessions, setSessions] = useState<HttpSession[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<HttpSession | null>(null);
  const [filter, setFilter] = useState('all');

  const load = async () => {
    setLoading(true);
    try {
      await fetch(`${API}/api/v1/http/analyze`, { method: 'POST' });
      const [sRes, stRes] = await Promise.all([fetch(`${API}/api/v1/http/sessions`), fetch(`${API}/api/v1/http/stats`)]);
      setSessions((await sRes.json()).sessions || []);
      setStats(await stRes.json());
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);

  const filtered = filter === 'all' ? sessions : sessions.filter(s => s.score === filter);

  return (
    <div className="space-y-6">
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Total Requests', value: stats.total_requests },
            { label: 'Anomalies Found', value: stats.anomalies_found, color: 'text-amber-400' },
            { label: 'Malicious', value: stats.malicious, color: 'text-red-400' },
            { label: 'Suspicious', value: stats.suspicious, color: 'text-amber-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
              <span className="text-xs text-gray-500">{label}</span>
              <div className={`text-2xl font-bold ${color || 'text-gray-100'}`}>{value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="flex gap-2">
        {['all', 'malicious', 'suspicious', 'clean'].map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1 rounded text-sm ${filter === f ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-400 hover:text-gray-200'}`}>{f}</button>
        ))}
      </div>

      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl overflow-hidden">
        {loading ? <div className="p-8 text-center text-gray-500">Analyzing HTTP traffic...</div> : (
          <table className="w-full text-sm">
            <thead><tr className="border-b border-gray-700/50 text-gray-500 text-xs">
              <th className="text-left p-3">Method</th><th className="text-left p-3">URI</th>
              <th className="text-left p-3 hidden md:table-cell">User-Agent</th>
              <th className="text-left p-3">Status</th><th className="text-left p-3">Score</th>
            </tr></thead>
            <tbody>
              {filtered.slice(0, 50).map(s => (
                <tr key={s.uid} onClick={() => setSelected(selected?.uid === s.uid ? null : s)}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer">
                  <td className="p-3"><MethodBadge method={s.method} /></td>
                  <td className="p-3 font-mono text-xs text-gray-300 truncate max-w-[300px]">{s.uri}</td>
                  <td className="p-3 text-gray-500 text-xs truncate max-w-[200px] hidden md:table-cell">{s.user_agent || '(empty)'}</td>
                  <td className="p-3 text-gray-400 text-xs">{s.status_code}</td>
                  <td className="p-3"><ScoreBadge score={s.score} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5 space-y-4">
          <h3 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <MethodBadge method={selected.method} /> <span className="font-mono text-sm">{selected.uri}</span>
          </h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-gray-500">Source:</span> <span className="text-gray-300 font-mono">{selected.src_ip}</span></div>
            <div><span className="text-gray-500">Dest:</span> <span className="text-gray-300 font-mono">{selected.dst_ip}:{selected.dst_port}</span></div>
            <div><span className="text-gray-500">User-Agent:</span> <span className="text-gray-300 text-xs">{selected.user_agent || '(empty)'}</span></div>
            <div><span className="text-gray-500">Body Size:</span> <span className="text-gray-300">{selected.request_body_len.toLocaleString()} bytes</span></div>
          </div>
          {selected.anomalies.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Anomalies</h4>
              {selected.anomalies.map((a, i) => <div key={i} className="text-sm text-amber-400 flex items-center gap-1"><AlertTriangle size={12} />{a}</div>)}
            </div>
          )}
          {selected.mitre.length > 0 && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">MITRE ATT&CK</h4>
              {selected.mitre.map((m, i) => <span key={i} className="inline-block bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs px-2 py-0.5 rounded mr-2 mb-1">{m}</span>)}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default HttpAnalysis;
