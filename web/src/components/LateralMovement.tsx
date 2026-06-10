import React, { useEffect, useState } from 'react';
import { ChevronRight } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || '';

interface Target { ip: string; port: number; service: string; ts: string; }
interface Detection {
  src_ip: string; targets: Target[]; target_count: number; services_used: string[];
  first_seen: string; last_seen: string; timespan_minutes: number;
  risk_score: number; risk_level: string; pattern: string; mitre: string[];
}

const RiskBadge: React.FC<{level: string; score: number}> = ({ level, score }) => {
  const c: Record<string, string> = { critical: 'bg-red-500/20 text-red-400', high: 'bg-orange-500/20 text-orange-400', medium: 'bg-amber-500/20 text-amber-400', low: 'bg-emerald-500/20 text-emerald-400' };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${c[level] || c.low}`}>{level} ({score})</span>;
};

const LateralMovement: React.FC = () => {
  const [detections, setDetections] = useState<Detection[]>([]);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<Detection | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      await fetch(`${API}/api/v1/lateral/analyze`, { method: 'POST' });
      const [dRes, sRes] = await Promise.all([fetch(`${API}/api/v1/lateral/detections`), fetch(`${API}/api/v1/lateral/stats`)]);
      setDetections((await dRes.json()).detections || []);
      setStats(await sRes.json());
    } finally { setLoading(false); }
  };

  useEffect(() => { void load(); }, []);

  return (
    <div className="space-y-6">
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: 'Detections', value: stats.total_detections },
            { label: 'Hosts Involved', value: stats.hosts_involved },
            { label: 'Critical', value: stats.risk_levels?.critical || 0, color: 'text-red-400' },
            { label: 'High', value: stats.risk_levels?.high || 0, color: 'text-orange-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-4">
              <span className="text-xs text-gray-500">{label}</span>
              <div className={`text-2xl font-bold ${color || 'text-gray-100'}`}>{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Detection list */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl overflow-hidden">
        {loading ? <div className="p-8 text-center text-gray-500">Analyzing lateral movement...</div> : detections.length === 0 ? (
          <div className="p-8 text-center text-gray-500">No lateral movement detected.</div>
        ) : (
          <table className="w-full text-sm">
            <thead><tr className="border-b border-gray-700/50 text-gray-500 text-xs">
              <th className="text-left p-3">Source</th><th className="text-left p-3">Targets</th>
              <th className="text-left p-3 hidden md:table-cell">Services</th>
              <th className="text-left p-3 hidden md:table-cell">Timespan</th><th className="text-left p-3">Risk</th>
            </tr></thead>
            <tbody>
              {detections.map(d => (
                <tr key={d.src_ip} onClick={() => setSelected(selected?.src_ip === d.src_ip ? null : d)}
                  className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer">
                  <td className="p-3 font-mono text-xs text-gray-100">{d.src_ip}</td>
                  <td className="p-3 text-gray-300 text-xs">{d.target_count} hosts</td>
                  <td className="p-3 text-gray-400 text-xs hidden md:table-cell">{d.services_used.join(', ')}</td>
                  <td className="p-3 text-gray-400 text-xs hidden md:table-cell">{d.timespan_minutes}m</td>
                  <td className="p-3"><RiskBadge level={d.risk_level} score={d.risk_score} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-gray-100 font-mono">{selected.src_ip}</h3>
            <RiskBadge level={selected.risk_level} score={selected.risk_score} />
          </div>

          <div className="grid grid-cols-3 gap-4 text-sm">
            <div><span className="text-gray-500">Pattern:</span> <span className="text-gray-300">{selected.pattern.replace(/_/g, ' ')}</span></div>
            <div><span className="text-gray-500">First seen:</span> <span className="text-gray-300 text-xs">{new Date(selected.first_seen).toLocaleTimeString()}</span></div>
            <div><span className="text-gray-500">Duration:</span> <span className="text-gray-300">{selected.timespan_minutes}m</span></div>
          </div>

          {/* Target flow */}
          <div>
            <h4 className="text-sm font-medium text-gray-400 mb-3">Target Hosts</h4>
            <div className="space-y-1.5 max-h-48 overflow-y-auto">
              {selected.targets.map((t, i) => (
                <div key={i} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-gray-500">{selected.src_ip}</span>
                  <ChevronRight size={12} className="text-gray-600" />
                  <span className="font-mono text-gray-200">{t.ip}:{t.port}</span>
                  <span className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">{t.service}</span>
                  <span className="text-gray-600 ml-auto">{new Date(t.ts).toLocaleTimeString()}</span>
                </div>
              ))}
            </div>
          </div>

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

export default LateralMovement;
