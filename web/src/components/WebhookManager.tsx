import React, { useEffect, useState } from 'react';
import { Plus, Trash2, Pencil, Check, X, Send } from 'lucide-react';

const API = import.meta.env.VITE_API_URL || '';

interface WebhookConfig { id: string; name: string; url: string; webhook_type: string; enabled: boolean; severity_threshold: string; event_types: string[]; }
interface DeliveryRecord { id: string; config_name: string; timestamp: number; status: string; response_code: number | null; payload_preview: string; error: string | null; }

const StatusBadge: React.FC<{status: string}> = ({ status }) => {
  const colors: Record<string, string> = {
    success: 'bg-emerald-500/20 text-emerald-400', failed: 'bg-red-500/20 text-red-400', pending: 'bg-amber-500/20 text-amber-400',
  };
  return <span className={`px-2 py-0.5 rounded text-xs ${colors[status] || colors.pending}`}>{status}</span>;
};

const EVENT_TYPES = ['new_threat', 'score_change', 'beacon_detected', 'cert_anomaly'];

const WebhookManager: React.FC = () => {
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([]);
  const [history, setHistory] = useState<DeliveryRecord[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<WebhookConfig | null>(null);
  const [toast, setToast] = useState<{msg: string; type: string} | null>(null);
  const [form, setForm] = useState({ name: '', url: '', webhook_type: 'generic', severity_threshold: 'medium', event_types: [...EVENT_TYPES] });

  const load = async () => {
    const [wRes, hRes] = await Promise.all([fetch(`${API}/api/v1/webhooks`), fetch(`${API}/api/v1/webhooks/history`)]);
    setWebhooks((await wRes.json()).webhooks || []);
    setHistory((await hRes.json()).history || []);
  };

  useEffect(() => { void load(); }, []);

  const showToast = (msg: string, type = 'success') => { setToast({ msg, type }); setTimeout(() => setToast(null), 3000); };

  const handleSave = async () => {
    if (editing) {
      await fetch(`${API}/api/v1/webhooks/${editing.id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
      showToast('Webhook updated');
    } else {
      await fetch(`${API}/api/v1/webhooks`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(form) });
      showToast('Webhook created');
    }
    setShowForm(false); setEditing(null); setForm({ name: '', url: '', webhook_type: 'generic', severity_threshold: 'medium', event_types: [...EVENT_TYPES] });
    await load();
  };

  const handleDelete = async (id: string) => {
    await fetch(`${API}/api/v1/webhooks/${id}`, { method: 'DELETE' });
    showToast('Webhook deleted'); await load();
  };

  const handleTest = async (id: string) => {
    const res = await fetch(`${API}/api/v1/webhooks/${id}/test`, { method: 'POST' });
    const data = await res.json();
    showToast(data.status === 'success' ? 'Test sent successfully!' : `Test failed: ${data.error || 'Unknown error'}`, data.status === 'success' ? 'success' : 'error');
    await load();
  };

  const startEdit = (w: WebhookConfig) => {
    setEditing(w); setForm({ name: w.name, url: w.url, webhook_type: w.webhook_type, severity_threshold: w.severity_threshold, event_types: [...w.event_types] });
    setShowForm(true);
  };

  const toggleEvent = (evt: string) => {
    setForm(f => ({ ...f, event_types: f.event_types.includes(evt) ? f.event_types.filter(e => e !== evt) : [...f.event_types, evt] }));
  };

  return (
    <div className="space-y-6">
      {toast && (
        <div className={`fixed top-4 right-4 z-50 px-4 py-2 rounded-lg text-sm ${toast.type === 'success' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' : 'bg-red-500/20 text-red-400 border border-red-500/30'}`}>
          {toast.msg}
        </div>
      )}

      {/* Webhook list */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl">
        <div className="flex items-center justify-between p-4 border-b border-gray-700/50">
          <h3 className="text-sm font-medium text-gray-300">Configured Webhooks ({webhooks.length})</h3>
          <button onClick={() => { setEditing(null); setForm({ name: '', url: '', webhook_type: 'generic', severity_threshold: 'medium', event_types: [...EVENT_TYPES] }); setShowForm(true); }}
            className="flex items-center gap-1 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs"><Plus size={14} />Add</button>
        </div>
        {webhooks.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No webhooks configured. Add one to get started.</div>
        ) : (
          <div className="divide-y divide-gray-800/50">
            {webhooks.map(w => (
              <div key={w.id} className="flex items-center justify-between p-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-100 font-medium text-sm">{w.name}</span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-gray-800 text-gray-400">{w.webhook_type}</span>
                    <span className={`w-2 h-2 rounded-full ${w.enabled ? 'bg-emerald-400' : 'bg-gray-600'}`} />
                  </div>
                  <div className="font-mono text-xs text-gray-500 mt-1 truncate max-w-md">{w.url}</div>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => handleTest(w.id)} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-cyan-400" title="Test"><Send size={14} /></button>
                  <button onClick={() => startEdit(w)} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-gray-200" title="Edit"><Pencil size={14} /></button>
                  <button onClick={() => handleDelete(w.id)} className="p-1.5 rounded hover:bg-gray-800 text-gray-400 hover:text-red-400" title="Delete"><Trash2 size={14} /></button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Add/Edit form */}
      {showForm && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5 space-y-4">
          <h3 className="text-sm font-medium text-gray-300">{editing ? 'Edit' : 'Add'} Webhook</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-500 block mb-1">Name</label>
              <input value={form.name} onChange={e => setForm(f => ({...f, name: e.target.value}))} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200" />
            </div>
            <div>
              <label className="text-xs text-gray-500 block mb-1">Type</label>
              <select value={form.webhook_type} onChange={e => setForm(f => ({...f, webhook_type: e.target.value}))} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200">
                <option value="generic">Generic</option><option value="discord">Discord</option><option value="slack">Slack</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">URL</label>
            <input value={form.url} onChange={e => setForm(f => ({...f, url: e.target.value}))} className="w-full bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm font-mono text-gray-200" placeholder="https://..." />
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-1">Severity Threshold</label>
            <select value={form.severity_threshold} onChange={e => setForm(f => ({...f, severity_threshold: e.target.value}))} className="bg-gray-800 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200">
              <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
            </select>
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-2">Event Types</label>
            <div className="flex gap-2 flex-wrap">
              {EVENT_TYPES.map(evt => (
                <button key={evt} onClick={() => toggleEvent(evt)}
                  className={`px-3 py-1 rounded text-xs ${form.event_types.includes(evt) ? 'bg-cyan-600/20 text-cyan-400 border border-cyan-500/30' : 'bg-gray-800 text-gray-500 border border-gray-700'}`}>
                  {evt.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-2">
            <button onClick={handleSave} className="flex items-center gap-1 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-sm"><Check size={14} />Save</button>
            <button onClick={() => { setShowForm(false); setEditing(null); }} className="flex items-center gap-1 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-sm"><X size={14} />Cancel</button>
          </div>
        </div>
      )}

      {/* Delivery history */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl">
        <div className="p-4 border-b border-gray-700/50">
          <h3 className="text-sm font-medium text-gray-300">Delivery History</h3>
        </div>
        {history.length === 0 ? (
          <div className="p-8 text-center text-gray-500 text-sm">No deliveries yet.</div>
        ) : (
          <table className="w-full text-sm">
            <thead><tr className="border-b border-gray-700/50 text-gray-500 text-xs">
              <th className="text-left p-3">Time</th><th className="text-left p-3">Webhook</th><th className="text-left p-3">Status</th><th className="text-left p-3 hidden md:table-cell">Code</th>
            </tr></thead>
            <tbody>
              {history.slice(0, 20).map(r => (
                <tr key={r.id} className="border-b border-gray-800/50">
                  <td className="p-3 text-gray-400 text-xs">{new Date(r.timestamp * 1000).toLocaleString()}</td>
                  <td className="p-3 text-gray-200 text-xs">{r.config_name}</td>
                  <td className="p-3"><StatusBadge status={r.status} /></td>
                  <td className="p-3 text-gray-500 text-xs hidden md:table-cell">{r.response_code || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default WebhookManager;
