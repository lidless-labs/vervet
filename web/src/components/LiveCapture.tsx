/**
 * Live Capture Component - Start/stop/manage packet capture sessions.
 */
import React, { useState, useEffect } from 'react';
import {
  Radio, Play, Square, Trash2, Download, RefreshCw, Wifi, Loader2, AlertCircle,
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface CaptureSession {
  session_id: string;
  interface: string;
  capture_filter: string;
  started_at: number;
  stopped_at: number | null;
  duration_seconds: number;
  packet_count: number;
  file_size_bytes: number;
  status: string;
  error: string;
}

interface NetworkInterface {
  name: string;
  state: string;
  mtu: number;
}

function formatDuration(s: number): string {
  if (s < 60) return `${s.toFixed(0)}s`;
  return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1048576).toFixed(1)} MB`;
}

interface LiveCaptureProps {
  className?: string;
}

const LiveCapture: React.FC<LiveCaptureProps> = ({ className = '' }) => {
  const [sessions, setSessions] = useState<CaptureSession[]>([]);
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [selectedIface, setSelectedIface] = useState('any');
  const [filter, setFilter] = useState('');
  const [maxPackets, setMaxPackets] = useState(10000);
  const [loading, setLoading] = useState(false);
  const [starting, setStarting] = useState(false);

  useEffect(() => {
    fetchInterfaces();
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchInterfaces = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/capture/interfaces`);
      if (res.ok) {
        const data = await res.json();
        setInterfaces(data.interfaces || []);
      }
    } catch {}
  };

  const fetchSessions = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/capture/sessions`);
      if (res.ok) {
        const data = await res.json();
        setSessions(data.sessions || []);
      }
    } catch {}
  };

  const startCapture = async () => {
    setStarting(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/capture/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          interface: selectedIface,
          filter,
          max_packets: maxPackets,
          max_seconds: 300,
        }),
      });
      if (res.ok) await fetchSessions();
    } catch (err) {
      console.error('Failed to start capture:', err);
    } finally {
      setStarting(false);
    }
  };

  const stopCapture = async (sessionId: string) => {
    try {
      await fetch(`${API_BASE}/api/v1/capture/stop/${sessionId}`, { method: 'POST' });
      await fetchSessions();
    } catch {}
  };

  const deleteCapture = async (sessionId: string) => {
    try {
      await fetch(`${API_BASE}/api/v1/capture/sessions/${sessionId}`, { method: 'DELETE' });
      await fetchSessions();
    } catch {}
  };

  const activeCount = sessions.filter(s => s.status === 'running').length;

  return (
    <div className={`space-y-5 ${className}`}>
      {/* Start Capture Panel */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-4">
          <Radio size={18} className="text-cyan-400" />
          <h3 className="text-lg font-semibold text-gray-100">Live Capture</h3>
          {activeCount > 0 && (
            <span className="text-xs bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full animate-pulse">
              {activeCount} active
            </span>
          )}
        </div>

        <div className="grid grid-cols-4 gap-3 mb-3">
          <div>
            <label className="text-xs text-gray-400 block mb-1">Interface</label>
            <select
              value={selectedIface}
              onChange={e => setSelectedIface(e.target.value)}
              className="w-full bg-gray-800 text-gray-200 text-sm border border-gray-700 rounded-lg px-3 py-2"
            >
              <option value="any">any (all interfaces)</option>
              {interfaces.map(iface => (
                <option key={iface.name} value={iface.name}>
                  {iface.name} ({iface.state})
                </option>
              ))}
            </select>
          </div>

          <div className="col-span-2">
            <label className="text-xs text-gray-400 block mb-1">BPF Filter (optional)</label>
            <input
              type="text"
              value={filter}
              onChange={e => setFilter(e.target.value)}
              placeholder="e.g., port 443, host 203.0.113.1, tcp"
              className="w-full bg-gray-800 text-gray-200 text-sm border border-gray-700 rounded-lg px-3 py-2"
            />
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-1">Max Packets</label>
            <input
              type="number"
              value={maxPackets}
              onChange={e => setMaxPackets(Math.max(100, Number(e.target.value)))}
              className="w-full bg-gray-800 text-gray-200 text-sm border border-gray-700 rounded-lg px-3 py-2"
              min={100}
              max={1000000}
            />
          </div>
        </div>

        <button
          onClick={startCapture}
          disabled={starting || activeCount >= 3}
          className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-500 disabled:bg-gray-700 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {starting ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
          {starting ? 'Starting...' : 'Start Capture'}
        </button>
        {activeCount >= 3 && (
          <p className="text-xs text-yellow-400 mt-2">Max 3 concurrent captures. Stop one first.</p>
        )}
      </div>

      {/* Session List */}
      {sessions.length > 0 && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Capture Sessions</h3>
          <div className="space-y-2">
            {sessions.map(session => (
              <div
                key={session.session_id}
                className={`flex items-center gap-3 p-3 rounded-lg border ${
                  session.status === 'running' ? 'border-green-500/50 bg-green-500/5' :
                  session.status === 'error' ? 'border-red-500/50 bg-red-500/5' :
                  'border-gray-700/50 bg-gray-800/30'
                }`}
              >
                {/* Status indicator */}
                <div className={`w-2 h-2 rounded-full ${
                  session.status === 'running' ? 'bg-green-500 animate-pulse' :
                  session.status === 'error' ? 'bg-red-500' :
                  'bg-gray-500'
                }`} />

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-sm">
                    <Wifi size={14} className="text-gray-500" />
                    <span className="font-mono text-gray-300">{session.interface}</span>
                    {session.capture_filter && (
                      <span className="text-xs text-gray-500 truncate">({session.capture_filter})</span>
                    )}
                  </div>
                  <div className="flex items-center gap-3 text-xs text-gray-500 mt-0.5">
                    <span>{formatDuration(session.duration_seconds)}</span>
                    {session.packet_count > 0 && <span>{session.packet_count.toLocaleString()} pkts</span>}
                    {session.file_size_bytes > 0 && <span>{formatBytes(session.file_size_bytes)}</span>}
                  </div>
                  {session.error && (
                    <div className="flex items-center gap-1 text-xs text-red-400 mt-1">
                      <AlertCircle size={12} /> {session.error}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex gap-1">
                  {session.status === 'running' && (
                    <button
                      onClick={() => stopCapture(session.session_id)}
                      className="p-1.5 bg-red-600 hover:bg-red-500 text-white rounded"
                      title="Stop capture"
                    >
                      <Square size={14} />
                    </button>
                  )}
                  {session.status !== 'running' && (
                    <button
                      onClick={() => deleteCapture(session.session_id)}
                      className="p-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded"
                      title="Delete"
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default LiveCapture;
