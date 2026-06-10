/**
 * Session View Component - Displays reconstructed network sessions with event timelines.
 */
import React, { useState, useEffect } from 'react';
import {
  Network, Clock, ChevronDown, ChevronRight,
  AlertTriangle, Globe, Activity,
} from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface SessionEvent {
  timestamp: number;
  event_type: string;
  summary: string;
  details: Record<string, unknown>;
  severity: string;
}

interface Session {
  session_id: string;
  src_ip: string;
  dst_ip: string;
  start_time: number;
  end_time: number;
  duration_seconds: number;
  total_bytes_sent: number;
  total_bytes_recv: number;
  total_bytes: number;
  connection_count: number;
  dns_query_count: number;
  alert_count: number;
  protocols: string[];
  services: string[];
  ports: number[];
  threat_score: number;
  threat_level: string;
  flags: string[];
  events?: SessionEvent[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'border-red-500 bg-red-500/10 text-red-400',
  high: 'border-orange-500 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500 bg-yellow-500/10 text-yellow-400',
  low: 'border-green-500 bg-green-500/10 text-green-400',
  info: 'border-gray-500 bg-gray-500/10 text-gray-400',
};

const EVENT_ICONS: Record<string, React.ElementType> = {
  connection: Network,
  dns: Globe,
  alert: AlertTriangle,
};

const FLAG_LABELS: Record<string, string> = {
  large_transfer: '📦 Large Transfer',
  rapid_connections: '⚡ Rapid Connections',
  long_session: '⏱ Long Session',
  has_alerts: '🚨 Has Alerts',
  beaconing_pattern: '📡 Beaconing Pattern',
};

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(0)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function formatTimestamp(ts: number): string {
  if (!ts) return 'N/A';
  return new Date(ts * 1000).toLocaleString();
}

interface SessionViewProps {
  className?: string;
}

const SessionView: React.FC<SessionViewProps> = ({ className = '' }) => {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [expandedEvents, setExpandedEvents] = useState<SessionEvent[]>([]);
  const [loadingEvents, setLoadingEvents] = useState(false);
  const [sortBy, setSortBy] = useState('threat_score');
  const [minThreat, setMinThreat] = useState('info');
  const [ipFilter, setIpFilter] = useState('');

  useEffect(() => {
    fetchSessions();
  }, [sortBy, minThreat, ipFilter]);

  const fetchSessions = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        sort_by: sortBy,
        order: 'desc',
        min_threat: minThreat,
        limit: '50',
      });
      if (ipFilter) params.set('src_ip', ipFilter);

      const res = await fetch(`${API_BASE}/api/sessions?${params}`);
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      const data = await res.json();
      setSessions(data.sessions || []);
      setTotal(data.total || 0);
    } catch (err) {
      console.error('Failed to fetch sessions:', err);
    } finally {
      setLoading(false);
    }
  };

  const toggleExpand = async (sessionId: string) => {
    if (expandedId === sessionId) {
      setExpandedId(null);
      setExpandedEvents([]);
      return;
    }

    setExpandedId(sessionId);
    setLoadingEvents(true);
    try {
      const res = await fetch(`${API_BASE}/api/sessions/${sessionId}`);
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      const data = await res.json();
      setExpandedEvents(data.events || []);
    } catch (err) {
      console.error('Failed to fetch session events:', err);
      setExpandedEvents([]);
    } finally {
      setLoadingEvents(false);
    }
  };

  return (
    <div className={`space-y-4 ${className}`}>
      {/* Header & Filters */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Network size={20} className="text-cyan-400" />
          <h2 className="text-lg font-semibold text-gray-100">Network Sessions</h2>
          <span className="text-sm text-gray-500">({total} total)</span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={sortBy}
            onChange={e => setSortBy(e.target.value)}
            className="bg-gray-800 text-gray-200 text-xs border border-gray-600 rounded px-2 py-1"
          >
            <option value="threat_score">Threat Score</option>
            <option value="start_time">Time</option>
            <option value="duration">Duration</option>
            <option value="bytes">Data Volume</option>
            <option value="connections">Connections</option>
          </select>

          <select
            value={minThreat}
            onChange={e => setMinThreat(e.target.value)}
            className="bg-gray-800 text-gray-200 text-xs border border-gray-600 rounded px-2 py-1"
          >
            <option value="info">All Levels</option>
            <option value="low">Low+</option>
            <option value="medium">Medium+</option>
            <option value="high">High+</option>
            <option value="critical">Critical</option>
          </select>

          <input
            type="text"
            placeholder="Filter IP..."
            value={ipFilter}
            onChange={e => setIpFilter(e.target.value)}
            className="bg-gray-800 text-gray-200 text-xs border border-gray-600 rounded px-2 py-1 w-32"
          />
        </div>
      </div>

      {/* Session List */}
      {loading ? (
        <div className="flex items-center justify-center py-12">
          <div className="w-6 h-6 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
        </div>
      ) : sessions.length === 0 ? (
        <div className="text-center py-12 text-gray-500">
          <Network size={32} className="mx-auto mb-2 opacity-50" />
          <p>No sessions found. Load log data first.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {sessions.map(session => (
            <div key={session.session_id} className={`border rounded-lg overflow-hidden ${SEVERITY_COLORS[session.threat_level] || SEVERITY_COLORS.info}`}>
              {/* Session Header */}
              <button
                onClick={() => toggleExpand(session.session_id)}
                className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
              >
                {expandedId === session.session_id ? (
                  <ChevronDown size={16} className="shrink-0" />
                ) : (
                  <ChevronRight size={16} className="shrink-0" />
                )}

                <div className="flex-1 min-w-0 grid grid-cols-6 gap-3 items-center text-sm">
                  <div className="col-span-2">
                    <span className="font-mono text-xs">{session.src_ip}</span>
                    <span className="text-gray-600 mx-1">↔</span>
                    <span className="font-mono text-xs">{session.dst_ip}</span>
                  </div>

                  <div className="text-xs text-gray-400">
                    <Clock size={12} className="inline mr-1" />
                    {formatDuration(session.duration_seconds)}
                  </div>

                  <div className="text-xs text-gray-400">
                    {session.connection_count} conn
                    {session.alert_count > 0 && (
                      <span className="ml-1 text-red-400">· {session.alert_count} alert{session.alert_count > 1 ? 's' : ''}</span>
                    )}
                  </div>

                  <div className="text-xs text-gray-400">
                    {formatBytes(session.total_bytes)}
                  </div>

                  <div className="flex items-center gap-2 justify-end">
                    {session.flags.map(flag => (
                      <span key={flag} className="text-xs" title={FLAG_LABELS[flag] || flag}>
                        {FLAG_LABELS[flag]?.split(' ')[0] || '🔹'}
                      </span>
                    ))}
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                      session.threat_level === 'critical' ? 'bg-red-500/20 text-red-400' :
                      session.threat_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      session.threat_level === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-gray-500/20 text-gray-400'
                    }`}>
                      {(session.threat_score * 100).toFixed(0)}
                    </span>
                  </div>
                </div>
              </button>

              {/* Expanded Event Timeline */}
              {expandedId === session.session_id && (
                <div className="border-t border-gray-700/50 px-4 py-3 bg-gray-950/50">
                  {/* Session Details */}
                  <div className="grid grid-cols-4 gap-4 mb-4 text-xs text-gray-400">
                    <div>
                      <span className="text-gray-600">Start:</span> {formatTimestamp(session.start_time)}
                    </div>
                    <div>
                      <span className="text-gray-600">End:</span> {formatTimestamp(session.end_time)}
                    </div>
                    <div>
                      <span className="text-gray-600">Protocols:</span> {session.protocols.join(', ') || 'N/A'}
                    </div>
                    <div>
                      <span className="text-gray-600">Services:</span> {session.services.join(', ') || 'N/A'}
                    </div>
                  </div>

                  {/* Event Timeline */}
                  {loadingEvents ? (
                    <div className="flex items-center justify-center py-4">
                      <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
                    </div>
                  ) : (
                    <div className="space-y-1 max-h-80 overflow-y-auto">
                      {expandedEvents.map((event, idx) => {
                        const Icon = EVENT_ICONS[event.event_type] || Activity;
                        return (
                          <div key={idx} className="flex items-start gap-2 py-1 text-xs">
                            <span className="text-gray-600 font-mono shrink-0 w-36">
                              {formatTimestamp(event.timestamp)}
                            </span>
                            <Icon size={14} className={`shrink-0 mt-0.5 ${
                              event.severity === 'critical' ? 'text-red-400' :
                              event.severity === 'high' ? 'text-orange-400' :
                              event.event_type === 'alert' ? 'text-yellow-400' :
                              event.event_type === 'dns' ? 'text-blue-400' :
                              'text-gray-500'
                            }`} />
                            <span className={`${
                              event.severity === 'critical' || event.severity === 'high'
                                ? 'text-gray-200 font-medium' : 'text-gray-400'
                            }`}>
                              {event.summary}
                            </span>
                          </div>
                        );
                      })}
                      {expandedEvents.length === 0 && (
                        <p className="text-gray-600 text-center py-2">No events in this session</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default SessionView;
