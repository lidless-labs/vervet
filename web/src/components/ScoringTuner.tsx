/**
 * Scoring Tuner Component - Adjustable threat scoring weights with real-time preview.
 */
import React, { useState, useEffect } from 'react';
import { Sliders, RotateCcw, RefreshCw, Radio, Globe, Shield, Timer } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface Weights {
  beacon: number;
  dns_threat: number;
  ids_alert: number;
  long_connection: number;
}

interface ThreatPreview {
  ip: string;
  original_score: number;
  weighted_score: number;
  delta: number;
  components: Record<string, number>;
  threat_level: string;
}

const WEIGHT_CONFIG = [
  { key: 'beacon', label: 'Beaconing (C2)', icon: Radio, color: 'cyan' },
  { key: 'dns_threat', label: 'DNS Threats', icon: Globe, color: 'blue' },
  { key: 'ids_alert', label: 'IDS/IPS Alerts', icon: Shield, color: 'orange' },
  { key: 'long_connection', label: 'Long Connections', icon: Timer, color: 'purple' },
] as const;

const DEFAULT_WEIGHTS: Weights = {
  beacon: 0.30,
  dns_threat: 0.25,
  ids_alert: 0.25,
  long_connection: 0.20,
};

interface ScoringTunerProps {
  className?: string;
}

const ScoringTuner: React.FC<ScoringTunerProps> = ({ className = '' }) => {
  const [weights, setWeights] = useState<Weights>(DEFAULT_WEIGHTS);
  const [, setSavedWeights] = useState<Weights>(DEFAULT_WEIGHTS);
  const [preview, setPreview] = useState<ThreatPreview[]>([]);
  const [, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [, setDirty] = useState(false);

  useEffect(() => {
    fetchWeights();
  }, []);

  const fetchWeights = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scoring/weights`);
      if (!res.ok) return;
      const data = await res.json();
      setWeights(data.weights);
      setSavedWeights(data.weights);
    } catch (err) {
      console.error('Failed to fetch weights:', err);
    }
  };

  const handleWeightChange = (key: keyof Weights, value: number) => {
    const newWeights = { ...weights, [key]: value };
    setWeights(newWeights);
    setDirty(true);
  };

  const normalize = (w: Weights): Weights => {
    const total = Object.values(w).reduce((a, b) => a + b, 0);
    if (total === 0) return DEFAULT_WEIGHTS;
    return {
      beacon: w.beacon / total,
      dns_threat: w.dns_threat / total,
      ids_alert: w.ids_alert / total,
      long_connection: w.long_connection / total,
    };
  };

  const handleApply = async () => {
    setSaving(true);
    try {
      const normalized = normalize(weights);
      const res = await fetch(`${API_BASE}/api/scoring/weights`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(normalized),
      });
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      const data = await res.json();
      setWeights(data.weights);
      setSavedWeights(data.weights);
      setDirty(false);

      // Recalculate and show preview
      await recalculate();
    } catch (err) {
      console.error('Failed to save weights:', err);
    } finally {
      setSaving(false);
    }
  };

  const recalculate = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/scoring/recalculate`, { method: 'POST' });
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      const data = await res.json();
      setPreview(data.top_threats || []);
    } catch (err) {
      console.error('Failed to recalculate:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleReset = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scoring/reset`, { method: 'POST' });
      if (!res.ok) throw new Error(`Failed: ${res.status}`);
      const data = await res.json();
      setWeights(data.weights);
      setSavedWeights(data.weights);
      setDirty(false);
      setPreview([]);
    } catch (err) {
      console.error('Failed to reset:', err);
    }
  };

  const weightSum = Object.values(weights).reduce((a, b) => a + b, 0);

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Weight Sliders */}
      <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Sliders size={18} className="text-cyan-400" />
            <h3 className="text-lg font-semibold text-gray-100">Scoring Weights</h3>
          </div>
          <span className={`text-xs px-2 py-1 rounded ${
            Math.abs(weightSum - 1.0) < 0.01 ? 'bg-green-500/20 text-green-400' : 'bg-yellow-500/20 text-yellow-400'
          }`}>
            Sum: {(weightSum * 100).toFixed(0)}% {Math.abs(weightSum - 1.0) >= 0.01 && '(will normalize)'}
          </span>
        </div>

        <div className="space-y-4">
          {WEIGHT_CONFIG.map(({ key, label, icon: Icon, color }) => (
            <div key={key} className="space-y-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-sm text-gray-300">
                  <Icon size={14} />
                  {label}
                </div>
                <span className="text-sm font-mono text-gray-400">
                  {(weights[key] * 100).toFixed(0)}%
                </span>
              </div>
              <input
                type="range"
                min={0}
                max={100}
                value={Math.round(weights[key] * 100)}
                onChange={e => handleWeightChange(key, Number(e.target.value) / 100)}
                className="w-full h-1.5 rounded-full appearance-none cursor-pointer bg-gray-700"
                style={{
                  accentColor: color === 'cyan' ? '#06b6d4' : color === 'blue' ? '#3b82f6' : color === 'orange' ? '#f97316' : '#a855f7',
                }}
              />
            </div>
          ))}
        </div>

        {/* Weight Distribution Bar */}
        <div className="mt-4 h-3 rounded-full overflow-hidden flex bg-gray-800">
          {WEIGHT_CONFIG.map(({ key, color }) => {
            const pct = weightSum > 0 ? (weights[key] / weightSum) * 100 : 25;
            const bgColor = color === 'cyan' ? 'bg-cyan-500' : color === 'blue' ? 'bg-blue-500' : color === 'orange' ? 'bg-orange-500' : 'bg-purple-500';
            return (
              <div
                key={key}
                className={`${bgColor} transition-all duration-300`}
                style={{ width: `${pct}%` }}
                title={`${key}: ${pct.toFixed(0)}%`}
              />
            );
          })}
        </div>

        {/* Actions */}
        <div className="flex gap-2 mt-4">
          <button
            onClick={handleApply}
            disabled={saving}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <RefreshCw size={14} className={saving ? 'animate-spin' : ''} />
            {saving ? 'Applying...' : 'Apply & Recalculate'}
          </button>
          <button
            onClick={handleReset}
            className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-300 text-sm rounded-lg transition-colors"
          >
            <RotateCcw size={14} />
            Reset
          </button>
        </div>
      </div>

      {/* Preview Table */}
      {preview.length > 0 && (
        <div className="bg-gray-900/50 border border-gray-700/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Top 10 Threats (Before → After)</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-gray-500 border-b border-gray-700/50">
                  <th className="text-left py-2 px-2">Host</th>
                  <th className="text-right py-2 px-2">Original</th>
                  <th className="text-right py-2 px-2">Weighted</th>
                  <th className="text-right py-2 px-2">Δ</th>
                  <th className="text-left py-2 px-2">Level</th>
                </tr>
              </thead>
              <tbody>
                {preview.map(t => (
                  <tr key={t.ip} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                    <td className="py-1.5 px-2 font-mono text-xs text-gray-300">{t.ip}</td>
                    <td className="py-1.5 px-2 text-right text-gray-400">{(t.original_score * 100).toFixed(0)}</td>
                    <td className="py-1.5 px-2 text-right text-gray-200 font-medium">{(t.weighted_score * 100).toFixed(0)}</td>
                    <td className={`py-1.5 px-2 text-right font-medium ${
                      t.delta > 0 ? 'text-red-400' : t.delta < 0 ? 'text-green-400' : 'text-gray-500'
                    }`}>
                      {t.delta > 0 ? '+' : ''}{(t.delta * 100).toFixed(0)}
                    </td>
                    <td className="py-1.5 px-2">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        t.threat_level === 'critical' ? 'bg-red-500/20 text-red-400' :
                        t.threat_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
                        t.threat_level === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                        'bg-gray-500/20 text-gray-400'
                      }`}>
                        {t.threat_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScoringTuner;
