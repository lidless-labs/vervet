/**
 * IOC Export Component - Export threat indicators in CSV, STIX, or OpenIOC format.
 */
import React, { useState } from 'react';
import { Download, FileText, FileJson, FileCode, ChevronDown, Filter } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

type ExportFormat = 'csv' | 'stix' | 'openioc';
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

const FORMAT_CONFIG: Record<ExportFormat, { label: string; icon: React.ElementType; ext: string }> = {
  csv: { label: 'CSV', icon: FileText, ext: '.csv' },
  stix: { label: 'STIX 2.1', icon: FileJson, ext: '.stix.json' },
  openioc: { label: 'OpenIOC', icon: FileCode, ext: '.xml' },
};

const SEVERITY_COLORS: Record<string, string> = {
  info: 'text-gray-400',
  low: 'text-green-400',
  medium: 'text-yellow-400',
  high: 'text-orange-400',
  critical: 'text-red-400',
};

interface IocExportProps {
  className?: string;
  compact?: boolean;
}

const IocExport: React.FC<IocExportProps> = ({ className = '', compact = false }) => {
  const [format, setFormat] = useState<ExportFormat>('csv');
  const [minSeverity, setMinSeverity] = useState<Severity>('low');
  const [types, setTypes] = useState<string[]>(['ip', 'domain']);
  const [limit, setLimit] = useState(1000);
  const [isOpen, setIsOpen] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const handleExport = async () => {
    setDownloading(true);
    try {
      const params = new URLSearchParams({
        format,
        min_severity: minSeverity,
        limit: String(limit),
      });
      if (types.length > 0) {
        params.set('types', types.join(','));
      }

      const res = await fetch(`${API_BASE}/api/export/iocs?${params}`);
      if (!res.ok) throw new Error(`Export failed: ${res.status}`);

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `vervet-iocs${FORMAT_CONFIG[format].ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Export error:', err);
    } finally {
      setDownloading(false);
    }
  };

  const toggleType = (t: string) => {
    setTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]);
  };

  if (compact) {
    return (
      <div className={`relative inline-block ${className}`}>
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-gray-800 hover:bg-gray-700 border border-gray-600 rounded-lg text-gray-200 transition-colors"
        >
          <Download size={14} />
          Export IOCs
          <ChevronDown size={12} className={`transition-transform ${isOpen ? 'rotate-180' : ''}`} />
        </button>

        {isOpen && (
          <div className="absolute right-0 top-full mt-1 w-64 bg-gray-900 border border-gray-700 rounded-lg shadow-xl z-50 p-3 space-y-3">
            <div>
              <label className="text-xs text-gray-400 block mb-1">Format</label>
              <div className="flex gap-1">
                {(Object.keys(FORMAT_CONFIG) as ExportFormat[]).map(f => {
                  const cfg = FORMAT_CONFIG[f];
                  return (
                    <button
                      key={f}
                      onClick={() => setFormat(f)}
                      className={`flex items-center gap-1 px-2 py-1 text-xs rounded ${
                        format === f ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
                      }`}
                    >
                      <cfg.icon size={12} />
                      {cfg.label}
                    </button>
                  );
                })}
              </div>
            </div>

            <div>
              <label className="text-xs text-gray-400 block mb-1">Min Severity</label>
              <select
                value={minSeverity}
                onChange={e => setMinSeverity(e.target.value as Severity)}
                className="w-full bg-gray-800 text-gray-200 text-xs border border-gray-600 rounded px-2 py-1"
              >
                {(['info', 'low', 'medium', 'high', 'critical'] as Severity[]).map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                ))}
              </select>
            </div>

            <button
              onClick={handleExport}
              disabled={downloading}
              className="w-full flex items-center justify-center gap-2 px-3 py-1.5 text-sm bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white rounded-lg transition-colors"
            >
              <Download size={14} />
              {downloading ? 'Exporting...' : 'Download'}
            </button>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={`bg-gray-900/50 border border-gray-700/50 rounded-xl p-5 ${className}`}>
      <div className="flex items-center gap-2 mb-4">
        <Download size={18} className="text-cyan-400" />
        <h3 className="text-lg font-semibold text-gray-100">Export IOCs</h3>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <label className="text-xs text-gray-400 block mb-2">Format</label>
          <div className="space-y-1">
            {(Object.keys(FORMAT_CONFIG) as ExportFormat[]).map(f => {
              const cfg = FORMAT_CONFIG[f];
              return (
                <button
                  key={f}
                  onClick={() => setFormat(f)}
                  className={`w-full flex items-center gap-2 px-3 py-2 text-sm rounded-lg transition-colors ${
                    format === f
                      ? 'bg-cyan-600/20 text-cyan-300 border border-cyan-500/50'
                      : 'bg-gray-800/50 text-gray-400 border border-gray-700/50 hover:bg-gray-800'
                  }`}
                >
                  <cfg.icon size={16} />
                  {cfg.label}
                </button>
              );
            })}
          </div>
        </div>

        <div className="space-y-3">
          <div>
            <label className="text-xs text-gray-400 block mb-2">Min Severity</label>
            <select
              value={minSeverity}
              onChange={e => setMinSeverity(e.target.value as Severity)}
              className="w-full bg-gray-800 text-gray-200 text-sm border border-gray-700 rounded-lg px-3 py-2"
            >
              {(['info', 'low', 'medium', 'high', 'critical'] as Severity[]).map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-2">Indicator Types</label>
            <div className="flex gap-2 flex-wrap">
              {['ip', 'domain', 'hash'].map(t => (
                <button
                  key={t}
                  onClick={() => toggleType(t)}
                  className={`px-2 py-1 text-xs rounded ${
                    types.includes(t) ? 'bg-cyan-600 text-white' : 'bg-gray-800 text-gray-500'
                  }`}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-xs text-gray-400 block mb-2">Limit</label>
            <input
              type="number"
              value={limit}
              onChange={e => setLimit(Math.max(1, Math.min(10000, Number(e.target.value))))}
              className="w-full bg-gray-800 text-gray-200 text-sm border border-gray-700 rounded-lg px-3 py-2"
              min={1}
              max={10000}
            />
          </div>
        </div>
      </div>

      <button
        onClick={handleExport}
        disabled={downloading}
        className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-gray-700 text-white font-medium rounded-lg transition-colors"
      >
        <Download size={16} />
        {downloading ? 'Exporting...' : `Export as ${FORMAT_CONFIG[format].label}`}
      </button>
    </div>
  );
};

export default IocExport;
