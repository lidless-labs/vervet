/**
 * WorkflowWizard: step-by-step PCAP upload and analysis pipeline.
 * Upload -> Processing (animated progress) -> Results redirect.
 */
import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Upload, Loader2, CheckCircle, AlertCircle, FileUp, ArrowRight } from 'lucide-react';
import { useNotificationStore } from '../stores/notificationStore';
// Direct access to store for add()

const API_BASE = import.meta.env.VITE_API_BASE || '';

type WizardStep = 'upload' | 'processing' | 'complete' | 'error';

interface JobState {
  job_id: string;
  status: string;
  progress: number;
  step: string;
  error: string;
  results: Record<string, any>;
  filename?: string;
}

interface WorkflowWizardProps {
  className?: string;
  onComplete?: (jobId: string) => void;
}

const WorkflowWizard: React.FC<WorkflowWizardProps> = ({ className = '', onComplete }) => {
  const [wizardStep, setWizardStep] = useState<WizardStep>('upload');
  const [file, setFile] = useState<File | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [job, setJob] = useState<JobState | null>(null);
  const [error, setError] = useState('');
  const fileRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const notify = useNotificationStore.add;

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) setFile(dropped);
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files?.[0]) setFile(e.target.files[0]);
  };

  const pollStatus = (jobId: string) => {
    pollRef.current = setInterval(async () => {
      try {
        const res = await fetch(`${API_BASE}/api/v1/workflow/status/${jobId}`);
        if (!res.ok) return;
        const data: JobState = await res.json();
        setJob(data);

        if (data.status === 'complete') {
          clearInterval(pollRef.current!);
          setWizardStep('complete');
          notify('success', 'Analysis complete', `${data.results?.logs_ingested || 0} log entries processed`);
          onComplete?.(jobId);
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current!);
          setWizardStep('error');
          setError(data.error || 'Pipeline failed');
          notify('error', 'Analysis failed', data.error);
        }
      } catch {
        // Keep polling on transient errors
      }
    }, 1000);
  };

  const startAnalysis = async () => {
    if (!file) return;
    setError('');
    setWizardStep('processing');

    try {
      const formData = new FormData();
      formData.append('file', file);

      const res = await fetch(`${API_BASE}/api/v1/workflow/upload-and-analyze`, {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: `HTTP ${res.status}` }));
        throw new Error(err.detail || `Upload failed (${res.status})`);
      }

      const data: JobState = await res.json();
      setJob(data);
      pollStatus(data.job_id);
    } catch (e: any) {
      setWizardStep('error');
      setError(e.message || 'Upload failed');
      notify('error', 'Upload failed', e.message);
    }
  };

  const reset = () => {
    if (pollRef.current) clearInterval(pollRef.current);
    setWizardStep('upload');
    setFile(null);
    setJob(null);
    setError('');
  };

  const stepLabels: Record<string, string> = {
    queued: 'Queued',
    validating: 'Validating PCAP',
    running_zeek: 'Running Zeek',
    running_suricata: 'Running Suricata',
    ingesting_logs: 'Ingesting logs',
    analyzing_threats: 'Analyzing threats',
    compiling_results: 'Compiling results',
    complete: 'Complete',
    failed: 'Failed',
  };

  return (
    <div className={`${className}`}>
      {/* Upload Step */}
      {wizardStep === 'upload' && (
        <div className="space-y-6">
          <div
            className={`border-2 border-dashed rounded-xl p-12 text-center transition-colors cursor-pointer
              ${dragOver ? 'border-cyan-400 bg-cyan-500/5' : 'border-gray-700 hover:border-gray-500'}`}
            onDrop={handleDrop}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onClick={() => fileRef.current?.click()}
          >
            <input
              ref={fileRef}
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileChange}
              className="hidden"
            />
            <Upload size={48} className="mx-auto text-gray-500 mb-4" />
            <p className="text-gray-300 text-lg font-medium">
              {file ? file.name : 'Drop a PCAP file here or click to browse'}
            </p>
            {file && (
              <p className="text-gray-500 text-sm mt-2">
                {(file.size / 1024 / 1024).toFixed(1)} MB
              </p>
            )}
            <p className="text-gray-600 text-xs mt-3">
              Accepts .pcap, .pcapng, .cap (max 100 MB)
            </p>
          </div>

          {file && (
            <button
              onClick={startAnalysis}
              className="flex items-center gap-2 px-6 py-3 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium transition-colors mx-auto"
            >
              <FileUp size={18} />
              Analyze PCAP
              <ArrowRight size={16} />
            </button>
          )}
        </div>
      )}

      {/* Processing Step */}
      {wizardStep === 'processing' && job && (
        <div className="text-center space-y-6 py-8">
          <Loader2 size={48} className="animate-spin text-cyan-500 mx-auto" />
          <div>
            <p className="text-lg font-medium text-gray-200">
              {stepLabels[job.step] || job.step}
            </p>
            <p className="text-gray-500 text-sm mt-1">{job.filename}</p>
          </div>

          {/* Progress bar */}
          <div className="max-w-md mx-auto">
            <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-500 rounded-full transition-all duration-500"
                style={{ width: `${job.progress}%` }}
              />
            </div>
            <p className="text-gray-500 text-xs mt-2">{job.progress}%</p>
          </div>
        </div>
      )}

      {/* Complete Step */}
      {wizardStep === 'complete' && job && (
        <div className="text-center space-y-6 py-8">
          <CheckCircle size={48} className="text-green-500 mx-auto" />
          <div>
            <p className="text-lg font-medium text-green-400">Analysis Complete</p>
            <p className="text-gray-500 text-sm mt-1">{job.filename}</p>
          </div>

          {job.results && (
            <div className="flex justify-center gap-4 text-sm">
              <div className="px-4 py-2 bg-gray-800/50 rounded-lg">
                <span className="text-gray-500">Logs: </span>
                <span className="text-gray-200 font-medium">{job.results.logs_ingested || 0}</span>
              </div>
              <div className="px-4 py-2 bg-gray-800/50 rounded-lg">
                <span className="text-gray-500">Zeek: </span>
                <span className={job.results.zeek_processed ? 'text-green-400' : 'text-gray-500'}>
                  {job.results.zeek_processed ? 'Yes' : 'No'}
                </span>
              </div>
              <div className="px-4 py-2 bg-gray-800/50 rounded-lg">
                <span className="text-gray-500">Suricata: </span>
                <span className={job.results.suricata_processed ? 'text-green-400' : 'text-gray-500'}>
                  {job.results.suricata_processed ? 'Yes' : 'No'}
                </span>
              </div>
            </div>
          )}

          <button
            onClick={reset}
            className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
          >
            Analyze Another
          </button>
        </div>
      )}

      {/* Error Step */}
      {wizardStep === 'error' && (
        <div className="text-center space-y-6 py-8">
          <AlertCircle size={48} className="text-red-500 mx-auto" />
          <div>
            <p className="text-lg font-medium text-red-400">Analysis Failed</p>
            <p className="text-gray-500 text-sm mt-2">{error}</p>
          </div>
          <button
            onClick={reset}
            className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white rounded-lg font-medium transition-colors"
          >
            Try Again
          </button>
        </div>
      )}
    </div>
  );
};

export default WorkflowWizard;
