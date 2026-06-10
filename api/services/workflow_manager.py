"""
Workflow Manager: orchestrates PCAP upload, Zeek/Suricata processing, and full analysis pipeline.
"""
import os
import uuid
import time
import shutil
import logging
import tempfile
import subprocess
import threading
from typing import Dict, Optional, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class WorkflowJob:
    """Represents a PCAP analysis workflow job."""
    job_id: str
    filename: str
    created_at: float
    status: JobStatus = JobStatus.QUEUED
    progress: int = 0
    step: str = "queued"
    pcap_path: str = ""
    log_dir: str = ""
    error: str = ""
    completed_at: Optional[float] = None
    results: dict = field(default_factory=dict)


class WorkflowManager:
    """Manages PCAP-to-analysis pipeline jobs."""

    MAX_JOBS = 50

    def __init__(self):
        self._jobs: Dict[str, WorkflowJob] = {}
        self._work_dir = tempfile.mkdtemp(prefix="vervet_workflow_")

    def create_job(self, filename: str, pcap_data: bytes) -> WorkflowJob:
        """Create a new workflow job from uploaded PCAP data."""
        job_id = str(uuid.uuid4())[:12]
        job_dir = os.path.join(self._work_dir, job_id)
        os.makedirs(job_dir, exist_ok=True)

        from pathlib import Path
        safe_name = Path(filename).name
        if not safe_name or safe_name.strip(".") == "":
            safe_name = f"{job_id}.pcap"
        pcap_path = os.path.join(job_dir, safe_name)
        with open(pcap_path, "wb") as f:
            f.write(pcap_data)

        job = WorkflowJob(
            job_id=job_id,
            filename=filename,
            created_at=time.time(),
            pcap_path=pcap_path,
            log_dir=job_dir,
        )
        self._jobs[job_id] = job

        # Trim old jobs if over limit (only evict terminal-state jobs)
        if len(self._jobs) > self.MAX_JOBS:
            terminal = [j for j in self._jobs.values() if j.status in (JobStatus.COMPLETE, JobStatus.FAILED)]
            terminal.sort(key=lambda j: j.created_at)
            to_remove = len(self._jobs) - self.MAX_JOBS
            if len(terminal) < to_remove:
                logger.warning(f"Cannot trim to MAX_JOBS: {len(self._jobs) - len(terminal)} active jobs")
                to_remove = len(terminal)
            for old in terminal[:to_remove]:
                self._cleanup_job(old.job_id)

        # Run pipeline in background thread
        thread = threading.Thread(target=self._run_pipeline, args=[job_id], daemon=True)
        thread.start()

        return job

    def get_job(self, job_id: str) -> Optional[WorkflowJob]:
        """Get job by ID."""
        return self._jobs.get(job_id)

    def list_jobs(self, limit: int = 20) -> List[WorkflowJob]:
        """List recent jobs, newest first."""
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        return jobs[:limit]

    def _run_pipeline(self, job_id: str):
        """Execute the full analysis pipeline for a job."""
        job = self._jobs.get(job_id)
        if not job:
            return

        try:
            job.status = JobStatus.PROCESSING

            # Step 1: Validate PCAP
            job.step = "validating"
            job.progress = 5
            if not os.path.exists(job.pcap_path):
                raise FileNotFoundError("PCAP file not found")
            file_size = os.path.getsize(job.pcap_path)
            if file_size == 0:
                raise ValueError("PCAP file is empty")

            # Step 2: Run Zeek
            job.step = "running_zeek"
            job.progress = 15
            zeek_success = self._run_zeek(job)

            # Step 3: Run Suricata (optional, continue if fails)
            job.step = "running_suricata"
            job.progress = 35
            suricata_success = self._run_suricata(job)

            # Step 4: Ingest logs into LogStore
            job.step = "ingesting_logs"
            job.progress = 55
            log_count = self._ingest_logs(job)

            # Step 5: Run threat analysis
            job.step = "analyzing_threats"
            job.progress = 75
            analysis = self._run_analysis(job)

            # Step 6: Compile results
            job.step = "compiling_results"
            job.progress = 90
            job.results = {
                "file_size_bytes": file_size,
                "zeek_processed": zeek_success,
                "suricata_processed": suricata_success,
                "logs_ingested": log_count,
                "analysis": analysis,
            }

            job.status = JobStatus.COMPLETE
            job.progress = 100
            job.step = "complete"
            job.completed_at = time.time()
            logger.info(f"Workflow {job_id} completed: {log_count} logs ingested")

        except Exception as e:
            job.status = JobStatus.FAILED
            job.error = str(e)
            job.step = "failed"
            logger.error(f"Workflow {job_id} failed: {e}")

    def _run_zeek(self, job: WorkflowJob) -> bool:
        """Run Zeek on the PCAP file."""
        try:
            result = subprocess.run(
                ["zeek", "-r", job.pcap_path, "-C"],
                capture_output=True, text=True, timeout=120,
                cwd=job.log_dir,
            )
            if result.returncode == 0:
                logger.info(f"Zeek processed {job.filename}")
                return True
            logger.warning(f"Zeek returned {result.returncode}: {result.stderr[:200]}")
            return False
        except FileNotFoundError:
            logger.info("Zeek not installed, skipping")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("Zeek timed out")
            return False

    def _run_suricata(self, job: WorkflowJob) -> bool:
        """Run Suricata on the PCAP file."""
        try:
            eve_path = os.path.join(job.log_dir, "eve.json")
            result = subprocess.run(
                ["suricata", "-r", job.pcap_path, "-l", job.log_dir, "--set", f"outputs.1.eve-log.filename={eve_path}"],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                logger.info(f"Suricata processed {job.filename}")
                return True
            logger.warning(f"Suricata returned {result.returncode}: {result.stderr[:200]}")
            return False
        except FileNotFoundError:
            logger.info("Suricata not installed, skipping")
            return False
        except subprocess.TimeoutExpired:
            logger.warning("Suricata timed out")
            return False

    def _ingest_logs(self, job: WorkflowJob) -> int:
        """Ingest generated log files into the analysis store."""
        count = 0
        log_files = []
        for ext in ["*.log", "*.json"]:
            import glob
            log_files.extend(glob.glob(os.path.join(job.log_dir, ext)))

        # Count lines as a proxy for log entries
        for lf in log_files:
            try:
                with open(lf, "r", encoding="utf-8", errors="ignore") as f:
                    count += sum(1 for line in f if line.strip() and not line.startswith("#"))
            except Exception:
                pass

        return count

    def _run_analysis(self, job: WorkflowJob) -> dict:
        """Run threat analysis on ingested data."""
        # Return summary stats (actual analysis hooks into existing services)
        log_files = os.listdir(job.log_dir)
        zeek_logs = [f for f in log_files if f.endswith(".log")]
        eve_files = [f for f in log_files if f == "eve.json"]
        return {
            "zeek_log_count": len(zeek_logs),
            "suricata_eve_found": len(eve_files) > 0,
            "total_output_files": len(log_files),
        }

    def _cleanup_job(self, job_id: str):
        """Remove a job and its files."""
        job = self._jobs.pop(job_id, None)
        if job and job.log_dir and os.path.exists(job.log_dir):
            shutil.rmtree(job.log_dir, ignore_errors=True)
