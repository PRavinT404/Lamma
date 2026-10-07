# logger.py
"""
APEX Session Logger
-------------------
Captures ALL console output and saves structured logs to:
  logs/sessions/<timestamp>_<sanitized_target>/
      full_session.log      - Raw console output (everything printed)
      summary.json          - Structured JSON: scores, steps, findings
      findings.json         - All vulnerabilities found (detailed)
      nmap_results.txt      - Raw Nmap output
      gobuster_results.txt  - Raw Gobuster output
      xss_payloads.json     - All tested payloads and results
"""

import os
import sys
import json
import time
import re
import threading
from datetime import datetime
from urllib.parse import urlparse


class TeeStream:
    """Duplicates all writes to both terminal and log file."""
    def __init__(self, original_stream, log_file):
        self.original = original_stream
        self.log_file = log_file
        self._lock = threading.Lock()

    def write(self, data):
        with self._lock:
            self.original.write(data)
            self.original.flush()
            try:
                clean = re.sub(r'\x1b\[[0-9;]*[mGKH]|\r', '', data)
                self.log_file.write(clean)
                self.log_file.flush()
            except Exception:
                pass

    def flush(self):
        self.original.flush()
        try:
            self.log_file.flush()
        except Exception:
            pass

    def __getattr__(self, name):
        return getattr(self.original, name)


class SessionLogger:
    def __init__(self, target_url):
        self.target_url = target_url
        self.start_time = time.time()
        self.start_dt = datetime.now()

        safe_target = self._sanitize_target(target_url)
        timestamp = self.start_dt.strftime("%Y%m%d_%H%M%S")
        self.session_name = f"{timestamp}_{safe_target}"
        self.session_dir = os.path.join("logs", "sessions", self.session_name)
        os.makedirs(self.session_dir, exist_ok=True)

        self._raw_log_path = os.path.join(self.session_dir, "full_session.log")
        self._raw_log_file = open(self._raw_log_path, "w", encoding="utf-8", errors="replace")

        self.step_events = []
        self.nmap_raw = ""
        self.gobuster_raw = ""
        self.findings = []
        self.xss_payloads = []
        self.errors = []

        self._orig_stdout = sys.stdout
        self._orig_stderr = sys.stderr
        self._attached = False

    def attach(self):
        sys.stdout = TeeStream(self._orig_stdout, self._raw_log_file)
        sys.stderr = TeeStream(self._orig_stderr, self._raw_log_file)
        self._attached = True
        header = (
            "=" * 80 + "\n"
            f"  APEX Session Log\n"
            f"  Target  : {self.target_url}\n"
            f"  Started : {self.start_dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Log Dir : {os.path.abspath(self.session_dir)}\n"
            "=" * 80 + "\n\n"
        )
        self._raw_log_file.write(header)
        self._raw_log_file.flush()
        print(f"[LOGGER] Session logging active -> {self.session_dir}")

    def detach(self):
        if not self._attached:
            return
        self._flush_all_logs()
        sys.stdout = self._orig_stdout
        sys.stderr = self._orig_stderr
        self._attached = False
        try:
            self._raw_log_file.close()
        except Exception:
            pass
        print(f"\n[LOGGER] All logs saved to: {os.path.abspath(self.session_dir)}")
        print(f"[LOGGER]   full_session.log   - complete console output")
        print(f"[LOGGER]   summary.json       - scores, steps, timings")
        print(f"[LOGGER]   findings.json      - vulnerabilities found")
        print(f"[LOGGER]   xss_payloads.json  - all tested payloads")
        if self.nmap_raw:
            print(f"[LOGGER]   nmap_results.txt   - raw nmap output")
        if self.gobuster_raw:
            print(f"[LOGGER]   gobuster_results.txt - raw gobuster output")

    def log_step(self, step_num, action_id, action_name, reward, total_reward, env_state=None):
        entry = {
            "step": step_num,
            "action_id": action_id,
            "action_name": action_name,
            "reward": round(reward, 4),
            "total_reward": round(total_reward, 4),
            "elapsed_seconds": round(time.time() - self.start_time, 1),
            "timestamp": datetime.now().isoformat(),
        }
        if env_state is not None:
            entry["confidence_score"] = round(getattr(env_state, "confidence_score", 0.0), 4)
            entry["learning_score"] = round(getattr(env_state, "learning_score", 0.0), 4)
            entry["recon_done"] = getattr(env_state, "recon_done", False)
            entry["dirs_done"] = getattr(env_state, "dirs_done", False)
            entry["crawl_done"] = getattr(env_state, "crawl_done", False)
            entry["targets_queued"] = len(list(getattr(env_state, "target_queue", [])))
            entry["vulns_found"] = len(getattr(env_state, "vulnerabilities_found", []))
        self.step_events.append(entry)

    def log_nmap(self, raw_output):
        self.nmap_raw = raw_output or ""

    def log_gobuster(self, raw_output):
        self.gobuster_raw = raw_output or ""

    def log_finding(self, vuln_data):
        record = dict(vuln_data)
        record["logged_at"] = datetime.now().isoformat()
        self.findings.append(record)

    def log_xss_payload(self, url, param, payload, technique, confirmed, confidence=0.0):
        self.xss_payloads.append({
            "url": url,
            "parameter": param,
            "payload": payload,
            "technique": technique,
            "confirmed": confirmed,
            "confidence": round(confidence, 4),
            "tested_at": datetime.now().isoformat(),
        })

    def log_error(self, context, error):
        self.errors.append({
            "context": context,
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.now().isoformat(),
        })

    def _sanitize_target(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.netloc or url
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in host)
            return safe[:40]
        except Exception:
            return "unknown_target"

    def _flush_all_logs(self):
        elapsed = time.time() - self.start_time
        summary = {
            "session": {
                "target": self.target_url,
                "started_at": self.start_dt.isoformat(),
                "finished_at": datetime.now().isoformat(),
                "duration_seconds": round(elapsed, 1),
                "duration_human": self._fmt_duration(elapsed),
                "log_directory": os.path.abspath(self.session_dir),
            },
            "performance": {
                "total_steps": len(self.step_events),
                "final_total_reward": self.step_events[-1]["total_reward"] if self.step_events else 0,
                "final_confidence_score": self.step_events[-1].get("confidence_score", 0) if self.step_events else 0,
                "final_learning_score": self.step_events[-1].get("learning_score", 0) if self.step_events else 0,
                "vulnerabilities_confirmed": len(self.findings),
                "xss_payloads_tested": len(self.xss_payloads),
                "xss_payloads_confirmed": sum(1 for p in self.xss_payloads if p["confirmed"]),
                "errors_encountered": len(self.errors),
            },
            "steps": self.step_events,
            "errors": self.errors,
        }
        self._write_json("summary.json", summary)
        self._write_json("findings.json", {
            "generated_at": datetime.now().isoformat(),
            "target": self.target_url,
            "total_findings": len(self.findings),
            "findings": self.findings,
        })
        self._write_json("xss_payloads.json", {
            "generated_at": datetime.now().isoformat(),
            "target": self.target_url,
            "total_tested": len(self.xss_payloads),
            "total_confirmed": sum(1 for p in self.xss_payloads if p["confirmed"]),
            "payloads": self.xss_payloads,
        })
        if self.nmap_raw:
            self._write_text("nmap_results.txt", self.nmap_raw)
        if self.gobuster_raw:
            self._write_text("gobuster_results.txt", self.gobuster_raw)

        footer = (
            "\n\n" + "=" * 80 + "\n"
            f"  Session Ended  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  Duration       : {self._fmt_duration(elapsed)}\n"
            f"  Findings       : {len(self.findings)}\n"
            f"  Payloads Tested: {len(self.xss_payloads)}\n"
            "=" * 80 + "\n"
        )
        self._raw_log_file.write(footer)
        self._raw_log_file.flush()

    def _write_json(self, filename, data):
        path = os.path.join(self.session_dir, filename)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str, ensure_ascii=False)
        except Exception as e:
            self._orig_stderr.write(f"[LOGGER] Warning: could not write {filename}: {e}\n")

    def _write_text(self, filename, text):
        path = os.path.join(self.session_dir, filename)
        try:
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                f.write(text)
        except Exception as e:
            self._orig_stderr.write(f"[LOGGER] Warning: could not write {filename}: {e}\n")

    @staticmethod
    def _fmt_duration(seconds):
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        return f"{h:02d}h {m:02d}m {s:02d}s"
