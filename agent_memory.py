# agent_memory.py
"""
APEX Persistent Agent Memory
----------------------------
Maintains persistent experience, historical scores, discovered assets,
and model iteration tracking across all sessions in 'agent_memory.json'.
"""

import os
import sys
import json
from datetime import datetime

# Fix Windows console encoding issues
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


class AgentMemory:
    def __init__(self, memory_file="agent_memory.json"):
        self.memory_file = os.path.abspath(memory_file)
        self.data = self._load()

    def _default_memory(self):
        return {
            "total_sessions": 0,
            "cumulative_learning_score": 0.0,
            "best_session_score": 0.0,
            "total_rewards_earned": 0.0,
            "model_updates_count": 0,
            "known_targets": [],
            "discovered_endpoints": [],
            "confirmed_vulnerabilities": [],
            "session_history": [],
            "created_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat()
        }

    def _load(self):
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    # Ensure all required keys exist
                    default = self._default_memory()
                    for k, v in default.items():
                        if k not in data:
                            data[k] = v
                    return data
            except Exception as e:
                print(f"[MEMORY] ⚠ Warning: Could not read {self.memory_file}: {e}. Initializing fresh memory.")
        return self._default_memory()

    def save(self):
        try:
            self.data["last_updated"] = datetime.now().isoformat()
            with open(self.memory_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2, ensure_ascii=False)
            print(f"[MEMORY] ✅ Persistent memory successfully saved -> {self.memory_file}")
        except Exception as e:
            print(f"[MEMORY] ❌ Error saving {self.memory_file}: {e}")

    def get_cumulative_score(self, current_session_score=0.0):
        """Returns the lifetime score including progress in the current session."""
        base = self.data.get("cumulative_learning_score", 0.0)
        return round(base + (current_session_score * 0.5), 3)

    def record_session(self, target, session_learning_score, session_confidence_score,
                       session_reward, endpoints=None, vulnerabilities=None):
        self.data["total_sessions"] += 1
        self.data["total_rewards_earned"] = round(self.data.get("total_rewards_earned", 0.0) + session_reward, 1)

        # Increment cumulative learning score based on session performance
        # Minimum gain of 0.05 per completed session to guarantee visible learning progress
        gain = max(0.05, session_reward / 40.0)
        self.data["cumulative_learning_score"] = round(self.data.get("cumulative_learning_score", 0.0) + gain, 3)

        if session_learning_score > self.data.get("best_session_score", 0.0):
            self.data["best_session_score"] = round(session_learning_score, 3)

        if target and target not in self.data["known_targets"]:
            self.data["known_targets"].append(target)

        # Merge discovered endpoints
        if endpoints:
            current_eps = set(self.data.get("discovered_endpoints", []))
            for ep in endpoints:
                if isinstance(ep, str):
                    current_eps.add(ep)
                elif isinstance(ep, dict) and "url" in ep:
                    current_eps.add(ep["url"])
            self.data["discovered_endpoints"] = sorted(list(current_eps))

        # Merge confirmed vulnerabilities
        if vulnerabilities:
            existing_vulns = self.data.get("confirmed_vulnerabilities", [])
            for v in vulnerabilities:
                v_entry = {
                    "type": v.get("type", "Unknown"),
                    "parameter": v.get("parameter", "unknown"),
                    "url": v.get("url", target),
                    "technique": v.get("technique", "N/A"),
                    "confirmed_at": datetime.now().isoformat()
                }
                # Check for duplicate
                is_dup = any(
                    ev.get("parameter") == v_entry["parameter"] and ev.get("url") == v_entry["url"]
                    for ev in existing_vulns
                )
                if not is_dup:
                    existing_vulns.append(v_entry)
            self.data["confirmed_vulnerabilities"] = existing_vulns

        # Add session history log (keep last 20)
        history_entry = {
            "session_id": self.data["total_sessions"],
            "target": target,
            "session_reward": session_reward,
            "session_learning_score": round(session_learning_score, 3),
            "session_confidence": round(session_confidence_score, 3),
            "vulnerabilities_found": len(vulnerabilities) if vulnerabilities else 0,
            "timestamp": datetime.now().isoformat()
        }
        history = self.data.get("session_history", [])
        history.append(history_entry)
        self.data["session_history"] = history[-20:]

    def print_banner(self):
        line = "=" * 70
        print(f"\n{line}")
        print("AGENT PERSISTENT MEMORY & ACCUMULATED EXPERIENCE")
        print(line)
        print(f"  * Total Sessions Executed    : {self.data.get('total_sessions', 0)}")
        print(f"  * Lifetime Experience Score  : {self.data.get('cumulative_learning_score', 0.0):.3f}")
        print(f"  * Best Session Score         : {self.data.get('best_session_score', 0.0):.3f}")
        print(f"  * Model Policy Weight Updates: Epoch #{self.data.get('model_updates_count', 0)}")
        print(f"  * Known Target Applications  : {len(self.data.get('known_targets', []))}")
        print(f"  * Discovered Endpoints Total : {len(self.data.get('discovered_endpoints', []))}")
        print(f"  * Confirmed Findings Total   : {len(self.data.get('confirmed_vulnerabilities', []))}")
        print(f"{line}\n")
