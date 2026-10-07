# mock_web_env.py
"""
MockWebEnv: High-Speed Synthetic Web Security Simulation Environment
-------------------------------------------------------------------
A pure-Python Gymnasium environment that simulates web penetration testing
workflows at CPU speed (no network calls). Procedurally generates application
topologies (ports, directories, forms, parameters, and simulated vulnerability sinks)
to train observation-driven RL agents (PPO) via curriculum learning.
"""

import gymnasium as gym
from gymnasium import spaces
import numpy as np


class MockWebEnv(gym.Env):
    metadata = {'render_modes': ['human']}

    def __init__(self, complexity=0.3, max_steps=12, seed=None):
        super(MockWebEnv, self).__init__()
        self.complexity = float(np.clip(complexity, 0.1, 1.0))
        self.max_steps = max_steps
        
        # 5 Macro-actions:
        # 0: Recon (port scan)
        # 1: Directory Enumeration
        # 2: Web Crawling (endpoints & parameters)
        # 3: Vulnerability Analysis & Verification
        # 4: Stop & Generate Assessment Report
        self.action_space = spaces.Discrete(5)
        
        # 16-Dimensional Normalized Observation Vector
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(16,), dtype=np.float32)
        
        self.rng = np.random.default_rng(seed)
        self.reset(seed=seed)

    def _generate_synthetic_topology(self):
        """Procedurally creates a synthetic web application profile based on complexity."""
        num_ports = int(1 + self.rng.integers(1, 4))
        self.synthetic_ports = [80, 443] + [int(p) for p in self.rng.choice([8080, 8443, 3000, 5000], size=min(2, num_ports), replace=False)]
        
        # Directory count scales with complexity (2 to 20)
        num_dirs = int(2 + round(self.complexity * 18))
        all_possible_dirs = [
            "/admin", "/api", "/login", "/search", "/users", "/dashboard",
            "/v1", "/v2", "/docs", "/static", "/assets", "/config", "/backup",
            "/portal", "/cart", "/checkout", "/profile", "/internal", "/status", "/health"
        ]
        self.synthetic_dirs = list(self.rng.choice(all_possible_dirs, size=min(num_dirs, len(all_possible_dirs)), replace=False))
        
        # Forms / testable parameter endpoints (1 to 8)
        num_forms = int(1 + round(self.complexity * 7))
        self.synthetic_forms = [{"path": f"/form_{i}", "param": f"q_{i}"} for i in range(num_forms)]
        
        # Candidate execution sinks planted in code
        num_sinks = int(round(self.complexity * 4))
        self.synthetic_sinks = [{"id": f"sink_{i}", "vulnerable": bool(self.rng.random() < 0.75)} for i in range(max(1, num_sinks))]
        
        # Track discoveries
        self.discovered_ports = []
        self.discovered_dirs = []
        self.queued_forms = []
        self.tested_forms = []
        self.confirmed_vulns = []

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        if seed is not None:
            self.rng = np.random.default_rng(seed)
            
        self._generate_synthetic_topology()
        
        self.step_count = 0
        self.recon_done = False
        self.dirs_done = False
        self.crawl_done = False
        self.last_action = -1
        self.repeated_action_count = 0
        self.last_action_yielded_data = False
        self.confidence_score = 0.0
        self.learning_score = 0.0

        return self._get_observation(), {"complexity": self.complexity}

    def _get_observation(self):
        obs = np.zeros(16, dtype=np.float32)
        
        # 0: Recon completed
        obs[0] = 1.0 if self.recon_done else 0.0
        # 1: Discovered dirs ratio
        obs[1] = min(len(self.discovered_dirs) / max(1, len(self.synthetic_dirs)), 1.0)
        # 2: Forms identified ratio
        obs[2] = min(len(self.queued_forms) / max(1, len(self.synthetic_forms)), 1.0)
        # 3: JS sinks identified ratio
        obs[3] = min(len(self.synthetic_sinks) / 5.0, 1.0)
        # 4: Candidate execution sinks found
        obs[4] = 1.0 if len(self.synthetic_sinks) > 0 else 0.0
        # 5: Confirmed findings ratio (max 3)
        obs[5] = min(len(self.confirmed_vulns) / 3.0, 1.0)
        # 6: Step budget remaining
        obs[6] = max(0.0, (self.max_steps - self.step_count) / float(self.max_steps))
        # 7: Last action yielded new data
        obs[7] = 1.0 if self.last_action_yielded_data else 0.0
        # 8: Repeated action penalty factor
        obs[8] = min(self.repeated_action_count / 3.0, 1.0)
        # 9: Crawl completed
        obs[9] = 1.0 if self.crawl_done else 0.0
        # 10: Target queue size normalized
        obs[10] = min(len(self.queued_forms) / 5.0, 1.0)
        # 11: Current confidence score
        obs[11] = np.clip(self.confidence_score, 0.0, 1.0)
        # 12: Current learning score
        obs[12] = np.clip(self.learning_score / 2.0, 0.0, 1.0)
        # 13: Open ports discovered normalized
        obs[13] = min(len(self.discovered_ports) / 5.0, 1.0)
        # 14: Has any vulnerability been confirmed
        obs[14] = 1.0 if len(self.confirmed_vulns) > 0 else 0.0
        # 15: Episode progress
        obs[15] = min(self.step_count / float(self.max_steps), 1.0)

        return obs

    def action_masks(self):
        """Action mask to prevent illegal transitions while allowing dynamic choices."""
        mask = [False] * 5
        # Recon is allowed if not done
        mask[0] = not self.recon_done
        # Dir enumeration is allowed once recon is done or after initial steps
        mask[1] = self.recon_done and (len(self.discovered_dirs) < len(self.synthetic_dirs))
        # Crawling is allowed once dirs are discovered
        mask[2] = (len(self.discovered_dirs) > 0) and not self.crawl_done
        # Vulnerability testing is allowed if we have queued forms/targets
        mask[3] = len(self.queued_forms) > 0
        # Stop & Report is always an option
        mask[4] = True
        
        # Safety fallback: if all masked except 4, allow 4
        if not any(mask):
            mask[4] = True
        return mask

    def step(self, action):
        self.step_count += 1
        reward = 0.0
        terminated = False
        truncated = self.step_count >= self.max_steps
        info = {"action": action}

        # Repetition tracking
        if action == self.last_action:
            self.repeated_action_count += 1
        else:
            self.repeated_action_count = 0
        self.last_action = action
        self.last_action_yielded_data = False

        # Action 0: Recon (Port & Service Scan)
        if action == 0:
            if not self.recon_done:
                self.recon_done = True
                self.discovered_ports = list(self.synthetic_ports)
                self.last_action_yielded_data = True
                self.confidence_score += 0.20
                reward += 10.0 + (len(self.discovered_ports) * 2.0)
            else:
                reward -= 10.0  # Redundant recon

        # Action 1: Directory Enumeration
        elif action == 1:
            if len(self.discovered_dirs) < len(self.synthetic_dirs):
                # Discover half or all remaining dirs
                to_discover = self.synthetic_dirs[len(self.discovered_dirs):]
                batch_size = max(1, len(to_discover) // 2 if len(to_discover) > 2 else len(to_discover))
                discovered_batch = to_discover[:batch_size]
                self.discovered_dirs.extend(discovered_batch)
                self.dirs_done = len(self.discovered_dirs) >= len(self.synthetic_dirs)
                self.last_action_yielded_data = True
                self.confidence_score += 0.20
                reward += 5.0 * len(discovered_batch)
            else:
                reward -= 10.0  # Redundant dir enumeration

        # Action 2: Web Crawling & Parameter Extraction
        elif action == 2:
            if not self.crawl_done or len(self.queued_forms) < len(self.synthetic_forms):
                self.crawl_done = True
                new_forms = [f for f in self.synthetic_forms if f not in self.queued_forms]
                self.queued_forms.extend(new_forms)
                self.last_action_yielded_data = len(new_forms) > 0
                self.confidence_score += 0.20
                reward += 10.0 * len(new_forms)
            else:
                reward -= 10.0

        # Action 3: Vulnerability Analysis & Verification
        elif action == 3:
            if self.queued_forms:
                target_form = self.queued_forms.pop(0)
                self.tested_forms.append(target_form)
                
                # Check if this form triggers a finding
                has_vuln = any(s.get("vulnerable", False) for s in self.synthetic_sinks)
                if has_vuln and (self.rng.random() < 0.85):
                    finding = {"type": "XSS", "target": target_form["path"], "param": target_form["param"], "confidence": 0.95}
                    self.confirmed_vulns.append(finding)
                    self.last_action_yielded_data = True
                    self.confidence_score += 0.40
                    reward += 35.0
                    info["vulnerability_found"] = True
                else:
                    reward += 5.0  # Clean/safe endpoint verified
            else:
                reward -= 10.0  # No targets to test

        # Action 4: Stop & Report
        elif action == 4:
            terminated = True
            if len(self.confirmed_vulns) > 0:
                reward += 50.0 + (len(self.confirmed_vulns) * 20.0)
            elif self.confidence_score >= 0.6:
                reward += 25.0  # Complete scan with no vulns found
            else:
                reward -= 15.0  # Stopped too early before meaningful assessment

        # Consecutive repeat penalty
        if self.repeated_action_count >= 2:
            reward -= 15.0 * (self.repeated_action_count - 1)

        self.confidence_score = float(np.clip(self.confidence_score, 0.0, 1.0))
        self.learning_score += max(0.0, reward / 50.0)

        return self._get_observation(), float(reward), terminated, truncated, info
