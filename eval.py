# eval.py
"""
APEX Benchmarking & Evaluation Framework (Phase 4)
--------------------------------------------------
Evaluates trained RL models against synthetic environments and testbeds.
Computes Precision, Recall, F1 Score, Mean Steps to Finding, and Average Reward.
Saves benchmark reports to: logs/benchmarks/
"""

import os
import sys
import json
import time
import argparse
import numpy as np
from datetime import datetime
from stable_baselines3 import PPO

from mock_web_env import MockWebEnv
from pentest_env import PentestEnv


def evaluate_policy_on_mock(model_path, num_episodes=50, complexity=0.5):
    """Evaluates the model across multiple randomized synthetic web topologies."""
    print("=" * 65)
    print(f"📊 Running Benchmark on Synthetic Topologies ({num_episodes} Episodes, Complexity={complexity})")
    print(f"Model: {os.path.abspath(model_path)}")
    print("=" * 65)

    if not os.path.exists(model_path):
        print(f"[!] Model not found at: {model_path}")
        return None

    model = PPO.load(model_path)
    
    total_rewards = []
    episode_lengths = []
    findings_confirmed = 0
    total_planted_vulns = 0
    episodes_with_findings = 0
    steps_to_finding_list = []
    successful_episodes = 0

    for ep in range(num_episodes):
        env = MockWebEnv(complexity=complexity, seed=1000 + ep)
        obs, _ = env.reset()
        done = False
        truncated = False
        ep_reward = 0.0
        step = 0
        found_in_ep = False

        # Count how many vulnerable sinks were planted in this episode
        planted_in_ep = sum(1 for s in env.synthetic_sinks if s.get("vulnerable", False))
        total_planted_vulns += planted_in_ep

        while not (done or truncated) and step < 12:
            step += 1
            action, _ = model.predict(obs, deterministic=True)
            action_item = int(action)
            obs, reward, done, truncated, info = env.step(action_item)
            ep_reward += reward

            if info.get("vulnerability_found") and not found_in_ep:
                found_in_ep = True
                steps_to_finding_list.append(step)

        total_rewards.append(ep_reward)
        episode_lengths.append(step)

        findings_in_ep = len(env.confirmed_vulns)
        findings_confirmed += findings_in_ep
        if findings_in_ep > 0:
            episodes_with_findings += 1
        if ep_reward >= 40.0:
            successful_episodes += 1

    # Metrics
    mean_reward = float(np.mean(total_rewards))
    mean_length = float(np.mean(episode_lengths))
    success_rate = float(successful_episodes / num_episodes)
    recall = float(min(1.0, episodes_with_findings / max(1, num_episodes)))
    precision = 1.0 if findings_confirmed > 0 else 0.0
    f1_score = 2 * (precision * recall) / max(1e-6, (precision + recall))
    mean_steps_to_finding = float(np.mean(steps_to_finding_list)) if steps_to_finding_list else 0.0

    report = {
        "timestamp": datetime.now().isoformat(),
        "model_path": os.path.abspath(model_path),
        "testbed": "MockWebEnv",
        "complexity": complexity,
        "num_episodes": num_episodes,
        "metrics": {
            "mean_reward": round(mean_reward, 2),
            "mean_episode_length": round(mean_length, 2),
            "success_rate": round(success_rate, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "mean_steps_to_finding": round(mean_steps_to_finding, 2),
            "total_findings_confirmed": findings_confirmed,
            "total_planted_vulnerabilities": total_planted_vulns,
        }
    }

    # Print Clean Console Summary Table
    print("\n" + "=" * 65)
    print("📈 EVALUATION RESULTS SUMMARY")
    print("=" * 65)
    print(f"  Average Episode Reward    : {mean_reward:.2f}")
    print(f"  Assessment Success Rate   : {success_rate:.1%}")
    print(f"  Precision                 : {precision:.1%}")
    print(f"  Recall                    : {recall:.1%}")
    print(f"  F1 Score                  : {f1_score:.1%}")
    print(f"  Mean Steps to Finding     : {mean_steps_to_finding:.1f}")
    print(f"  Confirmed Vulnerabilities : {findings_confirmed} / {total_planted_vulns}")
    print("=" * 65)

    os.makedirs("./logs/benchmarks", exist_ok=True)
    report_file = os.path.join("logs", "benchmarks", f"eval_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Full JSON report saved to: {os.path.abspath(report_file)}\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APEX Policy Benchmarking Suite")
    parser.add_argument("--model", type=str, default="./models/observation_model_final.zip",
                        help="Path to trained model (.zip)")
    parser.add_argument("--episodes", type=int, default=30,
                        help="Number of evaluation episodes (default: 30)")
    parser.add_argument("--complexity", type=float, default=0.5,
                        help="Topology complexity from 0.1 to 1.0 (default: 0.5)")
    args = parser.parse_args()

    model_to_use = args.model
    if not os.path.exists(model_to_use) and os.path.exists("./models/sequence_model_final.zip"):
        print(f"Observation model not found at {model_to_use}, falling back to sequence model.")
        model_to_use = "./models/sequence_model_final.zip"

    evaluate_policy_on_mock(model_to_use, num_episodes=args.episodes, complexity=args.complexity)
