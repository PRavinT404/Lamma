# train.py
"""
APEX Training Pipeline
-----------------------
Supports two training modes:
1. Observation-Driven Training (Recommended - Phase 1 & 2):
   Trains a PPO agent on MockWebEnv at CPU speed using full 16-dimensional state observations.
   Model saved to: ./models/observation_model_final.zip

2. Sequence-Only Training (Legacy):
   Trains a fixed sequence agent on synthetic states.
   Model saved to: ./models/sequence_model_final.zip
"""

import os
import sys
import argparse
import numpy as np
import time
from datetime import datetime
from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.vec_env import DummyVecEnv, SubprocVecEnv
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.utils import set_random_seed

from pentest_env import PentestEnv
from mock_web_env import MockWebEnv


class ObservationTrainingCallback(BaseCallback):
    """Tracks episode rewards, confirmed findings, and stopping criterion for observation training."""
    def __init__(self, target_success_rate=0.85, check_freq=50, verbose=1):
        super().__init__(verbose)
        self.target_success_rate = target_success_rate
        self.check_freq = check_freq
        self.episodes_completed = 0
        self.rewards = []
        self.successes = []
        self.best_reward = -float('inf')

    def _on_step(self) -> bool:
        for i, done in enumerate(self.locals.get('dones', [])):
            if done:
                info = self.locals.get('infos', [{}])[i]
                if 'episode' in info:
                    ep_reward = info['episode']['r']
                    ep_len = info['episode'].get('l', 0)
                    self.episodes_completed += 1
                    self.rewards.append(ep_reward)

                    # Success = reward >= 40 (meaningful assessment completed)
                    is_success = ep_reward >= 40.0
                    self.successes.append(1 if is_success else 0)

                    if ep_reward > self.best_reward:
                        self.best_reward = ep_reward

                    if self.episodes_completed % self.check_freq == 0:
                        recent_rew = self.rewards[-self.check_freq:]
                        recent_succ = self.successes[-self.check_freq:]
                        avg_rew = float(np.mean(recent_rew))
                        succ_rate = float(np.mean(recent_succ))
                        
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Episodes: {self.episodes_completed} | "
                              f"Avg Reward: {avg_rew:.1f} | Best: {self.best_reward:.1f} | "
                              f"Rolling Success: {succ_rate:.1%}")

                        if self.episodes_completed >= 200 and succ_rate >= self.target_success_rate:
                            print(f"\n[+] Reached target success rate of {self.target_success_rate:.0%}. Stopping training early.")
                            return False
        return True


def make_mock_env(complexity=0.4, seed=0):
    def _init():
        env = MockWebEnv(complexity=complexity, seed=seed)
        return Monitor(env)
    return _init


def train_observation_agent(total_timesteps=60000):
    print("=" * 65)
    print("🚀 Starting Observation-Driven PPO Training (MockWebEnv Simulation)")
    print("=" * 65)
    print(f"Goal: Train policy to map 16-D observations to optimal actions.")
    print(f"Target Timesteps: {total_timesteps:,}")

    os.makedirs("./models", exist_ok=True)
    os.makedirs("./logs/observation_training", exist_ok=True)
    final_model_path = "./models/observation_model_final.zip"

    # Multi-complexity environments for curriculum-style diversity
    complexities = [0.2, 0.4, 0.6, 0.8]
    env = DummyVecEnv([make_mock_env(c, seed=42 + i) for i, c in enumerate(complexities)])

    n_steps = 1024
    batch_size = 256
    n_epochs = 10

    if os.path.exists(final_model_path):
        print(f"[*] Found existing model at: {os.path.abspath(final_model_path)}")
        print("[*] Continuing training with existing weights...")
        model = PPO.load(final_model_path, env=env)
    else:
        print("[*] Initializing new PPO model with MLP architecture [128, 128]...")
        model = PPO(
            "MlpPolicy",
            env,
            learning_rate=3e-4,
            n_steps=n_steps,
            batch_size=batch_size,
            n_epochs=n_epochs,
            gamma=0.99,
            gae_lambda=0.95,
            clip_range=0.2,
            ent_coef=0.01,
            vf_coef=0.5,
            max_grad_norm=0.5,
            policy_kwargs=dict(net_arch=[128, 128]),
            verbose=0,
            device='auto'
        )

    callback = ObservationTrainingCallback(target_success_rate=0.88, check_freq=50)
    start_t = time.time()
    try:
        model.learn(total_timesteps=total_timesteps, callback=callback)
        model.save(final_model_path)
        elapsed = time.time() - start_t
        print("\n" + "=" * 65)
        print("✅ OBSERVATION-DRIVEN TRAINING COMPLETE!")
        print("=" * 65)
        print(f"Episodes trained: {callback.episodes_completed}")
        print(f"Best episode reward: {callback.best_reward:.1f}")
        print(f"Training time: {elapsed:.1f}s ({total_timesteps / max(0.1, elapsed):.0f} steps/sec)")
        print(f"Model saved: {os.path.abspath(final_model_path)}")
    except Exception as e:
        print(f"[ERROR] Training interrupted: {e}")
        raise
    finally:
        env.close()


def make_legacy_env(rank, seed=0):
    def _init():
        env = PentestEnv(target="virtual", sequence_only_mode=True)
        env.reset(seed=seed + rank)
        return Monitor(env)
    set_random_seed(seed)
    return _init


def train_sequence_agent():
    print("🚀 Starting Goal-Oriented 'Sequence-Only' Training")
    print("==================================================")
    num_cpu = max(1, os.cpu_count() // 2)
    env = SubprocVecEnv([make_legacy_env(i) for i in range(num_cpu)])
    final_model_path = "./models/sequence_model_final.zip"
    os.makedirs("./models", exist_ok=True)

    n_steps = 512
    batch_size = min(512, n_steps * num_cpu)

    if os.path.exists(final_model_path):
        model = PPO.load(final_model_path, env=env)
    else:
        model = PPO("MlpPolicy", env, learning_rate=0.0003, n_steps=n_steps,
                    batch_size=batch_size, n_epochs=10, gamma=0.99, gae_lambda=0.95,
                    ent_coef=0.01, verbose=0)
    
    total_timesteps = 500000
    try:
        model.learn(total_timesteps=total_timesteps)
        model.save(final_model_path)
        print(f"Saved: {final_model_path}")
    finally:
        env.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="APEX RL Training Pipeline")
    parser.add_argument("--mode", type=str, choices=["observation", "sequence"], default="observation",
                        help="Training mode: 'observation' (MockWebEnv 16-D, fast) or 'sequence' (legacy)")
    parser.add_argument("--timesteps", type=int, default=60000,
                        help="Total timesteps to train (default: 60000)")
    args = parser.parse_args()

    if args.mode == "observation":
        train_observation_agent(total_timesteps=args.timesteps)
    else:
        train_sequence_agent()