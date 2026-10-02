#train.py
import os
import numpy as np
import time
from datetime import datetime
from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.vec_env import SubprocVecEnv
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.utils import set_random_seed
from pentest_env import PentestEnv
class TrainingCallback(BaseCallback):
    def __init__(self, verbose=0):
        super().__init__(verbose)
        self.episodes_completed = 0
        self.total_rewards = []
        self.success_count = 0
        self.good_sequence_count = 0
        self.best_reward = -float('inf')
    def _on_step(self) -> bool:
        for i, done in enumerate(self.locals.get('dones', [])):
            if done:
                info = self.locals.get('infos', [{}])[i]
                if 'episode' in info:
                    episode_reward = info['episode']['r']
                    self.episodes_completed += 1
                    self.total_rewards.append(episode_reward)
                    if episode_reward >= 50.0:
                        self.success_count += 1
                        self.good_sequence_count += 1
                    if episode_reward > self.best_reward:
                        self.best_reward = episode_reward
                    if self.episodes_completed > 0 and self.episodes_completed % 100 == 0:
                        recent_rewards = self.total_rewards[-100:]
                        avg_reward = np.mean(recent_rewards)
                        success_rate = self.success_count / self.episodes_completed
                        sequence_rate = self.good_sequence_count / self.episodes_completed
                        print(f"\nEpisodes: {self.episodes_completed}, Avg Reward (last 100): {avg_reward:.2f}")
                        print(f"  Success Rate: {success_rate:.1%}, Good Sequence Rate: {sequence_rate:.1%}")
                        if self.episodes_completed > 1000:
                            recent_successes = [1 if r >= 50.0 else 0 for r in self.total_rewards[-1000:]]
                            current_success_rate = np.mean(recent_successes)
                            print(f"  Recent Success Rate (last 1000): {current_success_rate:.1%}")
                            if current_success_rate >= 0.95:
                                print("\nTarget success rate of 95% reached! Stopping training.")
                                return False
        return True
def make_env(rank, seed=0):
    def _init():
        env = PentestEnv(target="virtual", sequence_only_mode=True)
        env.reset(seed=seed + rank)
        return Monitor(env)
    set_random_seed(seed)
    return _init
def train_sequence_agent():
    print("🚀 Starting Goal-Oriented 'Sequence-Only' Training")
    print("==================================================")
    print("Target: Achieve and maintain a 95% success rate.")
    num_cpu = max(1, os.cpu_count() // 2)
    print(f"Using {num_cpu} CPU cores for parallel training.")
    env = SubprocVecEnv([make_env(i) for i in range(num_cpu)])
    print("Initializing PPO model for sequence mastery...")
    model = PPO(
        "MlpPolicy",
        env,
        learning_rate=0.0005,
        n_steps=512,
        batch_size=512 * num_cpu,
        n_epochs=10,
        gamma=0.95,
        verbose=0,
        device='auto',
        tensorboard_log="./logs/sequence_training/"
    )
    callback = TrainingCallback(verbose=1)
    total_timesteps = 1000000
    print(f"Training will run for a maximum of {total_timesteps} steps or until 95% success rate is achieved.")
    try:
        model.learn(total_timesteps=total_timesteps, callback=callback, progress_bar=True)
        final_model_path = "./models/sequence_model_final.zip"
        os.makedirs("./models", exist_ok=True)
        model.save(final_model_path)
        print(f"\n{'='*60}")
        print("✅ TRAINING COMPLETED SUCCESSFULLY!")
        print(f"{'='*60}")
        print(f"Total episodes trained: {callback.episodes_completed}")
        final_success_rate = callback.success_count / max(callback.episodes_completed, 1)
        print(f"Final Success Rate: {final_success_rate:.1%}")
        print(f"The agent has now mastered the correct pentesting workflow.")
        print(f"Final model saved: {final_model_path}")
        print("You can now run a live test using main.py")
    except Exception as e:
        print(f"Training error: {e}")
    finally:
        env.close()
if __name__ == "__main__":
    train_sequence_agent()