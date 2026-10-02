#autonomous_training.py
import numpy as np
import json
import os
from stable_baselines3 import PPO
from stable_baselines3.common.monitor import Monitor
from stable_baselines3.common.vec_env import DummyVecEnv
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.evaluation import evaluate_policy
from pentest_env import PentestEnv
import time
from collections import defaultdict, deque

class AutonomousLearningCallback(BaseCallback):
    """Advanced callback that enables autonomous learning and adaptation"""
    
    def __init__(self, save_freq=10000, save_path="./models/", verbose=0):
        super(AutonomousLearningCallback, self).__init__(verbose)
        self.save_freq = save_freq
        self.save_path = save_path
        self.episode_rewards = deque(maxlen=1000)
        self.episode_lengths = deque(maxlen=1000)
        self.vulnerability_found_count = 0
        self.total_episodes = 0
        self.learning_metrics = defaultdict(list)
        self.adaptation_triggers = []
        
        # Autonomous learning parameters
        self.performance_threshold = 0.6  # Success rate threshold for curriculum advancement
        self.adaptation_window = 100  # Episodes to look back for adaptation decisions
        self.last_adaptation = 0
        
        # Track which techniques work best
        self.technique_success_rates = defaultdict(lambda: {'attempts': 0, 'successes': 0})
        
    def _on_step(self) -> bool:
        # Collect episode data from each environment
        for env_idx in range(self.training_env.num_envs):
            if self.locals.get('dones')[env_idx]:
                self.total_episodes += 1
                
                # Get episode info
                info = self.locals.get('infos')[env_idx]
                if info.get('episode'):
                    episode_reward = info['episode']['r']
                    episode_length = info['episode']['l']
                    
                    self.episode_rewards.append(episode_reward)
                    self.episode_lengths.append(episode_length)
                    
                    # Track vulnerability discoveries
                    if episode_reward > 200:  # High reward indicates vulnerability found
                        self.vulnerability_found_count += 1
                    
                    # Extract learning metrics from environment if available
                    env = self.training_env.envs[env_idx]
                    if hasattr(env, 'env'):  # Unwrap Monitor
                        actual_env = env.env
                        if hasattr(actual_env, 'current_state'):
                            state = actual_env.current_state
                            
                            # Track technique effectiveness
                            if state.get('xss_found'):
                                self._update_technique_success('xss_testing', True)
                            elif state.get('params_found'):
                                self._update_technique_success('parameter_discovery', True)
                            
                            # Store learning metrics
                            if hasattr(actual_env, 'learning_score'):
                                self.learning_metrics['learning_score'].append(actual_env.learning_score)
                            if hasattr(actual_env, 'confidence_score'):
                                self.learning_metrics['confidence_score'].append(actual_env.confidence_score)
                
                # Autonomous adaptation logic
                if self.total_episodes > 0 and self.total_episodes % 50 == 0:
                    self._autonomous_adaptation_check()
                
                # Progress logging
                if self.total_episodes % 100 == 0:
                    self._log_learning_progress()
        
        # Autonomous model saving
        if self.num_timesteps % self.save_freq == 0:
            self._save_autonomous_checkpoint()
        
        return True
    
    def _update_technique_success(self, technique, success):
        """Track success rates of different techniques"""
        self.technique_success_rates[technique]['attempts'] += 1
        if success:
            self.technique_success_rates[technique]['successes'] += 1
    
    def _autonomous_adaptation_check(self):
        """Check if autonomous adaptation should occur"""
        if len(self.episode_rewards) < self.adaptation_window:
            return
        
        recent_rewards = list(self.episode_rewards)[-self.adaptation_window:]
        recent_success_rate = sum(1 for r in recent_rewards if r > 200) / len(recent_rewards)
        avg_reward = np.mean(recent_rewards)
        
        print(f"\nAutonomous Adaptation Check (Episode {self.total_episodes}):")
        print(f"  Recent Success Rate: {recent_success_rate:.2%}")
        print(f"  Average Reward: {avg_reward:.2f}")
        print(f"  Episodes since last adaptation: {self.total_episodes - self.last_adaptation}")
        
        # Trigger adaptation based on performance
        adaptation_needed = False
        adaptation_reason = ""
        
        if recent_success_rate < 0.3 and self.total_episodes - self.last_adaptation > 200:
            adaptation_needed = True
            adaptation_reason = "Low success rate - need easier targets"
            self._adapt_difficulty(decrease=True)
        elif recent_success_rate > 0.8 and avg_reward > 300:
            adaptation_needed = True
            adaptation_reason = "High success rate - increasing difficulty"
            self._adapt_difficulty(increase=True)
        elif avg_reward < 50 and self.total_episodes - self.last_adaptation > 150:
            adaptation_needed = True
            adaptation_reason = "Low rewards - adjusting training strategy"
            self._adapt_training_strategy()
        
        if adaptation_needed:
            self.adaptation_triggers.append({
                'episode': self.total_episodes,
                'reason': adaptation_reason,
                'success_rate': recent_success_rate,
                'avg_reward': avg_reward
            })
            self.last_adaptation = self.total_episodes
            print(f"  ADAPTATION TRIGGERED: {adaptation_reason}")
    
    def _adapt_difficulty(self, increase=False, decrease=False):
        """Autonomously adapt training difficulty"""
        try:
            # Access the environment and modify its parameters
            for env_idx in range(self.training_env.num_envs):
                env = self.training_env.envs[env_idx]
                if hasattr(env, 'env'):  # Unwrap Monitor
                    actual_env = env.env
                    
                    if hasattr(actual_env, 'complexity_level'):
                        current_complexity = actual_env.complexity_level
                        
                        if increase and current_complexity < 0.9:
                            actual_env.complexity_level = min(current_complexity + 0.1, 0.9)
                            print(f"    Increased complexity to {actual_env.complexity_level:.1f}")
                        elif decrease and current_complexity > 0.1:
                            actual_env.complexity_level = max(current_complexity - 0.1, 0.1)
                            print(f"    Decreased complexity to {actual_env.complexity_level:.1f}")
                    
                    # Adjust max steps based on performance
                    if hasattr(actual_env, 'max_steps'):
                        if increase:
                            actual_env.max_steps = min(actual_env.max_steps + 3, 30)
                        elif decrease:
                            actual_env.max_steps = max(actual_env.max_steps - 2, 15)
                        print(f"    Adjusted max steps to {actual_env.max_steps}")
        except Exception as e:
            print(f"    Error adapting difficulty: {e}")
    
    def _adapt_training_strategy(self):
        """Adapt training strategy based on technique effectiveness"""
        print("    Analyzing technique effectiveness...")
        
        # Calculate success rates for different techniques
        technique_performance = {}
        for technique, data in self.technique_success_rates.items():
            if data['attempts'] > 10:  # Only consider techniques with enough data
                success_rate = data['successes'] / data['attempts']
                technique_performance[technique] = success_rate
                print(f"      {technique}: {success_rate:.2%} ({data['successes']}/{data['attempts']})")
        
        # Adjust reward structure in environments if possible
        try:
            for env_idx in range(self.training_env.num_envs):
                env = self.training_env.envs[env_idx]
                if hasattr(env, 'env'):
                    actual_env = env.env
                    
                    # Boost rewards for underperforming but important techniques
                    if hasattr(actual_env, 'technique_rewards'):
                        for technique, success_rate in technique_performance.items():
                            if success_rate < 0.4:  # Boost low-performing techniques
                                actual_env.technique_rewards[technique] = 1.5
                                print(f"        Boosted reward for {technique}")
        except Exception as e:
            print(f"    Error adapting training strategy: {e}")
    
    def _log_learning_progress(self):
        """Log detailed learning progress"""
        recent_rewards = list(self.episode_rewards)[-100:]
        success_rate = self.vulnerability_found_count / max(self.total_episodes, 1)
        avg_reward = np.mean(recent_rewards) if recent_rewards else 0
        avg_length = np.mean(list(self.episode_lengths)[-100:]) if self.episode_lengths else 0
        
        print(f"\nLearning Progress Report (Episode {self.total_episodes}):")
        print(f"  Overall Success Rate: {success_rate:.2%}")
        print(f"  Recent Average Reward: {avg_reward:.2f}")
        print(f"  Average Episode Length: {avg_length:.1f}")
        print(f"  Total Vulnerabilities Found: {self.vulnerability_found_count}")
        
        # Learning metrics
        if self.learning_metrics['learning_score']:
            avg_learning_score = np.mean(self.learning_metrics['learning_score'][-100:])
            print(f"  Average Learning Score: {avg_learning_score:.3f}")
        
        if self.learning_metrics['confidence_score']:
            avg_confidence = np.mean(self.learning_metrics['confidence_score'][-100:])
            print(f"  Average Confidence: {avg_confidence:.3f}")
        
        # Technique analysis
        print("  Technique Performance:")
        for technique, data in self.technique_success_rates.items():
            if data['attempts'] > 5:
                success_rate = data['successes'] / data['attempts']
                print(f"    {technique}: {success_rate:.2%} ({data['successes']}/{data['attempts']})")
    
    def _save_autonomous_checkpoint(self):
        """Save model and learning state"""
        os.makedirs(self.save_path, exist_ok=True)
        
        # Save learning metrics
        learning_state = {
            'episode': self.total_episodes,
            'learning_metrics': dict(self.learning_metrics),
            'technique_success_rates': dict(self.technique_success_rates),
            'adaptation_triggers': self.adaptation_triggers,
            'vulnerability_count': self.vulnerability_found_count
        }
        
        with open(f"{self.save_path}/learning_state_{self.num_timesteps}.json", 'w') as f:
            json.dump(learning_state, f, indent=2, default=str)
        
        # Save model
        self.model.save(f"{self.save_path}/autonomous_model_{self.num_timesteps}")
        
        print(f"Autonomous checkpoint saved at timestep {self.num_timesteps}")

class CurriculumManager:
    """Manages autonomous curriculum learning"""
    
    def __init__(self):
        self.current_phase = 0
        self.phases = [
            {"name": "Basic Web Apps", "complexity": 0.1, "targets": ["simple_form", "basic_search"]},
            {"name": "Parameter Discovery", "complexity": 0.2, "targets": ["multi_param", "hidden_forms"]},
            {"name": "Protected Apps", "complexity": 0.4, "targets": ["csrf_protected", "basic_filtering"]},
            {"name": "Advanced Filtering", "complexity": 0.6, "targets": ["waf_basic", "input_validation"]},
            {"name": "WAF Bypass", "complexity": 0.8, "targets": ["advanced_waf", "modern_protections"]},
            {"name": "Expert Level", "complexity": 0.9, "targets": ["enterprise_app", "custom_protections"]}
        ]
        self.phase_performance = []
        
    def should_advance_phase(self, callback):
        """Determine if we should advance to the next curriculum phase"""
        if len(callback.episode_rewards) < 200:  # Need enough data
            return False
        
        recent_rewards = list(callback.episode_rewards)[-100:]
        success_rate = sum(1 for r in recent_rewards if r > 200) / len(recent_rewards)
        avg_reward = np.mean(recent_rewards)
        
        # Advance if performance is good enough
        advancement_threshold = 0.7 if self.current_phase < 3 else 0.6  # Higher bar for advanced phases
        
        return success_rate >= advancement_threshold and avg_reward > 250
    
    def advance_phase(self):
        """Advance to the next curriculum phase"""
        if self.current_phase < len(self.phases) - 1:
            self.current_phase += 1
            current = self.phases[self.current_phase]
            print(f"\nCURRICULUM ADVANCEMENT: Moving to Phase {self.current_phase + 1}: {current['name']}")
            print(f"  Complexity Level: {current['complexity']}")
            print(f"  Target Types: {current['targets']}")
            return True
        return False
    
    def get_current_phase(self):
        """Get current phase configuration"""
        return self.phases[self.current_phase]

def create_autonomous_environment(scenario):
    """Create environment with autonomous learning capabilities"""
    def _init():
        # Use the enhanced learning environment
        env = PentestEnv(
            target=scenario["target"], 
            simulator_mode=True
        )
        
        # Set complexity and other parameters
        if hasattr(env, 'complexity_level'):
            env.complexity_level = scenario["complexity"]
        
        # Configure learning parameters
        env.max_steps = scenario.get("max_steps", 20)
        
        # Setup logging
        log_path = f"./autonomous_logs/{scenario['name']}/"
        os.makedirs(log_path, exist_ok=True)
        
        return Monitor(env, log_path)
    return _init

def autonomous_training_loop():
    """Main autonomous training loop with self-adaptation"""
    
    print("Starting Autonomous Learning Pentest Agent Training")
    print("=" * 60)
    
    # Initialize curriculum manager
    curriculum = CurriculumManager()
    
    # Create directories
    os.makedirs("./models/autonomous/", exist_ok=True)
    os.makedirs("./autonomous_logs/", exist_ok=True)
    
    # Start with first phase
    current_phase = curriculum.get_current_phase()
    scenario = {
        "target": current_phase["targets"][0],
        "complexity": current_phase["complexity"],
        "name": current_phase["name"].replace(" ", "_"),
        "max_steps": 15 + int(current_phase["complexity"] * 10)
    }
    
    # Create initial environment
    env = DummyVecEnv([create_autonomous_environment(scenario)])
    
    # Initialize model with optimized hyperparameters for learning
    model = PPO(
        "MlpPolicy",
        env,
        verbose=1,
        tensorboard_log="./autonomous_logs/",
        learning_rate=1e-4,
        n_steps=4096,
        batch_size=64,
        n_epochs=10,
        gamma=0.99,
        gae_lambda=0.95,
        clip_range=0.2,
        ent_coef=0.01,  # Encourage exploration
        vf_coef=0.5,
        max_grad_norm=0.5
    )
    
    # Initialize autonomous callback
    callback = AutonomousLearningCallback(
        save_freq=25000,
        save_path="./models/autonomous/",
        verbose=1
    )
    
    training_phase = 1
    total_timesteps_trained = 0
    
    while curriculum.current_phase < len(curriculum.phases):
        current_phase_config = curriculum.get_current_phase()
        
        print(f"\nTraining Phase {training_phase}: {current_phase_config['name']}")
        print(f"Complexity: {current_phase_config['complexity']}")
        print(f"Targets: {current_phase_config['targets']}")
        
        # Train for this phase
        phase_timesteps = 100000 + int(current_phase_config['complexity'] * 50000) + int(current_phase_config['complexity'] * 50000)
        print(f"Training for {phase_timesteps:,} timesteps...")
        
        model.learn(
            total_timesteps=phase_timesteps,
            callback=callback,
            progress_bar=True,
            reset_num_timesteps=False
        )
        
        total_timesteps_trained += phase_timesteps
        
        # Evaluate current performance
        print(f"\nEvaluating Phase {training_phase} Performance...")
        mean_reward, std_reward = evaluate_policy(
            model, env, n_eval_episodes=20, deterministic=True
        )
        print(f"Mean Reward: {mean_reward:.2f} ± {std_reward:.2f}")
        
        # Save phase checkpoint
        model.save(f"./models/autonomous/phase_{training_phase}_{current_phase_config['name'].replace(' ', '_')}")
        
        # Check if we should advance curriculum
        if curriculum.should_advance_phase(callback):
            print(f"Phase {training_phase} mastered! Advancing curriculum...")
            
            if curriculum.advance_phase():
                # Update environment for next phase
                new_phase = curriculum.get_current_phase()
                new_scenario = {
                    "target": new_phase["targets"][0],
                    "complexity": new_phase["complexity"],
                    "name": new_phase["name"].replace(" ", "_"),
                    "max_steps": 15 + int(new_phase["complexity"] * 10)
                }
                
                env.close()
                env = DummyVecEnv([create_autonomous_environment(new_scenario)])
                model.set_env(env)
                
                training_phase += 1
            else:
                print("Curriculum completed!")
                break
        else:
            print(f"Phase {training_phase} needs more training. Continuing...")
            # Continue training current phase with adapted parameters
    
    # Final model save
    model.save("./models/autonomous/final_autonomous_model")
    
    # Save final training summary
    final_summary = {
        'total_timesteps': total_timesteps_trained,
        'phases_completed': training_phase,
        'final_curriculum_phase': curriculum.current_phase,
        'adaptation_triggers': callback.adaptation_triggers,
        'total_vulnerabilities_found': callback.vulnerability_found_count,
        'technique_success_rates': dict(callback.technique_success_rates)
    }
    
    with open("./models/autonomous/training_summary.json", 'w') as f:
        json.dump(final_summary, f, indent=2, default=str)
    
    print(f"\nAutonomous Training Complete!")
    print(f"Total Timesteps: {total_timesteps_trained:,}")
    print(f"Phases Completed: {training_phase}")
    print(f"Adaptations Made: {len(callback.adaptation_triggers)}")
    print(f"Vulnerabilities Found: {callback.vulnerability_found_count}")
    
    env.close()
    return model

if __name__ == "__main__":
    autonomous_training_loop()
