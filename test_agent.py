#test_agent.py
import numpy as np
import matplotlib.pyplot as plt
from stable_baselines3 import PPO
from pentest_env import PentestEnv
import time
import json
from collections import defaultdict
import argparse

class AdvancedAgentAnalyzer:
    def __init__(self, model_path):
        self.model = self.load_model(model_path)
        self.test_results = []
        self.behavior_patterns = defaultdict(list)
    def load_model(self, model_path):
        try:
            model = PPO.load(model_path)
            print(f"✅ Loaded model: {model_path}")
            return model
        except Exception as e:
            print(f"❌ Failed to load {model_path}: {e}")
            return None
    def analyze_decision_making(self, env, max_steps=15):
        print("\n🧠 Analyzing Agent Decision-Making Process")
        print("-" * 50)
        obs, _ = env.reset()
        done = False
        step_count = 0
        decisions = []
        action_names = {
            0: "NMAP_SCAN", 1: "GOBUSTER_SCAN", 2: "ADVANCED_CRAWL", 
            3: "XSS_TEST", 4: "DEEP_ANALYSIS", 5: "PAYLOAD_REFINEMENT", 6: "STOP"
        }
        while not done and step_count < max_steps:
            action_probs = self.model.policy.get_distribution(obs).distribution.probs.detach().numpy()
            action, _ = self.model.predict(obs, deterministic=True)
            action_item = action.item()
            decision = {
                "step": step_count + 1,
                "observation": obs.copy(),
                "action": action_item,
                "action_name": action_names.get(action_item, f"UNKNOWN_{action_item}"),
                "action_probabilities": action_probs,
                "confidence": action_probs[action_item],
                "valid_actions": [i for i in range(len(action_probs)) if env._is_action_valid(i)],
                "state_before": env.current_state.copy()
            }
            print(f"\nStep {step_count + 1}: {decision['action_name']} (confidence: {decision['confidence']:.3f})")
            print(f"   Valid actions: {[action_names.get(i, str(i)) for i in decision['valid_actions']]}")
            print(f"   State: {self.format_state(env.current_state)}")
            obs, reward, done, _, info = env.step(action_item)
            decision["reward"] = reward
            decision["state_after"] = env.current_state.copy()
            decision["done"] = done
            decisions.append(decision)
            step_count += 1
            print(f"   Reward: {reward}")
            if done:
                print(f"\n🏁 Episode completed in {step_count} steps")
                break
        return decisions
    def format_state(self, state):
        key_items = []
        if state.get('http_found'): key_items.append("HTTP✅")
        if state.get('dirs_found'): key_items.append("DIRS✅") 
        if state.get('params_found'): key_items.append("PARAMS✅")
        if state.get('xss_found'): key_items.append("XSS🚨")
        if state.get('csrf_protected'): key_items.append("CSRF🛡️")
        if state.get('intelligence_gathered'): key_items.append("INTEL🧠")
        return " | ".join(key_items) if key_items else "NONE"
    def test_multiple_scenarios(self, scenarios, runs_per_scenario=5):
        print("\n🎯 Multi-Scenario Testing")
        print("=" * 50)
        results = []
        for scenario in scenarios:
            print(f"\n📋 Testing Scenario: {scenario['name']}")
            scenario_results = []
            for run in range(runs_per_scenario):
                print(f"   Run {run + 1}/{runs_per_scenario}")
                env = PentestEnv(scenario['target'], simulator_mode=True)
                env.complexity_level = scenario['complexity']
                decisions = self.analyze_decision_making(env, max_steps=20)
                final_state = env.current_state
                success = final_state.get('xss_found', False)
                steps_taken = len(decisions)
                total_reward = sum(d['reward'] for d in decisions)
                tools_used = len(env.executed_tools)
                run_result = {
                    "scenario": scenario['name'],
                    "complexity": scenario['complexity'],
                    "success": success,
                    "steps": steps_taken,
                    "reward": total_reward,
                    "tools_used": tools_used,
                    "final_state": final_state,
                    "decisions": decisions
                }
                scenario_results.append(run_result)
                env.close()
            success_rate = sum(r['success'] for r in scenario_results) / len(scenario_results)
            avg_reward = np.mean([r['reward'] for r in scenario_results])
            avg_steps = np.mean([r['steps'] for r in scenario_results])
            print(f"   📊 Results: {success_rate:.1%} success, {avg_reward:.1f} avg reward, {avg_steps:.1f} avg steps")
            results.extend(scenario_results)
        return results
    def identify_failure_patterns(self, test_results):
        print("\n🔍 Failure Pattern Analysis")
        print("-" * 50)
        failures = [r for r in test_results if not r['success']]
        successes = [r for r in test_results if r['success']]
        print(f"Total tests: {len(test_results)}")
        print(f"Failures: {len(failures)} ({len(failures)/len(test_results):.1%})")
        print(f"Successes: {len(successes)} ({len(successes)/len(test_results):.1%})")
        if not failures:
            print("🎉 No failures to analyze!")
            return
        failure_patterns = {
            "stuck_after_crawl": 0,
            "never_found_params": 0,
            "xss_always_failed": 0,
            "stopped_too_early": 0,
            "inefficient_sequence": 0
        }
        for failure in failures:
            final_state = failure['final_state']
            decisions = failure['decisions']
            if final_state.get('params_found') and not final_state.get('xss_found'):
                if any(d['action'] == 3 for d in decisions):
                    failure_patterns["xss_always_failed"] += 1
                else:
                    failure_patterns["stuck_after_crawl"] += 1
            elif not final_state.get('params_found'):
                failure_patterns["never_found_params"] += 1
            elif len(decisions) < 5:
                failure_patterns["stopped_too_early"] += 1
            else:
                failure_patterns["inefficient_sequence"] += 1
        print("\n🚨 Common Failure Patterns:")
        for pattern, count in failure_patterns.items():
            if count > 0:
                percentage = count / len(failures) * 100
                print(f"   {pattern}: {count} ({percentage:.1f}% of failures)")
        print("\n💡 Recommendations:")
        if failure_patterns["xss_always_failed"] > 0:
            print("   - Improve XSS payload generation and testing strategies")
            print("   - Train on targets with different protection mechanisms")
        if failure_patterns["stuck_after_crawl"] > 0:
            print("   - Improve action selection after parameter discovery")
            print("   - Add reward shaping for attempting XSS tests")
        if failure_patterns["never_found_params"] > 0:
            print("   - Improve crawling effectiveness")
            print("   - Train on targets with hidden or complex forms")
        if failure_patterns["inefficient_sequence"] > 0:
            print("   - Add curriculum learning for optimal action sequences")
            print("   - Implement expert demonstrations")
    def compare_models(self, model_paths, test_scenarios):
        print("\n🏆 Model Comparison")
        print("=" * 50)
        model_results = {}
        for model_path in model_paths:
            print(f"\n🤖 Testing model: {model_path}")
            try:
                model = PPO.load(model_path)
                original_model = self.model
                self.model = model
                results = self.test_multiple_scenarios(test_scenarios, runs_per_scenario=3)
                success_rate = sum(r['success'] for r in results) / len(results)
                avg_reward = np.mean([r['reward'] for r in results])
                avg_steps = np.mean([r['steps'] for r in results])
                model_results[model_path] = {
                    "success_rate": success_rate,
                    "avg_reward": avg_reward,
                    "avg_steps": avg_steps,
                    "detailed_results": results
                }
                print(f"   📊 {success_rate:.1%} success, {avg_reward:.1f} reward, {avg_steps:.1f} steps")
                self.model = original_model
            except Exception as e:
                print(f"   ❌ Failed to test {model_path}: {e}")
        print("\n📊 Comparison Summary:")
        print("Model".ljust(30) + "Success Rate".ljust(15) + "Avg Reward".ljust(15) + "Avg Steps")
        print("-" * 60)
        for model_path, metrics in model_results.items():
            model_name = model_path.split('/')[-1][:25]
            print(f"{model_name:<30}{metrics['success_rate']:<15.1%}{metrics['avg_reward']:<15.1f}{metrics['avg_steps']:.1f}")
        return model_results
    def generate_training_insights(self, test_results):
        print("\n🎓 Training Insights and Recommendations")
        print("=" * 50)
        complexity_performance = defaultdict(list)
        for result in test_results:
            complexity_performance[result['complexity']].append(result['success'])
        print("\n📈 Performance by Complexity:")
        for complexity in sorted(complexity_performance.keys()):
            successes = complexity_performance[complexity]
            success_rate = sum(successes) / len(successes)
            print(f"   Complexity {complexity:.1f}: {success_rate:.1%} success rate")
        complexity_threshold = None
        for complexity in sorted(complexity_performance.keys()):
            success_rate = sum(complexity_performance[complexity]) / len(complexity_performance[complexity])
            if success_rate < 0.5 and complexity_threshold is None:
                complexity_threshold = complexity
        if complexity_threshold:
            print(f"\n⚠️  Performance drops significantly at complexity {complexity_threshold}")
            print("   Recommendation: Focus training on targets with complexity 0.3-0.6")
        successful_sequences = []
        failed_sequences = []
        for result in test_results:
            sequence = [d['action'] for d in result['decisions']]
            if result['success']:
                successful_sequences.append(sequence)
            else:
                failed_sequences.append(sequence)
        if successful_sequences:
            print(f"\n✅ Most Common Successful Sequences:")
            sequence_counts = defaultdict(int)
            for seq in successful_sequences:
                sequence_counts[tuple(seq[:4])] += 1
            for seq, count in sorted(sequence_counts.items(), key=lambda x: x[1], reverse=True)[:3]:
                action_names = [["NMAP", "GOBUSTER", "CRAWL", "XSS", "DEEP", "REFINE", "STOP"][a] for a in seq]
                print(f"   {' -> '.join(action_names)}: {count} times")
        print("\n🎯 Key Recommendations:")
        print("1. Implement curriculum learning starting at complexity 0.2")
        print("2. Add reward shaping for efficient action sequences")
        print("3. Train longer on intermediate complexity targets (0.4-0.6)")
        print("4. Consider behavioral cloning from expert demonstrations")
        print("5. Add domain randomization to improve generalization")

def test_specific_agent(model_path, target):
    print(f"Testing agent with model: {model_path}")
    print(f"Target: {target}")
    if not model_path or not os.path.exists(model_path):
        print("Model file not found")
        return
    env = PentestEnv(target=target, simulator_mode=False)
    analyzer = AdvancedAgentAnalyzer(model_path)
    if not analyzer.model:
        return
    decisions = analyzer.analyze_decision_making(env)
    env.close()
    print(f"\n📋 Test completed with {len(decisions)} steps")

def main():
    parser = argparse.ArgumentParser(description="Test a trained PPO agent for penetration testing.")
    parser.add_argument("--model-path", type=str, default="./models/autonomous/final_autonomous_model.zip", help="Path to the trained model.")
    parser.add_argument("--target", type=str, default="http://127.0.0.1", help="Target URL for the penetration test.")
    args = parser.parse_args()
    test_specific_agent(model_path=args.model_path, target=args.target)

if __name__ == "__main__":
    main()