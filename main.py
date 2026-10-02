#main.py
import argparse
import time
import os
from stable_baselines3 import PPO
from ui_display import UIDisplay
from pentest_env import PentestEnv
def run_live_test(target):
    ui = UIDisplay()
    ui.print_header()
    ui.print_target_info(target, "LIVE")
    print("Loading trained model...")
    model_path = "./models/sequence_model_final.zip"
    if not os.path.exists(model_path):
        model_path = "./models/quick_live_model.zip"
    model = None
    if os.path.exists(model_path):
        try:
            model = PPO.load(model_path)
            print(f"Successfully loaded: {os.path.abspath(model_path)}")
        except Exception as e:
            print(f"Failed to load model: {e}")
            return
    else:
        print(f"Model not found. Please train a model first using train.py")
        return
    live_env = PentestEnv(target=target, simulator_mode=False)
    sequence_env = PentestEnv(target="virtual", sequence_only_mode=True)
    live_obs, _ = live_env.reset()
    sequence_obs, _ = sequence_env.reset()
    done = False
    truncated = False
    total_reward = 0
    step = 1
    tools_used = []
    action_names = {
        0: "RECON: Nmap Port Scan",
        1: "RECON: Gobuster Directory Scan",
        2: "DISCOVERY: AI-Powered Crawling",
        3: "ATTACK: AI-Driven XSS Testing",
        4: "STOP & REPORT"
    }
    print(f"Starting live test with model: {os.path.abspath(model_path)}")
    while not (done or truncated) and step <= 10:
        action, _ = model.predict(sequence_obs, deterministic=True)
        action_item = action.item() if hasattr(action, 'item') else action
        action_name = action_names.get(action_item, f"ACTION_{action_item}")
        ui.print_step_header(step, 10, action_name, live_env)
        print(f"Agent Intelligence:")
        print(f"  Learning Score: {live_env.learning_score:.3f}")
        print(f"  Confidence Score: {live_env.confidence_score:.3f}")
        ui.print_queue_status(len(live_env.target_queue), len(live_env.js_queue))
        live_obs, reward, done, truncated, info = live_env.step(action_item)
        sequence_obs, _, _, _, _ = sequence_env.step(action_item)
        if action_item != 4:
            tools_used.append(action_name)
        ui.print_state_summary(live_env)
        ui.print_reward_info(reward, total_reward + reward)
        if info.get("vulnerability_found_in_step", False):
            latest_vuln = live_env.vulnerabilities_found[-1]
            ui.print_vulnerability_alert(latest_vuln)
        total_reward += reward
        step += 1
        if done or truncated:
            break
        time.sleep(0.5)
    ui.print_final_report(live_env, total_reward, step - 1, tools_used, model_path)
    print(f"FINAL PERFORMANCE:")
    print(f"  Final Learning Score: {live_env.learning_score:.3f}")
    print(f"  Final Confidence Score: {live_env.confidence_score:.3f}")
    print(f"  Model Used: {os.path.abspath(model_path)}")
    if live_env.vulnerabilities_found:
        print("  ASSESSMENT: XSS vulnerability successfully found!")
    else:
        print("  ASSESSMENT: No vulnerabilities found in this session.")
    live_env.close()
    sequence_env.close()
def main():
    parser = argparse.ArgumentParser(description='AI Pentesting Agent')
    parser.add_argument('--target', type=str, help='Target URL for live testing')
    parser.add_argument('--live', action='store_true', help='Run live test against target')
    parser.add_argument('--train', action='store_true', help='(DEPRECATED) The train.py script now trains automatically.')
    args = parser.parse_args()
    print("AI Pentesting Agent System")
    print("=" * 50)
    if args.train:
        print("To train, please run 'python3 train.py' directly.")
    elif args.target and args.live:
        run_live_test(args.target)
    else:
        print("Usage:")
        print("  For training: python3 train.py")
        print("  For live test: python3 main.py --target <URL> --live")
if __name__ == "__main__":
    main()