#main.py
import argparse
import time
import os
from stable_baselines3 import PPO
from ui_display import UIDisplay
from pentest_env import PentestEnv
from logger import SessionLogger
from agent_memory import AgentMemory
def run_live_test(target):
    # -----------------------------------------------------------------
    # Load persistent agent memory across sessions
    # -----------------------------------------------------------------
    memory = AgentMemory()

    # -----------------------------------------------------------------
    # Start session logger — captures ALL output from this point onward
    # -----------------------------------------------------------------
    logger = SessionLogger(target)
    logger.attach()

    ui = UIDisplay()
    ui.print_header()
    ui.print_target_info(target, "LIVE")
    memory.print_banner()

    print("Loading trained model...")
    obs_model_path = "./models/observation_model_final.zip"
    seq_model_path = "./models/sequence_model_final.zip"
    quick_model_path = "./models/quick_live_model.zip"

    is_observation_model = False
    if os.path.exists(obs_model_path):
        model_path = obs_model_path
        is_observation_model = True
        print(f"[*] Found Observation-Driven model: {model_path}")
    elif os.path.exists(seq_model_path):
        model_path = seq_model_path
        print(f"[*] Found Sequence-Only model: {model_path}")
    elif os.path.exists(quick_model_path):
        model_path = quick_model_path
        print(f"[*] Found Quick-Live model: {model_path}")
    else:
        model_path = None

    model = None
    if model_path and os.path.exists(model_path):
        try:
            custom_objects = {"tensorboard_log": None}
            model = PPO.load(model_path, custom_objects=custom_objects)
            model.tensorboard_log = None
            print(f"Successfully loaded: {os.path.abspath(model_path)}")
        except Exception as e:
            print(f"Failed to load model: {e}")
            logger.log_error("model_load", e)
            logger.detach()
            return
    else:
        print(f"Model not found. Please train a model first using train.py")
        logger.detach()
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
    mode_label = "Observation-Driven (16-D State)" if is_observation_model else "Fixed Sequence (Legacy)"
    print(f"Starting live test with model [{mode_label}]: {os.path.abspath(model_path)}")

    try:
        while not (done or truncated) and step <= 10:
            if is_observation_model:
                action, _ = model.predict(live_obs, deterministic=True)
            else:
                action, _ = model.predict(sequence_obs, deterministic=True)
            action_item = action.item() if hasattr(action, 'item') else action
            action_name = action_names.get(action_item, f"ACTION_{action_item}")
            ui.print_step_header(step, 10, action_name, live_env)
            cumulative_exp = memory.get_cumulative_score(live_env.learning_score)
            print(f"Agent Intelligence:")
            print(f"  Session Learning Score  : {live_env.learning_score:.3f}")
            print(f"  Lifetime Experience     : {cumulative_exp:.3f}")
            print(f"  Confidence Score        : {live_env.confidence_score:.3f}")
            ui.print_queue_status(len(live_env.target_queue), len(live_env.js_queue))

            live_obs, reward, done, truncated, info = live_env.step(action_item)
            if not is_observation_model:
                sequence_obs, _, _, _, _ = sequence_env.step(action_item)

            if action_item != 4:
                tools_used.append(action_name)

            # Log Nmap / Gobuster raw output when available
            if action_item == 0 and live_env.nmap_results:
                logger.log_nmap(str(live_env.nmap_results))
            if action_item == 1 and live_env.gobuster_results:
                logger.log_gobuster(str(live_env.gobuster_results))

            ui.print_state_summary(live_env)
            ui.print_reward_info(reward, total_reward + reward)

            if info.get("vulnerability_found_in_step", False):
                num_new = info.get("vuln_count", len(live_env.vulnerabilities_found))
                new_vulns = live_env.vulnerabilities_found[-num_new:] if num_new > 0 else live_env.vulnerabilities_found
                for vuln in new_vulns:
                    ui.print_vulnerability_alert(vuln)
                    logger.log_finding(vuln)   # <-- log finding to findings.json

            total_reward += reward

            # Log structured step data
            logger.log_step(
                step_num=step,
                action_id=action_item,
                action_name=action_name,
                reward=reward,
                total_reward=total_reward,
                env_state=live_env,
            )

            step += 1
            if done or truncated:
                break
            time.sleep(0.5)

        # -----------------------------------------------------------------
        # CONTINUOUS ONLINE LEARNING & PERSISTENT MEMORY UPDATE
        # -----------------------------------------------------------------
        discovered_dirs = []
        if live_env.gobuster_results and live_env.gobuster_results.get("found_directories"):
            discovered_dirs = live_env.gobuster_results.get("found_directories", [])

        print("\n" + "=" * 80)
        print("🧠 CONTINUOUS LEARNING: UPDATING NEURAL POLICY & PERSISTENT MEMORY")
        print("=" * 80)
        try:
            custom_objects = {"tensorboard_log": None}
            if is_observation_model:
                from mock_web_env import MockWebEnv
                fine_tune_env = MockWebEnv(complexity=0.5)
                fine_tune_model = PPO.load(model_path, env=fine_tune_env, custom_objects=custom_objects)
                fine_tune_model.tensorboard_log = None
                print("[*] Performing incremental policy optimization step from live experience...")
                fine_tune_model.learn(total_timesteps=256)
                fine_tune_model.save(model_path)
                fine_tune_env.close()
            else:
                fine_tune_model = PPO.load(model_path, env=sequence_env, custom_objects=custom_objects)
                fine_tune_model.tensorboard_log = None
                print("[*] Performing incremental policy optimization step from live experience...")
                fine_tune_model.learn(total_timesteps=256)
                fine_tune_model.save(model_path)
            memory.data["model_updates_count"] = memory.data.get("model_updates_count", 0) + 1
            print(f"[*] ✅ Model weights successfully fine-tuned & saved to: {os.path.abspath(model_path)}")
        except Exception as e:
            print(f"[*] Continuous training update note: {e}")

        memory.record_session(
            target=target,
            session_learning_score=live_env.learning_score,
            session_confidence_score=live_env.confidence_score,
            session_reward=total_reward,
            endpoints=discovered_dirs,
            vulnerabilities=live_env.vulnerabilities_found
        )
        memory.save()

        ui.print_final_report(live_env, total_reward, step - 1, tools_used, model_path)
        print(f"FINAL PERFORMANCE & PERSISTENT STATUS:")
        print(f"  Session Learning Score   : {live_env.learning_score:.3f}")
        print(f"  Lifetime Experience Score: {memory.data['cumulative_learning_score']:.3f}")
        print(f"  Session Confidence Score : {live_env.confidence_score:.3f}")
        print(f"  Total Sessions Mastered  : {memory.data['total_sessions']}")
        print(f"  Discovered Endpoints Pool: {len(memory.data['discovered_endpoints'])}")
        print(f"  Policy Weight Version    : Epoch #{memory.data['model_updates_count']}")
        print(f"  Model File Saved To      : {os.path.abspath(model_path)}")
        if live_env.vulnerabilities_found:
            print(f"  ASSESSMENT: {len(live_env.vulnerabilities_found)} vulnerabilities successfully found!")
        else:
            print("  ASSESSMENT: No vulnerabilities found in this session.")

        # Generate Executive PDF Report
        try:
            from reporting import generate_pdf_report
            all_discovered = list(set((discovered_dirs or []) + list(memory.data.get('discovered_endpoints', []))))
            pdf_path = generate_pdf_report(
                target=target,
                vulnerabilities=live_env.vulnerabilities_found,
                discovered_endpoints=all_discovered,
                scan_stats={
                    "learning_score": live_env.learning_score,
                    "confidence_score": live_env.confidence_score,
                    "reward": total_reward
                }
            )
        except Exception as report_err:
            print(f"[REPORT] Error generating PDF report: {report_err}")

    except Exception as e:
        logger.log_error("run_live_test_main_loop", e)
        print(f"\n[ERROR] Unhandled exception: {e}")
        raise
    finally:
        # Always save logs — even if crashed or Ctrl+C'd
        live_env.close()
        sequence_env.close()
        logger.detach()   # <-- writes all files to logs/sessions/<timestamp>/
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