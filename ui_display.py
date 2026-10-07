# ui_display.py
import time
from datetime import datetime, timedelta
class UIDisplay:
    def __init__(self):
        self.session_start = time.time()
        self.chars = {
            'block': '█', 'light_shade': '░', 'top_left': '┌', 'top_right': '┐',
            'bottom_left': '└', 'bottom_right': '┘', 'horizontal': '─', 'vertical': '│',
            'tee_right': '├', 'robot': '🤖', 'target': '🎯', 'chart': '📊',
            'alert': '🚨', 'check': '✅', 'cross_mark': '❌', 'warning': '⚠️'
        }
    def print_header(self):
        logo = [
    "           _",
    "            \\",
    "             \\         ___  ___  ___  _ _  ___   _  ___  _ _ _  _  _ _",
    "             |\\       / __>|_ _|| __>| | || __> | || . \\| | | || || \\ |",
    "             /|       \\__ \\ | | | _> | ' || _>  | ||   /| | | || ||   |",
    "            /'|       <___/ |_| |___>|__/ |___> |_||_\\_\\|__/_/ |_||_\\_|",
    "          ,' //                         We will",
    "        ,'..`/                         Miss You",
    "       /   '/                Still I want to see the Video             _...._.---._",
    "     /:   ,'                                                         .' ,--. ,--.  \\",
    "   ,'    ,                                                           | /... /...|  |,..._",
    "  ,'    /                                   _..---------..__         \\.\\_O_/  O /  '     \\",
    " .'  _, /                 .---..._       ,-'  __.-.....__   '-  ___.-----._'---'     ,'  |",
    " |-`'  (                  |       `--..,'_,-''   '.     `''\"-._( .-.'.--.         _.'   /",
    " |      \\                 |  ,.__     /,'  |      |      \\     \\ | / |  /      ,,'  __ /",
    " |     .`.               /  .'  _)--..'    |       |     '\\     \\`  ..--:`     _.--' \\",
    " |   .'  .-.__           |  |,-' _.-\\      |       |      |     |`\\''''''''_.-'   ,' (__...'",
    "  \\         ,-`''-- =--::|   \\-'|    |     |       |      |     | `'.....-' .,:-'  |  \\",
    "   `.    ,  /  /     '`. |   |  |    |     |       |      |     |  \\__.-` `..      \\   \\",
    "    '.  /  /  /         '|   |  |    [     |       |       |    |    ,       '._    |  |fsr",
    "      `.  /  | .--------'    `-. |   '     |       |       |    |,L______       `--..   \\",
    "        ``.  | \\               |-^---''\".  |      |       .'    |.'      ``-..._         \\",
    "           `.-..\\.__...---....,'-.....--'`'\"-........_____|.. `'                `'`--..../",
];
        title = "A P E X"
        print("\n" + self.chars['horizontal'] * 100)
        for line in logo:
            print(line.center(100))
        print(title.center(100))
        print("AI REINFORCEMENT LEARNING PENTESTING AGENT".center(100))
        print(f"Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}".center(100))
        print(self.chars['horizontal'] * 100)
    def print_target_info(self, target, mode="LIVE"):
        print(f"\n{self.chars['top_left']}{self.chars['horizontal'] * 98}{self.chars['top_right']}")
        print(f"{self.chars['vertical']} TARGET INFORMATION{' ' * 80}{self.chars['vertical']}")
        print(f"{self.chars['tee_right']}{self.chars['horizontal'] * 98}{self.chars['vertical']}")
        print(f"{self.chars['vertical']} URL: {target:<91}{self.chars['vertical']}")
        print(f"{self.chars['vertical']} Mode: {mode:<90}{self.chars['vertical']}")
        print(f"{self.chars['vertical']} Agent: RL-PPO Enhanced with Dynamic Analysis{' ' * 54}{self.chars['vertical']}")
        print(f"{self.chars['bottom_left']}{self.chars['horizontal'] * 98}{self.chars['bottom_right']}")
    def print_step_header(self, step_num, total_steps, action_name, agent_state):
        progress = (step_num - 1) / total_steps
        progress_bar = self.chars['block'] * int(40 * progress) + self.chars['light_shade'] * (40 - int(40 * progress))
        percentage = f"{progress * 100:.1f}%"
        elapsed_str = str(timedelta(seconds=int(time.time() - self.session_start)))
        print(f"\n{'─' * 100}")
        print(f"{self.chars['robot']} AI STEP {step_num:02d}/{total_steps:02d}: {action_name:<30} │ Progress: [{progress_bar}] {percentage}")
        print(f"{'─' * 100}")
        print(f"Session Time: {elapsed_str:<20} │ Current Phase: DYNAMIC ANALYSIS")
    def print_queue_status(self, target_count, js_count):
        print(f"Queue Status: {target_count} targets, {js_count} JS files pending")
    def print_vulnerability_alert(self, vuln_data):
        alert_char = self.chars['alert']
        confidence_val = vuln_data.get('confidence', 'medium')
        confidence_str = f"{confidence_val:.0%}" if isinstance(confidence_val, float) else str(confidence_val).upper()
        print(f"\n{alert_char * 3} VULNERABILITY DETECTED! {alert_char * 3}")
        print(f"{self.chars['top_left']}{self.chars['horizontal'] * 98}{self.chars['top_right']}")
        print(f"{self.chars['vertical']} Type: {vuln_data.get('type', 'Unknown'):<89}{self.chars['vertical']}")
        print(f"{self.chars['vertical']} Parameter: {vuln_data.get('parameter', 'unknown'):<84}{self.chars['vertical']}")
        print(f"{self.chars['vertical']} Confidence: {confidence_str:<83}{self.chars['vertical']}")
        print(f"{self.chars['vertical']} Payload: {str(vuln_data.get('payload', ''))[:80]:<86}{self.chars['vertical']}")
        print(f"{self.chars['bottom_left']}{self.chars['horizontal'] * 98}{self.chars['bottom_right']}")
    def print_state_summary(self, state):
        indicators = []
        check = self.chars['check']
        alert = self.chars['alert']
        if getattr(state, 'recon_done', False):
            indicators.append(f"RECON{check}")
        if getattr(state, 'dirs_done', False):
            indicators.append(f"DIRS{check}")
        if getattr(state, 'crawl_done', False):
            indicators.append(f"CRAWL{check}")
        if getattr(state, 'vulnerabilities_found', []):
            indicators.append(f"XSS{alert}")
        chart = self.chars['chart']
        if indicators:
            print(f"\n{chart} Agent State: {' | '.join(indicators)}")
        else:
            print(f"\n{chart} Agent State: INITIALIZING...")
    def print_reward_info(self, step_reward, total_reward):
        if step_reward > 25:
            color = "\033[92m"
        elif step_reward >= 0:
            color = "\033[32m"
        else:
            color = "\033[91m"
        print(f"\n{self.chars['target']} Reward: {color}{step_reward:+.1f}\033[0m | Total: {total_reward:.1f}")
    def print_final_report(self, final_state, total_reward, steps_taken, tools_used, model_path):
        session_time = time.time() - self.session_start
        target = getattr(final_state, 'target', 'Unknown')
        vulnerabilities_list = getattr(final_state, 'vulnerabilities_found', [])
        print(f"\n{'=' * 100}")
        print("AI PENTESTING AGENT FINAL REPORT".center(100))
        print(f"{'=' * 100}")
        print(f"\n{self.chars['target']} Target: {target}")
        print(f"🕒 Session Duration: {str(timedelta(seconds=int(session_time)))}")
        print(f"🐾 Steps Taken: {steps_taken}")
        print(f"💰 Total Reward: {total_reward:.1f}")
        print("-" * 100)
        if vulnerabilities_list:
            print(f"\n{self.chars['alert']} VULNERABILITIES FOUND: {len(vulnerabilities_list)} {self.chars['alert']}")
            for i, vuln in enumerate(vulnerabilities_list, 1):
                # Vulnerability dicts are flat — use top-level keys directly
                confidence_val = vuln.get('confidence', 'N/A')
                confidence_str = f"{confidence_val:.0%}" if isinstance(confidence_val, float) else str(confidence_val).upper()
                print(f"\n--- VULNERABILITY #{i} ---")
                print(f"  Type        : {vuln.get('type', 'Unknown')}")
                print(f"  URL         : {vuln.get('url', 'N/A')}")
                print(f"  Parameter   : {vuln.get('parameter', 'N/A')}")
                print(f"  Confidence  : {confidence_str}")
                print(f"  Technique   : {vuln.get('technique', 'N/A')}")
                print(f"  Payload     : {str(vuln.get('payload', 'N/A'))[:80]}")
                print(f"  AI Summary  : {vuln.get('ai_explanation', 'N/A')[:120]}")
                print(f"  Source → Sink: {vuln.get('source_code', 'N/A')} → {vuln.get('sink_code', 'N/A')}")
                print(f"  Filters Bypassed: {vuln.get('bypassed_filters', [])}")
                print(f"  Validation  : {vuln.get('validation_method', 'N/A')}")
                print(f"  Test URL    : {vuln.get('test_url', 'N/A')}")
                print("-" * 26)
        else:
            print(f"\n{self.chars['check']} No vulnerabilities confirmed in this session.")
        print(f"\n{'=' * 100}")