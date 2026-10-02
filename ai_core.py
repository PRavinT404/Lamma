#ai_core.py
import sys
import subprocess
import requests
import json
import re
import time
import logging
from pathlib import Path

# Fix Windows console UTF-8 encoding issues
if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

OLLAMA_API_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.1"
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)
def _check_ollama_initial():
    try:
        response = requests.get("http://localhost:11434", timeout=3)
        response.raise_for_status()
        print("[AI_CORE] [+] Ollama server connected. AI features enabled.")
        return True
    except requests.RequestException:
        pass
    print("="*60)
    print("[AI_CORE] [!] Ollama server not detected. AI features will be disabled.")
    print("[AI_CORE] [*] To enable AI, run 'ollama serve' in a separate terminal.")
    print("="*60)
    return False
OLLAMA_AVAILABLE = _check_ollama_initial()
class AICore:
    @staticmethod
    def run_command(command, timeout=300):
        command_str = ' '.join(str(arg) for arg in command)
        logger.info(f"Executing command: {command_str}")
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout
            )
            if result.stdout:
                logger.info("Command executed successfully")
                return result.stdout
            elif result.returncode == 0:
                return result.stdout
            return None
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return None
def ask_ollama(prompt, model=OLLAMA_MODEL):
    if not OLLAMA_AVAILABLE:
        return None
    logger.info(f"Contacting AI model {model}...")
    data = {"model": model, "prompt": prompt, "stream": False, "format": "json"}
    try:
        response = requests.post(OLLAMA_API_URL, json=data, timeout=600)
        response.raise_for_status()
        response_json = response.json()
        if "response" in response_json:
            parsed_response = json.loads(response_json["response"])
            if parsed_response:
                return parsed_response
    except requests.HTTPError as http_err:
        logger.error(f"Ollama server returned an error: {http_err}")
    except (requests.RequestException, json.JSONDecodeError) as e:
        logger.error(f"AI request error: {e}")
    return None
def analyze_content_for_targets(url, html_content, js_content_map):
    js_summary = "\n".join(f"--- JS File: {name} ---\n{content[:2000]}\n" for name, content in js_content_map.items())
    prompt = f"""As a security researcher, analyze this JavaScript and HTML code from {url} to find DOM XSS sources and sinks.
- Sources are inputs like 'url.searchParams.get'.
- Sinks are dangerous functions/properties like '.innerHTML', '.href', or 'setTimeout' with string concatenation.
- Identify the exact parameter names from sources.
- Trace the data flow from source to sink and describe any filters.

HTML:
{html_content[:4000]}
JavaScript:
{js_summary}

Respond ONLY with a valid JSON object.
{{
    "analysis_summary": "Brief summary of potential vulnerabilities.",
    "discovered_targets": [
        {{
            "parameter": "callback",
            "type": "DOM-Based XSS via setTimeout",
            "source_code": "params.get('callback')",
            "sink_code": "setTimeout(callback + '()', 2000);",
            "description": "The application executes user-provided input from the 'callback' parameter within a setTimeout sink after a 2-second delay. This is equivalent to an eval sink and is highly vulnerable."
        }}
    ]
}}
"""
    return ask_ollama(prompt)
def generate_exploits_for_target(target_info):
    prompt = f"""You are an XSS exploit crafter. A vulnerability has been identified.
- Vulnerability: {target_info.get('type')}
- Parameter: {target_info.get('parameter')}
- Sink: {target_info.get('sink_code')}
- Flaw Description: {target_info.get('description')}

Your task is to craft 5 diverse payloads to exploit this `setTimeout` sink. The payload needs to be a valid JavaScript statement that can be placed inside `setTimeout(payload, ...)`.
Respond in valid JSON.
{{
    "payloads": [
        {{"payload": "alert(1)//", "technique": "setTimeout execution with comment"}},
        {{"payload": "alert(document.domain)//", "technique": "setTimeout execution with comment"}}
    ]
}}
"""
    return ask_ollama(prompt)