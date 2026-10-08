#ai_core.py
import sys
import subprocess
import requests
import json
import re
import time
import logging
import concurrent.futures
import threading
import os
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
# Number of parallel AI threads — uses all logical CPU cores up to 8
AI_PARALLEL_WORKERS = min(8, (os.cpu_count() or 4))

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Persistent HTTP session with connection pooling for Ollama
# Re-using connections avoids TCP handshake overhead on every request
# ---------------------------------------------------------------------------
_ollama_session = requests.Session()
_retry = Retry(
    total=1,
    connect=1,
    read=0,  # Never cascade multiple 300s retries on local Ollama read timeouts
    status_forcelist=[429, 503],
    allowed_methods=["POST", "GET"]
)
_ollama_lock = threading.Lock()  # Serialize CPU inference to guarantee 100% core dedication without queuing stalls
_adapter = HTTPAdapter(
    max_retries=_retry,
    pool_connections=AI_PARALLEL_WORKERS,
    pool_maxsize=AI_PARALLEL_WORKERS * 2
)
_ollama_session.mount("http://", _adapter)
_ollama_session.mount("https://", _adapter)
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
# In-memory prompt cache to eliminate redundant LLM calls
_ai_cache = {}

def repair_and_parse_json(raw_text):
    """Clean markdown code fences, repair unclosed quotes/brackets, and return parsed JSON."""
    if not raw_text:
        return None
    raw_text = raw_text.strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]
    raw_text = raw_text.strip()

    try:
        return json.loads(raw_text)
    except Exception:
        pass

    # Heuristic repair for truncated tokens: balance quotes and brackets
    cleaned = raw_text
    if cleaned.count('"') % 2 != 0:
        cleaned += '"'
    open_braces = cleaned.count('{') - cleaned.count('}')
    open_brackets = cleaned.count('[') - cleaned.count(']')
    cleaned += ']' * max(0, open_brackets)
    cleaned += '}' * max(0, open_braces)
    try:
        return json.loads(cleaned)
    except Exception:
        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except Exception:
                pass
    return None

def ask_ollama(prompt, model=OLLAMA_MODEL, timeout=180):
    """Send a prompt to Ollama and return the parsed JSON response.

    - Uses all CPU cores (num_thread=8)
    - keep_alive=-1 (integer) keeps model loaded in RAM permanently
    - num_ctx=2048 keeps context in RAM without paging to disk
    - num_predict=1024 prevents mid-string truncation
    - Mutex lock serializes calls so 100% CPU is given to each request without queue stalls
    - In-memory cache eliminates redundant calls
    """
    if not OLLAMA_AVAILABLE:
        return None

    import hashlib
    cache_key = hashlib.md5(f"{model}:{prompt}".encode('utf-8')).hexdigest()
    if cache_key in _ai_cache:
        logger.info(f"AI cache hit for request (model {model})")
        return _ai_cache[cache_key]

    data = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "keep_alive": -1,
        "options": {
            "num_thread": os.cpu_count() or 8,
            "num_ctx": 2048,
            "num_predict": 1024,
            "temperature": 0.2,
        }
    }

    # Acquire lock so only one prompt runs on CPU at a time
    with _ollama_lock:
        logger.info(f"Contacting AI model {model} (timeout={timeout}s)...")
        try:
            response = _ollama_session.post(OLLAMA_API_URL, json=data, timeout=timeout)
            response.raise_for_status()
            response_json = response.json()
            if "response" in response_json:
                raw_text = response_json["response"]
                parsed_response = repair_and_parse_json(raw_text)
                if parsed_response:
                    _ai_cache[cache_key] = parsed_response
                    return parsed_response
        except requests.HTTPError as http_err:
            logger.error(f"Ollama server returned an error: {http_err}")
        except (requests.RequestException, json.JSONDecodeError) as e:
            logger.error(f"AI request error: {e}")
    return None


def ask_ollama_parallel(prompts, model=OLLAMA_MODEL, timeout=300):
    """Send multiple prompts to Ollama in parallel using a thread pool.

    Args:
        prompts: list of prompt strings
        model:   Ollama model name
        timeout: per-request timeout in seconds

    Returns:
        list of parsed JSON responses (None for failed calls), same order as prompts
    """
    if not OLLAMA_AVAILABLE or not prompts:
        return [None] * len(prompts)

    logger.info(f"[AI_CORE] Dispatching {len(prompts)} parallel AI requests (workers={AI_PARALLEL_WORKERS})...")
    results = [None] * len(prompts)

    def _call(idx_prompt):
        idx, prompt = idx_prompt
        return idx, ask_ollama(prompt, model=model, timeout=timeout)

    with concurrent.futures.ThreadPoolExecutor(max_workers=AI_PARALLEL_WORKERS) as executor:
        futures = {executor.submit(_call, (i, p)): i for i, p in enumerate(prompts)}
        for future in concurrent.futures.as_completed(futures):
            try:
                idx, result = future.result(timeout=timeout + 10)
                results[idx] = result
            except Exception as e:
                logger.error(f"[AI_CORE] Parallel AI call failed: {e}")

    completed = sum(1 for r in results if r is not None)
    logger.info(f"[AI_CORE] Parallel AI complete: {completed}/{len(prompts)} successful")
    return results
SAFE_SINKS = [".textcontent", ".innertext", "console.log"]

def is_safe_sink(sink_code: str) -> bool:
    """Checks whether the identified sink is inherently safe (e.g. textContent)."""
    if not sink_code:
        return False
    clean = sink_code.lower().replace(" ", "")
    return any(safe in clean for safe in SAFE_SINKS)

def validate_discovered_targets(raw_response: dict) -> dict:
    """Enforces strict schema validation and filters false positives from LLM response."""
    if not isinstance(raw_response, dict):
        return {"analysis_summary": "Invalid response format", "discovered_targets": []}
    
    summary = raw_response.get("analysis_summary", "")
    targets = raw_response.get("discovered_targets", [])
    if not isinstance(targets, list):
        targets = []
        
    validated_targets = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        param = str(item.get("parameter", "")).strip()
        sink = str(item.get("sink_code", "")).strip()
        vuln_type = str(item.get("type", "DOM-Based XSS")).strip()
        source = str(item.get("source_code", "")).strip()
        desc = str(item.get("description", "")).strip()
        
        # Drop false positive / safe sinks
        if is_safe_sink(sink):
            logger.info(f"[AI_CORE] Filtered out safe sink false-positive: {sink}")
            continue
            
        if param:
            validated_targets.append({
                "parameter": param,
                "type": vuln_type,
                "source_code": source,
                "sink_code": sink,
                "description": desc,
                "confidence": float(item.get("confidence", 0.8))
            })
            
    return {
        "analysis_summary": summary,
        "discovered_targets": validated_targets
    }

def analyze_content_for_targets(url, html_content, js_content_map):
    js_summary = "\n".join(f"--- JS File: {name} ---\n{content[:2000]}\n" for name, content in js_content_map.items())
    prompt = f"""As a security researcher, analyze this JavaScript and HTML code from {url} to find DOM XSS sources and sinks.
- Sources are inputs like 'url.searchParams.get'.
- Sinks are dangerous functions/properties like '.innerHTML', '.href', or 'setTimeout' with string concatenation.
- Identify the exact parameter names from sources.
- Trace the data flow from source to sink and describe any filters.
- Note: '.textContent' and '.innerText' are safe and should NOT be flagged as vulnerable sinks.

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
            "description": "The application executes user-provided input from the 'callback' parameter within a setTimeout sink."
        }}
    ]
}}
"""
    raw_res = ask_ollama(prompt)
    if raw_res:
        return validate_discovered_targets(raw_res)
    return None

def generate_exploits_for_target(target_info):
    prompt = f"""You are an XSS test payload generator. A vulnerability sink has been identified.
- Vulnerability: {target_info.get('type')}
- Parameter: {target_info.get('parameter')}
- Sink: {target_info.get('sink_code')}
- Flaw Description: {target_info.get('description')}

Your task is to craft 5 diverse test payloads for verification testing. The payload needs to be a valid JavaScript statement that can test this sink safely.
Respond in valid JSON.
{{
    "payloads": [
        {{"payload": "alert(1)//", "technique": "setTimeout test execution with comment"}},
        {{"payload": "alert(document.domain)//", "technique": "setTimeout domain verification"}}
    ]
}}
"""
    raw_res = ask_ollama(prompt)
    if raw_res and isinstance(raw_res, dict) and "payloads" in raw_res:
        return raw_res
    return None