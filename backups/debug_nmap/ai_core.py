# ai_core.py - Enhanced AI analysis core with caching and specialized prompts
import subprocess
import requests
import json
import hashlib
from pathlib import Path
import re
import time
import logging

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama3.1"
CACHE_DIR = Path("llm_cache")
CACHE_DIR.mkdir(exist_ok=True, parents=True)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_command(command, timeout=300):
    """Enhanced command execution with better error handling and logging"""
    command_str = ' '.join(str(arg) for arg in command)
    logger.info(f"Executing command: {command_str}")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout
        )
        logger.info("Command executed successfully")
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with exit code {e.returncode}")
        return e.stdout if e.stdout else None
    except FileNotFoundError:
        logger.error(f"Command not found: {command[0]}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error running command: {e}")
        return None

def _cache_key(prompt, context):
    """Generate cache key for AI responses"""
    combined_text = f"{prompt}\n{context}"
    hash_obj = hashlib.sha256(combined_text.encode('utf-8'))
    return CACHE_DIR / f"{hash_obj.hexdigest()}.json"

def ask_ollama_advanced(prompt, context_data, force_remote=False, analysis_type="general"):
    """Advanced AI analysis with caching, retry logic, and specialized prompts"""
    cache_file = _cache_key(prompt, context_data)
    if cache_file.exists() and not force_remote:
        logger.info("Loading response from cache")
        try:
            cached_data = json.loads(cache_file.read_text())
            return cached_data
        except (json.JSONDecodeError, FileNotFoundError):
            logger.warning("Cache file corrupted, proceeding with API call")

    logger.info(f"Performing {analysis_type} analysis with AI")

    system_prompts = {
        "vulnerability": """You are an elite penetration tester with 15+ years of experience in web application security. 
        Your expertise includes finding complex vulnerabilities that automated tools miss, understanding business logic flaws, 
        and identifying subtle injection points. You think like both an attacker and defender.""",
        "technology": """You are a senior security architect and technology analyst specializing in web application 
        technology stack identification. You can identify frameworks, libraries, server technologies, security mechanisms, 
        and configuration issues from minimal information.""",
        "payload": """You are a specialist in crafting sophisticated, evasive payloads that bypass modern security controls. 
        You have deep knowledge of WAFs, CSP policies, input validation mechanisms, output encoding, and context-aware filtering.""",
        "reconnaissance": """You are a reconnaissance expert who excels at gathering maximum intelligence from minimal data. 
        You can identify hidden functionality, development artifacts, information disclosure vulnerabilities, and 
        non-obvious attack vectors."""
    }

    system_prompt = system_prompts.get(analysis_type, system_prompts["vulnerability"])

    context_str = str(context_data)
    if len(context_str) > 10000:
        context_str = context_str[:10000] + "\n[... content truncated ...]"

    full_prompt = f"""SYSTEM ROLE: {system_prompt}

ANALYSIS TASK: {prompt}

TARGET DATA FOR ANALYSIS:
{context_str}

ANALYSIS REQUIREMENTS:
1. Provide detailed, actionable technical analysis
2. Think step-by-step through your reasoning process
3. Consider advanced attack vectors and edge cases
4. Focus on practical, exploitable findings
5. Respond ONLY with valid JSON - no additional text
6. Include confidence levels and risk assessments where applicable

Begin your analysis now:"""

    max_retries = 3
    base_delay = 1

    for attempt in range(max_retries):
        try:
            request_data = {
                "model": OLLAMA_MODEL,
                "prompt": full_prompt,
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0.3,
                    "top_p": 0.9,
                    "repeat_penalty": 1.1,
                    "num_ctx": 4096,
                    "num_predict": 2048
                }
            }

            logger.debug(f"Sending request to Ollama (attempt {attempt + 1}/{max_retries})")

            response = requests.post(
                OLLAMA_URL,
                json=request_data,
                timeout=300,
                headers={'Content-Type': 'application/json'}
            )

            response.raise_for_status()
            response_json = response.json()

            ai_response = response_json.get("response", "{}")

            if not ai_response.strip():
                raise ValueError("Empty response from AI")

            ai_response = ai_response.strip()
            if not ai_response.startswith('{'):
                json_match = re.search(r'\{.*\}', ai_response, re.DOTALL)
                if json_match:
                    ai_response = json_match.group()
                else:
                    raise ValueError("No JSON found in response")

            parsed_response = json.loads(ai_response)

            try:
                cache_file.write_text(json.dumps(parsed_response, indent=2))
                logger.info("Response cached successfully")
            except Exception as e:
                logger.warning(f"Failed to cache response: {e}")

            logger.info("AI analysis completed successfully")
            return parsed_response

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                logger.info(f"Retrying in {delay} seconds...")
                time.sleep(delay)

        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing error (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                logger.info("Retrying with simplified prompt...")
                full_prompt = f"{prompt}\n\nData: {context_str[:5000]}\n\nRespond with JSON only:"

        except Exception as e:
            logger.error(f"Unexpected error (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                time.sleep(delay)

    logger.error("All retry attempts failed")
    return None

def multi_stage_analysis(data, analysis_stages):
    """Perform multi-stage AI analysis with dependency management"""
    results = {}
    total_stages = len(analysis_stages)

    logger.info(f"Starting multi-stage analysis with {total_stages} stages")

    for stage_num, (stage_name, stage_config) in enumerate(analysis_stages.items(), 1):
        logger.info(f"Stage {stage_num}/{total_stages}: {stage_name}")

        context_data = str(data)
        if results:
            context_data += f"\n\nPREVIOUS ANALYSIS RESULTS:\n{json.dumps(results, indent=2)}"

        stage_result = ask_ollama_advanced(
            stage_config["prompt"],
            context_data,
            analysis_type=stage_config.get("type", "general")
        )

        if stage_result:
            results[stage_name] = stage_result
            logger.info(f"Stage {stage_name} completed successfully")
        else:
            logger.error(f"Stage {stage_name} failed")

        time.sleep(1)

    return results

def ask_ollama(prompt, context_data, force_remote=False):
    """Backward compatibility wrapper"""
    return ask_ollama_advanced(prompt, context_data, force_remote, "general")

def generate_context_aware_payloads(target_context, vulnerability_type="xss"):
    """Generate sophisticated payloads based on target context"""
    payload_prompts = {
        "xss": """Generate 10 diverse, creative, and effective XSS payloads specifically for web applications. 
        Focus on modern bypass techniques that work against WAFs, CSP, and input filters.
        Include payloads for different contexts: HTML content, attribute values, JavaScript strings, and event handlers.

        Target context: {context}

        Respond with JSON: {{"payloads": [
            {{"payload": "payload_string", "technique": "bypass_method", "description": "how_it_works", "context": "where_to_use"}}
        ]}}""",
        "sqli": """Generate 10 advanced SQL injection payloads for different database types and injection contexts.
        Include: WAF bypass techniques, blind SQLi, time-based, boolean-based, union-based, and error-based attacks.
        Consider different database systems (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).

        Target context: {context}

        Respond with JSON: {{"payloads": [
            {{"payload": "payload_string", "technique": "attack_type", "database_type": "target_db", "description": "explanation"}}
        ]}}""",
        "lfi": """Generate 10 advanced Local File Inclusion payloads with various bypass techniques.
        Include: Path traversal variations, wrapper abuse, log poisoning, filter bypasses, and null byte injection.
        Consider different operating systems and web server configurations.

        Target context: {context}

        Respond with JSON: {{"payloads": [
            {{"payload": "payload_string", "technique": "bypass_method", "description": "explanation", "target_files": ["file1", "file2"]}}
        ]}}"""
    }

    prompt = payload_prompts.get(vulnerability_type, payload_prompts["xss"]).format(context=target_context)

    return ask_ollama_advanced(prompt, str(target_context), analysis_type="payload")

def deep_response_analysis(response_text, request_info):
    """Perform deep analysis of HTTP responses for subtle vulnerabilities"""
    analysis_prompt = """Perform comprehensive security analysis of this HTTP response. Look for:

    1. INFORMATION DISCLOSURE:
       - Version numbers, internal paths, debug information
       - Error messages revealing system details
       - Directory listing or file exposure
       - Source code comments or debugging data

    2. INJECTION VULNERABILITIES:
       - Reflected input without proper encoding
       - SQL error messages indicating injection points
       - XSS reflection patterns
       - Command injection indicators

    3. AUTHENTICATION/AUTHORIZATION FLAWS:
       - Unprotected admin interfaces
       - Session management issues
       - Privilege escalation opportunities
       - Access control bypasses

    4. SECURITY MISCONFIGURATIONS:
       - Missing security headers
       - Dangerous HTTP methods enabled
       - Insecure cookie settings
       - CORS misconfigurations

    5. BUSINESS LOGIC VULNERABILITIES:
       - Workflow bypasses
       - Price/quantity manipulation opportunities
       - Race condition indicators
       - State management flaws

    Request Information: {request_info}

    Provide detailed, actionable findings with specific exploitation techniques where applicable.
    Respond with JSON: {{
        "critical_findings": [list of high-impact vulnerabilities],
        "information_disclosure": [list of information leaks],
        "injection_points": [list of potential injection vulnerabilities],
        "security_misconfigurations": [list of configuration issues],
        "business_logic_flaws": [list of logic vulnerabilities],
        "recommendations": [list of remediation steps],
        "overall_risk_level": "low/medium/high/critical"
    }}"""

    return ask_ollama_advanced(
        analysis_prompt.format(request_info=request_info),
        response_text[:12000],
        analysis_type="vulnerability"
    )
