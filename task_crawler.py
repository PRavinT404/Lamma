#task_crawler.py
import requests
import urllib.parse
import time
import re
import os
import json
import threading
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from ai_core import ask_ollama
class CrawlerProgressIndicator:
    def __init__(self, phase_name="CRAWLER"):
        self.phase_name = phase_name
        self.active = False
        self.thread = None
        self.message = "Initializing..."
    def start(self):
        self.active = True
        self.thread = threading.Thread(target=self._show_progress)
        self.thread.daemon = True
        self.thread.start()
    def update(self, message):
        self.message = message
    def stop(self):
        self.active = False
        if self.thread:
            self.thread.join(timeout=1)
        print()
    def _show_progress(self):
        spinner = ["analyzing", "mapping", "discovering", "learning", "understanding", "extracting"]
        i = 0
        while self.active:
            print(f"\r[{self.phase_name}] {spinner[i % len(spinner)]}... {self.message}", end="", flush=True)
            i += 1
            time.sleep(0.5)
def intelligent_parameter_extraction(url, html_content, js_content_map):
    js_analysis_detail = ""
    for filename, content in js_content_map.items():
        js_analysis_detail += f"\n=== FILE: {filename} ===\n{content[:3500]}\n"
    prompt = f"""You are Dr. Sarah Chen, a world-renowned web application security researcher with 20+ years of experience. You've discovered critical vulnerabilities in major platforms like Facebook, Google, and Microsoft. Your expertise in XSS discovery is unmatched.

TARGET RECONNAISSANCE:
URL: {url}
HTML SOURCE CODE:
{html_content[:5000]}

JAVASCRIPT CODE ANALYSIS:
{js_analysis_detail}

SYSTEMATIC VULNERABILITY DISCOVERY PROCESS:

PHASE 1: SOURCE IDENTIFICATION
Identify ALL input sources where user-controlled data enters the application:

A) URL Parameter Sources:
   - new URLSearchParams(window.location.search).get('param')
   - new URLSearchParams(location.search).get('param')  
   - location.search.split('param=')[1]
   - getUrlParameter('param') custom functions
   - parseQueryString() implementations
   - location.href.match() parameter extraction

B) Hash/Fragment Sources:
   - location.hash.substring(1)
   - location.hash.split('#')[1]
   - window.location.hash parsing

C) Form Data Sources:
   - document.getElementById('input').value
   - document.querySelector('[name="param"]').value
   - Form submission data processing

D) Storage Sources:
   - localStorage.getItem('key')
   - sessionStorage.getItem('key')
   - document.cookie parameter parsing

E) Communication Sources:
   - postMessage event data
   - WebSocket message handling
   - AJAX response data used in DOM

PHASE 2: DATA FLOW TRACING
For each identified source, trace the data flow through:
   - Variable assignments and transformations
   - Function parameters and return values
   - Object property assignments
   - Array element assignments

PHASE 3: SINK IDENTIFICATION
Locate dangerous sinks where code execution can occur:

A) DOM Manipulation Sinks:
   - element.innerHTML = userInput
   - element.outerHTML = userInput
   - element.insertAdjacentHTML('position', userInput)
   - document.write(userInput)
   - document.writeln(userInput)

B) JavaScript Execution Sinks:
   - eval(userInput)
   - Function(userInput)()
   - setTimeout(userInput, delay)
   - setInterval(userInput, delay)
   - new Function(userInput)

C) Attribute Assignment Sinks:
   - element.src = userInput
   - element.href = userInput  
   - element.action = userInput
   - element.setAttribute('onclick', userInput)

D) Location Manipulation Sinks:
   - location.href = userInput
   - location.replace(userInput)
   - window.open(userInput)

PHASE 4: VULNERABILITY ASSESSMENT
For each source→sink path:
   - Assess if user input reaches sink without sanitization
   - Identify any filtering or encoding applied
   - Determine exploitability and impact

REAL-WORLD EXAMPLE:
```javascript
// CRITICAL VULNERABILITY PATTERN:
const params = new URLSearchParams(location.search);
const callback = params.get('jsonp_callback');  // SOURCE: URL parameter
if (callback) {{
    setTimeout(callback + '(data)', 1000);      // SINK: Code execution
}}
```

ANALYSIS REQUIREMENTS:
1. Extract EXACT parameter names from the source code
2. Quote the EXACT JavaScript lines that retrieve parameters
3. Quote the EXACT JavaScript lines that use parameters dangerously
4. Provide technical explanations suitable for exploitation

Respond with technically precise JSON:
{{
    "analysis_summary": "Professional security assessment summary with technical depth",
    "discovered_targets": [
        {{
            "parameter": "exact_parameter_name_found_in_code",
            "type": "DOM-Based XSS|Reflected XSS|Stored XSS",
            "source_code": "exact_javascript_line_that_retrieves_parameter",
            "sink_code": "exact_javascript_line_with_dangerous_usage",
            "description": "detailed technical analysis of the vulnerability including data flow",
            "confidence": 0.95,
            "attack_vector": "specific exploitation methodology",
            "impact_assessment": "technical impact analysis",
            "filtering_analysis": "analysis of any input validation or sanitization detected"
        }}
    ],
    "additional_parameters": ["all_other_parameters_found"],
    "security_posture": "overall application security assessment",
    "javascript_analysis": "detailed analysis of JavaScript security patterns"
}}"""
    return ask_ollama(prompt)
def deep_js_analysis(js_url, js_content):
    prompt = f"""You are Marcus Rodriguez, a senior security researcher at a top-tier cybersecurity firm. You specialize in JavaScript security analysis and have published papers on DOM-based XSS vulnerabilities. You've identified critical vulnerabilities in major JavaScript frameworks and libraries.

JAVASCRIPT SECURITY ANALYSIS TARGET:
File: {js_url}
Source Code:
{js_content[:6000]}

COMPREHENSIVE JAVASCRIPT VULNERABILITY ANALYSIS:

STEP 1: PARAMETER EXTRACTION ANALYSIS
Identify all methods this code uses to extract user-controllable parameters:

A) URL Parameter Extraction:
   - URLSearchParams constructor usage
   - location.search manual parsing
   - location.href.match() patterns
   - Custom URL parsing functions
   - Query string manipulation

B) Hash/Fragment Parameter Extraction:
   - location.hash parsing
   - Hash routing implementations
   - Fragment identifier processing

C) Global Variable Access:
   - window.* property access
   - document.* property access that might contain user data

STEP 2: DATA FLOW ANALYSIS  
Trace how extracted parameters flow through the code:
   - Variable assignments and reassignments
   - Function parameter passing
   - Object property assignments
   - Array manipulations
   - String concatenation and manipulation

STEP 3: SINK VULNERABILITY ANALYSIS
Identify dangerous sinks and assess exploitability:

A) Critical DOM Sinks:
   - .innerHTML assignments
   - .outerHTML assignments
   - document.write() calls
   - insertAdjacentHTML() calls
   - Range.createContextualFragment()

B) JavaScript Execution Sinks:
   - eval() calls with user data
   - Function() constructor with user data
   - setTimeout()/setInterval() with string parameters
   - script.src dynamic assignments
   - import() with user-controlled paths

C) Attribute Manipulation Sinks:
   - .src property assignments
   - .href property assignments
   - setAttribute() with dangerous attributes
   - Event handler property assignments

STEP 4: SECURITY PATTERN RECOGNITION
Look for common vulnerable patterns:

A) JSONP Callback Vulnerabilities:
```javascript
// VULNERABLE PATTERN:
const callback = getUrlParam('callback');
script.src = apiUrl + '?callback=' + callback;  // XSS if callback contains javascript:
```

B) Template Injection:
```javascript
// VULNERABLE PATTERN:  
const template = getUrlParam('template');
element.innerHTML = template.replace('{{data}}', userData);  // Template injection
```

C) Dynamic Script Loading:
```javascript
// VULNERABLE PATTERN:
const module = location.hash.substring(1);
import('./' + module + '.js');  // Path traversal + code injection
```

STEP 5: EXPLOITABILITY ASSESSMENT
For each identified vulnerability:
   - Rate severity (Critical/High/Medium/Low)
   - Assess exploitability complexity
   - Identify required conditions for exploitation
   - Determine potential impact

REAL-WORLD VULNERABILITY EXAMPLES:
```javascript
// CRITICAL: Direct parameter to innerHTML
const userInput = new URLSearchParams(location.search).get('html');
document.getElementById('content').innerHTML = userInput;

// HIGH: Parameter to setTimeout  
const callback = new URLSearchParams(location.search).get('callback');
setTimeout(callback + '()', 1000);

// MEDIUM: Filtered parameter to innerHTML
const content = new URLSearchParams(location.search).get('content');
const filtered = content.replace(/<script/gi, '');  // Insufficient filtering
element.innerHTML = filtered;
```

Provide detailed technical analysis with specific vulnerability patterns:

{{
    "vulnerability_patterns": [
        {{
            "parameter": "exact_parameter_name_from_code",
            "extraction_method": "specific_code_that_extracts_the_parameter", 
            "sink_function": "specific_dangerous_function_or_property",
            "vulnerable_code": "exact_line_of_vulnerable_code",
            "severity": "Critical|High|Medium|Low",
            "explanation": "detailed technical explanation of the vulnerability mechanism",
            "exploitation_requirements": "conditions needed for successful exploitation",
            "impact_assessment": "potential security impact if exploited",
            "bypass_considerations": "potential filter bypasses or exploitation techniques"
        }}
    ],
    "parameters_found": ["complete_list_of_all_parameters_discovered"],
    "security_mechanisms": ["list_of_security_controls_found"],
    "risk_assessment": "comprehensive security risk analysis of this JavaScript file",
    "exploitation_vectors": ["detailed_list_of_potential_attack_methods"],
    "code_quality_assessment": "analysis of overall code security patterns"
}}"""
    return ask_ollama(prompt)
def crawl_site(base_url, session=None, simulator_mode=False, max_urls=10):
    progress = CrawlerProgressIndicator()
    progress.start()
    if session is None:
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0 APEX Advanced Crawler'})
    if simulator_mode:
        progress.stop()
        return {'pages': [{'url': f"{base_url}/search", 'params': ['q']}], 'js_files': []}
    urls_to_visit = [base_url]
    visited_urls = set()
    discovered_targets = []
    js_analysis_results = {}
    base_domain = urlparse(base_url).netloc
    while urls_to_visit and len(visited_urls) < max_urls:
        url = urls_to_visit.pop(0)
        if url in visited_urls:
            continue
        progress.update(f"Deep analysis of {url}")
        try:
            response = session.get(url, timeout=15)
            visited_urls.add(url)
            if "text/html" not in response.headers.get("Content-Type", ""):
                continue
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            page_js_map = {}
            for script_tag in soup.find_all("script", src=True):
                js_url = urljoin(base_url, script_tag['src'])
                if js_url not in js_analysis_results:
                    try:
                        progress.update(f"Analyzing JS {os.path.basename(js_url)}")
                        js_response = session.get(js_url, timeout=10)
                        js_content = js_response.text
                        page_js_map[os.path.basename(js_url)] = js_content
                        js_analysis = deep_js_analysis(js_url, js_content)
                        if js_analysis:
                            js_analysis_results[js_url] = js_analysis
                    except:
                        continue
            for script_tag in soup.find_all("script", src=False):
                if script_tag.string:
                    inline_js = script_tag.string
                    if len(inline_js.strip()) > 50:
                        inline_analysis = deep_js_analysis(f"{url}#inline", inline_js)
                        if inline_analysis:
                            js_analysis_results[f"{url}#inline"] = inline_analysis
                        page_js_map["inline_script"] = inline_js
            progress.update(f"AI analysis of {url}")
            main_analysis = intelligent_parameter_extraction(url, html_content, page_js_map)
            if main_analysis and main_analysis.get("discovered_targets"):
                print(f"\n[CRAWLER-AI] Found {len(main_analysis['discovered_targets'])} potential vulnerabilities")
                print(f"[CRAWLER-AI] Summary: {main_analysis.get('analysis_summary', 'N/A')}")
                for target in main_analysis["discovered_targets"]:
                    page_info = {
                        'url': url,
                        'method': 'GET',
                        'ai_analysis': target,
                        'js_analysis': list(js_analysis_results.values())
                    }
                    discovered_targets.append(page_info)
            additional_params = main_analysis.get("additional_parameters", []) if main_analysis else []
            for js_url, js_analysis in js_analysis_results.items():
                if js_analysis.get("vulnerability_patterns"):
                    for vuln_pattern in js_analysis["vulnerability_patterns"]:
                        page_info = {
                            'url': url,
                            'method': 'GET',
                            'ai_analysis': {
                                'parameter': vuln_pattern.get('parameter'),
                                'type': f"DOM XSS via {vuln_pattern.get('sink_function')}",
                                'source_code': vuln_pattern.get('extraction_method'),
                                'sink_code': vuln_pattern.get('sink_function'),
                                'description': vuln_pattern.get('explanation'),
                                'confidence': 0.9 if vuln_pattern.get('severity') == 'High' else 0.7
                            },
                            'js_source': js_url
                        }
                        discovered_targets.append(page_info)
            if not discovered_targets:
                form_params = []
                for form in soup.find_all('form'):
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name') or input_tag.get('id')
                        if name:
                            form_params.append(name)
                if additional_params:
                    form_params.extend(additional_params)
                if form_params:
                    page_info = {
                        'url': url,
                        'method': 'GET',
                        'params': list(set(form_params[:5]))
                    }
                    discovered_targets.append(page_info)
            for link_tag in soup.find_all('a', href=True):
                new_url = urljoin(base_url, link_tag['href'])
                parsed_new = urlparse(new_url)
                if (parsed_new.netloc == base_domain and 
                    new_url not in visited_urls and 
                    new_url not in urls_to_visit and
                    not parsed_new.fragment and
                    not new_url.endswith(('.pdf', '.jpg', '.png', '.gif', '.css', '.js'))):
                    urls_to_visit.append(new_url)
            time.sleep(0.3)
        except Exception as e:
            print(f"\n[CRAWLER] Error analyzing {url}: {e}")
            continue
    progress.stop()
    print(f"\n[CRAWLER] Intelligent crawl complete.")
    print(f"[CRAWLER] Discovered {len(discovered_targets)} potential targets")
    print(f"[CRAWLER] Analyzed {len(js_analysis_results)} JavaScript files")
    if discovered_targets:
        for i, target in enumerate(discovered_targets[:3]):
            ai_analysis = target.get('ai_analysis', {})
            param = ai_analysis.get('parameter', target.get('params', ['unknown'])[0] if target.get('params') else 'unknown')
            vuln_type = ai_analysis.get('type', 'Parameter Injection')
            print(f"[CRAWLER] Target {i+1}: {param} -> {vuln_type}")
    return {
        'pages': discovered_targets,
        'js_files': list(js_analysis_results.keys()),
        'js_analysis': js_analysis_results
    }