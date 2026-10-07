#task_crawler.py
import requests
import urllib.parse
import time
import re
import os
import json
import threading
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from ai_core import ask_ollama, AI_PARALLEL_WORKERS
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
    js_summary = ""
    for filename, content in list(js_content_map.items())[:3]:
        js_summary += f"\n--- JS: {filename} ---\n{content[:1500]}\n"
    prompt = f"""You are an automated web security analyzer identifying attack surfaces and XSS targets.
Analyze this target:
URL: {url}
HTML:
{html_content[:2500]}
JavaScript:
{js_summary}

Task: Find input parameters, form actions, and DOM/reflected XSS sources and sinks.
Respond in valid JSON using this exact schema:
{{
    "analysis_summary": "Summary of findings",
    "discovered_targets": [
        {{
            "endpoint": "/target_endpoint_path",
            "parameter": "param_name",
            "type": "Reflected XSS | DOM XSS",
            "method": "GET | POST",
            "source_code": "code snippet",
            "sink_code": "sink snippet",
            "description": "brief description",
            "confidence": 0.9
        }}
    ]
}}"""
    return ask_ollama(prompt)

def deep_js_analysis(js_url, js_content):
    prompt = f"""You are an automated security researcher detecting DOM XSS in JavaScript.
File: {js_url}
JavaScript Code:
{js_content[:3000]}

Task: Identify parameters read from URL/DOM sources and passed to dangerous sinks (innerHTML, eval, setTimeout, document.write, etc.).
Respond in valid JSON using this exact schema:
{{
    "vulnerability_patterns": [
        {{
            "parameter": "param_name",
            "extraction_method": "source line",
            "sink_function": "sink function/property",
            "vulnerable_code": "vulnerable snippet",
            "severity": "High",
            "explanation": "brief mechanism description"
        }}
    ]
}}"""
    return ask_ollama(prompt)
def crawl_site(base_url, session=None, simulator_mode=False, max_urls=25, max_ai_audits=3):
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
    js_content_cache = {}
    ai_audits_performed = 0
    base_domain = urlparse(base_url).netloc

    while urls_to_visit and len(visited_urls) < max_urls:
        url = urls_to_visit.pop(0)
        if url in visited_urls:
            continue
        progress.update(f"Analyzing {url}")
        try:
            response = session.get(url, timeout=10)
            visited_urls.add(url)
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            page_js_map = {}

            # Process external scripts with caching
            for script_tag in soup.find_all("script", src=True):
                js_url = urljoin(base_url, script_tag['src'])
                js_filename = os.path.basename(urlparse(js_url).path) or "script.js"
                
                # Fetch content if not in cache
                if js_url not in js_content_cache:
                    try:
                        progress.update(f"Fetching JS {js_filename}")
                        js_response = session.get(js_url, timeout=5)
                        js_content_cache[js_url] = js_response.text
                    except Exception:
                        continue
                
                cached_content = js_content_cache.get(js_url, "")
                if cached_content:
                    page_js_map[js_filename] = cached_content

            # ---------------------------------------------------------------
            # Parallel JS analysis: analyze ALL new JS files simultaneously
            # ---------------------------------------------------------------
            js_to_analyze = [
                (js_url, js_content_cache[js_url])
                for js_url in page_js_map.keys()
                if js_url not in js_analysis_results and js_content_cache.get(js_url)
            ]

            if js_to_analyze:
                def _analyze_js(args):
                    u, content = args
                    return u, deep_js_analysis(u, content)

                progress.update(f"Parallel AI analysis of {len(js_to_analyze)} JS files")
                with concurrent.futures.ThreadPoolExecutor(max_workers=AI_PARALLEL_WORKERS) as pool:
                    for js_url, js_result in pool.map(_analyze_js, js_to_analyze):
                        if js_result:
                            js_analysis_results[js_url] = js_result

            # Inline scripts
            for script_tag in soup.find_all("script", src=False):
                if script_tag.string:
                    inline_js = script_tag.string.strip()
                    if len(inline_js) > 50:
                        inline_key = f"{url}#inline"
                        page_js_map["inline_script"] = inline_js
                        if inline_key not in js_analysis_results and len(js_analysis_results) < 2:
                            inline_analysis = deep_js_analysis(inline_key, inline_js)
                            if inline_analysis:
                                js_analysis_results[inline_key] = inline_analysis

            # Check if this page has attack surfaces (forms, inputs, url query params, or JS)
            parsed_curr = urlparse(url)
            has_inputs = bool(soup.find_all(['form', 'input', 'textarea', 'select']))
            has_query = bool(parsed_curr.query)
            has_js_handlers = bool(page_js_map)

            main_analysis = None
            if (has_inputs or has_query or has_js_handlers) and ai_audits_performed < max_ai_audits:
                progress.update(f"AI analysis of {url}")
                main_analysis = intelligent_parameter_extraction(url, html_content[:2500], page_js_map)
                ai_audits_performed += 1

            if main_analysis and main_analysis.get("discovered_targets"):
                print(f"\n[CRAWLER-AI] Found {len(main_analysis['discovered_targets'])} potential targets on {url}")
                for target in main_analysis["discovered_targets"]:
                    endpoint = target.get('endpoint') or ''
                    target_url = urljoin(url, endpoint) if endpoint else url
                    param = target.get('parameter') or 'q'
                    method = (target.get('method') or 'GET').upper()
                    page_info = {
                        'url': target_url,
                        'method': method,
                        'params': [param],
                        'ai_analysis': target,
                        'js_analysis': list(js_analysis_results.values())
                    }
                    existing = next((t for t in discovered_targets if t.get('url') == target_url), None)
                    if existing:
                        if param not in existing.get('params', []):
                            existing['params'].append(param)
                    else:
                        discovered_targets.append(page_info)

            # Map patterns from JS analysis
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

            # Form discovery & fallback: extract form actions and inputs directly
            for form in soup.find_all('form'):
                form_action = form.get('action') or ''
                form_method = (form.get('method') or 'GET').upper()
                action_url = urljoin(url, form_action) if form_action else url
                
                # Add action_url to crawl queue if on same domain
                parsed_act = urlparse(action_url)
                if (parsed_act.netloc == base_domain and 
                    action_url not in visited_urls and 
                    action_url not in urls_to_visit and 
                    not parsed_act.fragment):
                    urls_to_visit.append(action_url)

                form_inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name') or input_tag.get('id')
                    if name and name not in form_inputs:
                        form_inputs.append(name)

                if form_inputs:
                    form_page_info = {
                        'url': action_url,
                        'method': form_method,
                        'params': list(set(form_inputs[:5]))
                    }
                    existing = next((t for t in discovered_targets if t.get('url') == action_url), None)
                    if existing:
                        for inp in form_inputs:
                            if inp not in existing.get('params', []):
                                existing['params'].append(inp)
                    else:
                        discovered_targets.append(form_page_info)

            # Query params on current visited URL
            if parsed_curr.query:
                query_params = urllib.parse.parse_qs(parsed_curr.query)
                base_page_url = urllib.parse.urlunparse((parsed_curr.scheme, parsed_curr.netloc, parsed_curr.path, '', '', ''))
                qp_list = list(query_params.keys())
                if qp_list:
                    existing = next((t for t in discovered_targets if t.get('url') == base_page_url), None)
                    if existing:
                        for p in qp_list:
                            if p not in existing.get('params', []):
                                existing['params'].append(p)
                    else:
                        qp_page_info = {
                            'url': base_page_url,
                            'method': 'GET',
                            'params': qp_list[:5]
                        }
                        discovered_targets.append(qp_page_info)

            # Discover links on same domain
            for link_tag in soup.find_all('a', href=True):
                new_url = urljoin(base_url, link_tag['href'])
                parsed_new = urlparse(new_url)
                if (parsed_new.netloc == base_domain and 
                    new_url not in visited_urls and 
                    new_url not in urls_to_visit and
                    not parsed_new.fragment and
                    not new_url.endswith(('.pdf', '.jpg', '.png', '.gif', '.css', '.svg'))):
                    urls_to_visit.append(new_url)

            # Discover API endpoint strings in responses
            for ep_match in re.findall(r'["\'](/[\w/-]+)["\']', html_content):
                ep_url = urljoin(base_url, ep_match)
                parsed_ep = urlparse(ep_url)
                if (parsed_ep.netloc == base_domain and 
                    ep_url not in visited_urls and 
                    ep_url not in urls_to_visit and 
                    not parsed_ep.fragment and
                    not ep_url.endswith(('.pdf', '.jpg', '.png', '.gif', '.css', '.svg', '.js'))):
                    urls_to_visit.append(ep_url)

            time.sleep(0.1)
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