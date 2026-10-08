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
        last_msg = ""
        while self.active:
            cur_msg = self.message
            if cur_msg != last_msg:
                print(f"\r[{self.phase_name}] {spinner[i % len(spinner)]}... {cur_msg}               ", end="", flush=True)
                last_msg = cur_msg
                i += 1
            time.sleep(0.3)
def prune_html_for_analysis(html_content):
    """Extract only attack-surface HTML tags (forms, inputs, scripts) to minimize prompt tokens."""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        parts = []
        for form in soup.find_all('form'):
            parts.append(str(form)[:600])
        for inp in soup.find_all(['input', 'textarea', 'select']):
            parts.append(str(inp))
        for script in soup.find_all('script'):
            if script.string:
                s = script.string.strip()
                if any(kw in s for kw in ['location', 'search', 'get', 'eval', 'innerHTML', 'setTimeout', 'param']):
                    parts.append(s[:600])
        if parts:
            return "\n".join(parts)[:1800]
    except Exception:
        pass
    return html_content[:1000]

def intelligent_parameter_extraction(url, html_content, js_content_map):
    pruned_html = prune_html_for_analysis(html_content)
    js_summary = ""
    for filename, content in list(js_content_map.items())[:3]:
        # Only include relevant JS snippets containing DOM sources/sinks
        relevant_lines = [line for line in content.splitlines() if any(kw in line for kw in ['URLSearch', 'searchParams', 'location', 'innerHTML', 'eval', 'setTimeout', 'document.write', 'get'])]
        snippet = "\n".join(relevant_lines[:15]) if relevant_lines else content[:500]
        js_summary += f"\n--- JS: {filename} ---\n{snippet[:800]}\n"
    prompt = f"""You are an automated web security analyzer identifying attack surfaces and XSS targets.
Analyze this target:
URL: {url}
HTML:
{pruned_html}
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
    # Fast heuristic check: if no source or sink keywords exist, skip LLM call entirely
    sinks_sources = ['search', 'param', 'location', 'hash', 'query', 'url', 'innerhtml', 'eval', 'settimeout', 'document.write']
    content_lower = js_content.lower()
    if not any(k in content_lower for k in sinks_sources):
        return {"vulnerability_patterns": []}

    lines = js_content.splitlines()
    relevant_lines = [l for l in lines if any(k in l.lower() for k in sinks_sources)]
    compact_code = "\n".join(relevant_lines[:25]) if relevant_lines else js_content[:1500]

    prompt = f"""You are an automated security researcher detecting DOM XSS in JavaScript.
File: {js_url}
JavaScript Code:
{compact_code}

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
def crawl_site(base_url, session=None, simulator_mode=False, max_urls=25, max_ai_audits=2):
    progress = CrawlerProgressIndicator()
    progress.start()
    if session is None:
        session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
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
                    page_js_map[js_url] = cached_content

            # Filter out third-party/vendor/analytics scripts
            vendor_blacklist = [
                'jquery', 'bootstrap', 'react', 'vue', 'angular', 'lodash', 'moment',
                'gtm', 'analytics', 'clarity', 'facebook', 'pixel', 'chunk', 'vendor',
                'polyfill', 'webpack', 'core-js', 'cdn-cgi'
            ]
            js_candidates = []
            for u, content in page_js_map.items():
                if u in js_analysis_results or not content:
                    continue
                filename_lower = os.path.basename(urlparse(u).path).lower()
                u_lower = u.lower()
                if any(v in filename_lower or v in u_lower for v in vendor_blacklist):
                    continue
                js_candidates.append((u, content))

            # Cap to at most 2 first-party candidate scripts to avoid queue starvation
            js_to_analyze = js_candidates[:2]
            if js_to_analyze:
                progress.update(f"AI analysis of {len(js_to_analyze)} JS files")
                for u, content in js_to_analyze:
                    js_result = deep_js_analysis(u, content)
                    if js_result:
                        js_analysis_results[u] = js_result

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
            # Only perform deep LLM extraction on unique pages without query strings (e.g. root or clean endpoints)
            # Query strings (like ?callback=hello) are already accurately parsed statically by parse_qs
            should_ai_audit = (
                ai_audits_performed < max_ai_audits and
                not has_query and
                (has_inputs or has_js_handlers)
            )
            if should_ai_audit:
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

            # Map patterns from JS analysis ONLY to pages that actually load this script
            for js_url, js_analysis in js_analysis_results.items():
                if js_url in page_js_map and js_analysis.get("vulnerability_patterns"):
                    for vuln_pattern in js_analysis["vulnerability_patterns"]:
                        param_name = vuln_pattern.get('parameter')
                        if not param_name:
                            continue
                        if any(t.get('url') == url and t.get('ai_analysis', {}).get('parameter') == param_name for t in discovered_targets):
                            continue
                        page_info = {
                            'url': url,
                            'method': 'GET',
                            'params': [param_name],
                            'ai_analysis': {
                                'parameter': param_name,
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