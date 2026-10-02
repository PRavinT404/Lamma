# APEX AI Pentest Bot — Architecture & Knowledge Base

---

## 1. Executive Summary & Architecture

**APEX (AI-Pentest-Bot)** is an automated web penetration testing framework that combines two distinct AI paradigms:

1. **Reinforcement Learning (RL) — Strategic Decision Making:**
   - Powered by **Stable-Baselines3 (PPO)** and **Gymnasium**.
   - Determines the macro-level order of operations (Recon $\rightarrow$ Directory Enumeration $\rightarrow$ Web Crawling $\rightarrow$ Vulnerability Testing $\rightarrow$ Reporting).
2. **Local Large Language Model (LLM) — Tactical Code Analysis:**
   - Powered by **Llama 3.1 8B** running locally via **Ollama**.
   - Analyzes HTML source code and client-side JavaScript to identify DOM sources, sinks, data flows, and craft context-aware filter bypass payloads.

---

## 2. System Workflow & Component Map

```
[Target URL]
     │
     ▼
[RL Policy (PPO)] ── Determines optimal next action
     │
     ├─ Action 0: task_nmap.py      (Port & Service Recon)
     ├─ Action 1: task_gobuster.py  (Directory Discovery via wordlist.txt)
     ├─ Action 2: task_crawler.py   (Crawl endpoints, fetch JS, query Ollama)
     ├─ Action 3: task_xss.py       (Analyze filters, generate payloads via Ollama, verify)
     └─ Action 4: Reporting         (Generate assessment summary)
```

### Core File Reference

| File | Purpose | Key Details |
| :--- | :--- | :--- |
| `main.py` | CLI Entrypoint | Loads trained RL model (`sequence_model_final.zip`), executes steps, updates UI. |
| `pentest_env.py` | RL Environment | Gymnasium environment (`Discrete(5)` action space, 16-element observation vector). |
| `train.py` | Model Training | Multi-core parallel PPO training until a 95% sequence success rate is reached. |
| `ai_core.py` | Ollama Connector | Sends HTTP requests to `http://localhost:11434/api/generate` with JSON enforcement. |
| `task_nmap.py` | Port Scanning | Executes Nmap command-line utility to identify open ports and services. |
| `task_gobuster.py`| Directory Enumeration| Runs Gobuster with `wordlist.txt` to find hidden web paths (`/admin`, `/api`). |
| `task_crawler.py` | Crawling & Source Audit| Extracts links, inline/external scripts, and uses Llama 3.1 to map sources/sinks. |
| `task_xss.py` | XSS Attack Engine | Probes active security filters, generates tailored payloads via LLM, and verifies execution. |
| `config.py` | Configuration | Resolves executable paths for Nmap and Gobuster and points to `wordlist.txt`. |
| `Vulnerable_app.py`| Built-in Target | Flask test application with reflected XSS and DOM-based XSS for safe testing. |

---

## 3. How Scoring Works

In `pentest_env.py`, two scores are tracked in real time:

### A. Confidence Score (0.0 to 1.0)
Calculated based on completing key penetration testing phases:
- **Recon phase complete:** `+0.2`
- **Directory enumeration complete:** `+0.2`
- **Crawling & discovery complete:** `+0.2`
- **Confirmed vulnerability found:** `+0.4`
- **Maximum:** `1.0` (100% Confidence)

### B. Learning Score (0.0 to 2.0)
Represents the accumulated reward divided by 100:
$$\text{Learning Score} = \min\left(2.0, \max\left(0.0, \text{Score} + \frac{\text{Reward}}{100}\right)\right)$$
- **Open ports detected:** $+10.0 + (2.0 \times \text{ports})$
- **Directories discovered:** $+15.0 + (1.0 \times \text{directories})$
- **Endpoints crawled:** $+20.0 + (2.0 \times \text{endpoints})$
- **Vulnerability confirmed:** $+100.0$
- **Successful episode completion:** $+50.0$ bonus

> **Note on Training vs. Inference:** Running `main.py --live` is **inference mode** (evaluating the model). The model's weights do not update live. To update the model's neural network weights, run `python train.py`.

---

## 4. Safe & Authorized Practice Environments

> **Legal Warning:** Automated security testing tools should **only** be executed against systems you own or have explicit written permission to test. Unauthorized scanning of third-party websites is illegal.

### Recommended Local Targets (Best for Learning & High Scores)

1. **Built-in Testbed (`Vulnerable_app.py`):**
   - URL: `http://127.0.0.1:5000`
   - Contains: Reflected XSS on `/search?q=`, DOM XSS on `/static/app.js`, hidden endpoints (`/admin`, `/api`).
   - How to run: `python Vulnerable_app.py`

2. **OWASP Juice Shop (Modern Vulnerable App):**
   - The official OWASP testbed covering the entire OWASP Top 10.
   - Run via Docker:
     ```bash
     docker run --rm -p 3000:3000 bkimminich/juice-shop
     ```
   - Target: `http://127.0.0.1:3000`

3. **DVWA (Damn Vulnerable Web App):**
   - Classic PHP/MySQL testbed with adjustable security levels (Low, Medium, High).
   - Run via Docker:
     ```bash
     docker run --rm -it -p 80:80 vulnerables/web-dvwa
     ```
   - Target: `http://127.0.0.1:80`

### Publicly Sanctioned Testing Websites (Designed for Scanners)
These public testbeds are provided by security firms specifically for testing automated tools:
- **Acunetix Vulnweb:** `http://testphp.vulnweb.com` (PHP testbed)
- **Altoro Mutual (IBM/HCL Demo):** `http://demo.testfire.net`

---

## 5. Study & Knowledge Roadmap

To deepen your understanding and improve this system, focus on these three domains:

### 1. Reinforcement Learning (Decision Making)
- **Frameworks:** Gymnasium (Env, action/observation spaces), Stable-Baselines3 (PPO algorithm).
- **Key Concepts:** Markov Decision Processes (MDP), reward shaping, action masking, curriculum learning.
- **Resource:** *Spinning Up in Deep RL* (OpenAI documentation).

### 2. Web Application Security
- **Standards:** OWASP Top 10, PortSwigger Web Security Academy (Free).
- **Core Topics:** DOM XSS (Sources & Sinks), Reflected XSS, Content Security Policy (CSP), Filter Bypasses.
- **Tools:** Nmap scripting engine (NSE), Gobuster/Feroxbuster, Burp Suite Community.

### 3. LLM Integration & Prompt Engineering
- **Concepts:** Structured JSON extraction, few-shot prompting, temperature and top-p tuning.
- **Frameworks:** Ollama REST API, LangChain / LlamaIndex.
