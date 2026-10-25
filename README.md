```markdown
# 🛡️ Low-Latency Defensive AI Gateway & Autonomous Red-Teaming PoC

A high-performance, dual-layer security reverse proxy designed to protect legacy and microservice backends against autonomous, agentic LLM attacks and path traversal vulnerabilities with sub-millisecond inspection overhead.

---

## 💡 Project Inspiration & Vision
This project was inspired by the recent **"Black October"** cybersecurity events—a stark industry reminder highlighting how rapidly automated threat actors, autonomous agentic worms, and LLM-driven reconnaissance tools can weaponize application vulnerabilities at scale. Traditional static firewalls often struggle against adaptive payloads, prompting the need for lightweight, intelligent edge defenses.

**Future Roadmap & Enterprise Expansion:** 
This repository represents an active Proof-of-Concept. I am continuously expanding this gateway into a robust, production-grade security appliance by integrating advanced architecture features:
* **Token-Bucket Rate Limiting:** Automated anti-fuzzing and DoS protection to throttle aggressive scanning IP addresses.
* **ONNX-Quantized ML Classifiers:** Upgrading Layer 2 semantic checks with lightweight transformer-based intent scoring.
* **Recursive Canonicalization:** Multi-stage decoding pipelines to neutralize complex triple-URL encoding, Unicode obfuscation, and null-byte tricks.
* **Structured SIEM Audit Logging:** Streaming security telemetry into JSON-formatted event logs for enterprise observability.
* **Deception Honeypots:** Returning intelligent decoy payloads instead of standard `403 Forbidden` errors to exhaust automated reconnaissance agents.

---

## 🎯 Project Overview
Modern web applications face increasingly sophisticated threats driven by automated and generative AI agents. This project demonstrates a complete Proof-of-Concept (PoC) architecture featuring a **vulnerable target backend**, a **high-speed defensive proxy gateway**, and an **autonomous LLM red-teaming agent** that dynamically mutates attack payloads to probe for weaknesses.

---

## 🏗️ System Architecture

The project operates on a 3-terminal concurrent execution model:

1. **Target Backend (`target_app.py`)**: A FastAPI microservice hosting an intentional path traversal vulnerability (`/api/v1/download?file=...`) simulating an insecure internal storage endpoint.
2. **Defensive Gateway Proxy (`defensive_gateway.py`)**: A dual-layer security reverse proxy intercepting all inbound traffic. It features an administrative toggle (`/admin/toggle-security`) for live demonstration switching between vulnerable (Audit) and protected (Secure) modes.
3. **LLM Attacker Agent (`attacker_agent.py`)**: An autonomous offensive testing agent powered by a local LLM (`llama3.2:3b` via Ollama) that analyzes previous HTTP response feedback loops to adaptively mutate and scale its payload generation strategy.

---

## 🛡️ Defense Mechanics

When security mode is enabled, incoming requests undergo a two-tier inspection pipeline:
* **Layer 1 (Deterministic Regex & Pattern Matching):** Instantly flags and intercepts known path traversal sequences (`../`, URL-encoded dots, hex variations, null-byte injections) in **< 1ms**.
* **Layer 2 (Semantic Intent Analysis):** Evaluates query parameter structure and behavioral anomaly heuristics to catch novel evasion attempts.

---

## 🚀 Quick Start Guide

### Prerequisites
* Python 3.10+
* [Ollama](https://ollama.com/) installed locally with `llama3.2:3b` pulled (`ollama pull llama3.2:3b`).

### Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/Froskersss/defensive-ai-gateway.git](https://github.com/Froskersss/defensive-ai-gateway.git)
   cd defensive-ai-gateway

```

2. Create and activate a virtual environment:
```bash
python -m venv venv
# On Windows (PowerShell):
.\venv\Scripts\Activate

```


3. Install dependencies:
```bash
pip install fastapi uvicorn httpx rich ollama

```



---

## 🖥️ Running the Live Demonstration

Open **3 separate terminal windows** inside your virtual environment to run the system concurrently:

* **Terminal 1: Start the Vulnerable Backend**
```bash
python target_app.py

```


* **Terminal 2: Start the Defensive Gateway Proxy**
```bash
python defensive_gateway.py

```


* **Terminal 3: Execute the Autonomous AI Attacker Agent**
```bash
python attacker_agent.py

```



### Activating Defense Live

To toggle the gateway's security protections on during your demo, run:

```powershell
curl -UseBasicParsing "[http://127.0.0.1:8000/admin/toggle-security?enable=true](http://127.0.0.1:8000/admin/toggle-security?enable=true)"

```

*(To disable security and demonstrate the raw vulnerability again, set `enable=false`).*

---

## 📊 Security Telemetry & Results

The simulation tracks real-time operational metrics, outputting a detailed statistical evaluation report at the end of each run:

* **Attack Interception Efficacy:** Achieves **100% block efficacy** against malicious traversal probes and AI-generated evasion variants (`../../etc/shadow`, encoded sequences).
* **Inspection Overhead:** Adds an average latency penalty of **< 0.9 ms** per request, ensuring high throughput for legitimate users.

---

## 🛠️ Tech Stack

* **Core Framework:** FastAPI, Uvicorn, Python `httpx`
* **Offensive AI Engine:** Ollama (`llama3.2:3b`)
* **Terminal UI & Telemetry:** Rich Console & Panels

```

```
