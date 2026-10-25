# 🛡️ Defensive AI Gateway

A reverse-proxy security gateway that sits in front of a sample web application and
inspects traffic for common attack patterns, plus an autonomous LLM-driven agent that
probes the protected app so the gateway's effect can be measured directly.

Built as a minor project, inspired by the **"Black October" (October 2026)** wave of
AI-assisted cybersecurity incidents, which highlighted how quickly automated and
LLM-driven agents can probe and exploit web applications at scale.

---

## 🏗️ Architecture

Three components run as separate processes, all on `127.0.0.1` only:

| Component | File | Port | Role |
|---|---|---|---|
| Target website | `target_website/` (FastAPI + MySQL) | 8002 | A sample internal portal app with login, signup, an employee directory and a project search — the thing being protected. Not hardened on its own. |
| Defensive gateway | `defensive_gateway.py` | 8000 | Reverse proxy in front of the target. Inspects, rate-limits and logs traffic before forwarding it. |
| Attacker agent | `attacker_agent.py` | — | A local-LLM-driven script (via [Ollama](https://ollama.com/), `llama3.2:3b`) that performs recon, credential guessing, bulk data requests and injection-style probes against the gateway. Hard-restricted to `127.0.0.1` targets only. |

The attacker always talks to the gateway (port 8000), never directly to the target
app (port 8002), so every attack passes through inspection when the gateway is enabled.

---

## 🎯 What the gateway does

The gateway has three modes, switched at runtime via an authenticated admin endpoint:

- **`off`** — pure pass-through. Baseline for showing the target app's own weaknesses.
- **`monitor`** — inspects and logs what *would* be blocked, but still forwards everything.
- **`enforce`** — inspects and actively blocks.

When enforcing, it checks for:

- **Path traversal** and known sensitive-file patterns (`../`, `/etc/passwd`, etc.)
- **SQL injection–style patterns** (boolean, UNION, stacked queries, time-based, comment injection)
- **XSS and command-injection–style patterns**
- **Input canonicalization** — values are URL-decoded and Unicode-normalized repeatedly
  before matching, to catch simple encoding-based evasion (e.g. `%2e%2e%2f`, double encoding)
- **Login rate limiting** — per-client and per-username token buckets, to slow down
  credential stuffing
- **Signup throttling**
- **Bulk-scrape protection** on the employee directory — requested page sizes are capped
- **Repeat-offender bans** — clients that repeatedly trigger blocks are temporarily banned
- **Hidden API docs** — `/openapi.json`, `/docs`, `/redoc` return a plain 404 when enforcing,
  so the schema isn't trivially discoverable
- **Generic block responses** — the client is told a request was blocked but not which rule
  fired or why, so an adaptive attacker gets minimal feedback to learn from

All decisions are written to `gateway_events.jsonl` (timestamp, client, rule, action, latency).

---

## 🤖 What the attacker agent does

`attacker_agent.py` runs a fixed recon/credential-stuffing opener, then hands control to
the local LLM for a few follow-up steps. Per run it attempts:

1. API schema discovery (`/openapi.json`)
2. A bulk employee-directory request
3. A short credential wordlist against the login endpoint
4. An injection-style probe against the search endpoint
5. 2 LLM-chosen follow-up actions, based on the server's responses so far

Every attempt (endpoint, status code, latency) is appended to `attack_results.jsonl`.

The agent will only ever target `127.0.0.1` / `localhost` — this is enforced in code,
not just by convention, since it is an autonomous script making its own requests.

---

## 📊 Measuring results

`summarize_results.py` reads `attack_results.jsonl` and `gateway_events.jsonl` and prints:

- Per-run status code breakdown (success / blocked / rate-limited / unauthorized)
- Which rules fired and how often
- Average and max inspection latency

Workflow to get a before/after comparison:

```bash
# 1. gateway starts in 'off' mode by default
python attacker_agent.py

# 2. switch to enforce mode (see "Admin controls" below)

python attacker_agent.py

# 3. compare the two runs
python summarize_results.py
```

---

## 🚀 Setup

### Prerequisites
- Python 3.10+
- MySQL, running locally, with a database created for the target app
- [Ollama](https://ollama.com/) with `llama3.2:3b` pulled (`ollama pull llama3.2:3b`)

### Install
```bash
git clone https://github.com/Froskersss/defensive-ai-gateway.git
cd defensive-ai-gateway
python -m venv venv
# Windows (PowerShell):
.\venv\Scripts\Activate
pip install -r requirements.txt
```

### Configure secrets
Copy `.env.example` to `.env` and fill in your own values — **`.env` is gitignored and
must never be committed**:
```bash
cp .env.example .env
```
```
DATABASE_URL=mysql+pymysql://root:yourpassword@localhost:3306/your_db_name
GATEWAY_ADMIN_KEY=choose-a-long-random-secret
```

---

## 🖥️ Running the demo

Open four terminals:

**Terminal 1 — target website**
```bash
cd target_website
python main.py          # runs on :8002
```

**Terminal 2 — gateway**
```bash
# (reads GATEWAY_ADMIN_KEY and DATABASE_URL from .env automatically if using python-dotenv,
#  or set them in this shell session first)
python defensive_gateway.py     # runs on :8000, starts in 'off' mode
```

**Terminal 3 — admin controls**

Switch modes (replace the key with your own from `.env`):
```bash
curl -X POST http://127.0.0.1:8000/__gateway/mode \
  -H "X-Admin-Key: choose-a-long-random-secret" \
  -H "Content-Type: application/json" \
  -d '{"mode":"enforce"}'
```
Valid modes: `off`, `monitor`, `enforce`.

Check current state:
```bash
curl http://127.0.0.1:8000/__gateway/stats \
  -H "X-Admin-Key: choose-a-long-random-secret"
```

**Terminal 4 — attacker agent**
```bash
ollama serve             # if not already running
python attacker_agent.py
```

---

## 📈 Sample results

| Scenario | Security OFF | Security ENFORCE |
|---|---|---|
| Admin login (correct password) | ✅ Succeeds | ✅ Succeeds (until rate-limited by repeated attempts) |
| Employee directory, `limit=500` | Returns all matching records uncapped | Clamped to a fixed maximum |
| `/openapi.json` schema discovery | 200, full schema returned | 404 |
| Injection-style search probe | Passed through (target query is parameterized, so not actually exploitable) | Blocked with a generic 403 |

*(Run `summarize_results.py` after your own test runs to generate current numbers —
the table above reflects the shape of the results, not a specific run's exact counts.)*

---

## ⚠️ Limitations

This is a minor-project proof of concept, not a production security tool:

- Detection rules are signature-based (regex on canonicalized input) — they will miss
  novel encodings or logic-level attacks that don't match known patterns.
- The target app's `/search` endpoint uses parameterized queries, so it isn't actually
  SQL-injectable; the gateway blocks injection-*looking* input regardless, but this
  doesn't demonstrate stopping a real exploit on this particular endpoint.
- Rate limiting is per-process, in-memory — it resets on restart and doesn't share
  state across multiple gateway instances.
- No distinction yet between a genuine LLM agent and a scripted tool making similar
  requests — detection is based on request content and pacing, not attacker identity.
- All testing was done against a backend running on localhost, under my control.

Planned next steps (dissertation phase): broader vulnerability coverage (SSRF, more
injection classes), a baseline comparison against an existing WAF (e.g. ModSecurity +
OWASP CRS), and evaluating whether session-level behavioral features can distinguish
LLM-agent traffic from scripted or human traffic.

---

## 🛠️ Tech stack

- **Target app:** FastAPI, SQLAlchemy, MySQL (PyMySQL), Pydantic, Passlib/bcrypt
- **Gateway:** FastAPI, httpx, Rich (console output)
- **Attacker agent:** Ollama (`llama3.2:3b`), httpx, Rich

---

## 📄 License & scope

Built for educational use. All attack traffic in this project targets a backend running
on `127.0.0.1` under the author's own control — the attacker agent is hard-restricted
to localhost targets in code.