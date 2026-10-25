"""
Component B: Defensive Gateway Proxy (defensive_gateway.py)
Features dual-layer inspection (Deterministic + Semantic) and a live Security Kill Switch.
"""

import time
import re
import httpx
from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse
from rich.console import Console
from rich.panel import Panel

console = Console()
app = FastAPI(title="Defensive AI Gateway with Security Kill-Switch", version="2.1.0")

TARGET_BACKEND_URL = "http://127.0.0.1:8001"

# GLOBAL SECURITY TOGGLE (Controlled live via endpoint)
SECURITY_STATE = {
    "enabled": False  # Starts OFF to demonstrate vulnerability first!
}

METRICS = {
    "total_requests": 0,
    "layer1_blocks": 0,
    "layer2_blocks": 0,
    "backend_success": 0,
    "backend_errors": 0
}

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),               
    re.compile(r"\.\.%2f", re.IGNORECASE), 
    re.compile(r"%2e%2e", re.IGNORECASE),  
    re.compile(r"/admin", re.IGNORECASE),  
    re.compile(r"etc/passwd", re.IGNORECASE) 
]

def normalize_uri(path: str, query_string: str) -> str:
    combined = f"{path}?{query_string}" if query_string else path
    return combined.replace("//", "/")

def print_metrics_dashboard():
    status_label = "[bold green]ACTIVE (Secure)[/bold green]" if SECURITY_STATE["enabled"] else "[bold red]DISABLED (Vulnerable)[/bold red]"
    summary = (
        f"[cyan]Gateway Defense State:[/cyan] {status_label}\n"
        f"[cyan]Total Requests Handled:[/cyan] {METRICS['total_requests']}\n"
        f"[red]Layer 1 Blocks (Deterministic):[/red] {METRICS['layer1_blocks']}\n"
        f"[yellow]Layer 2 Blocks (Semantic):[/yellow] {METRICS['layer2_blocks']}\n"
        f"[green]Allowed by Gateway (200 OK):[/green] {METRICS['backend_success']}"
    )
    console.print(Panel(summary, title="🛡️ Gateway Security Telemetry Dashboard", expand=False))

@app.get("/admin/toggle-security")
def toggle_security(enable: bool = Query(..., description="True to turn security ON, False to turn OFF")):
    """Live control switch to enable or disable the defense gateway mechanism."""
    SECURITY_STATE["enabled"] = enable
    state_str = "ENABLED 🛡️" if enable else "DISABLED ⚠️"
    console.print(f"\n[bold yellow]>>> SYSTEM ALERT: Security Switch toggled -> {state_str} <<<\n[/bold yellow]")
    return {"status": "success", "security_enabled": SECURITY_STATE["enabled"]}

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def gateway_proxy(request: Request, path_name: str):
    start_time = time.perf_counter()
    METRICS["total_requests"] += 1
    client_ip = request.client.host if request.client else "unknown"
    raw_query = request.url.query
    full_path_uri = f"/{path_name}"

    console.print(f"\n[cyan][GATEWAY] Request #{METRICS['total_requests']} (Security: {SECURITY_STATE['enabled']}) -> {full_path_uri}?{raw_query}[/cyan]")

    # IF SECURITY IS ENABLED, RUN INSPECTION LAYERS
    if SECURITY_STATE["enabled"]:
        # LAYER 1: Deterministic Path Inspection
        normalized_target = normalize_uri(full_path_uri, raw_query)
        for pattern in PATH_TRAVERSAL_PATTERNS:
            if pattern.search(normalized_target):
                METRICS["layer1_blocks"] += 1
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                console.print(f"[bold red][GATEWAY BLOCK - LAYER 1] Signature matched: '{pattern.pattern}' | Latency: {elapsed_ms:.2f}ms[/bold red]")
                print_metrics_dashboard()
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Forbidden by Defensive Gateway",
                        "reason": "Layer 1 Deterministic Path Traversal / Probe Detected",
                        "latency_ms": round(elapsed_ms, 2),
                        "telemetry": METRICS
                    }
                )

        # LAYER 2: Semantic Intent Check
        for key, value in request.query_params.items():
            val_lower = value.lower()
            if "passwd" in val_lower or "root" in val_lower or "shadow" in val_lower:
                METRICS["layer2_blocks"] += 1
                elapsed_ms = (time.perf_counter() - start_time) * 1000
                console.print(f"[bold red][GATEWAY BLOCK - LAYER 2] Semantic anomaly in param '{key}': '{value}' | Latency: {elapsed_ms:.2f}ms[/bold red]")
                print_metrics_dashboard()
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Forbidden by Defensive Gateway",
                        "reason": "Layer 2 Semantic Intent Violation Detected",
                        "latency_ms": round(elapsed_ms, 2),
                        "telemetry": METRICS
                    }
                )

    # FORWARD TO TARGET BACKEND
    target_url = f"{TARGET_BACKEND_URL}/{path_name}"
    if raw_query:
        target_url += f"?{raw_query}"

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=dict(request.headers),
                content=await request.body(),
                timeout=5.0
            )
            
            if resp.status_code == 200:
                METRICS["backend_success"] += 1
            else:
                METRICS["backend_errors"] += 1
                
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            if not SECURITY_STATE["enabled"]:
                console.print(f"[bold magenta][AUDIT MODE] Security OFF - Request passed straight to backend! Status: {resp.status_code}[/bold magenta]")
            else:
                console.print(f"[bold green][GATEWAY ALLOW] Status: {resp.status_code} | Latency: {elapsed_ms:.2f}ms[/bold green]")
                
            print_metrics_dashboard()
            
            return Response(
                content=resp.content,
                status_code=resp.status_code,
                headers=dict(resp.headers)
            )
            
        except httpx.RequestError as exc:
            METRICS["backend_errors"] += 1
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            console.print(f"[bold red][GATEWAY ERROR] Backend connection failed: {exc}[/bold red]")
            print_metrics_dashboard()
            return JSONResponse(
                status_code=502,
                content={"error": "Bad Gateway", "details": str(exc), "latency_ms": round(elapsed_ms, 2)}
            )

if __name__ == "__main__":
    import uvicorn
    console.print("[bold green]Starting Gateway with Security Switch on http://127.0.0.1:8000[/bold green]")
    uvicorn.run(app, host="127.0.0.1", port=8000)