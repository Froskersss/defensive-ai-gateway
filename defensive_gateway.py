"""
defensive_gateway_v2.py - Defensive reverse proxy for the Aegis portal (backend on :8002).

Modes (change with POST /__gateway/mode and header X-Admin-Key):
  off      pass-through, nothing inspected (vulnerable baseline)
  monitor  inspect and log what WOULD be blocked, but forward everything
  enforce  inspect and block

Run:
  set GATEWAY_ADMIN_KEY=choose-a-secret      (PowerShell: $env:GATEWAY_ADMIN_KEY="...")
  python defensive_gateway_v2.py

Events are appended to gateway_events.jsonl (one JSON object per line).
"""
import json
import os
import re
import secrets
import time
import unicodedata
import uuid
from collections import Counter, defaultdict, deque
from contextlib import asynccontextmanager
from urllib.parse import parse_qsl, unquote_plus, urlencode

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from rich.console import Console
from rich.markup import escape

console = Console()

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8002")
ADMIN_KEY = os.getenv("GATEWAY_ADMIN_KEY") or secrets.token_urlsafe(16)
ADMIN_KEY_WAS_GENERATED = not os.getenv("GATEWAY_ADMIN_KEY")
LOG_FILE = os.getenv("GATEWAY_LOG", "gateway_events.jsonl")

# On localhost every client shares 127.0.0.1. For demos only, set
# TRUST_CLIENT_ID_HEADER=1 and give the attacker and the benign test script
# different X-Client-ID headers so limits are tracked separately.
# NEVER enable this in production: clients could spoof the header to evade limits.
TRUST_CLIENT_ID = os.getenv("TRUST_CLIENT_ID_HEADER") == "1"

MAX_BODY_BYTES = 64 * 1024
MAX_EMPLOYEE_LIMIT = 20
STRIKE_LIMIT, STRIKE_WINDOW_S, BAN_SECONDS = 6, 120, 300
RECON_PATHS = {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}
SKIP_BODY_KEYS = {"password"}  # passwords may legitimately contain quotes etc.

DROP_REQ_HEADERS = {
    "host", "content-length", "connection", "keep-alive", "transfer-encoding",
    "upgrade", "accept-encoding", "te", "trailer", "proxy-authorization",
    "proxy-authenticate",
}
DROP_RESP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection", "keep-alive"}

state = {"mode": os.getenv("GATEWAY_MODE", "off")}
stats: Counter = Counter()


# ----------------------------------------------------------------------------
# Rate limiting and strikes
# ----------------------------------------------------------------------------
class RateLimiter:
    """Token bucket: `capacity` requests allowed per `per_seconds`, per key."""

    def __init__(self, capacity: int, per_seconds: float):
        self.capacity = capacity
        self.rate = capacity / per_seconds
        self.buckets: dict[str, tuple[float, float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last = self.buckets.get(key, (float(self.capacity), now))
        tokens = min(float(self.capacity), tokens + (now - last) * self.rate)
        if tokens >= 1:
            self.buckets[key] = (tokens - 1, now)
            return True
        self.buckets[key] = (tokens, now)
        return False


login_by_client = RateLimiter(10, 60)
login_by_user = RateLimiter(5, 300)
signup_by_client = RateLimiter(5, 300)
scrape_by_client = RateLimiter(10, 60)

strikes: dict[str, deque] = defaultdict(deque)
bans: dict[str, float] = {}


def add_strike(client: str) -> None:
    now = time.time()
    q = strikes[client]
    q.append(now)
    while q and now - q[0] > STRIKE_WINDOW_S:
        q.popleft()
    if len(q) >= STRIKE_LIMIT:
        bans[client] = now + BAN_SECONDS
        q.clear()


def client_key(request: Request) -> str:
    if TRUST_CLIENT_ID and request.headers.get("x-client-id"):
        return "id:" + request.headers["x-client-id"][:64]
    return "ip:" + (request.client.host if request.client else "unknown")


# ----------------------------------------------------------------------------
# Canonicalization and content rules
# ----------------------------------------------------------------------------
def canonicalize(value: str, max_rounds: int = 4) -> tuple[str, bool]:
    """Decode repeatedly until stable. Returns (canonical lowercase text, still_changing)."""
    for _ in range(max_rounds):
        decoded = unquote_plus(value)
        decoded = unicodedata.normalize("NFKC", decoded).replace("\x00", "").replace("\\", "/")
        if decoded == value:
            return value.lower(), False
        value = decoded
    return value.lower(), True


RULES = [
    ("path_traversal", re.compile(r"(^|/)\.\.(/|$)")),
    ("sensitive_file", re.compile(r"/etc/(passwd|shadow|hosts)|boot\.ini|win\.ini|c:/windows")),
    ("sqli_boolean", re.compile(r"['\"]\s*(or|and)\s+['\"\w]+\s*=\s*['\"\w]+")),
    ("sqli_union", re.compile(r"union\s+(all\s+)?select")),
    ("sqli_stacked", re.compile(r";\s*(drop|delete|update|insert|alter)\s")),
    ("sqli_time_based", re.compile(r"\b(sleep|benchmark)\s*\(")),
    ("sqli_schema", re.compile(r"information_schema")),
    ("sqli_comment", re.compile(r"['\"]\s*(--|#|/\*)")),
    ("xss", re.compile(r"<\s*script|javascript:|\bon(error|load|click|mouseover)\s*=")),
    ("cmd_injection", re.compile(r"[;&|`]\s*(cat|ls|whoami|id|curl|wget|nc)\b|\$\(")),
]


def scan(text: str) -> str | None:
    canon, unstable = canonicalize(text)
    if unstable:
        return "excessive_encoding"
    for name, rx in RULES:
        if rx.search(canon):
            return name
    return None


def iter_strings(obj, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from iter_strings(v, str(k))
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_strings(v, key)
    elif isinstance(obj, str):
        yield key, obj


def evaluate(request: Request, body: bytes, client: str) -> tuple[str, int] | None:
    """Return (rule, http_status) if the request violates policy, else None."""
    path = request.url.path
    method = request.method

    if time.time() < bans.get(client, 0):
        return "client_banned", 429
    if path in RECON_PATHS:
        return "recon_path", 404
    if len(body) > MAX_BODY_BYTES:
        return "body_too_large", 413

    parsed = None
    if body and "json" in request.headers.get("content-type", ""):
        try:
            parsed = json.loads(body)
        except ValueError:
            return "malformed_json", 400

    # Behavioural limits
    if method == "POST" and path == "/api/v1/login":
        if not login_by_client.allow(client):
            return "login_rate_limit_client", 429
        username = str(parsed.get("username", "")).lower()[:64] if isinstance(parsed, dict) else ""
        if username and not login_by_user.allow(username):
            return "login_rate_limit_user", 429
    if method == "POST" and path == "/api/v1/signup" and not signup_by_client.allow(client):
        return "signup_rate_limit", 429
    if path == "/api/v1/employees" and not scrape_by_client.allow(client):
        return "bulk_enumeration", 429

    # Content rules on path, query values and body values
    raw_path = request.scope.get("raw_path", path.encode()).decode("latin-1")
    candidates = [("path", raw_path)]
    candidates += [(f"query:{k}", v) for k, v in request.query_params.multi_items()]
    if parsed is not None:
        candidates += [(f"body:{k}", v) for k, v in iter_strings(parsed) if k.lower() not in SKIP_BODY_KEYS]
    elif body:
        candidates.append(("body", body.decode("utf-8", "ignore")))
    for label, text in candidates:
        rule = scan(text)
        if rule:
            return f"{rule}@{label}", 403
    return None


def clamp_limit(query: str) -> str:
    """Force ?limit= on the employees endpoint to a sane maximum (adds it if missing)."""
    out, seen = [], False
    for k, v in parse_qsl(query, keep_blank_values=True):
        if k == "limit":
            seen = True
            if not v.isdigit() or not (1 <= int(v) <= MAX_EMPLOYEE_LIMIT):
                v = str(MAX_EMPLOYEE_LIMIT)
        out.append((k, v))
    if not seen:
        out.append(("limit", str(MAX_EMPLOYEE_LIMIT)))
    return urlencode(out)


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------
def log(**event) -> None:
    event["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")
    colour = {"block": "red", "monitor_would_block": "yellow", "allow": "green"}.get(event["action"], "white")
    console.print(
        f"[{colour}]{event['action']:<20}[/{colour}] {event['method']} "
        f"{escape(event['path'])} {escape(str(event.get('rule') or ''))} "
        f"[{event.get('status')}] {event.get('latency_ms')} ms"
    )


# ----------------------------------------------------------------------------
# App
# ----------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(base_url=BACKEND_URL, timeout=10.0)
    yield
    await app.state.client.aclose()


app = FastAPI(title="Aegis Defensive Gateway", version="2.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def require_admin(x_admin_key: str | None) -> None:
    if not x_admin_key or not secrets.compare_digest(x_admin_key, ADMIN_KEY):
        raise HTTPException(status_code=404, detail="Not Found")  # do not reveal the endpoint exists


@app.post("/__gateway/mode")
async def set_mode(payload: dict, x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    mode = payload.get("mode")
    if mode not in {"off", "monitor", "enforce"}:
        raise HTTPException(status_code=400, detail="mode must be off, monitor or enforce")
    state["mode"] = mode
    console.print(f"[bold cyan]MODE -> {mode}[/bold cyan]")
    return {"mode": mode}


@app.get("/__gateway/stats")
async def get_stats(x_admin_key: str | None = Header(default=None)):
    require_admin(x_admin_key)
    return {"mode": state["mode"], "stats": dict(stats)}


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(request: Request, full_path: str):
    t0 = time.perf_counter()
    rid = uuid.uuid4().hex[:8]
    client = client_key(request)
    body = await request.body()
    mode = state["mode"]
    path = request.url.path
    query = request.url.query
    stats["total"] += 1

    base = {"id": rid, "client": client, "method": request.method, "path": path, "mode": mode}

    if mode != "off":
        verdict = evaluate(request, body, client)
        if verdict:
            rule, status = verdict
            rule_name = rule.split("@")[0]
            ms = round((time.perf_counter() - t0) * 1000, 2)
            if mode == "enforce":
                stats["blocked"] += 1
                stats[f"rule:{rule_name}"] += 1
                if rule_name != "client_banned":
                    add_strike(client)
                log(action="block", rule=rule, status=status, latency_ms=ms, **base)
                # Generic body on purpose: do not tell an attacker which rule fired.
                content = {"detail": "Not Found"} if status == 404 else {"error": "Request blocked", "request_id": rid}
                headers = {"Retry-After": "60"} if status == 429 else None
                return JSONResponse(status_code=status, content=content, headers=headers)
            stats["would_block"] += 1
            log(action="monitor_would_block", rule=rule, status=status, latency_ms=ms, **base)
        if mode == "enforce" and path == "/api/v1/employees":
            query = clamp_limit(query)

    raw_path = request.scope.get("raw_path", path.encode()).decode("latin-1")
    url = raw_path + (f"?{query}" if query else "")
    headers = {k: v for k, v in request.headers.items() if k.lower() not in DROP_REQ_HEADERS}
    headers["x-forwarded-for"] = request.client.host if request.client else ""

    try:
        r = await request.app.state.client.request(request.method, url, headers=headers, content=body)
    except httpx.RequestError as exc:
        log(action="backend_error", rule=str(exc)[:80], status=502, latency_ms=round((time.perf_counter() - t0) * 1000, 2), **base)
        return JSONResponse(status_code=502, content={"error": "Bad Gateway"})

    resp = Response(content=r.content, status_code=r.status_code)
    for k, v in r.headers.multi_items():  # keeps repeated headers such as Set-Cookie
        if k.lower() not in DROP_RESP_HEADERS:
            resp.raw_headers.append((k.lower().encode("latin-1"), v.encode("latin-1")))
    stats["allowed"] += 1
    log(action="allow", rule=None, status=r.status_code, latency_ms=round((time.perf_counter() - t0) * 1000, 2), **base)
    return resp


if __name__ == "__main__":
    import uvicorn

    if ADMIN_KEY_WAS_GENERATED:
        console.print(f"[bold yellow]Generated admin key (set GATEWAY_ADMIN_KEY to choose your own): {ADMIN_KEY}[/bold yellow]")
    console.print(f"[bold cyan]Gateway on http://127.0.0.1:8000 -> {BACKEND_URL} | mode={state['mode']}[/bold cyan]")
    uvicorn.run(app, host="127.0.0.1", port=8000)



    '''
    Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/__gateway/mode" `
>>   -Headers @{"X-Admin-Key"="a"} `                  
>>   -ContentType "application/json" -Body '{"mode":"enforce"}'

    '''