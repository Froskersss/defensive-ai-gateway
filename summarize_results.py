"""
summarize_results.py
Reads attack_results.jsonl (written by attacker_agent_v2.py) and
gateway_events.jsonl (written by defensive_gateway_v2.py) and prints
a before/after metrics table you can paste into your report.

Usage: run this AFTER you've done at least one attacker run with the
gateway in 'off' mode and one run with it in 'enforce' mode.

    python summarize_results.py
"""
import json
from collections import Counter, defaultdict
from pathlib import Path

ATTACK_LOG = Path("attack_results.jsonl")
GATEWAY_LOG = Path("gateway_events.jsonl")


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def summarize():
    attacks = load_jsonl(ATTACK_LOG)
    events = load_jsonl(GATEWAY_LOG)

    if not attacks:
        print(f"No data in {ATTACK_LOG} yet — run attacker_agent_v2.py first.")
        return

    by_run = defaultdict(list)
    for a in attacks:
        by_run[a.get("run_id", "unknown")].append(a)

    # Match each attacker run to the gateway mode active at the time, using
    # the gateway event log's mode field for events in the same time window.
    print("=" * 70)
    print("ATTACKER RUNS")
    print("=" * 70)
    for run_id, steps in by_run.items():
        modes_seen = set()
        statuses = Counter()
        for s in steps:
            statuses[s.get("status_code")] += 1
        # best-effort: look up mode from gateway events with matching ts prefix
        ts_set = {s.get("ts", "")[:5] for s in steps}
        for e in events:
            if e.get("ts", "")[-8:-3] in ts_set:
                modes_seen.add(e.get("mode"))
        mode_str = "/".join(sorted(modes_seen)) if modes_seen else "unknown"
        print(f"\nRun {run_id}  (gateway mode seen: {mode_str})  {len(steps)} steps")
        for code, count in sorted(statuses.items(), key=lambda x: (x[0] is None, x[0])):
            label = {200: "success", 401: "unauthorized", 403: "blocked",
                     404: "not found", 422: "bad request (bug, not a block)",
                     429: "rate limited", 502: "backend error", None: "connection error"}.get(code, str(code))
            print(f"    {str(code):>5}  x{count:<3}  {label}")

    if events:
        print("\n" + "=" * 70)
        print("GATEWAY EVENTS (all time)")
        print("=" * 70)
        action_counts = Counter(e.get("action") for e in events)
        for action, count in action_counts.most_common():
            print(f"  {action:<22} {count}")

        rule_counts = Counter(e.get("rule") for e in events if e.get("rule"))
        if rule_counts:
            print("\nRules triggered:")
            for rule, count in rule_counts.most_common():
                print(f"  {rule:<35} {count}")

        latencies = [e["latency_ms"] for e in events if isinstance(e.get("latency_ms"), (int, float))]
        if latencies:
            print(f"\nLatency: avg {sum(latencies)/len(latencies):.2f} ms, "
                  f"max {max(latencies):.2f} ms, n={len(latencies)}")
    else:
        print(f"\n(no {GATEWAY_LOG} found — make sure it's in this directory)")

    print("\n" + "=" * 70)
    print("SUGGESTED TABLE FOR YOUR REPORT")
    print("=" * 70)
    print("| Metric                        | Security OFF | Security ENFORCE |")
    print("|--------------------------------|---------------|-------------------|")
    print("| fill in from the per-run breakdown above |")


if __name__ == "__main__":
    summarize()
    '''
    >> $env:GATEWAY_ADMIN_KEY="choose-a-secret-key"
>> python defensive_gateway.py  



terminal (separate)
Invoke-RestMethod -Uri "http://127.0.0.1:8000/__gateway/stats" -Headers @{"X-Admin-Key"="choose-a-secret-key"}

'''