"""Rank evidence-grounded attack hypotheses from normalized events and a graph.

Usage: python hypothesis_engine.py rca_output/<scenario>
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


def build_hypotheses(events, graph):
    by_type = {}
    for event in events:
        by_type.setdefault(event["event_type"], []).append(event)
    edges = graph.get("edges", [])

    specs = [
        ("Valid account or remote-service access", {"authentication"}, "A successful authentication or remote access event exists.", ["successful authentication", "source IP and account context"]),
        ("Web-application workflow or script execution", {"web_activity", "web_access"}, "Application or web activity contains a suspicious workflow, upload, shell, or exploit action.", ["suspicious web activity", "server-side process evidence"]),
        ("Payload download and execution", {"process_activity", "proxy_request", "network_alert"}, "A process, proxy, or network event supports a payload transfer or execution chain.", ["download evidence", "process execution evidence", "payload hash"]),
        ("Command-and-control connection", {"network_alert"}, "Network security telemetry records suspicious external traffic.", ["network alert", "process-to-connection link"]),
        ("Clipboard data collection", {"process_activity"}, "A process command reads clipboard contents.", ["clipboard command evidence"]),
        ("DNS reconnaissance", {"dns_query"}, "A DNS reconnaissance burst or repeated suspicious DNS activity exists.", ["high-volume DNS burst", "queried domain context"]),
        ("Account or service persistence", {"persistence_change"}, "The host records a new account, cron entry, SSH key, or service change.", ["persistence event", "preceding access event"])
    ]
    results = []
    for name, types, reason, expected in specs:
        supporting = [e for e in events if e["event_type"] in types and (e.get("suspicious") or e.get("behavior"))]
        if name == "Payload download and execution":
            supporting = [e for e in events if e["event_id"] in {x["from"] for x in edges if x["relation"] == "downloaded_then_executed"} or e["event_id"] in {x["to"] for x in edges if x["relation"] == "downloaded_then_executed"}]
        if name == "Clipboard data collection":
            supporting = [e for e in events if e.get("behavior") == "clipboard_collection"]
        if not supporting:
            continue
        source_count = len({e["source"] for e in supporting})
        edge_count = sum(1 for edge in edges if edge["from"] in {e["event_id"] for e in supporting} or edge["to"] in {e["event_id"] for e in supporting})
        confidence = min(0.95, round(0.35 + 0.12 * source_count + 0.02 * min(edge_count, 10), 2))
        missing = [item for item in expected if not any(item.split()[0] in (e.get("summary", "") + " " + e["event_type"]).lower() for e in supporting)]
        results.append({"name": name, "confidence": confidence, "reason": reason,
                        "supporting_event_ids": [e["event_id"] for e in supporting[:20]],
                        "supporting_sources": sorted({e["source"] for e in supporting}),
                        "missing_evidence": missing})
    return sorted(results, key=lambda item: item["confidence"], reverse=True)


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python hypothesis_engine.py <output-folder>")
    folder = Path(sys.argv[1])
    event_path, graph_path = folder / "normalized_events.jsonl", folder / "investigation_graph.json"
    if not event_path.exists() or not graph_path.exists():
        raise SystemExit("Run rca_engine.py and correlation_engine.py for this scenario first.")
    events = [json.loads(line) for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    hypotheses = build_hypotheses(events, graph)
    event_by_id = {event["event_id"]: event for event in events}
    candidates = [event_by_id[event_id] for item in hypotheses for event_id in item["supporting_event_ids"] if event_id in event_by_id]
    candidates.sort(key=lambda event: datetime.fromisoformat(event["timestamp"]) if "T" in event["timestamp"] else datetime.max)
    result = {"scenario_id": events[0].get("scenario_id") if events else None,
              "generator": "evidence-grounded deterministic baseline; LLM can refine these hypotheses",
              "ranked_hypotheses": hypotheses,
              "likely_root_cause_event_id": candidates[0]["event_id"] if candidates else None}
    (folder / "hypotheses.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    prompt = {"task": "Review the ranked hypotheses, generate alternatives, and return only hypotheses supported by supplied event IDs.",
              "scenario_id": result["scenario_id"], "events": [{"event_id": e["event_id"], "timestamp": e["timestamp"], "type": e["event_type"], "summary": e["summary"], "source": e["source"], "command": e.get("command"), "behavior": e.get("behavior"), "technique_id": e.get("technique_id"), "technique_name": e.get("technique_name"), "tactic": e.get("tactic"), "user_name": e.get("user_name")} for e in events if e.get("suspicious")][:100],
              "edges": [{key: edge[key] for key in ("from", "to", "relation", "confidence") if key in edge}
                        for edge in graph.get("edges", [])[:200]], "baseline_hypotheses": hypotheses}
    (folder / "hypothesis_prompt.json").write_text(json.dumps(prompt, indent=2), encoding="utf-8")
    print(f"Wrote {len(hypotheses)} ranked hypotheses to {folder / 'hypotheses.json'}")
    assert all(item["supporting_event_ids"] for item in hypotheses)


if __name__ == "__main__": main()
