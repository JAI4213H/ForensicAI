"""Build an explainable entity and event graph from normalized events."""
from __future__ import annotations

import json
import argparse
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def time_of(item):
    try:
        return datetime.fromisoformat(item["timestamp"])
    except (KeyError, ValueError):
        return None


def correlate(events):
    nodes, node_ids, edges, seen = [], set(), [], set()

    def add_node(node):
        if node["id"] not in node_ids:
            node_ids.add(node["id"])
            nodes.append(node)

    def add_edge(source, target, relation, reason, confidence, evidence=None):
        key = (source, target, relation)
        if key in seen or source == target:
            return
        seen.add(key)
        edges.append({"from": source, "to": target, "relation": relation, "reason": reason,
                      "confidence": confidence, "evidence": evidence or []})

    def event_link(a, b, relation, reason, confidence):
        add_edge(a["event_id"], b["event_id"], relation, reason, confidence,
                 [{"file": a.get("source_file"), "line": a.get("source_line")},
                  {"file": b.get("source_file"), "line": b.get("source_line")}])

    for event in events:
        add_node({"id": event["event_id"], "node_type": "event", "timestamp": event["timestamp"],
                  "event_type": event["event_type"], "source": event["source"], "summary": event["summary"],
                  "source_file": event.get("source_file"), "source_line": event.get("source_line")})
        values = [("host", event.get("host")), ("user", event.get("user")),
                  ("source_ip", event.get("src_ip")), ("destination_ip", event.get("dst_ip")),
                  ("process", event.get("process")), ("request_id", event.get("request_id")),
                  ("domain", event.get("domain"))]
        if event.get("executable"):
            values.append(("file", Path(event["executable"]).name))
        if event.get("url"):
            domain = urlparse(event["url"]).hostname
            if domain:
                values.append(("domain", domain))
        for kind, value in values:
            if not value or value in {"--", "unknown", "None"}:
                continue
            entity_id = f"entity:{kind}:{value}"
            add_node({"id": entity_id, "node_type": "entity", "entity_type": kind, "value": value})
            add_edge(event["event_id"], entity_id, f"observed_{kind}", f"Event contains {kind} {value}.", 1.0,
                     [{"file": event.get("source_file"), "line": event.get("source_line")}])

    def adjacent_by(field, relation, reason, confidence, window=120):
        groups = {}
        for event in events:
            value = event.get(field)
            if value:
                groups.setdefault(value, []).append(event)
        for group in groups.values():
            group.sort(key=lambda e: time_of(e) or datetime.max)
            for a, b in zip(group, group[1:]):
                ta, tb = time_of(a), time_of(b)
                if ta and tb and 0 <= (tb - ta).total_seconds() <= window:
                    event_link(a, b, relation, reason, confidence)

    # Exact request identity is strong. Broad same-user/IP edges are omitted to reduce noise.
    adjacent_by("request_id", "same_web_request", "Both events share the same request ID.", 0.98)

    for a in events:
        if a["event_type"] not in {"web_activity", "web_access", "proxy_request"}:
            continue
        text = f"{a.get('summary', '')} {a.get('raw_event', '')}"
        for b in events:
            if b["event_type"] != "process_activity" or not b.get("process"):
                continue
            ta, tb = time_of(a), time_of(b)
            if ta and tb and 0 <= (tb - ta).total_seconds() <= 120 and b["process"] in text:
                event_link(a, b, "downloaded_then_executed", f"Application evidence contains process {b['process']}.", 0.90)

    for a in events:
        if a["event_type"] != "authentication" or a.get("outcome") != "success":
            continue
        ta = time_of(a)
        for b in events:
            tb = time_of(b)
            if not ta or not tb or b is a or b["event_type"] not in {"web_activity", "process_activity", "persistence_change"}:
                continue
            if 0 <= (tb - ta).total_seconds() <= 300 and a.get("host") == b.get("host"):
                relation = "created_persistence" if b["event_type"] == "persistence_change" else "logged_in_then_acted"
                event_link(a, b, relation, "Successful authentication precedes related activity on the same host.", 0.82)

    return {"nodes": nodes, "edges": edges, "summary": {"event_count": len(events), "node_count": len(nodes), "edge_count": len(edges)}}


def compact_graph(graph):
    """Keep fields consumed by hypothesis/correlation consumers; evidence stays in normalized_events.jsonl."""
    nodes = []
    for node in graph["nodes"]:
        keys = ("id", "node_type", "timestamp", "event_type", "source", "summary") if node.get("node_type") == "event" else ("id", "node_type", "entity_type", "value")
        nodes.append({key: node[key] for key in keys if key in node})
    return {"nodes": nodes,
            "edges": [{key: edge[key] for key in ("from", "to", "relation", "confidence") if key in edge}
                      for edge in graph["edges"]],
            "summary": graph["summary"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="Normalized events file or scenario output folder")
    parser.add_argument("--full", action="store_true", help="Also write the detailed graph with edge reasons/evidence")
    args = parser.parse_args()
    source = Path(args.source)
    event_file = source / "normalized_events.jsonl" if source.is_dir() else source
    if not event_file.exists():
        raise SystemExit(f"Normalized event file not found: {event_file}")
    events = [json.loads(line) for line in event_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    graph = correlate(events)
    scenario_id = events[0].get("scenario_id") if events else None
    output = event_file.parent / "investigation_graph.json"
    output.write_text(json.dumps({"scenario_id": scenario_id, **compact_graph(graph)}, indent=2), encoding="utf-8")
    if args.full:
        full_output = event_file.parent / "investigation_graph_full.json"
        full_output.write_text(json.dumps({"scenario_id": scenario_id, **graph}, indent=2), encoding="utf-8")
        print(f"Wrote detailed graph to {full_output}")
    print(f"Wrote compact graph ({graph['summary']['node_count']} nodes, {graph['summary']['edge_count']} edges) to {output}")
    assert all(edge["from"] in {node["id"] for node in graph["nodes"]} and edge["to"] in {node["id"] for node in graph["nodes"]} for edge in graph["edges"])


if __name__ == "__main__": main()
