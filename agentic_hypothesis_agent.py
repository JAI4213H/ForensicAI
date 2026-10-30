"""Chunked Groq agent for evidence-grounded hypothesis generation.

The API key is read from GROQ_API_KEY and is never written to disk.
Usage: $env:GROQ_API_KEY = '...'; python agentic_hypothesis_agent.py rca_output/7-6
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


MODEL = "openai/gpt-oss-120b"
API_URL = "https://api.groq.com/openai/v1/chat/completions"


def chunks(items, max_chars):
    result, current, size = [], [], 0
    for item in items:
        encoded = json.dumps(item, ensure_ascii=False)
        if current and size + len(encoded) > max_chars:
            result.append(current)
            current, size = [], 0
        current.append(item)
        size += len(encoded)
    if current:
        result.append(current)
    return result


def ask_groq(api_key, system, user, max_output_tokens=600):
    body = {"model": MODEL, "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.1, "max_tokens": max_output_tokens, "reasoning_effort": "low",
            "response_format": {"type": "json_object"}}
    request = urllib.request.Request(API_URL, data=json.dumps(body).encode(), headers={
        "Authorization": f"Bearer {api_key}", "Content-Type": "application/json", "User-Agent": "cam-lds-rca/1.0"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                payload = json.loads(response.read().decode())
            break
        except urllib.error.HTTPError as error:
            detail = error.read().decode(errors="replace")
            if error.code == 429:
                wait_match = re.search(r"try again in ([0-9.]+)s", detail, re.IGNORECASE)
                wait_seconds = float(wait_match.group(1)) + 1.0 if wait_match else min(10 * (attempt + 1), 60)
                if attempt == 5:
                    raise RuntimeError(f"Groq rate limit persisted after retries: {detail}") from error
                print(f"Groq rate limit; waiting {wait_seconds:.1f}s before retry {attempt + 1}/5")
                time.sleep(wait_seconds)
                continue
            if error.code == 403:
                raise RuntimeError(f"Groq denied model access (HTTP 403). Check the Groq project/org model permissions for {MODEL} and the key's project. Server detail: {detail}") from error
            raise RuntimeError(f"Groq request failed: {detail}") from error
        except urllib.error.URLError as error:
            raise RuntimeError(f"Groq request failed: {error}") from error
    content = payload["choices"][0]["message"]["content"]
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"raw_model_output": content}


def make_chunk_payload(prompt, event_chunk):
    ids = {event["event_id"] for event in event_chunk}
    # Keep each request bounded; the full graph remains on disk for later inspection.
    edges = [edge for edge in prompt.get("edges", []) if edge.get("from") in ids or edge.get("to") in ids or edge.get("from_event") in ids or edge.get("to_event") in ids][:12]
    return {"scenario_id": prompt.get("scenario_id"), "events": event_chunk, "edges": edges,
            "baseline_hypotheses": prompt.get("baseline_hypotheses", [])}


def collect_event_ids(value, known_ids):
    found = set()
    if isinstance(value, dict):
        for child in value.values():
            found.update(collect_event_ids(child, known_ids))
    elif isinstance(value, list):
        for child in value:
            found.update(collect_event_ids(child, known_ids))
    elif isinstance(value, str) and value in known_ids:
        found.add(value)
    return found


def load_normalized_events(folder, fallback):
    """Load rich events for the story; fall back to the compact prompt events."""
    path = folder / "normalized_events.jsonl"
    if not path.exists():
        return fallback
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("event_id"):
            events.append(event)
    return events or fallback


def time_text(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime("%H:%M:%S")
    except (TypeError, ValueError):
        return str(value or "unknown time")


def event_text(event):
    return str(event.get("summary") or "").strip()


def extract_workflow_command(events):
    for event in events:
        summary = event_text(event)
        match = re.search(r"sh\s+-c\s+['\"](.+?)['\"]", summary)
        if match:
            return match.group(1), event
    for event in events:
        summary = event_text(event)
        if "curl" in summary and "chmod" in summary:
            return summary, event
    return "", None


def workflow_config_event(events):
    for event in events:
        summary = event_text(event)
        if "Flow rule qualified" in summary and "operation\":\"" in summary:
            match = re.search(r'operation\":\"(.+?)\",\"entity', summary)
            if match:
                return match.group(1), event
    return "", None


def build_attack_story(events, selected_ids=None):
    """Create a short, chronological, evidence-only incident narrative."""
    if selected_ids is not None:
        events = [event for event in events if event.get("event_id") in selected_ids]
    ordered = sorted(events, key=lambda item: str(item.get("timestamp") or ""))
    sentences = []
    used_ids = []

    def add(text, selected):
        if text:
            sentences.append(text)
            used_ids.extend(event.get("event_id") for event in selected if event.get("event_id"))

    login = next((event for event in ordered
                  if event.get("event_type") == "authentication"
                  and re.search(r"login\s+successful|authentication\s+success", event_text(event), re.I)), None)
    if login:
        actor = login.get("src_ip") or "an external source"
        user = login.get("user") or "an account"
        host = login.get("host") or "the monitored host"
        if str(host).lower() in {"nclog", "nextcloud"}:
            host = "the Nextcloud host"
        add(f"At {time_text(login.get('timestamp'))}, source IP {actor} successfully logged in to {host} as {user}.", [login])

    configured_command, configured = workflow_config_event(ordered)
    if configured:
        actor = re.search(r'scope_actor_id\":\"([^\"]+)', event_text(configured))
        user = actor.group(1) if actor else (login.get("user") if login else "the account")
        names = [name for name in ("curl", "chmod", "wget", "bash")
                 if re.search(rf"\b{re.escape(name)}\b", configured_command)]
        payloads = re.findall(r"\./([A-Za-z0-9_.-]+)", configured_command)
        names += [name for name in payloads if name not in names]
        names = list(dict.fromkeys(names))
        if names:
            name_text = ", ".join(names[:-1]) + (f", and execution of {names[-1]}" if len(names) > 1 else names[0])
            add(f"At {time_text(configured.get('timestamp'))}, {user} configured a Nextcloud workflow containing {name_text}.", [configured])

    command, workflow = extract_workflow_command(ordered)
    if workflow and not configured:
        commands = [name for name in ("curl", "wget", "chmod", "bash")
                    if re.search(rf"\b{re.escape(name)}\b", command)]
        payloads = re.findall(r"\./([A-Za-z0-9_.-]+)", command)
        names = commands + [name for name in payloads if name not in commands]
        names = list(dict.fromkeys(names))
        if names:
            name_text = ", ".join(names[:-1]) + (f", and {names[-1]}" if len(names) > 1 else names[0])
            add(f"At {time_text(workflow.get('timestamp'))}, a workflow ran {name_text}.", [workflow])
        else:
            add(f"At {time_text(workflow.get('timestamp'))}, a workflow executed a shell command.", [workflow])

    clipboard = next((event for event in ordered if event.get("behavior") == "clipboard_collection"), None)
    if clipboard:
        actor = clipboard.get("user_name") or clipboard.get("user") or "an account"
        command = clipboard.get("command") or clipboard.get("process") or "clipboard utility"
        technique = clipboard.get("technique_name") or "clipboard data collection"
        technique_id = clipboard.get("technique_id")
        tactic = clipboard.get("tactic")
        label = f"MITRE ATT&CK {technique_id} - {technique}" if technique_id else technique
        if tactic:
            label += f" ({tactic} tactic)"
        add(f"At {time_text(clipboard.get('timestamp'))}, Linux audit logs recorded {command} as user {actor} (PID {clipboard.get('pid')}), consistent with {label}.", [clipboard])

    process_events = [event for event in ordered
                      if event.get("event_type") == "process_activity"
                      and any(name in event_text(event).lower() for name in ("curl", "chmod", "rjzmo", "wget"))]
    if process_events:
        names = list(dict.fromkeys(event.get("process") or event_text(event).split(" executed", 1)[0]
                                  for event in process_events))
        names = [name for name in names if name]
        name_text = ", ".join(names[:-1]) + (f", and {names[-1]}" if len(names) > 1 else names[0])
        add(f"At {time_text(process_events[0].get('timestamp'))}, Linux audit logs confirmed {name_text} executed.", process_events)

    network = [event for event in ordered if event.get("event_type") == "network_alert"]
    if network:
        elf = next((event for event in network if "ELF" in event_text(event) or "executable" in event_text(event).lower()), network[0])
        port_4444 = any(str(event.get("dst_port")) == "4444" or ":4444" in event_text(event) for event in network)
        detail = "an executable transfer"
        if port_4444:
            detail += " and traffic involving port 4444"
        add(f"At {time_text(elf.get('timestamp'))}, Suricata detected {detail}.", network)

    if not sentences and ordered:
        # Audit/AVC logs often emit many records for one PID. Group them so
        # library loads are not mistaken for repeated process executions.
        groups = {}
        for event in ordered:
            key = (time_text(event.get("timestamp")), event.get("process"), event.get("user"), event.get("pid"))
            groups.setdefault(key, []).append(event)
        for (timestamp, process, user, pid), group in list(groups.items())[:8]:
            if process:
                detail = f"Linux audit logs recorded {process} activity"
                if user and str(user) not in {"--", "(null)"}:
                    detail += f" as user {user}"
                if pid:
                    detail += f" (PID {pid})"
                add(f"At {timestamp}, {detail}.", group)
            else:
                add(f"At {timestamp}, {event_text(group[0]) or group[0].get('event_type', 'an event')}.", group)
        if {event.get("event_type") for event in ordered} <= {"process_activity"}:
            add("The available telemetry contains only local process activity; it does not by itself confirm an attack.", [])
    return " ".join(sentences), list(dict.fromkeys(used_ids))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("folder", help="Scenario output folder containing hypothesis_prompt.json")
    parser.add_argument("--chunk-chars", type=int, default=2500, help="Approximate evidence size per LLM call; keep below the organization TPM limit")
    parser.add_argument("--delay-seconds", type=float, default=8.0, help="Delay between API calls for low TPM limits")
    parser.add_argument("--dry-run", action="store_true", help="Build chunks without calling Groq")
    args = parser.parse_args()
    folder = Path(args.folder)
    prompt_path = folder / "hypothesis_prompt.json"
    if not prompt_path.exists():
        raise SystemExit("Run hypothesis_engine.py first to create hypothesis_prompt.json.")
    prompt = json.loads(prompt_path.read_text(encoding="utf-8"))
    prompt_events = prompt.get("events", [])
    events = load_normalized_events(folder, prompt_events)
    if not prompt_events:
        prompt_events = [{key: event.get(key) for key in (
            "event_id", "timestamp", "event_type", "summary", "source", "user", "src_ip",
            "dst_ip", "dst_port", "process", "executable", "pid", "rule_key") if event.get(key) is not None}
                        for event in events]
    event_chunks = chunks(prompt_events, args.chunk_chars)
    if not event_chunks:
        event_chunks = [[]]
    payloads = [make_chunk_payload(prompt, event_chunk) for event_chunk in event_chunks]
    if args.dry_run:
        print(f"Prepared {len(payloads)} evidence chunks for model {MODEL}")
        return
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise SystemExit("Set GROQ_API_KEY in the environment; the key is never stored in this project.")
    system = "You are a cybersecurity investigation analyst. Generate only evidence-grounded hypotheses. Never invent evidence or identifiers. Return JSON with a hypotheses array; each item must have name, confidence, supporting_event_ids, contradicting_event_ids, missing_evidence, and explanation."
    last_call = [0.0]

    def call(user, output_tokens=600):
        wait = args.delay_seconds - (time.monotonic() - last_call[0])
        if wait > 0:
            time.sleep(wait)
        result = ask_groq(api_key, system, user, output_tokens)
        last_call[0] = time.monotonic()
        return result

    chunk_results = []
    for index, payload in enumerate(payloads, 1):
        result = call(f"Analyze evidence chunk {index}/{len(payloads)}. Keep the response concise.\n{json.dumps(payload, ensure_ascii=False)}")
        chunk_results.append({"chunk": index, "event_count": len(payload["events"]), "result": result})

    merged = []
    reduction_rounds = 0
    current = chunk_results
    reduction_limit = max(args.chunk_chars * 2, 6000)
    while len(json.dumps(current, ensure_ascii=False)) > reduction_limit:
        reduction_rounds += 1
        merged = []
        for batch in chunks(current, reduction_limit):
            merged.append(call("Merge these analyses without dropping event IDs. Keep the response concise and return JSON with a hypotheses array.\n" + json.dumps(batch, ensure_ascii=False), 1200))
        current = merged
    known_ids = {event["event_id"] for event in events}
    referenced_ids = collect_event_ids(current, known_ids)
    evidence_index = []
    for event in events:
        if event["event_id"] in referenced_ids:
            evidence_index.append({"event_id": event["event_id"], "timestamp": event["timestamp"],
                                   "event_type": event.get("event_type", event.get("type")), "summary": event.get("summary", "")[:500],
                                   "source": event.get("source"), "user": event.get("user"),
                                   "src_ip": event.get("src_ip"), "dst_ip": event.get("dst_ip"),
                                   "process": event.get("process"), "executable": event.get("executable"),
                                   "command": event.get("command"), "behavior": event.get("behavior"),
                                   "technique_id": event.get("technique_id"), "technique_name": event.get("technique_name"),
                                   "tactic": event.get("tactic"), "user_name": event.get("user_name"),
                                   "source_file": event.get("source_file"), "source_line": event.get("source_line")})
    final_input = {"merged_chunk_analyses": current, "evidence_index": evidence_index}
    final_instruction = "Produce the final ranked result as JSON with ranked_hypotheses, likely_root_cause_event_id, attack_summary, attack_story, and timeline. Write attack_story as 3-5 plain chronological sentences in this style: 'At HH:MM:SS, source IP ... logged in ... At HH:MM:SS, ... At HH:MM:SS, Linux audit logs confirmed ... At HH:MM:SS, Suricata detected ...'. Name the observed source IP, user, host, command or process, and consequence when those facts exist. Every factual claim must be supported by an event_id in evidence_index; do not invent IPs, users, commands, or outcomes. If the evidence is only routine local process or library activity, say that it does not establish an attack instead of calling it malicious."
    final = call(final_instruction + "\n" + json.dumps(final_input, ensure_ascii=False), 1200)
    if not isinstance(final, dict):
        final = {"ranked_hypotheses": [], "raw_model_output": str(final)}
    final_evidence = {key: value for key, value in final.items()
                      if key not in {"attack_story", "attack_story_event_ids", "story_format"}}
    final_event_ids = collect_event_ids(final_evidence, known_ids)
    story_source_ids = final_event_ids or referenced_ids
    if story_source_ids:
        story, story_event_ids = build_attack_story(events, story_source_ids)
    else:
        story, story_event_ids = ("No evidence-linked event IDs were returned; an attack story cannot be established from this result.", [])
    # Keep the model's hypotheses, but enforce a stable evidence-derived story format.
    final["attack_story"] = story
    final["attack_story_event_ids"] = story_event_ids
    final["story_format"] = "chronological evidence narrative"
    output = {"scenario_id": prompt.get("scenario_id"), "model": MODEL, "chunk_chars": args.chunk_chars,
              "chunk_count": len(payloads), "reduction_rounds": reduction_rounds, "chunk_results": chunk_results, "merged_results": current if reduction_rounds else [], "final_result": final}
    path = folder / "agentic_hypotheses.json"
    path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")
    (folder / "attack_story.txt").write_text(story + "\n", encoding="utf-8")
    print(f"Processed {len(payloads)} evidence chunks and wrote {path}")
    print(f"\nAttack story:\n{story}")


if __name__ == "__main__": main()
