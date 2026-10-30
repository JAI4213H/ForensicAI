"""Evidence-first RCA normalizer for a CAM-LDS scenario folder.

Usage: python rca_engine.py manifestations_filtered/sequences/<scenario>
Attacker-side files are deliberately excluded: they are evaluation labels, not defender telemetry.
"""
from __future__ import annotations

import json
import hashlib
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


def evt(ts, kind, source, summary, **data):
    return {"timestamp": ts, "event_type": kind, "source": source, "summary": summary, **data}


def iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat()


def parse_json_lines(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "rule" in row and "timestamp" in row:  # Wazuh alert
            rule, agent = row["rule"], row.get("agent", {})
            mitre = rule.get("mitre", {})
            events.append(evt(iso(row["timestamp"]), "security_alert", "wazuh.alerts.json", rule.get("description", "Wazuh alert"),
                host=agent.get("name"), host_ip=agent.get("ip"), severity=rule.get("level", 0),
                mitre_ids=mitre.get("id", []), mitre_techniques=mitre.get("technique", []),
                src_ip=row.get("data", {}).get("srcip"), user=row.get("data", {}).get("dstuser"),
                raw=row.get("full_log"), suspicious=rule.get("level", 0) >= 3))
        elif "time" in row and "message" in row:  # Nextcloud application / audit logs
            message = row.get("message", "")
            lower = message.lower()
            login = "login successful" in lower or "login attempt" in lower
            risky = any(x in lower for x in ("run script", "curl ", "chmod ", "workflow", "executing sh"))
            if login or risky:
                source = "nextcloud_app_audit.log" if path.name == "audit.log" else "nextcloud.log"
                events.append(evt(iso(row["time"]), "authentication" if login else "web_activity", source, message,
                    host=row.get("host") or row.get("hostname") or path.parent.name, user=row.get("user"), src_ip=row.get("remoteAddr"), url=row.get("url"),
                    request_id=row.get("reqId"), outcome="success" if "successful" in lower else "attempt" if login else None,
                    suspicious=risky or "successful" in lower))
        elif "log" in row and "time" in row:  # Docker JSON container log
            events.extend(parse_access_line(row.get("log", ""), iso(row["time"]), path.name))
    return events


def parse_audit(path, year):
    records = defaultdict(list)
    # Audit records can contain ASCII group separators; split only physical lines.
    for line in path.read_text(encoding="utf-8", errors="replace").split("\n"):
        match = re.search(r'audit\((\d+\.\d+):(\d+)\)', line)
        if match:
            records[(match.group(1), match.group(2))].append(line)

    events = []
    for (epoch, _serial), lines in records.items():
        syscall = next((line for line in lines if line.startswith("type=SYSCALL")), "")
        if not syscall:
            continue
        data = dict(re.findall(r'(comm|exe|uid|pid|ppid|key)="?([^\s"]+)', syscall))
        if not data:
            continue
        args = dict((int(index), value) for index, value in re.findall(r'\ba(\d+)="([^"]*)"', "\n".join(lines)))
        command = " ".join(args[index] for index in sorted(args))
        if not command:
            title = next((re.search(r'proctitle=([0-9a-fA-F]+)', line) for line in lines if "proctitle=" in line), None)
            if title:
                try:
                    command = bytes.fromhex(title.group(1)).decode(errors="replace").replace("\x00", " ").strip()
                except ValueError:
                    pass
        process = data.get("comm", "process")
        lower_command = command.lower()
        clipboard = process.lower() in {"xclip", "xsel", "wl-paste", "pbpaste"} and "clipboard" in lower_command
        user_name = re.search(r'\bAUID="([^"]+)"', syscall)
        behavior = "clipboard_collection" if clipboard else None
        summary = f'{command or process} executed ({data.get("key", "unclassified")})'
        events.append(evt(datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(), "process_activity", "linux.audit.log",
            summary, process=process, command=command or None, executable=data.get("exe"),
            user=data.get("uid"), user_name=user_name.group(1) if user_name else None,
            pid=data.get("pid"), parent_pid=data.get("ppid"), rule_key=data.get("key"), behavior=behavior,
            technique_id="T1115" if clipboard else None, technique_name="Clipboard Data" if clipboard else None,
            tactic="Collection" if clipboard else None,
            suspicious=clipboard or process in {"curl", "wget", "chmod", "nc", "ncat", "bash", "sh", "python", "perl"}))
    return events


FLOW = re.compile(r"\{\w+\}\s+(\S+):(\d+)\s+->\s+(\S+):(\d+)$")


def parse_suricata(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        time_match, flow_match = re.match(r"^(\d\d/\d\d/\d{4}-[\d:.]+)", line), FLOW.search(line)
        if not time_match or not flow_match:
            continue
        src_ip, src_port, dst_ip, dst_port = flow_match.groups()
        signature = line.split("] ", 2)[-1].split(" [**]", 1)[0]
        ts = datetime.strptime(time_match.group(1), "%m/%d/%Y-%H:%M:%S.%f").replace(tzinfo=timezone.utc).isoformat()
        events.append(evt(ts, "network_alert", "suricata.fast.log", signature, src_ip=src_ip, src_port=int(src_port),
            dst_ip=dst_ip, dst_port=int(dst_port), suspicious=True))
    return events


def parse_access_line(line, timestamp, source):
    match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+.*?\"(GET|POST|PUT|DELETE)\s+(\S+).*?\"\s+(\d{3})", line)
    if not match:
        return []
    ip, method, url, status = match.groups()
    risky = method == "DELETE" or any(x in url.lower() for x in ("workflow", "shell", "upload"))
    return [evt(timestamp, "web_access", source, f"{method} {url} -> {status}", src_ip=ip, method=method, url=url,
                status=int(status), suspicious=risky)]


def parse_apache(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r'^(\S+) .*?\[([^\]]+)\] "(GET|POST|PUT|DELETE) (\S+).*?" (\d{3})', line)
        if not match:
            continue
        ip, stamp, method, url, status = match.groups()
        try: ts = datetime.strptime(stamp, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
        except ValueError: continue
        risky = method in {"POST", "PUT", "DELETE"} or any(x in url.lower() for x in ("upload", "shell", "exploit"))
        events.append(evt(ts, "web_access", "apache.access.log", f"{method} {url} -> {status}", src_ip=ip,
            method=method, url=url, status=int(status), suspicious=risky))
    return events


def parse_squid(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        try: ts = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%dT%H:%M:%S.%f %z").astimezone(timezone.utc).isoformat()
        except ValueError: continue
        method, url, mime = parts[5], parts[6], parts[-1]
        direct = next((part.split("/", 1)[1] for part in parts if part.startswith("HIER_DIRECT/")), None)
        executable = "executable" in mime.lower()
        events.append(evt(ts, "proxy_request", "squid.access.log", f"{method} {url} ({mime})", src_ip=parts[2],
            url=url, dst_ip=direct, mime_type=mime, suspicious=executable))
    return events


def parse_auth_or_syslog(path, year):
    events = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"^(\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+(\S+)", line)
        if not match:
            continue
        if year is None:
            ts = f"unknown-year {match.group(1)}"
        else:
            try:
                ts = datetime.strptime(f"{year} {match.group(1)}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc).isoformat()
            except ValueError:
                continue
        if "dnsmasq" in line and ("auth[" in line or "query[" in line):
            domain = (re.search(r"(?:auth|query)\[[A-Z]+\]\s+(\S+)", line) or [None, None])[1]
            src_ip = (re.search(r"from (\d+\.\d+\.\d+\.\d+)", line) or [None, None])[1]
            events.append(evt(ts, "dns_query", "dns.syslog", f"DNS query for {domain}", host=match.group(2),
                src_ip=src_ip, domain=domain, suspicious=False))
            continue
        persistence = any(x in line.lower() for x in ("crontab", " cron[", "authorized_keys", "useradd", "adduser", "usermod", "/etc/systemd/system"))
        if persistence:
            events.append(evt(ts, "persistence_change", path.name, line.strip(), host=match.group(2), suspicious=True))
            continue
        if not any(x in line for x in ("Accepted ", "Failed password", "session opened", "sudo:")):
            continue
        src_ip = (re.search(r"from (\d+\.\d+\.\d+\.\d+)", line) or [None, None])[1]
        user = (re.search(r"for (?:invalid user )?([^\s(]+)", line) or [None, None])[1]
        success = "Accepted " in line or "session opened" in line
        events.append(evt(ts, "authentication", path.name, line.strip(), host=match.group(2), src_ip=src_ip, user=user,
            outcome="success" if success else "failure", suspicious=success and src_ip is not None))
    return events


def parse_path(path, root, year):
    rel = path.relative_to(root).as_posix()
    if "/attacker/" in f"/{rel}":
        return []
    lower = path.name.lower()
    if lower == "alerts.json" or lower == "nextcloud.log" or lower.endswith("-json.log") or (lower == "audit.log" and "nclog" in rel):
        return parse_json_lines(path, year)
    if lower == "audit.log": return parse_audit(path, year)
    if lower == "fast.log": return parse_suricata(path, year)
    if "squid/access.log" in rel: return parse_squid(path, year)
    if "/apache2/access.log" in rel or lower.startswith("access.log"): return parse_apache(path, year)
    if lower in {"auth.log", "syslog", "daemon.log", "messages", "kern.log"}: return parse_auth_or_syslog(path, year)
    if "access.log" in lower:  # Apache access logs with a syslog timestamp are not guaranteed; leave raw ones for a later parser.
        return []
    return []


def sort_key(event):
    try: return datetime.fromisoformat(event["timestamp"])
    except ValueError: return datetime.max.replace(tzinfo=timezone.utc)


def attach_provenance(path, root, scenario, events):
    """Attach stable identity and the closest original source line to each event."""
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    cursor = 0
    relative = path.relative_to(root).as_posix()
    for item in events:
        process = item.get("process")
        rule = item.get("rule_key")
        summary = item.get("summary", "")
        needles = [summary[:80]] if summary else []
        if ", config:" in summary:
            needles.insert(0, summary.split(", config:", 1)[0])
        if process: needles.append(f'comm="{process}"')
        if rule: needles.append(f'key="{rule}"')
        weak_needles = [x for x in (item.get("url"), item.get("domain")) if x]
        line_no, raw = None, item.get("summary", "")
        for index in range(cursor, len(lines)):
            if any(needle and needle in lines[index] for needle in needles):
                line_no, raw, cursor = index + 1, lines[index], index + 1
                break
        if line_no is None:
            for index in range(cursor, len(lines)):
                if any(needle in lines[index] for needle in weak_needles):
                    line_no, raw, cursor = index + 1, lines[index], index + 1
                    break
        identity = f"{scenario}|{relative}|{line_no}|{item.get('timestamp')}|{item.get('summary')}"
        item.update(event_id=hashlib.sha1(identity.encode()).hexdigest()[:16], scenario_id=scenario,
                    source_file=relative, source_line=line_no, raw_event=raw)
    return events


def infer_year(root):
    """Use only defender telemetry; old syslog lines do not contain a year."""
    for path in root.rglob("alerts.json"):
        try:
            return datetime.fromisoformat(json.loads(path.read_text(encoding="utf-8").splitlines()[0])["timestamp"].replace("Z", "+00:00")).year
        except (IndexError, KeyError, ValueError, json.JSONDecodeError):
            pass
    return None


def annotate_dns_bursts(events):
    groups = defaultdict(list)
    for item in events:
        if item["event_type"] == "dns_query":
            groups[(item.get("src_ip"), item["timestamp"])].append(item)
    bursts = []
    for (src_ip, timestamp), items in groups.items():
        unique_domains = {item.get("domain") for item in items if item.get("domain")}
        if len(unique_domains) >= 20:
            burst = {"src_ip": src_ip, "timestamp": timestamp, "event_count": len(items), "unique_domains": len(unique_domains)}
            bursts.append(burst)
            for item in items:
                item.update(suspicious=True, behavior="dns_reconnaissance", burst_event_count=len(items),
                            burst_unique_domains=len(unique_domains))
    return bursts


def analyse(events):
    sources = Counter(e["source"] for e in events)
    suspicious = [e for e in events if e.get("suspicious")]
    auth = [e for e in events if e["event_type"] == "authentication" and e.get("outcome") == "success"]
    web = [e for e in events if e["event_type"] in {"web_activity", "web_access"} and e.get("suspicious")]
    processes = [e for e in events if e["event_type"] == "process_activity" and e.get("suspicious")]
    network = [e for e in events if e["event_type"] == "network_alert"]
    persistence = [e for e in events if e["event_type"] == "persistence_change"]
    dns_bursts = [e for e in events if e.get("behavior") == "dns_reconnaissance"]
    hypotheses = []
    if auth: hypotheses.append("valid-account or remote-service access")
    if web: hypotheses.append("web-application workflow or script execution")
    if processes: hypotheses.append("post-access command execution")
    if persistence: hypotheses.append("account creation or persistence change")
    if dns_bursts: hypotheses.append("DNS reconnaissance burst")
    if network: hypotheses.append("suspicious network transfer or command-and-control")
    confidence = min(95, 30 + 15 * len({e["source"] for e in suspicious}) + 10 * bool(auth) + 10 * bool(processes) + 10 * bool(persistence))
    ips = Counter(x for e in events for x in (e.get("src_ip"), e.get("dst_ip")) if x)
    return {"confidence": confidence, "hypotheses": hypotheses or ["insufficient correlated suspicious evidence"],
            "sources": sources, "top_ips": ips.most_common(5), "auth": auth, "web": web, "processes": processes, "persistence": persistence, "network": network, "dns_bursts": dns_bursts}


def compact_timeline(events):
    rows, seen_bursts = [], set()
    for item in events:
        if item.get("behavior") == "dns_reconnaissance":
            key = (item.get("src_ip"), item["timestamp"])
            if key not in seen_bursts:
                seen_bursts.add(key)
                rows.append(f"- `{item['timestamp']}` — **dns_reconnaissance** — {item.get('src_ip')} queried {item['burst_unique_domains']} unique domains in {item['burst_event_count']} DNS requests")
            continue
        rows.append(f"- `{item['timestamp']}` — **{item['event_type']}** — {item['summary']}")
    return rows


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python rca_engine.py <scenario-folder>")
    root = Path(sys.argv[1])
    if not root.is_dir(): raise SystemExit(f"Scenario folder not found: {root}")
    year = infer_year(root)
    events = []
    for path in root.rglob("*"):
        if path.is_file():
            parsed = parse_path(path, root, year)
            events.extend(attach_provenance(path, root, root.name, parsed))
    events.sort(key=sort_key)
    dns_bursts = annotate_dns_bursts(events)
    result = analyse(events)
    out = Path("rca_output") / root.name
    out.mkdir(parents=True, exist_ok=True)
    (out / "normalized_events.jsonl").write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    source_rows = "\n".join(f"- {source}: {count} events" for source, count in result["sources"].most_common())
    hypotheses = "\n".join(f"- {item}" for item in result["hypotheses"])
    timeline_rows = compact_timeline(events)
    behavior_rows = "\n".join(f"- {b['src_ip']} queried {b['unique_domains']} unique domains in {b['event_count']} requests at {b['timestamp']}" for b in dns_bursts) or "- None"
    report = f"# RCA report: {root.name}\n\n## Candidate explanations\n\n{hypotheses}\n\nConfidence: **{result['confidence']}%**\n\n## Derived behaviors\n\n{behavior_rows}\n\n## Parsed evidence sources\n\n{source_rows}\n\n## Timeline ({len(events)} stored events; {len(timeline_rows)} report rows)\n\n" + "\n".join(timeline_rows) + "\n"
    (out / "rca_report.md").write_text(report, encoding="utf-8")
    print(f"Parsed {len(events)} defender-visible events into {out.resolve()}")
    assert not any("attacker" in e["source"] for e in events), "attacker labels must be excluded"
    assert events or not list(root.rglob("*.log")), "expected telemetry to produce events"


if __name__ == "__main__": main()
