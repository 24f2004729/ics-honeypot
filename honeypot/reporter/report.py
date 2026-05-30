# =============================================================================
#  ics_honeypot / reporter / report.py
#  ---------------------------------------------------------------------------
#  HTML Report Generator
#  ---------------------------------------------------------------------------
#  Reads events.jsonl and produces a self-contained HTML report showing:
#    • Summary statistics (total events, unique attackers, protocols)
#    • Severity breakdown (Critical / High / Medium)
#    • Per-attacker activity timeline
#    • Top targeted protocols
#    • Raw event table (filterable by protocol)
#
#  The report is completely self-contained (no external CSS/JS dependencies)
#  so it can be emailed, archived, or shared without any additional files.
#
#  Usage:
#      from honeypot.reporter.report import generate_report
#      generate_report()   # reads events.jsonl, writes report.html
# =============================================================================

import json
import os
import datetime
from collections import defaultdict, Counter

from honeypot.shared.config import EVENT_FILE, REPORT_FILE


# =============================================================================
#  Data loading and aggregation
# =============================================================================

def _load_events() -> list[dict]:
    """
    Read all JSON objects from events.jsonl.
    Silently skips malformed lines so a corrupt log doesn't break the report.
    """
    events = []
    if not os.path.exists(EVENT_FILE):
        return events
    with open(EVENT_FILE, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass   # skip malformed line
    return events


def _compute_stats(events: list[dict]) -> dict:
    """
    Aggregate raw events into summary statistics for the dashboard.
    Returns a dict of metrics used in report rendering.
    """
    if not events:
        return {}

    # Filter to attack events only for severity analysis
    attacks = [e for e in events if e.get("event") == "attack"]

    # Count unique source IPs
    unique_ips = set(e.get("src_ip", "") for e in events)

    # Protocol breakdown
    proto_counter = Counter(e.get("protocol", "UNKNOWN") for e in attacks)

    # Severity breakdown — inferred from action field keywords
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for e in attacks:
        action = e.get("action", "").upper()
        sev    = e.get("severity", "")
        if "CRITICAL" in action or sev == "CRITICAL":
            severity_counts["CRITICAL"] += 1
        elif "HIGH" in action or sev == "HIGH":
            severity_counts["HIGH"] += 1
        elif "WRITE" in action or "OPERATE" in action:
            severity_counts["HIGH"] += 1
        elif "CONNECT" in action and ("password" in e or "username" in e):
            severity_counts["HIGH"] += 1
        else:
            severity_counts["MEDIUM"] += 1

    # Per-IP event counts
    ip_counts = Counter(e.get("src_ip", "") for e in attacks)

    # Most targeted actions
    action_counts = Counter(e.get("action", "unknown") for e in attacks)

    # Time range
    timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
    first_seen = min(timestamps) if timestamps else "N/A"
    last_seen  = max(timestamps) if timestamps else "N/A"

    return {
        "total_events":      len(events),
        "total_attacks":     len(attacks),
        "unique_ips":        len(unique_ips),
        "protocols":         dict(proto_counter),
        "severity":          severity_counts,
        "top_ips":           ip_counts.most_common(10),
        "top_actions":       action_counts.most_common(10),
        "first_seen":        first_seen,
        "last_seen":         last_seen,
        "ip_list":           sorted(unique_ips)
    }


# =============================================================================
#  HTML generation helpers
# =============================================================================

def _severity_badge(action: str, event_data: dict) -> str:
    """Return a coloured HTML badge for severity level."""
    action_up = action.upper()
    sev = event_data.get("severity", "")
    if "CRITICAL" in action_up or sev == "CRITICAL":
        return '<span class="badge critical">CRITICAL</span>'
    elif "HIGH" in action_up or sev == "HIGH" or "WRITE" in action_up or "OPERATE" in action_up:
        return '<span class="badge high">HIGH</span>'
    elif "CONNECT" in action_up:
        return '<span class="badge medium">MEDIUM</span>'
    else:
        return '<span class="badge low">LOW</span>'


def _proto_badge(proto: str) -> str:
    colours = {"MODBUS": "#3B82F6", "DNP3": "#8B5CF6", "MQTT": "#10B981"}
    colour  = colours.get(proto.upper(), "#6B7280")
    return f'<span class="proto-badge" style="background:{colour}">{proto}</span>'


def _escape(text: str) -> str:
    """Minimal HTML escaping to prevent XSS in attacker-controlled strings."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


# =============================================================================
#  Main report generator
# =============================================================================

def generate_report():
    """
    Entry point.  Loads events.jsonl, computes statistics, and writes report.html.
    Prints the output path on success.
    """
    events = _load_events()
    stats  = _compute_stats(events)

    # Format timestamps for display
    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    html = _render_html(events, stats, generated_at)

    os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
    with open(REPORT_FILE, "w", encoding="utf-8") as fh:
        fh.write(html)

    print(f"[Reporter] Report written to: {REPORT_FILE}")
    return REPORT_FILE


def _render_html(events: list[dict], stats: dict, generated_at: str) -> str:
    """Build and return the complete HTML report as a string."""

    # ------------------------------------------------------------------
    # Summary cards
    # ------------------------------------------------------------------
    total_events  = stats.get("total_events",  0)
    total_attacks = stats.get("total_attacks", 0)
    unique_ips    = stats.get("unique_ips",    0)
    severity      = stats.get("severity",      {})
    protocols     = stats.get("protocols",     {})

    cards_html = f"""
    <div class="cards">
      <div class="card"><div class="card-val">{total_events}</div><div class="card-label">Total Events</div></div>
      <div class="card"><div class="card-val">{total_attacks}</div><div class="card-label">Attack Events</div></div>
      <div class="card"><div class="card-val">{unique_ips}</div><div class="card-label">Unique Attackers</div></div>
      <div class="card critical-card"><div class="card-val">{severity.get("CRITICAL", 0)}</div><div class="card-label">Critical Events</div></div>
      <div class="card high-card"><div class="card-val">{severity.get("HIGH", 0)}</div><div class="card-label">High Severity</div></div>
    </div>
    """

    # ------------------------------------------------------------------
    # Protocol breakdown table
    # ------------------------------------------------------------------
    proto_rows = "".join(
        f"<tr><td>{_proto_badge(p)}</td><td>{c}</td></tr>"
        for p, c in sorted(protocols.items(), key=lambda x: -x[1])
    )

    # ------------------------------------------------------------------
    # Top attackers table
    # ------------------------------------------------------------------
    top_ip_rows = "".join(
        f"<tr><td><code>{_escape(ip)}</code></td><td>{count}</td></tr>"
        for ip, count in stats.get("top_ips", [])
    )

    # ------------------------------------------------------------------
    # Top actions table
    # ------------------------------------------------------------------
    top_action_rows = "".join(
        f"<tr><td><code>{_escape(action)}</code></td><td>{count}</td></tr>"
        for action, count in stats.get("top_actions", [])
    )

    # ------------------------------------------------------------------
    # Event log table — only attack events, most recent first
    # ------------------------------------------------------------------
    attack_events = [e for e in events if e.get("event") == "attack"]
    attack_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    event_rows = ""
    for e in attack_events[:500]:   # cap at 500 rows for browser performance
        ts      = _escape(e.get("timestamp", "")[:19].replace("T", " "))
        proto   = _proto_badge(e.get("protocol", "?"))
        src_ip  = _escape(e.get("src_ip",  "?"))
        src_port= _escape(str(e.get("src_port", "?")))
        action  = _escape(e.get("action",  "?"))
        badge   = _severity_badge(e.get("action", ""), e)
        raw_hex = _escape(e.get("raw_hex", "")[:40])

        event_rows += f"""
        <tr>
          <td>{ts}</td>
          <td>{proto}</td>
          <td><code>{src_ip}:{src_port}</code></td>
          <td><code>{action}</code></td>
          <td>{badge}</td>
          <td><code style="font-size:11px">{raw_hex}</code></td>
        </tr>"""

    # ------------------------------------------------------------------
    # Full HTML document
    # ------------------------------------------------------------------
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ICS Honeypot — Threat Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0F172A; color: #E2E8F0; padding: 24px; }}
  h1   {{ font-size: 1.6rem; color: #F1F5F9; margin-bottom: 4px; }}
  h2   {{ font-size: 1.1rem; color: #94A3B8; margin: 28px 0 12px; border-bottom: 1px solid #1E293B; padding-bottom: 8px; }}
  .subtitle {{ color: #64748B; font-size: 0.85rem; margin-bottom: 24px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 8px; }}
  .card {{ background: #1E293B; border-radius: 10px; padding: 20px 24px; min-width: 140px; flex: 1; border: 1px solid #334155; }}
  .card-val {{ font-size: 2rem; font-weight: 700; color: #38BDF8; }}
  .critical-card .card-val {{ color: #F87171; }}
  .high-card .card-val {{ color: #FB923C; }}
  .card-label {{ font-size: 0.8rem; color: #94A3B8; margin-top: 4px; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  table {{ width: 100%; border-collapse: collapse; background: #1E293B; border-radius: 8px; overflow: hidden; }}
  th {{ background: #0F172A; color: #94A3B8; font-size: 0.78rem; text-transform: uppercase; padding: 10px 14px; text-align: left; letter-spacing: 0.05em; }}
  td {{ padding: 9px 14px; border-bottom: 1px solid #0F172A; font-size: 0.85rem; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #263244; }}
  code {{ background: #0F172A; padding: 2px 6px; border-radius: 4px; font-family: 'Cascadia Code', monospace; font-size: 0.82rem; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; }}
  .badge.critical {{ background: #7F1D1D; color: #FCA5A5; }}
  .badge.high     {{ background: #7C2D12; color: #FDBA74; }}
  .badge.medium   {{ background: #713F12; color: #FDE68A; }}
  .badge.low      {{ background: #1E3A2F; color: #6EE7B7; }}
  .proto-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; color: white; }}
  .event-table-wrap {{ overflow-x: auto; }}
  .footer {{ margin-top: 40px; color: #475569; font-size: 0.78rem; text-align: center; }}
  .filter-bar {{ margin: 12px 0; }}
  .filter-bar input {{ background: #1E293B; border: 1px solid #334155; color: #E2E8F0; padding: 7px 12px; border-radius: 6px; font-size: 0.85rem; width: 280px; }}
</style>
</head>
<body>

<h1>🛡 ICS Honeypot — Threat Intelligence Report</h1>
<p class="subtitle">Generated: {generated_at} &nbsp;|&nbsp; Monitoring: Modbus TCP (502) · DNP3 (20000) · MQTT (1883)</p>

{cards_html}

<div class="grid2">
  <div>
    <h2>Protocol Breakdown</h2>
    <table>
      <thead><tr><th>Protocol</th><th>Attack Count</th></tr></thead>
      <tbody>{proto_rows}</tbody>
    </table>
  </div>
  <div>
    <h2>Top Attackers</h2>
    <table>
      <thead><tr><th>Source IP</th><th>Events</th></tr></thead>
      <tbody>{top_ip_rows if top_ip_rows else "<tr><td colspan='2' style='color:#475569'>No data</td></tr>"}</tbody>
    </table>
  </div>
</div>

<h2>Top Attack Actions</h2>
<table>
  <thead><tr><th>Action</th><th>Count</th></tr></thead>
  <tbody>{top_action_rows if top_action_rows else "<tr><td colspan='2' style='color:#475569'>No data</td></tr>"}</tbody>
</table>

<h2>Event Log (latest 500 attacks)</h2>
<div class="filter-bar">
  <input type="text" id="filterInput" placeholder="Filter by IP, action, protocol…" oninput="filterTable()">
</div>
<div class="event-table-wrap">
  <table id="eventTable">
    <thead>
      <tr>
        <th>Timestamp (UTC)</th>
        <th>Protocol</th>
        <th>Source</th>
        <th>Action</th>
        <th>Severity</th>
        <th>Raw (hex)</th>
      </tr>
    </thead>
    <tbody id="eventBody">
      {event_rows if event_rows else "<tr><td colspan='6' style='color:#475569;text-align:center;padding:24px'>No attack events logged yet</td></tr>"}
    </tbody>
  </table>
</div>

<div class="footer">
  ICS Honeypot — Multi-Protocol SCADA Threat Detection &nbsp;|&nbsp;
  First seen: {stats.get("first_seen", "N/A")[:19]} &nbsp;|&nbsp;
  Last seen: {stats.get("last_seen", "N/A")[:19]}
</div>

<script>
function filterTable() {{
  const query = document.getElementById("filterInput").value.toLowerCase();
  const rows  = document.getElementById("eventBody").getElementsByTagName("tr");
  for (const row of rows) {{
    row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
  }}
}}
</script>

</body>
</html>"""
