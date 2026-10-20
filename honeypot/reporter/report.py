# =============================================================================
#  ics_honeypot / reporter / report.py
#  ---------------------------------------------------------------------------
#  HTML Threat Intelligence Dashboard Generator
#  ---------------------------------------------------------------------------
#  Reads events.jsonl and produces a self-contained, interactive HTML report:
#    • Executive KPI Summary Cards
#    • MITRE ATT&CK® for ICS Technique & Tactic Matrix
#    • Simulated Industrial Process State (Telemetry & Actuator status)
#    • Targeted Protocols & Top Attacker IPs
#    • Real-time filterable Attack Event Log with MITRE tags
# =============================================================================

import json
import os
import datetime
from collections import Counter
from typing import List, Dict, Any

from honeypot.shared.config import EVENT_FILE, REPORT_FILE
from honeypot.simulation.process import simulator


def _load_events() -> List[Dict[str, Any]]:
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
                pass
    return events


def _compute_stats(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not events:
        return {}

    attacks = [e for e in events if e.get("event") == "attack"]
    unique_ips = set(e.get("src_ip", "") for e in events if e.get("src_ip"))

    proto_counter = Counter(e.get("protocol", "UNKNOWN") for e in attacks)
    severity_counter = Counter(e.get("severity", "MEDIUM") for e in attacks)

    # MITRE ATT&CK breakdown
    mitre_counter = Counter(
        f"{e.get('mitre_id', 'T0846')} - {e.get('mitre_name', 'Discovery')}"
        for e in attacks if e.get("mitre_id")
    )
    tactic_counter = Counter(e.get("mitre_tactic", "Discovery") for e in attacks if e.get("mitre_tactic"))

    ip_counts = Counter(e.get("src_ip", "") for e in attacks)
    action_counts = Counter(e.get("action", "unknown") for e in attacks)

    timestamps = [e.get("timestamp", "") for e in events if e.get("timestamp")]
    first_seen = min(timestamps) if timestamps else "N/A"
    last_seen  = max(timestamps) if timestamps else "N/A"

    return {
        "total_events": len(events),
        "total_attacks": len(attacks),
        "unique_ips": len(unique_ips),
        "protocols": dict(proto_counter),
        "severity": dict(severity_counter),
        "mitre_techniques": mitre_counter.most_common(8),
        "mitre_tactics": dict(tactic_counter),
        "top_ips": ip_counts.most_common(10),
        "top_actions": action_counts.most_common(10),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def _severity_badge(sev: str) -> str:
    s = (sev or "MEDIUM").upper()
    if s == "CRITICAL":
        return '<span class="badge critical">CRITICAL</span>'
    elif s == "HIGH":
        return '<span class="badge high">HIGH</span>'
    elif s == "LOW":
        return '<span class="badge low">LOW</span>'
    return '<span class="badge medium">MEDIUM</span>'


def _proto_badge(proto: str) -> str:
    colours = {"MODBUS": "#3B82F6", "DNP3": "#8B5CF6", "MQTT": "#10B981"}
    colour = colours.get(proto.upper(), "#6B7280")
    return f'<span class="proto-badge" style="background:{colour}">{proto}</span>'


def _escape(text: Any) -> str:
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def generate_report() -> str:
    events = _load_events()
    stats  = _compute_stats(events)
    telemetry = simulator.get_telemetry_dict()
    generated_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    html = _render_html(events, stats, telemetry, generated_at)

    os.makedirs(os.path.dirname(REPORT_FILE), exist_ok=True)
    with open(REPORT_FILE, "w", encoding="utf-8") as fh:
        fh.write(html)

    return REPORT_FILE


def _render_html(events: List[Dict[str, Any]], stats: Dict[str, Any], telemetry: Dict[str, Any], generated_at: str) -> str:
    total_events  = stats.get("total_events",  0)
    total_attacks = stats.get("total_attacks", 0)
    unique_ips    = stats.get("unique_ips",    0)
    severity      = stats.get("severity",      {})
    protocols     = stats.get("protocols",     {})

    cards_html = f"""
    <div class="cards">
      <div class="card"><div class="card-val">{total_events}</div><div class="card-label">Total Events</div></div>
      <div class="card"><div class="card-val">{total_attacks}</div><div class="card-label">Attack Probes</div></div>
      <div class="card"><div class="card-val">{unique_ips}</div><div class="card-label">Unique Attackers</div></div>
      <div class="card critical-card"><div class="card-val">{severity.get("CRITICAL", 0)}</div><div class="card-label">Critical Exploits</div></div>
      <div class="card high-card"><div class="card-val">{severity.get("HIGH", 0)}</div><div class="card-label">High Severity</div></div>
    </div>
    """

    # Physical Simulation Telemetry Grid
    telemetry_html = f"""
    <div class="telemetry-box">
      <div class="telemetry-item"><span>Grid Voltage:</span> <strong>{telemetry.get('voltage_v')} V</strong></div>
      <div class="telemetry-item"><span>Current Load:</span> <strong>{telemetry.get('current_a')} A</strong></div>
      <div class="telemetry-item"><span>Oil Temperature:</span> <strong>{telemetry.get('oil_temp_c')} °C</strong></div>
      <div class="telemetry-item"><span>Tank Pressure:</span> <strong>{telemetry.get('pressure_hpa')} hPa</strong></div>
      <div class="telemetry-item"><span>Cooling Fan:</span> <strong>{telemetry.get('cooling_fan')}</strong></div>
      <div class="telemetry-item"><span>Emergency Cutoff:</span> <strong>{telemetry.get('emergency_cutoff')}</strong></div>
    </div>
    """

    # MITRE ATT&CK Matrix rows
    mitre_rows = "".join(
        f"<tr><td><code>{_escape(tech)}</code></td><td>{count}</td></tr>"
        for tech, count in stats.get("mitre_techniques", [])
    )

    proto_rows = "".join(
        f"<tr><td>{_proto_badge(p)}</td><td>{c}</td></tr>"
        for p, c in sorted(protocols.items(), key=lambda x: -x[1])
    )

    top_ip_rows = "".join(
        f"<tr><td><code>{_escape(ip)}</code></td><td>{count}</td></tr>"
        for ip, count in stats.get("top_ips", [])
    )

    attack_events = [e for e in events if e.get("event") == "attack"]
    attack_events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

    event_rows = ""
    for e in attack_events[:500]:
        ts       = _escape(e.get("timestamp", "")[:19].replace("T", " "))
        proto    = _proto_badge(e.get("protocol", "?"))
        src_ip   = _escape(e.get("src_ip",  "?"))
        src_port = _escape(str(e.get("src_port", "?")))
        action   = _escape(e.get("action",  "?"))
        badge    = _severity_badge(e.get("severity", ""))
        mitre_id = _escape(e.get("mitre_id", "T0846"))
        raw_hex  = _escape(e.get("raw_hex", "")[:36])

        event_rows += f"""
        <tr>
          <td>{ts}</td>
          <td>{proto}</td>
          <td><code>{src_ip}:{src_port}</code></td>
          <td><code>{action}</code></td>
          <td><span class="mitre-tag">{mitre_id}</span></td>
          <td>{badge}</td>
          <td><code style="font-size:11px">{raw_hex}</code></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ICS Honeypot — Threat & ATT&CK® Intelligence Dashboard</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B1120; color: #E2E8F0; padding: 24px; }}
  h1 {{ font-size: 1.6rem; color: #F8FAFC; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }}
  h2 {{ font-size: 1.05rem; color: #94A3B8; margin: 24px 0 12px; border-bottom: 1px solid #1E293B; padding-bottom: 8px; }}
  .subtitle {{ color: #64748B; font-size: 0.85rem; margin-bottom: 20px; }}
  .cards {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 20px; }}
  .card {{ background: #131E32; border-radius: 8px; padding: 18px 20px; min-width: 140px; flex: 1; border: 1px solid #1E293B; }}
  .card-val {{ font-size: 1.9rem; font-weight: 700; color: #38BDF8; }}
  .critical-card .card-val {{ color: #F87171; }}
  .high-card .card-val {{ color: #FB923C; }}
  .card-label {{ font-size: 0.8rem; color: #94A3B8; margin-top: 4px; }}
  .telemetry-box {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; background: #131E32; padding: 14px 18px; border-radius: 8px; border: 1px solid #1E293B; margin-bottom: 20px; }}
  .telemetry-item span {{ color: #94A3B8; font-size: 0.78rem; display: block; }}
  .telemetry-item strong {{ color: #38BDF8; font-size: 1.1rem; }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  table {{ width: 100%; border-collapse: collapse; background: #131E32; border-radius: 8px; overflow: hidden; }}
  th {{ background: #0B1120; color: #94A3B8; font-size: 0.75rem; text-transform: uppercase; padding: 10px 12px; text-align: left; letter-spacing: 0.05em; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1E293B; font-size: 0.82rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1A263D; }}
  code {{ background: #0B1120; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.8rem; }}
  .badge {{ display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }}
  .badge.critical {{ background: #7F1D1D; color: #FCA5A5; }}
  .badge.high {{ background: #7C2D12; color: #FDBA74; }}
  .badge.medium {{ background: #713F12; color: #FDE68A; }}
  .badge.low {{ background: #1E3A2F; color: #6EE7B7; }}
  .mitre-tag {{ background: #312E81; color: #C7D2FE; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; font-family: monospace; }}
  .proto-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: 700; color: white; }}
  .event-table-wrap {{ overflow-x: auto; }}
  .footer {{ margin-top: 36px; color: #475569; font-size: 0.78rem; text-align: center; }}
  .filter-bar {{ margin: 12px 0; }}
  .filter-bar input {{ background: #131E32; border: 1px solid #334155; color: #E2E8F0; padding: 8px 12px; border-radius: 6px; font-size: 0.85rem; width: 320px; }}
</style>
</head>
<body>

<h1>🛡 ICS Honeypot — SCADA Threat & ATT&CK® Dashboard</h1>
<p class="subtitle">Generated: {generated_at} &nbsp;|&nbsp; Modbus TCP (:502) · DNP3 (:20000) · MQTT (:1883)</p>

{cards_html}

<h2>Simulated Process Telemetry (Substation Transformer Model)</h2>
{telemetry_html}

<div class="grid2">
  <div>
    <h2>MITRE ATT&CK® for ICS Techniques</h2>
    <table>
      <thead><tr><th>Technique</th><th>Count</th></tr></thead>
      <tbody>{mitre_rows if mitre_rows else "<tr><td colspan='2' style='color:#475569'>No attacks classified yet</td></tr>"}</tbody>
    </table>
  </div>
  <div>
    <h2>Top Attacker IP Addresses</h2>
    <table>
      <thead><tr><th>Source IP</th><th>Probes</th></tr></thead>
      <tbody>{top_ip_rows if top_ip_rows else "<tr><td colspan='2' style='color:#475569'>No data</td></tr>"}</tbody>
    </table>
  </div>
</div>

<h2>Attack Event Stream (Latest 500 Events with ATT&CK Mapping)</h2>
<div class="filter-bar">
  <input type="text" id="filterInput" placeholder="Filter by IP, action, MITRE ID, protocol…" oninput="filterTable()">
</div>
<div class="event-table-wrap">
  <table id="eventTable">
    <thead>
      <tr>
        <th>Timestamp (UTC)</th>
        <th>Protocol</th>
        <th>Source</th>
        <th>Action</th>
        <th>MITRE ID</th>
        <th>Severity</th>
        <th>Raw Hex</th>
      </tr>
    </thead>
    <tbody id="eventBody">
      {event_rows if event_rows else "<tr><td colspan='7' style='color:#475569;text-align:center;padding:24px'>No attack events logged yet</td></tr>"}
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
  const rows = document.getElementById("eventBody").getElementsByTagName("tr");
  for (const row of rows) {{
    row.style.display = row.textContent.toLowerCase().includes(query) ? "" : "none";
  }}
}}
</script>

</body>
</html>"""
