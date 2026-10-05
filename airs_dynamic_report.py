#!/usr/bin/env python3
"""
AIRS Red Teaming — Dynamic (Agent) Scan Report Generator

Pulls agentic scan data from the AIRS Red Teaming data-plane API.
Dynamic scans use a goal > stream > iteration hierarchy where the AI attacker
adapts its strategy across multi-turn conversations.

Prerequisites:
    None — uses only Python standard library.

Usage:
    python airs_dynamic_report.py --job-id <uuid> --token "<token>"
    python airs_dynamic_report.py --job-id <uuid> --client-id X --client-secret Y --tsg-id Z
    python airs_dynamic_report.py --list-scans --token "<token>"
"""

import argparse
import base64
import html
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

BASE_URL = "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane"
TOKEN_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"
_token = ""


def set_token(t):
    global _token
    _token = t


def get_access_token(cid, csec, tsg):
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "scope": f"tsg_id:{tsg}"}).encode()
    creds = base64.b64encode(f"{cid}:{csec}".encode()).decode()
    req = urllib.request.Request(TOKEN_URL, data=data, headers={
        "Content-Type": "application/x-www-form-urlencoded", "Authorization": f"Basic {creds}"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["access_token"]


def refresh_access_token(refresh_token):
    data = urllib.parse.urlencode({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": "scm",
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, headers={
        "Content-Type": "application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["access_token"]


def api_get(path, params=None):
    url = f"{BASE_URL}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {_token}"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} from {path}: {e.read().decode(errors='replace')[:500]}")
        raise


def paginate(path, params=None, limit=100):
    params = dict(params or {})
    params["limit"] = limit
    skip = 0
    while True:
        params["skip"] = skip
        data = api_get(path, params)
        items = data.get("data", data)
        if isinstance(items, list):
            yield from items
            total = (data.get("pagination") or {}).get("total_items")
            skip += len(items)
            if not items or (total is not None and skip >= total):
                break
        else:
            yield items
            break


# ── Data collection ─────────────────────────────────────────────────────────

def fetch_scan(job_id):
    return api_get(f"/v1/scan/{job_id}")

def fetch_dynamic_report(job_id):
    return api_get(f"/v1/report/dynamic/{job_id}/report")

def fetch_asr_breakdown(job_id):
    return api_get(f"/v1/report/dynamic/{job_id}/asr")

def fetch_goals(job_id):
    return list(paginate(f"/v1/report/dynamic/{job_id}/list-goals", limit=100))

def fetch_streams(job_id, goal_id):
    data = api_get(f"/v1/report/dynamic/{job_id}/goal/{goal_id}/list-streams")
    return data.get("data", [])

def fetch_stream_detail(stream_id):
    return api_get(f"/v1/report/dynamic/stream/{stream_id}")

def fetch_error_logs(job_id):
    return list(paginate(f"/v1/error-log/job/{job_id}", limit=100))

def fetch_remediation(job_id):
    try:
        return api_get(f"/v1/report/dynamic/{job_id}/remediation")
    except Exception:
        return {"remediations": []}


# ── Helpers ─────────────────────────────────────────────────────────────────

def esc(text):
    return html.escape(str(text)) if text is not None else ""


def md_to_html(text):
    if not text:
        return ""
    import re
    t = html.escape(text)
    t = re.sub(r'^### (.+)$', r'<h4 style="margin:16px 0 8px;color:var(--text)">\1</h4>', t, flags=re.MULTILINE)
    t = re.sub(r'^## (.+)$', r'<h3 style="margin:20px 0 8px;color:var(--text)">\1</h3>', t, flags=re.MULTILINE)
    t = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', t)
    t = re.sub(r'^- (.+)$', r'<li>\1</li>', t, flags=re.MULTILINE)
    t = re.sub(r'(<li>.*?</li>\n?)+', lambda m: '<ul style="margin:8px 0 12px 20px">' + m.group(0) + '</ul>', t)
    t = re.sub(r'\n\n+', '</p><p style="margin-bottom:10px">', t)
    t = '<p style="margin-bottom:10px">' + t + '</p>'
    return t


def verdict_badge(threat, td=None):
    if td and td.get("threat_override") is not None:
        label = "THREAT (Override)" if threat else "SAFE (Override)"
        border = "2px dashed #f39c12"
    else:
        label = "THREAT" if threat else "SAFE"
        border = "none"
    color = "#e74c3c" if threat else "#27ae60"
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;border:{border}">{label}</span>'


def score_badge(score):
    if score is None:
        return '<span style="color:var(--text-muted)">-</span>'
    if score >= 3:
        color = "#dc2626"
    elif score >= 2:
        color = "#ea580c"
    else:
        color = "#22c55e"
    return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">{score}/10</span>'


def strategy_badge(strategy):
    if not strategy or strategy.lower() == "legacy":
        return ""
    colors = {"goat": "#6366f1", "crescendo": "#8b5cf6"}
    c = colors.get(strategy.lower(), "#8b8fa3")
    return f'<span style="background:{c};color:#fff;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase">{esc(strategy)}</span>'


def build_comparison_bar_svg(raw_asr, adj_asr, raw_label, adj_label):
    max_val = max(raw_asr, adj_asr, 1)
    chart_w, bar_h, label_w, gap = 560, 28, 160, 2
    bar_area = chart_w - label_w - 60
    def bx(v): return int(v / max(max_val * 1.2, 1) * bar_area)
    rw, aw = max(bx(raw_asr), 2), max(bx(adj_asr), 2)
    return f'''<svg viewBox="0 0 {chart_w} 120" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{chart_w}px;font-family:system-ui,sans-serif">
      <text x="{label_w-8}" y="42" text-anchor="end" fill="var(--svg-muted)" font-size="12" font-weight="600">Raw</text>
      <rect x="{label_w}" y="24" width="{rw}" height="{bar_h}" rx="4" fill="#3987e5"/>
      <text x="{label_w+rw+8}" y="43" fill="var(--svg-text)" font-size="13" font-weight="700">{raw_asr:.1f}%</text>
      <text x="{label_w+rw+52}" y="43" fill="var(--svg-muted)" font-size="11">{esc(raw_label)}</text>
      <text x="{label_w-8}" y="{42+bar_h+gap+24}" text-anchor="end" fill="var(--svg-muted)" font-size="12" font-weight="600">Adjusted</text>
      <rect x="{label_w}" y="{24+bar_h+gap+12}" width="{aw}" height="{bar_h}" rx="4" fill="#d95926"/>
      <text x="{label_w+aw+8}" y="{43+bar_h+gap+24}" fill="var(--svg-text)" font-size="13" font-weight="700">{adj_asr:.1f}%</text>
      <text x="{label_w+aw+52}" y="{43+bar_h+gap+24}" fill="var(--svg-muted)" font-size="11">{esc(adj_label)}</text>
    </svg>'''


def build_category_bar_svg(categories):
    if not categories:
        return ""
    bar_h, gap, label_w = 24, 2, 200
    row_h = bar_h + gap + 16
    chart_w = 560
    bar_area = chart_w - label_w - 80
    chart_h = len(categories) * row_h + 20
    max_asr = max((c.get("asr", 0) for c in categories), default=1) or 1
    bars = ""
    for i, cat in enumerate(categories):
        name = cat.get("display_name", "")[:28]
        asr = cat.get("asr", 0)
        succ = cat.get("successful", 0)
        tot = cat.get("total", 0)
        y = i * row_h + 10
        w = max(int(asr / (max_asr * 1.2) * bar_area), 2) if asr > 0 else 0
        bars += f'''
        <text x="{label_w-8}" y="{y+16}" text-anchor="end" fill="var(--svg-muted)" font-size="11">{esc(name)}</text>
        <rect x="{label_w}" y="{y}" width="{w}" height="{bar_h}" rx="4" fill="#3987e5"/>
        <text x="{label_w+w+8}" y="{y+16}" fill="var(--svg-text)" font-size="12" font-weight="700">{asr:.1f}%</text>
        <text x="{label_w+w+52}" y="{y+16}" fill="var(--svg-muted)" font-size="10">({succ}/{tot})</text>'''
    return f'<svg viewBox="0 0 {chart_w} {chart_h}" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:{chart_w}px;font-family:system-ui,sans-serif">{bars}</svg>'


# ── HTML report ─────────────────────────────────────────────────────────────

def render_html(scan, report, asr_data, goals, streams_by_goal, error_logs, remediation):
    scan_name = esc(scan.get("name", "Unknown"))
    scan_status = esc(scan.get("status", ""))
    target_name = esc((scan.get("target") or {}).get("name", ""))
    created_at = scan.get("created_at", "")
    if created_at:
        try:
            dt = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            created_at = dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            pass

    raw_asr = report.get("asr", 0) or 0
    raw_score = report.get("score", 0) or 0
    total_goals = report.get("total_goals", 0)
    total_streams = report.get("total_streams", 0)
    total_threats = report.get("total_threats", 0)
    goals_achieved = report.get("goals_achieved", 0)
    report_summary = report.get("report_summary") or ""

    total_iterations = sum(
        len(s.get("iterations", []))
        for streams in streams_by_goal.values()
        for s in streams
    )
    threat_iterations = sum(
        1 for streams in streams_by_goal.values()
        for s in streams
        for it in s.get("iterations", [])
        if it.get("threat")
    )

    goals_safe = total_goals - goals_achieved
    comparison_chart = build_comparison_bar_svg(
        raw_asr, raw_asr,
        f"({goals_achieved}/{total_goals} goals breached)",
        f"({total_threats} threats in {total_iterations} turns)",
    )

    asr_categories = (asr_data or {}).get("categories", [])
    category_chart = build_category_bar_svg(asr_categories)

    # Goal rows
    goal_rows = ""
    for gi, goal in enumerate(goals):
        goal_text = esc(goal.get("goal_to_show") or goal.get("goal", ""))
        goal_id = goal.get("uuid", "")
        goal_threat = goal.get("threat", False)
        goal_error = goal.get("error", False)
        raw_cat = goal.get("goal_category", "") or goal.get("goal_type", "") or ""
        goal_category = esc(raw_cat.replace("_", " ").title())
        g_badge = verdict_badge(goal_threat)

        streams = streams_by_goal.get(goal_id, [])
        threat_streams = sum(1 for s in streams if s.get("threat"))

        stream_cards = ""
        for si, stream in enumerate(streams):
            s_threat = stream.get("threat", False)
            s_badge = verdict_badge(s_threat, stream.get("threat_details"))
            s_strategy = strategy_badge(stream.get("attack_strategy", "legacy"))
            s_error = stream.get("error", False)
            iterations = stream.get("iterations", [])
            max_score = max((it.get("score") or 0 for it in iterations), default=0)

            iter_rows = ""
            for it in iterations:
                it_num = it.get("iteration", 0)
                it_prompt = esc(it.get("prompt", ""))
                it_output = esc(it.get("output", "") or "")
                it_score = it.get("score")
                it_threat = it.get("threat", False)
                it_jr = esc(it.get("judge_reasoning", "") or "")
                it_techniques = esc(it.get("techniques", "") or "")
                it_preview = it_output[:80] + ("..." if len(it_output or "") > 80 else "")

                iter_rows += f'''
                <details class="output-card{" output-guardrail" if it_threat else ""}">
                  <summary class="output-header">
                    <span class="output-num">Turn {it_num + 1}</span>
                    {score_badge(it_score)}
                    {verdict_badge(it_threat)}
                    <span class="output-preview">{it_preview}</span>
                  </summary>
                  <div class="output-body"><div class="output-label">Attack Prompt</div><div class="output-text">{it_prompt}</div></div>
                  <div class="output-body"><div class="output-label">Target Output</div><div class="output-text">{it_output}</div></div>
                  {"<div class='output-body'><div class='output-label'>Techniques</div><div class='output-reasoning'>" + it_techniques + "</div></div>" if it_techniques else ""}
                  {"<div class='output-body'><div class='output-label'>Judge Reasoning</div><div class='output-reasoning'>" + it_jr + "</div></div>" if it_jr else ""}
                </details>'''

            stream_cards += f'''
            <details class="stream-card{" stream-threat" if s_threat else ""}">
              <summary class="stream-header">
                <span class="output-num">Stream {si+1}/{len(streams)}</span>
                {s_badge} {s_strategy}
                <span class="attack-meta">{len(iterations)} turns &middot; max score {max_score}/10</span>
                {"<span class='tag-error'>ERROR</span>" if s_error else ""}
              </summary>
              <div class="stream-body">
                <div class="outputs-list">{iter_rows}</div>
              </div>
            </details>'''

        goal_rows += f'''
        <div class="attack-row" data-verdict="{"THREAT" if goal_threat else "SAFE"}" data-category="{esc(raw_cat)}">
          <details>
            <summary class="attack-summary">
              <div class="attack-summary-left">
                <span class="attack-idx">#{gi+1}</span>
                {g_badge}
                {"<span class='tag-error'>ERROR</span>" if goal_error else ""}
                <span class="attack-prompt-preview">{goal_text[:120]}{"..." if len(goal_text) > 120 else ""}</span>
              </div>
              <div class="attack-summary-right">
                <span class="attack-meta">{goal_category}</span>
                <span class="attack-meta">{len(streams)} streams &middot; {threat_streams} breached</span>
              </div>
            </summary>
            <div class="attack-detail-body">
              <div class="full-prompt"><div class="output-label">Goal</div><div class="output-text">{goal_text}</div></div>
              <div class="outputs-list">{stream_cards}</div>
            </div>
          </details>
        </div>'''

    # Error log
    error_rows = ""
    error_types, error_sources = set(), set()
    for err in error_logs:
        et = esc(err.get("error_type", "") or "UNKNOWN")
        es = esc(err.get("error_source", "") or "UNKNOWN")
        error_types.add(et)
        error_sources.add(es)
        error_rows += f'<tr data-error-type="{et}" data-error-source="{es}"><td><span class="error-type-badge">{et}</span></td><td>{es}</td><td class="output-cell">{esc(err.get("error_message",""))}</td><td>{esc(err.get("created_at",""))}</td></tr>'
    eto = "".join(f'<option value="{t}">{t}</option>' for t in sorted(error_types))
    eso = "".join(f'<option value="{s}">{s}</option>' for s in sorted(error_sources))

    # Remediation
    remediation_rows = ""
    for r in (remediation or {}).get("remediations", []):
        cats = ", ".join(c.get("display_name", "") for c in r.get("categories", []))
        remediation_rows += f'<tr><td>{esc(r.get("remediation",""))}</td><td class="output-cell">{esc(r.get("description",""))}</td><td>{esc(r.get("priority_level",""))}</td><td>{cats}</td></tr>'

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    goal_categories = sorted(set(g.get("goal_category", "") or g.get("goal_type", "") or "" for g in goals if g.get("goal_category") or g.get("goal_type")))
    goal_cat_display = {c: c.replace("_", " ").title() for c in goal_categories}

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Red Teaming Agent Report — {scan_name}</title>
<style>
  :root, [data-theme="dark"] {{
    --bg:#0f1117; --surface:#1a1d27; --surface-2:#242736; --border:#2e3142;
    --text:#e1e4ed; --text-muted:#8b8fa3; --accent:#6366f1; --accent-light:#818cf8;
    --threat:#ef4444; --safe:#22c55e; --warning:#f59e0b;
    --header-bg:linear-gradient(135deg,#1e1b4b,#312e81);
    --svg-text:#e1e4ed; --svg-muted:#8b8fa3;
  }}
  [data-theme="light"] {{
    --bg:#f4f5f7; --surface:#ffffff; --surface-2:#f0f1f3; --border:#d1d5db;
    --text:#1f2937; --text-muted:#6b7280; --accent:#4f46e5; --accent-light:#6366f1;
    --threat:#dc2626; --safe:#16a34a; --warning:#d97706;
    --header-bg:linear-gradient(135deg,#312e81,#4338ca);
    --svg-text:#1f2937; --svg-muted:#6b7280;
  }}
  *{{margin:0;padding:0;box-sizing:border-box}}
  body{{font-family:system-ui,-apple-system,'Segoe UI',sans-serif;background:var(--bg);color:var(--text);line-height:1.6;padding:32px}}
  .container{{max-width:1400px;margin:0 auto}}
  .header{{background:var(--header-bg);border-radius:16px;padding:40px;margin-bottom:32px;border:1px solid rgba(99,102,241,0.3);position:relative}}
  .header h1{{font-size:28px;font-weight:700;color:#fff;margin-bottom:8px}}
  .header .subtitle{{color:rgba(255,255,255,0.8);font-size:15px}}
  .meta-row{{display:flex;gap:32px;margin-top:20px;flex-wrap:wrap}}
  .meta-item{{font-size:13px;color:rgba(255,255,255,0.7)}}
  .meta-item strong{{color:#fff}}
  .theme-toggle{{position:absolute;top:20px;right:20px;background:rgba(255,255,255,0.15);border:1px solid rgba(255,255,255,0.25);color:#fff;padding:6px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer}}
  .theme-toggle:hover{{background:rgba(255,255,255,0.25)}}
  .kpi-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}}
  .kpi{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:24px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
  .kpi .value{{font-size:36px;font-weight:700;line-height:1.2}}
  .kpi .label{{font-size:12px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:0.5px}}
  .kpi.threat .value{{color:var(--threat)}}
  .kpi.safe .value{{color:var(--safe)}}
  .kpi.warning .value{{color:var(--warning)}}
  .kpi.accent .value{{color:var(--accent-light)}}
  .section{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:28px;margin-bottom:24px;box-shadow:0 1px 3px rgba(0,0,0,0.08)}}
  .section h2{{font-size:18px;font-weight:600;margin-bottom:16px;color:var(--text);display:flex;align-items:center;gap:8px}}
  .section h2 .badge{{background:var(--accent);color:#fff;font-size:11px;padding:2px 8px;border-radius:10px;font-weight:600}}
  .section h3{{font-size:15px;font-weight:600;color:var(--text-muted);margin:24px 0 12px}}
  .data-table{{width:100%;border-collapse:collapse;font-size:13px}}
  .data-table th{{text-align:left;padding:10px 12px;border-bottom:2px solid var(--border);color:var(--text-muted);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:0.5px;position:sticky;top:0;background:var(--surface)}}
  .data-table td{{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}}
  .data-table tr:hover{{background:var(--surface-2)}}
  .table-scroll{{overflow-x:auto;max-height:600px;overflow-y:auto;border-radius:8px;border:1px solid var(--border)}}
  .output-cell{{max-width:400px;word-break:break-word}}
  .filter-bar{{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap}}
  .filter-bar input,.filter-bar select{{background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:13px}}
  .filter-bar input::placeholder{{color:var(--text-muted)}}
  .tag-error{{background:#451a1a;color:#f87171;border:1px solid #ef4444;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;flex-shrink:0;white-space:nowrap}}
  [data-theme="light"] .tag-guardrail{{background:#dbeafe;color:#1d4ed8;border-color:#93c5fd}}
  [data-theme="light"] .tag-ratelimit{{background:#fef3c7;color:#92400e;border-color:#fcd34d}}
  [data-theme="light"] .tag-error{{background:#fee2e2;color:#991b1b;border-color:#fca5a5}}
  .error-type-badge{{background:var(--surface-2);border:1px solid var(--border);padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;color:var(--text);white-space:nowrap}}
  .attack-row{{border:1px solid var(--border);border-radius:8px;margin-bottom:8px;overflow:hidden;transition:border-color 0.15s}}
  .attack-row:hover{{border-color:var(--accent)}}
  .attack-row details{{margin:0}}
  .attack-summary{{display:flex;justify-content:space-between;align-items:center;padding:12px 16px;cursor:pointer;background:var(--surface-2);gap:12px;list-style:none}}
  .attack-summary::-webkit-details-marker{{display:none}}
  .attack-summary::before{{content:"▶";font-size:10px;color:var(--text-muted);transition:transform 0.15s;flex-shrink:0}}
  details[open]>.attack-summary::before{{transform:rotate(90deg)}}
  .attack-summary-left{{display:flex;align-items:center;gap:8px;flex:1;min-width:0;flex-wrap:nowrap}}
  .attack-summary-left>span{{flex-shrink:0;white-space:nowrap}}
  .attack-idx{{color:var(--text-muted);font-size:12px;font-weight:600;flex-shrink:0;width:32px}}
  .attack-prompt-preview{{font-size:13px;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:1}}
  .attack-summary-right{{display:flex;align-items:center;gap:16px;flex-shrink:0}}
  .attack-meta{{font-size:12px;color:var(--text-muted);white-space:nowrap}}
  .attack-detail-body{{padding:16px;border-top:1px solid var(--border)}}
  .full-prompt{{margin-bottom:16px;padding:12px;background:var(--bg);border-radius:6px}}
  .outputs-list{{display:flex;flex-direction:column;gap:10px}}
  .stream-card{{border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:4px}}
  .stream-card.stream-threat{{border-color:var(--threat)}}
  .stream-header{{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface-2);font-size:12px;cursor:pointer;list-style:none}}
  .stream-header::-webkit-details-marker{{display:none}}
  .stream-header::before{{content:"▶";font-size:9px;color:var(--text-muted);transition:transform 0.15s;flex-shrink:0}}
  details.stream-card[open]>.stream-header::before{{transform:rotate(90deg)}}
  .stream-body{{padding:12px}}
  .output-card{{border:1px solid var(--border);border-radius:6px;overflow:hidden}}
  .output-card.output-guardrail{{border-color:var(--threat)}}
  details.output-card{{margin:0}}
  details.output-card>summary{{list-style:none;cursor:pointer}}
  details.output-card>summary::-webkit-details-marker{{display:none}}
  details.output-card>summary::before{{content:"▶";font-size:9px;color:var(--text-muted);transition:transform 0.15s;flex-shrink:0}}
  details.output-card[open]>summary::before{{transform:rotate(90deg)}}
  .output-header{{display:flex;align-items:center;gap:10px;padding:8px 12px;background:var(--surface-2);font-size:12px}}
  .output-num{{color:var(--text-muted);font-weight:600}}
  .output-preview{{color:var(--text-muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0;flex:1}}
  details.output-card[open] .output-preview{{display:none}}
  .output-body{{padding:10px 12px}}
  .output-label{{font-size:11px;text-transform:uppercase;letter-spacing:0.5px;color:var(--text-muted);margin-bottom:4px;font-weight:600}}
  .output-text{{font-size:13px;line-height:1.5;word-break:break-word;white-space:pre-wrap}}
  .output-reasoning{{font-size:12px;color:var(--text-muted);line-height:1.5;word-break:break-word}}
  .section>details{{margin-top:12px}}
  .section>details>summary{{cursor:pointer;color:var(--accent-light);font-size:13px;font-weight:600}}
  .section>details>summary:hover{{text-decoration:underline}}
  body,.section,.kpi,.attack-row,.stream-card,.output-card,.data-table th{{transition:background 0.2s,color 0.2s,border-color 0.2s}}
  .footer{{text-align:center;padding:24px;color:var(--text-muted);font-size:12px}}
  @media print{{body{{background:#fff;color:#000;padding:16px}}.header{{background:#f0f0f8 !important}}.theme-toggle{{display:none}}.table-scroll{{max-height:none;overflow:visible}}}}
</style>
</head>
<body>
<div class="container">

  <div class="header">
    <button class="theme-toggle" onclick="toggleTheme()" id="themeBtn">Light Mode</button>
    <h1>AI Red Teaming Report</h1>
    <div class="subtitle">Agent Scan — Dynamic Multi-Turn Analysis</div>
    <div class="meta-row">
      <div class="meta-item">Scan: <strong>{scan_name}</strong></div>
      <div class="meta-item">Target: <strong>{target_name}</strong></div>
      <div class="meta-item">Status: <strong>{scan_status}</strong></div>
      <div class="meta-item">Created: <strong>{created_at}</strong></div>
      <div class="meta-item">Report generated: <strong>{now}</strong></div>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi threat"><div class="value">{raw_asr:.1f}%</div><div class="label">Attack Success Rate</div></div>
    <div class="kpi"><div class="value">{raw_score:.0f}</div><div class="label">Risk Score</div></div>
    <div class="kpi accent"><div class="value">{total_goals}</div><div class="label">Goals Tested</div></div>
    <div class="kpi threat"><div class="value">{goals_achieved}</div><div class="label">Goals Breached</div></div>
    <div class="kpi accent"><div class="value">{total_streams}</div><div class="label">Attack Streams</div></div>
    <div class="kpi accent"><div class="value">{total_iterations}</div><div class="label">Total Turns</div></div>
    <div class="kpi threat"><div class="value">{total_threats}</div><div class="label">Threats Found</div></div>
    <div class="kpi threat"><div class="value">{threat_iterations}</div><div class="label">Threat Turns</div></div>
  </div>

  {"<div class='section'><h2>Executive Summary</h2><div style='color:var(--text-muted);font-size:14px;line-height:1.8'>" + md_to_html(report_summary) + "</div></div>" if report_summary else ""}

  {"<div class='section'><h2>Attack Success Rate by Goal Category</h2>" + category_chart + "</div>" if category_chart else ""}

  {"" if not remediation_rows else f'''
  <div class="section">
    <h2>Remediation Recommendations</h2>
    <div class="table-scroll"><table class="data-table"><thead><tr><th>Remediation</th><th>Description</th><th>Priority</th><th>Categories</th></tr></thead>
    <tbody>{remediation_rows}</tbody></table></div>
  </div>'''}

  <div class="section">
    <h2>Goals &amp; Streams <span class="badge">{len(goals)} goals</span></h2>
    <p style="color:var(--text-muted);font-size:13px;margin-bottom:16px">
      Each goal is tested by multiple attack streams. Each stream is a multi-turn conversation
      where the AI attacker adapts its strategy to breach the target. Expand to see every turn.
    </p>
    <div class="filter-bar">
      <input type="text" id="searchInput" placeholder="Search goals..." onkeyup="filterGoals()">
      <select id="verdictFilter" onchange="filterGoals()"><option value="">All</option><option value="THREAT">Breached</option><option value="SAFE">Defended</option></select>
      <select id="categoryFilter" onchange="filterGoals()"><option value="">All categories</option>{"".join(f'<option value="{esc(c)}">{esc(goal_cat_display.get(c,c))}</option>' for c in goal_categories)}</select>
      <button onclick="toggleAll(true)" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:13px;cursor:pointer">Expand All</button>
      <button onclick="toggleAll(false)" style="background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:6px;font-size:13px;cursor:pointer">Collapse All</button>
    </div>
    <div id="goalList">{goal_rows}</div>
  </div>

  {"" if not error_rows else f'''
  <div class="section">
    <h2>Error Log <span class="badge">{len(error_logs)}</span></h2>
    <div class="filter-bar">
      <select id="errorTypeFilter" onchange="filterErrors()"><option value="">All types</option>{eto}</select>
      <select id="errorSourceFilter" onchange="filterErrors()"><option value="">All sources</option>{eso}</select>
      <input type="text" id="errorSearch" placeholder="Search..." onkeyup="filterErrors()">
      <span id="errorCount" style="font-size:12px;color:var(--text-muted);align-self:center">{len(error_logs)} entries</span>
    </div>
    <div class="table-scroll"><table class="data-table" id="errorTable"><thead><tr><th>Type</th><th>Source</th><th>Message</th><th>Time</th></tr></thead>
    <tbody>{error_rows}</tbody></table></div>
  </div>'''}

  <div class="footer">Generated by AIRS Red Teaming Dynamic Report Tool &bull; Prisma AIRS API v0.93.0 &bull; {now}</div>

</div>
<script>
function toggleTheme(){{const r=document.documentElement,b=document.getElementById('themeBtn'),n=(r.getAttribute('data-theme')||'dark')==='dark'?'light':'dark';r.setAttribute('data-theme',n);b.textContent=n==='dark'?'Light Mode':'Dark Mode'}}
function filterGoals(){{const s=document.getElementById('searchInput').value.toLowerCase(),v=document.getElementById('verdictFilter').value,c=document.getElementById('categoryFilter').value;document.querySelectorAll('.attack-row').forEach(r=>{{const ok=(!s||r.textContent.toLowerCase().includes(s))&&(!v||r.dataset.verdict===v)&&(!c||r.dataset.category===c);r.style.display=ok?'':'none'}})}}
function toggleAll(o){{document.querySelectorAll('#goalList details').forEach(d=>d.open=o)}}
function filterErrors(){{const t=document.getElementById('errorTypeFilter').value,s=document.getElementById('errorSourceFilter').value,q=document.getElementById('errorSearch').value.toLowerCase();let n=0;document.querySelectorAll('#errorTable tbody tr').forEach(r=>{{const ok=(!t||r.dataset.errorType===t)&&(!s||r.dataset.errorSource===s)&&(!q||r.textContent.toLowerCase().includes(q));r.style.display=ok?'':'none';if(ok)n++}});const c=document.getElementById('errorCount');if(c)c.textContent=n+' entries'}}
</script>
</body>
</html>"""


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AIRS Red Teaming — Dynamic Scan Report Generator")
    parser.add_argument("--job-id", help="Scan job UUID")
    parser.add_argument("--list-scans", action="store_true", help="List recent scans and exit")
    parser.add_argument("--output", help="Output HTML file path")
    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--refresh-token", help="Refresh token (auto-exchanges for access token)")
    parser.add_argument("--client-id", help="SCM service account client ID")
    parser.add_argument("--client-secret", help="SCM service account client secret")
    parser.add_argument("--tsg-id", help="Tenant Service Group ID")
    args = parser.parse_args()

    if args.token:
        set_token(args.token)
    elif args.refresh_token:
        print("Exchanging refresh token...")
        set_token(refresh_access_token(args.refresh_token))
    else:
        cid = args.client_id or os.environ.get("SASE_CLIENT_ID")
        csec = args.client_secret or os.environ.get("SASE_CLIENT_SECRET")
        tsg = args.tsg_id or os.environ.get("SASE_TSG_ID")
        if cid and csec and tsg:
            print("Authenticating...")
            set_token(get_access_token(cid, csec, tsg))
        else:
            print("Error: Provide --token, --refresh-token, or --client-id/--client-secret/--tsg-id (or env vars)")
            sys.exit(1)

    if args.list_scans:
        print("Dynamic scans:\n")
        fmt = "{:<38} {:<30} {:<12} {:<8} {:<20}"
        print(fmt.format("JOB ID", "NAME", "STATUS", "ASR", "CREATED"))
        print("-" * 110)
        for s in paginate("/v1/scan", {"job_type": "DYNAMIC"}, limit=20):
            asr = s.get("asr")
            print(fmt.format(s.get("uuid", ""), (s.get("name", "") or "")[:28],
                             s.get("status", ""), f"{asr:.1f}%" if asr is not None else "-",
                             (s.get("created_at", "") or "")[:19]))
        sys.exit(0)

    if not args.job_id:
        print("Error: Provide --job-id or --list-scans")
        sys.exit(1)

    job_id = args.job_id

    print(f"Fetching scan {job_id}...")
    scan = fetch_scan(job_id)
    print(f"  Scan: {scan.get('name')} — Status: {scan.get('status')} — Type: {scan.get('job_type')}")

    print("Fetching dynamic report...")
    report = fetch_dynamic_report(job_id)

    print("Fetching ASR breakdown...")
    asr_data = fetch_asr_breakdown(job_id)

    print("Fetching goals...")
    goals = fetch_goals(job_id)
    print(f"  {len(goals)} goals")

    print("Fetching streams per goal (parallel)...")
    streams_by_goal = {}

    def _fetch_streams(goal):
        gid = goal["uuid"]
        return gid, fetch_streams(job_id, gid)

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fetch_streams, g): g for g in goals if g.get("uuid")}
        for f in as_completed(futures):
            try:
                gid, streams = f.result()
                streams_by_goal[gid] = streams
            except Exception as e:
                print(f"  Warning: stream fetch failed ({e})")

    total_streams = sum(len(v) for v in streams_by_goal.values())
    print(f"  {total_streams} streams across {len(goals)} goals")

    print("Fetching stream details (parallel)...")
    all_stream_ids = []
    for gid, streams in streams_by_goal.items():
        for s in streams:
            all_stream_ids.append((gid, s))

    def _fetch_detail(item):
        gid, stream = item
        sid = stream.get("uuid")
        return gid, sid, fetch_stream_detail(sid)

    detail_errors = 0
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_fetch_detail, item): item for item in all_stream_ids if item[1].get("uuid")}
        done = 0
        for f in as_completed(futures):
            done += 1
            try:
                gid, sid, detail = f.result()
                for i, s in enumerate(streams_by_goal.get(gid, [])):
                    if s.get("uuid") == sid:
                        streams_by_goal[gid][i] = detail
                        break
            except Exception:
                detail_errors += 1
            if done % 50 == 0:
                print(f"  {done}/{len(all_stream_ids)} processed")

    print(f"  Done ({detail_errors} errors)")

    print("Fetching error logs...")
    try:
        error_logs = fetch_error_logs(job_id)
    except Exception:
        error_logs = []
    print(f"  {len(error_logs)} entries")

    print("Fetching remediation...")
    remediation = fetch_remediation(job_id)

    print("Rendering HTML report...")
    html_out = render_html(scan, report, asr_data, goals, streams_by_goal, error_logs, remediation)

    output_path = args.output or f"dynamic_report_{job_id[:8]}.html"
    Path(output_path).write_text(html_out, encoding="utf-8")
    print(f"\nReport saved to: {output_path}")
    print(f"Open in browser: file://{Path(output_path).resolve()}")


if __name__ == "__main__":
    main()
