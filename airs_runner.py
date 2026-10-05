#!/usr/bin/env python3
"""
AIRS Red Teaming — Scan Runner

Programmatic target management and scan execution via the AIRS Red Teaming API.
Supports listing targets, creating targets, starting scans, and monitoring progress.

Prerequisites:
    None — uses only Python standard library.

Auth (pick one):
    python airs_runner.py --token "<bearer-token>" <command>
    python airs_runner.py --client-id X --client-secret Y --tsg-id Z <command>

Commands:
    # List existing targets
    python airs_runner.py --token T list-targets

    # List existing scans
    python airs_runner.py --token T list-scans

    # List custom prompt sets
    python airs_runner.py --token T list-prompt-sets

    # Create a target (REST API with headers auth)
    python airs_runner.py --token T create-target \\
        --name "My GPT Target" \\
        --target-type MODEL \\
        --connection-type CUSTOM \\
        --response-mode REST \\
        --api-endpoint "https://api.openai.com/v1/chat/completions" \\
        --request-header "Authorization: Bearer sk-xxx" \\
        --request-header "Content-Type: application/json" \\
        --request-json '{"model":"gpt-4","messages":[{"role":"user","content":"{INPUT}"}]}' \\
        --response-key "choices[0].message.content" \\
        --validate

    # Start a static (attack library) scan
    python airs_runner.py --token T start-scan \\
        --name "Weekly Security Scan" \\
        --target-id <target-uuid> \\
        --scan-type STATIC \\
        --categories SECURITY:JAILBREAK,PROMPT_INJECTION SAFETY:BIAS

    # Start a custom prompt-set scan
    python airs_runner.py --token T start-scan \\
        --name "Custom Prompt Test" \\
        --target-id <target-uuid> \\
        --scan-type CUSTOM \\
        --prompt-set-ids <uuid1> <uuid2>

    # Start a dynamic (agentic) scan
    python airs_runner.py --token T start-scan \\
        --name "Agentic Scan" \\
        --target-id <target-uuid> \\
        --scan-type DYNAMIC

    # Monitor a running scan
    python airs_runner.py --token T watch --job-id <scan-uuid>

    # Check quota
    python airs_runner.py --token T quota
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from time import sleep

MGMT_URL = "https://api.sase.paloaltonetworks.com/ai-red-teaming/mgmt-plane"
DP_URL = "https://api.sase.paloaltonetworks.com/ai-red-teaming/data-plane"
TOKEN_URL = "https://auth.apps.paloaltonetworks.com/am/oauth2/access_token"

_token = ""


def set_token(token: str):
    global _token
    _token = token


def get_access_token(client_id: str, client_secret: str, tsg_id: str) -> str:
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "scope": f"tsg_id:{tsg_id}",
    }).encode()
    creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    req = urllib.request.Request(
        TOKEN_URL,
        data=data,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {creds}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())["access_token"]


def api_call(base_url, method, path, params=None, body=None):
    url = f"{base_url}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {_token}",
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        err_body = e.read().decode(errors="replace")
        print(f"HTTP {e.code} from {method} {path}: {err_body[:500]}")
        sys.exit(1)


def mgmt(method, path, **kw):
    return api_call(MGMT_URL, method, path, **kw)


def dp(method, path, **kw):
    return api_call(DP_URL, method, path, **kw)


def paginate(base_url, path, params=None, limit=50):
    params = dict(params or {})
    params["limit"] = limit
    skip = 0
    while True:
        params["skip"] = skip
        data = api_call(base_url, "GET", path, params)
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


# ── Commands ────────────────────────────────────────────────────────────────


def cmd_list_targets(args):
    print("Targets:\n")
    fmt = "{:<38} {:<30} {:<12} {:<10} {:<12} {:<20}"
    print(fmt.format("UUID", "NAME", "TYPE", "STATUS", "CONNECTION", "CREATED"))
    print("-" * 124)
    for t in paginate(MGMT_URL, "/v1/target", limit=50):
        print(fmt.format(
            t.get("uuid", ""),
            (t.get("name", "") or "")[:28],
            t.get("target_type", "") or "",
            t.get("status", ""),
            t.get("connection_type", "") or "",
            (t.get("created_at", "") or "")[:19],
        ))


def cmd_list_scans(args):
    print("Scans:\n")
    fmt = "{:<38} {:<30} {:<10} {:<16} {:<8} {:<20}"
    print(fmt.format("JOB ID", "NAME", "TYPE", "STATUS", "ASR", "CREATED"))
    print("-" * 124)
    for s in paginate(DP_URL, "/v1/scan", limit=50):
        asr = s.get("asr")
        asr_str = f"{asr:.1f}%" if asr is not None else "-"
        print(fmt.format(
            s.get("uuid", ""),
            (s.get("name", "") or "")[:28],
            s.get("job_type", ""),
            s.get("status", ""),
            asr_str,
            (s.get("created_at", "") or "")[:19],
        ))


def cmd_list_prompt_sets(args):
    print("Custom Prompt Sets:\n")
    fmt = "{:<38} {:<35} {:<10} {:<20}"
    print(fmt.format("UUID", "NAME", "PROMPTS", "CREATED"))
    print("-" * 105)
    for ps in paginate(MGMT_URL, "/v1/custom-attack/list-custom-prompt-sets", limit=50):
        print(fmt.format(
            ps.get("uuid", ""),
            (ps.get("name", "") or "")[:33],
            str(ps.get("prompt_count", "") or ""),
            (ps.get("created_at", "") or "")[:19],
        ))


def _build_response_template(response_key):
    """Build a response_json template from a dotpath like 'choices[0].message.content'."""
    parts = response_key.replace("]", "").split(".")
    result = "{RESPONSE}"
    for part in reversed(parts):
        if "[" in part:
            key, idx = part.split("[")
            result = {key: [result]}
        else:
            result = {part: result}
    return result


def cmd_create_target(args):
    connection_params = {
        "api_endpoint": args.api_endpoint,
        "request_headers": {},
        "response_key": args.response_key or "",
    }

    for h in args.request_header or []:
        key, _, value = h.partition(":")
        connection_params["request_headers"][key.strip()] = value.strip()

    if args.request_json:
        connection_params["request_json"] = json.loads(args.request_json)

    if args.response_json:
        connection_params["response_json"] = json.loads(args.response_json)
    elif args.response_key:
        response_tmpl = _build_response_template(args.response_key)
        connection_params["response_json"] = response_tmpl

    body = {
        "name": args.name,
        "target_type": args.target_type,
        "connection_type": args.connection_type,
        "response_mode": args.response_mode or "REST",
        "api_endpoint_type": args.api_endpoint_type or "PUBLIC",
        "auth_type": "HEADERS",
        "connection_params": connection_params,
        "target_metadata": {},
    }

    if args.target_background_industry or args.target_background_use_case:
        body["target_background"] = {
            "industry": args.target_background_industry,
            "use_case": args.target_background_use_case,
        }

    params = {"validate": "true"} if args.validate else {}
    print(f"Creating target '{args.name}'...")
    result = mgmt("POST", "/v1/target", params=params, body=body)
    print(f"  UUID: {result.get('uuid')}")
    print(f"  Status: {result.get('status')}")
    print(f"  Validated: {result.get('validated')}")

    if args.validate:
        print("\nTarget is being validated. Check status with:")
        print(f"  python airs_runner.py --token T list-targets")


def cmd_start_scan(args):
    scan_type = args.scan_type.upper()

    body = {
        "name": args.name,
        "target": {"uuid": args.target_id},
        "job_type": scan_type,
    }

    if scan_type == "STATIC":
        categories = {}
        for cat_spec in args.categories or []:
            parts = cat_spec.split(":")
            cat = parts[0]
            subcats = parts[1].split(",") if len(parts) > 1 else []
            categories[cat] = subcats
        body["job_metadata"] = {"categories": categories}

    elif scan_type == "CUSTOM":
        if not args.prompt_set_ids:
            print("Error: --prompt-set-ids required for CUSTOM scan type")
            sys.exit(1)
        body["job_metadata"] = {"custom_prompt_sets": args.prompt_set_ids}

    elif scan_type == "DYNAMIC":
        metadata = {}
        if args.stream_breadth:
            metadata["stream_breadth"] = args.stream_breadth
        if args.stream_depth:
            metadata["stream_depth"] = args.stream_depth
        if args.goal_categories:
            metadata["goal_categories"] = args.goal_categories
        body["job_metadata"] = metadata

    else:
        print(f"Error: Unknown scan type '{scan_type}'. Use STATIC, DYNAMIC, or CUSTOM.")
        sys.exit(1)

    if args.rate_limit:
        body["job_metadata"]["rate_limit_enabled"] = True
        body["job_metadata"]["rate_limit"] = args.rate_limit

    print(f"Starting {scan_type} scan '{args.name}' against target {args.target_id}...")
    result = dp("POST", "/v1/scan", body=body)
    job_id = result.get("uuid")
    print(f"  Job ID: {job_id}")
    print(f"  Status: {result.get('status')}")

    if args.watch:
        print(f"\nMonitoring scan progress...\n")
        watch_scan(job_id)
    else:
        print(f"\nMonitor with: python airs_runner.py --token T watch --job-id {job_id}")
        print(f"Report with:  python airs_custom_report.py --job-id {job_id} --token T")


def watch_scan(job_id):
    while True:
        scan = dp("GET", f"/v1/scan/{job_id}")
        status = scan.get("status", "")
        completed = scan.get("completed") or 0
        total = scan.get("total") or 0
        asr = scan.get("asr")
        score = scan.get("score")
        name = scan.get("name", "")

        metrics = scan.get("runtime_metrics") or {}
        eta = metrics.get("eta_seconds")
        error_pct = metrics.get("error_percentage", 0)
        currently = metrics.get("currently_attacking", "")

        progress = f"{completed}/{total}" if total else "..."
        asr_str = f"ASR: {asr:.1f}%" if asr is not None else ""
        eta_str = f"ETA: {eta // 60}m{eta % 60}s" if eta else ""

        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"  [{ts}] {status:<20} {progress:<12} {asr_str:<14} {eta_str:<14} {currently}")

        if status in ("COMPLETED", "PARTIALLY_COMPLETE", "FAILED", "ABORTED"):
            print(f"\nScan finished: {status}")
            if asr is not None:
                print(f"  Attack Success Rate: {asr:.1f}%")
            if score is not None:
                print(f"  Risk Score: {score:.1f}")
            if error_pct:
                print(f"  Error Rate: {error_pct:.1f}%")
            print(f"\nGenerate report: python airs_custom_report.py --job-id {job_id} --token T")
            break

        sleep(15)


def cmd_watch(args):
    print(f"Monitoring scan {args.job_id}...\n")
    watch_scan(args.job_id)


def cmd_quota(args):
    result = dp("POST", "/v1/metering/quota")
    print("Scan Quota:\n")
    for scan_type in ("static", "dynamic", "custom"):
        q = result.get(scan_type, {})
        allocated = q.get("allocated", 0)
        consumed = q.get("consumed", 0)
        unlimited = q.get("unlimited", False)
        remaining = "unlimited" if unlimited else f"{allocated - consumed}"
        print(f"  {scan_type.upper():<10} {consumed} used / {allocated} allocated ({remaining} remaining)")


# ── CLI ─────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="AIRS Red Teaming — Scan Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--token", help="Bearer token")
    parser.add_argument("--client-id", help="SCM service account client ID")
    parser.add_argument("--client-secret", help="SCM service account client secret")
    parser.add_argument("--tsg-id", help="Tenant Service Group ID")

    sub = parser.add_subparsers(dest="command", help="Command to run")

    sub.add_parser("list-targets", help="List existing targets")
    sub.add_parser("list-scans", help="List existing scans")
    sub.add_parser("list-prompt-sets", help="List custom prompt sets")
    sub.add_parser("quota", help="Check scan quota")

    # create-target
    ct = sub.add_parser("create-target", help="Create a new target")
    ct.add_argument("--name", required=True, help="Target name")
    ct.add_argument("--target-type", default="MODEL", choices=["APPLICATION", "AGENT", "MODEL"], help="Target type")
    ct.add_argument("--connection-type", default="CUSTOM", help="Connection type (CUSTOM, OPENAI, BEDROCK, etc.)")
    ct.add_argument("--response-mode", default="REST", choices=["REST", "STREAMING", "WEBSOCKET"], help="Response mode")
    ct.add_argument("--api-endpoint-type", default="PUBLIC", choices=["PUBLIC", "PRIVATE", "NETWORK_BROKER"])
    ct.add_argument("--api-endpoint", required=True, help="Target API endpoint URL")
    ct.add_argument("--request-header", action="append", help="Request header as 'Key: Value' (repeatable)")
    ct.add_argument("--request-json", help="Request body JSON template (use {INPUT} placeholder)")
    ct.add_argument("--response-json", help="Response body JSON template (use {RESPONSE} placeholder)")
    ct.add_argument("--response-key", help="JSON key path to extract response text")
    ct.add_argument("--target-background-industry", help="Target industry (e.g., Finance, Healthcare)")
    ct.add_argument("--target-background-use-case", help="Target use case (e.g., Customer Support)")
    ct.add_argument("--validate", action="store_true", help="Validate target after creation (probe the endpoint)")

    # start-scan
    ss = sub.add_parser("start-scan", help="Start a new scan")
    ss.add_argument("--name", required=True, help="Scan name")
    ss.add_argument("--target-id", required=True, help="Target UUID")
    ss.add_argument("--scan-type", required=True, choices=["STATIC", "DYNAMIC", "CUSTOM"], help="Scan type")
    ss.add_argument("--categories", nargs="+", help="For STATIC: categories as CAT:SUB1,SUB2 (e.g., SECURITY:JAILBREAK,PROMPT_INJECTION)")
    ss.add_argument("--prompt-set-ids", nargs="+", help="For CUSTOM: prompt set UUIDs")
    ss.add_argument("--goal-categories", nargs="+", help="For DYNAMIC: goal categories")
    ss.add_argument("--stream-breadth", type=int, help="For DYNAMIC: parallel streams (1-20)")
    ss.add_argument("--stream-depth", type=int, help="For DYNAMIC: depth per stream (1-20)")
    ss.add_argument("--rate-limit", type=int, help="Rate limit (requests per minute)")
    ss.add_argument("--watch", action="store_true", help="Monitor scan progress after starting")

    # watch
    w = sub.add_parser("watch", help="Monitor a running scan")
    w.add_argument("--job-id", required=True, help="Scan job UUID")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.token:
        set_token(args.token)
    else:
        cid = args.client_id or os.environ.get("SASE_CLIENT_ID")
        csec = args.client_secret or os.environ.get("SASE_CLIENT_SECRET")
        tsg = args.tsg_id or os.environ.get("SASE_TSG_ID")
        if cid and csec and tsg:
            print("Authenticating...")
            set_token(get_access_token(cid, csec, tsg))
        else:
            print("Error: Provide --token or --client-id/--client-secret/--tsg-id (or env vars)")
            sys.exit(1)

    commands = {
        "list-targets": cmd_list_targets,
        "list-scans": cmd_list_scans,
        "list-prompt-sets": cmd_list_prompt_sets,
        "create-target": cmd_create_target,
        "start-scan": cmd_start_scan,
        "watch": cmd_watch,
        "quota": cmd_quota,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
