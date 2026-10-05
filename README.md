# AIRS Red Teaming Toolkit

Programmatic target management, scan execution, and custom reporting for **Prisma AIRS AI Red Teaming**.

Zero dependencies — Python 3.10+ standard library only.

**[Full Documentation](https://rmfincher.github.io/AI-Red-Teaming-Auto/)**

## Scripts

| Script | Scan Type | Description |
|---|---|---|
| `airs_custom_report.py` | Custom | Report for custom prompt-set scans with adjusted Attack Success Rate, guardrail/rate-limit detection, severity ranking |
| `airs_static_report.py` | Static | Report for attack library scans with category/subcategory breakdown, compliance mapping, remediation recommendations |
| `airs_dynamic_report.py` | Dynamic | Report for agent scans with goal/stream/iteration drill-down, attack strategy badges, multi-turn conversation view |
| `airs_runner.py` | All | Target creation, scan execution, progress monitoring, quota management |

## Quick Start

### Authentication

All scripts support three auth methods:

```bash
# Option 1: Bearer token (from browser)
python3 airs_static_report.py --job-id <uuid> --token "<token>"

# Option 2: Service account (for automation)
export SASE_CLIENT_ID="<client-id>"
export SASE_CLIENT_SECRET="<client-secret>"
export SASE_TSG_ID="<tsg-id>"
python3 airs_static_report.py --job-id <uuid>

# Option 3: Refresh token
python3 airs_static_report.py --job-id <uuid> --refresh-token "<token>"
```

### Generate a Report

```bash
# List available scans
python3 airs_static_report.py --list-scans --token "<token>"

# Static scan report
python3 airs_static_report.py --job-id <uuid> --token "<token>"

# Dynamic (agent) scan report
python3 airs_dynamic_report.py --job-id <uuid> --token "<token>"

# Custom prompt-set report with target-specific patterns
python3 airs_custom_report.py --job-id <uuid> --token "<token>" \
    --guardrail-pattern "safety filter triggered" \
    --ratelimit-pattern "unable to respond to this volume"
```

### Manage Targets & Run Scans

```bash
# List targets
python3 airs_runner.py --token "<token>" list-targets

# Create a target
python3 airs_runner.py --token "<token>" create-target \
    --name "GPT-4o" \
    --target-type MODEL \
    --connection-type OPENAI \
    --api-endpoint "https://api.openai.com/v1/chat/completions" \
    --request-header "Authorization: Bearer sk-xxx" \
    --request-header "Content-Type: application/json" \
    --request-json '{"model":"gpt-4o","messages":[{"role":"user","content":"{INPUT}"}]}' \
    --response-key "choices[0].message.content" \
    --validate

# Start a scan
python3 airs_runner.py --token "<token>" start-scan \
    --name "Security Scan" \
    --target-id <target-uuid> \
    --scan-type STATIC \
    --categories "SECURITY:JAILBREAK,PROMPT_INJECTION" \
    --watch

# Check quota
python3 airs_runner.py --token "<token>" quota
```

## Report Features

All reports include:
- **Adjusted Attack Success Rate** — excludes errored and rate-limited attacks for true coverage
- **Guardrail detection** — identifies target safety filter blocks (Copilot, ChatGPT, Claude, Gemini patterns built-in)
- **Rate-limit detection** — identifies throttled responses counted as "safe"
- **Severity ranking** — attacks sorted by breach rate (CRITICAL/HIGH/MEDIUM)
- **Collapsible drill-down** — prompts, attempts, outputs, judge reasoning
- **Interactive filters** — search, verdict, category, error type
- **Light/dark mode** toggle
- **Print-friendly** layout

### Static reports add:
- Category/subcategory ASR breakdown
- Compliance mapping (OWASP, MITRE ATLAS, NIST, DASF)
- AIRS-generated executive summary and remediation recommendations

### Dynamic reports add:
- Goal > Stream > Iteration hierarchy
- Attack strategy badges (GOAT, CRESCENDO)
- Per-turn score (0-10) with judge reasoning
- Goal category breakdown

## Built-in Detection Patterns

The reports automatically detect common guardrail and rate-limit responses:

| Target | Guardrail | Rate Limit |
|---|---|---|
| M365 Copilot | "Disengaged safety filter triggered" | "temporarily unable to respond to this volume" |
| ChatGPT / OpenAI | "I can't assist with that" | "Rate limit reached", "Too many requests" |
| Claude / Anthropic | "I cannot and will not" | "rate_limit_error" |
| Gemini / Google | "I'm not able to generate" | — |

Add custom patterns with `--guardrail-pattern` and `--ratelimit-pattern`.

## API Reference

The toolkit uses three API planes, all under `https://api.sase.paloaltonetworks.com`:

| Plane | Base Path | Used By |
|---|---|---|
| Data Plane | `/ai-red-teaming/data-plane/v1/` | Report scripts, scan runner (scans) |
| Management Plane | `/ai-red-teaming/mgmt-plane/v1/` | Scan runner (targets, prompt sets) |
| Network Broker | `/ai-red-teaming/network-broker/v1/` | Private endpoint configuration |

OpenAPI specs: [PaloAltoNetworks/pan.dev](https://github.com/PaloAltoNetworks/pan.dev/tree/master/openapi-specs/prisma-airs-redteam)

## Documentation

**[Full interactive documentation](https://rmfincher.github.io/AI-Red-Teaming-Auto/)** — sidebar navigation, CLI reference for all scripts, end-to-end examples, API reference, and troubleshooting.

Or open `docs/index.html` locally in a browser.

## Sample Reports

The `outputs/` directory contains sample reports generated against GPT-4o-mini:
- `static_report_4e64337a.html` — Jailbreak category scan (1104 attacks, 41.4% ASR)
- `dynamic_report_8b0ed608.html` — Agent scan (10 goals, 30 streams, 12.7% ASR)
