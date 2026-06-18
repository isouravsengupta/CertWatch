# CertWatch Demo Presentation Script (8-10 minutes)

Use this script to deliver a clear, high-signal demo for PKI platform teams.

## Demo objective

Show that CertWatch identifies certificate outage risk early, prioritizes what to fix first, and sends actionable alerts to Slack.

## Suggested audience framing (30-45 sec)

Say:

> "This demo focuses on one urgent operational challenge: shrinking certificate lifetimes make manual renewal workflows fail at scale. CertWatch gives early risk visibility across inventory and live TLS endpoints, then pushes prioritized alerts to Slack."

## Live demo flow

## 1) Open with problem + architecture (1 min)

Show `README.md` architecture diagram.

Say:

> "CertWatch ingests cert inventory and endpoint scans, scores risk using explainable factors, outputs JSON for observability, and pushes top risks to Slack."

## 2) Run baseline scan (2 min)

Run:

```bash
python3 risk_scorer.py \
  --input sample_certs.csv \
  --endpoints-csv sample_endpoints.csv \
  --output-json report_with_endpoints.json
```

Say while output appears:

- "The model weights imminent expiry, manual renewal, prod environment, and service criticality."
- "Endpoint scan failures are also treated as risk because failed trust checks can be outage precursors."
- "We can sort instantly by blast radius and urgency."

## 3) Explain top risky rows (2 min)

Use top 3 entries from terminal output.

Say:

- "These are critical because they combine short expiry windows with production and manual renewal."
- "This gives us a clear action queue for teams before incidents."
- "Same risk output is also written to JSON for automation."

## 4) Trigger Slack alert (1-2 min)

Run:

```bash
python3 risk_scorer.py \
  --input sample_certs.csv \
  --endpoints-csv sample_endpoints.csv \
  --output-json report_with_endpoints.json \
  --slack-webhook-url "${SLACK_WEBHOOK_URL}" \
  --slack-top-n 5
```

Say:

> "Now the top risk summary is delivered to channel so owners can respond quickly without waiting for manual reporting."

## 5) Show productionization path (1-2 min)

Point to:

- `.github/workflows/daily-scan.yml`
- `docs/slack-setup.md`

Say:

- "Daily scan runs in GitHub Actions and uploads report artifacts."
- "Slack webhook is kept in secrets; no hardcoded credentials."
- "Next iteration includes EKU policy checks, pinning-risk checks, and private CA trust-list validation."

## Q&A prep (quick answers)

- **What makes this useful now?**  
  "Shrinking lifetimes force automation; this gives immediate risk visibility and triage."
- **How does this help non-paved environments?**  
  "CSV + endpoint mode works without deep platform dependencies."
- **How does this extend to A2A security?**  
  "It becomes the identity hygiene layer: cert freshness, trust compliance, and ownership visibility for machine-to-machine trust."

## Demo fallback plan

If network issues affect endpoint scans:

1. Run inventory-only command.
2. Show existing `report_with_endpoints.json` checked into your local run history.
3. Continue with Slack step and architecture narrative.
