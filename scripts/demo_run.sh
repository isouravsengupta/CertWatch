#!/usr/bin/env bash
set -euo pipefail

echo "Running CertWatch demo scan..."
python3 risk_scorer.py \
  --input sample_certs.csv \
  --endpoints-csv sample_endpoints.csv \
  --output-json report_with_endpoints.json

if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
  echo "Posting top risks to Slack..."
  python3 risk_scorer.py \
    --input sample_certs.csv \
    --endpoints-csv sample_endpoints.csv \
    --output-json report_with_endpoints.json \
    --slack-webhook-url "${SLACK_WEBHOOK_URL}" \
    --slack-top-n 5
else
  echo "SLACK_WEBHOOK_URL is not set; skipping Slack post."
fi

echo "Demo complete. Report saved to report_with_endpoints.json"
