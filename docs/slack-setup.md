# Slack setup for CertWatch

Use this guide to post CertWatch risk summaries into a Slack channel.

## 1) Create an Incoming Webhook

1. Go to [https://api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App**.
3. Pick **From scratch** and name it `CertWatch`.
4. Choose your workspace.
5. In **Features**, open **Incoming Webhooks** and enable it.
6. Click **Add New Webhook to Workspace**.
7. Select your target channel (for example, `#pki-alerts`).
8. Copy the webhook URL.

## 2) Local test

From repo root:

```bash
python3 risk_scorer.py \
  --input sample_certs.csv \
  --endpoints-csv sample_endpoints.csv \
  --output-json report_with_endpoints.json \
  --slack-webhook-url "https://hooks.slack.com/services/XXX/YYY/ZZZ" \
  --slack-top-n 5
```

Expected result:

- terminal prints score summary
- Slack channel receives `Cert Expiry Risk Report`

## 3) GitHub Actions setup

1. Open repo **Settings** -> **Secrets and variables** -> **Actions**.
2. Add new repository secret:
   - Name: `SLACK_WEBHOOK_URL`
   - Value: your webhook URL
3. Run **CertWatch Daily Scan** workflow manually once from the **Actions** tab.
4. Confirm:
   - Workflow succeeds
   - `certwatch-report` artifact is uploaded
   - Slack message is posted

## 4) Demo checklist

- [ ] Endpoint scan runs without network errors
- [ ] At least one high/critical entry appears in output
- [ ] Slack summary includes top risks
- [ ] Artifact report is available in workflow run

## 5) Security notes

- Never commit webhook URLs in code.
- Always store webhook URLs in secrets (`SLACK_WEBHOOK_URL`).
- Rotate webhook URLs if leaked.
