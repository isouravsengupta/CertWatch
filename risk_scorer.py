#!/usr/bin/env python3
"""Cert Expiry + Risk Scorer PoC.

This script models operational pressure caused by shrinking certificate
lifetime policies by scoring upcoming expirations with simple, explainable rules.
Supports:
1) inventory CSV input
2) live TLS endpoint scanning input
3) optional Slack webhook alerts
"""

from __future__ import annotations

import argparse
import csv
import json
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib import error, request


DATE_FMT = "%Y-%m-%d"


@dataclass
class CertRecord:
    service_name: str
    owner_team: str
    environment: str
    cert_id: str
    expires_on: Optional[datetime]
    renewal_automated: bool
    criticality: str
    source: str = "inventory"
    endpoint: Optional[str] = None
    scan_error: Optional[str] = None

    @staticmethod
    def from_row(row: dict) -> "CertRecord":
        expires_on = datetime.strptime(row["expires_on"], DATE_FMT).replace(tzinfo=timezone.utc)
        return CertRecord(
            service_name=row["service_name"],
            owner_team=row["owner_team"],
            environment=row["environment"],
            cert_id=row["cert_id"],
            expires_on=expires_on,
            renewal_automated=row["renewal_automated"].strip().lower() == "true",
            criticality=row["criticality"].strip().lower(),
            source="inventory",
        )


def days_until_expiry(expires_on: datetime, now: datetime) -> int:
    return (expires_on.date() - now.date()).days


def score_cert(record: CertRecord, days_left: Optional[int]) -> tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []

    if record.scan_error:
        score += 85
        reasons.append("endpoint certificate check failed")

    # Lifetime pressure gets stronger as policy windows shrink.
    if days_left is None:
        reasons.append("expiry unknown")
    elif days_left < 0:
        score += 100
        reasons.append("already expired")
    elif days_left <= 7:
        score += 70
        reasons.append("expires within 7 days")
    elif days_left <= 30:
        score += 45
        reasons.append("expires within 30 days")
    elif days_left <= 60:
        score += 25
        reasons.append("expires within 60 days")
    elif days_left <= 200:
        score += 10
        reasons.append("inside 200-day policy pressure window")

    # Manual renewal is a scaling bottleneck.
    if not record.renewal_automated:
        score += 25
        reasons.append("manual renewal path")

    # Production critical services need aggressive risk handling.
    if record.environment == "prod":
        score += 15
        reasons.append("production environment")

    if record.criticality == "high":
        score += 20
        reasons.append("high service criticality")
    elif record.criticality == "medium":
        score += 10
        reasons.append("medium service criticality")

    return min(score, 100), reasons


def risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def load_records(csv_path: Path) -> List[CertRecord]:
    records: List[CertRecord] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required_fields = {
            "service_name",
            "owner_team",
            "environment",
            "cert_id",
            "expires_on",
            "renewal_automated",
            "criticality",
        }
        missing = required_fields - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required CSV columns: {', '.join(sorted(missing))}")
        for row in reader:
            records.append(CertRecord.from_row(row))
    return records


def fetch_endpoint_expiry(hostname: str, port: int, timeout: float) -> tuple[Optional[datetime], Optional[str]]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert = tls_sock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None, "missing notAfter in certificate"
        expires_on = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return expires_on, None
    except Exception as exc:  # noqa: BLE001 - keep endpoint errors visible in report
        return None, str(exc)


def load_endpoint_records(csv_path: Path, timeout: float) -> List[CertRecord]:
    records: List[CertRecord] = []
    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        required_fields = {
            "service_name",
            "owner_team",
            "environment",
            "endpoint",
            "port",
            "renewal_automated",
            "criticality",
        }
        missing = required_fields - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required endpoint CSV columns: {', '.join(sorted(missing))}")

        for row in reader:
            endpoint = row["endpoint"].strip()
            port = int(row["port"])
            expires_on, scan_error = fetch_endpoint_expiry(endpoint, port, timeout)
            cert_id = f"endpoint:{endpoint}:{port}"
            records.append(
                CertRecord(
                    service_name=row["service_name"],
                    owner_team=row["owner_team"],
                    environment=row["environment"],
                    cert_id=cert_id,
                    expires_on=expires_on,
                    renewal_automated=row["renewal_automated"].strip().lower() == "true",
                    criticality=row["criticality"].strip().lower(),
                    source="endpoint_scan",
                    endpoint=f"{endpoint}:{port}",
                    scan_error=scan_error,
                )
            )
    return records


def build_report(records: List[CertRecord], now: datetime) -> dict:
    results = []
    by_level = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for record in records:
        days_left = days_until_expiry(record.expires_on, now) if record.expires_on else None
        score, reasons = score_cert(record, days_left)
        level = risk_level(score)
        by_level[level] += 1
        results.append(
            {
                "service_name": record.service_name,
                "owner_team": record.owner_team,
                "environment": record.environment,
                "cert_id": record.cert_id,
                "expires_on": record.expires_on.strftime(DATE_FMT) if record.expires_on else None,
                "days_until_expiry": days_left,
                "renewal_automated": record.renewal_automated,
                "criticality": record.criticality,
                "source": record.source,
                "endpoint": record.endpoint,
                "scan_error": record.scan_error,
                "risk_score": score,
                "risk_level": level,
                "risk_reasons": reasons,
            }
        )

    results.sort(key=lambda item: item["risk_score"], reverse=True)

    return {
        "generated_at": now.isoformat(),
        "summary": {
            "total_certs": len(results),
            "critical": by_level["critical"],
            "high": by_level["high"],
            "medium": by_level["medium"],
            "low": by_level["low"],
        },
        "results": results,
    }


def print_table(report: dict) -> None:
    print("Cert Expiry + Risk Scorer")
    print("=" * 86)
    print(
        f"{'Service':20} {'Env':5} {'Days':>5} {'Auto':>5} "
        f"{'Crit':>6} {'Score':>5} {'Level':>9} {'Source':>11}"
    )
    print("-" * 86)
    for row in report["results"]:
        days_str = "n/a" if row["days_until_expiry"] is None else str(row["days_until_expiry"])
        print(
            f"{row['service_name'][:20]:20} "
            f"{row['environment'][:5]:5} "
            f"{days_str:>5} "
            f"{str(row['renewal_automated'])[:5]:>5} "
            f"{row['criticality'][:6]:>6} "
            f"{row['risk_score']:>5} "
            f"{row['risk_level']:>9} "
            f"{row['source'][:11]:>11}"
        )
    print("-" * 86)
    s = report["summary"]
    print(
        "Summary: "
        f"total={s['total_certs']} critical={s['critical']} high={s['high']} "
        f"medium={s['medium']} low={s['low']}"
    )


def post_to_slack(webhook_url: str, report: dict, top_n: int = 5) -> None:
    summary = report["summary"]
    top_results = report["results"][:top_n]
    lines = [
        "*Cert Expiry Risk Report*",
        (
            "Summary: "
            f"total={summary['total_certs']} critical={summary['critical']} "
            f"high={summary['high']} medium={summary['medium']} low={summary['low']}"
        ),
        "",
        "*Top Risks:*",
    ]
    for row in top_results:
        days = "n/a" if row["days_until_expiry"] is None else str(row["days_until_expiry"])
        lines.append(
            f"- `{row['service_name']}` ({row['environment']}) "
            f"score={row['risk_score']} level={row['risk_level']} days={days}"
        )
    payload = {"text": "\n".join(lines)}
    req = request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=10) as resp:  # noqa: S310
            if resp.status >= 300:
                raise RuntimeError(f"Slack webhook failed with status {resp.status}")
    except error.URLError as exc:
        raise RuntimeError(f"Failed to post Slack alert: {exc}") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score certificate renewal risk under shrinking lifetime policies."
    )
    parser.add_argument(
        "--input",
        default="sample_certs.csv",
        help="Path to CSV input with certificate metadata.",
    )
    parser.add_argument(
        "--endpoints-csv",
        default=None,
        help=(
            "Optional endpoint CSV path to perform live TLS cert checks. "
            "Rows are merged with --input data."
        ),
    )
    parser.add_argument(
        "--output-json",
        default="report.json",
        help="Path to write JSON report.",
    )
    parser.add_argument(
        "--as-of",
        default=None,
        help="Override current date in YYYY-MM-DD format for deterministic demos.",
    )
    parser.add_argument(
        "--endpoint-timeout-seconds",
        type=float,
        default=3.0,
        help="Network timeout used for live endpoint checks.",
    )
    parser.add_argument(
        "--slack-webhook-url",
        default=None,
        help="Optional Slack Incoming Webhook URL for alert posting.",
    )
    parser.add_argument(
        "--slack-top-n",
        type=int,
        default=5,
        help="Top N risky services to include in Slack message.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output_json)

    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    now = datetime.now(timezone.utc)
    if args.as_of:
        now = datetime.strptime(args.as_of, DATE_FMT).replace(tzinfo=timezone.utc)

    records = load_records(input_path)
    if args.endpoints_csv:
        endpoint_path = Path(args.endpoints_csv)
        if not endpoint_path.exists():
            raise FileNotFoundError(f"Endpoint input file not found: {endpoint_path}")
        endpoint_records = load_endpoint_records(endpoint_path, args.endpoint_timeout_seconds)
        records.extend(endpoint_records)

    report = build_report(records, now)

    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print_table(report)
    print(f"\nWrote JSON report to: {output_path}")
    if args.slack_webhook_url:
        post_to_slack(args.slack_webhook_url, report, args.slack_top_n)
        print("Posted risk summary to Slack webhook.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
