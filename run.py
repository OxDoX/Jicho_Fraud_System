"""
CLI entry point.

Usage:
    python3 run.py --data data/sample_transactions.csv --config config/default_config.yaml
"""

import argparse
import json
import sys

import pandas as pd

from jicho.engine import FraudEngine
from jicho.exceptions import JichoError
from jicho.hunting import FraudHunter
from jicho.hunt_suggestions import annotate_alerts_with_hunts


def main():
    parser = argparse.ArgumentParser(description="Jicho fraud detection engine")
    parser.add_argument("--data", required=True, help="Path to transactions CSV")
    parser.add_argument("--config", default=None, help="Path to YAML config (optional)")
    parser.add_argument("--out-json", default="output/alerts.json")
    parser.add_argument("--out-csv", default="output/alerts.csv")
    args = parser.parse_args()

    try:
        df = pd.read_csv(args.data, parse_dates=["timestamp"])
        engine = FraudEngine(config_path=args.config)
        alerts = engine.run(df)
        hunter = FraudHunter(df)
        enriched = annotate_alerts_with_hunts(alerts, hunter)
    except JichoError as e:
        print(f"Jicho error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*70}\nFRAUD ALERT SUMMARY — {len(alerts)} alerts generated\n{'='*70}")
    for a, e in zip(alerts, enriched):
        hunt_count = len(e["suggested_hunts"])
        print(f"[{a.severity:8}] {a.rule_id} {a.rule_name:38} score={a.score}  ({hunt_count} hunt lead(s))")

    with open(args.out_json, "w") as f:
        json.dump(enriched, f, indent=2, default=str)
    pd.DataFrame(enriched).to_csv(args.out_csv, index=False)
    print(f"\nWrote {args.out_json} and {args.out_csv}")


if __name__ == "__main__":
    main()
