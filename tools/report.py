"""Run the whole pipeline from the command line and write a Markdown report.

    python -m tools.report data/attacks --out investigation.md
    python -m tools.report /var/log/auth.log /var/log/nginx/access.log
    python -m tools.report data/attacks --incident LH-2026-003 --out one.md

Useful for CI, for cron, and for checking the toolkit without the dashboard.
Exits 1 when a critical-risk incident is found, so it can gate a pipeline.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys

import parser
from correlation import correlate
from detection import DetectionConfig, run_all
from reports import incident_report, investigation_report
from scoring import risk as risk_scoring


def collect_paths(inputs: list[str]) -> list[str]:
    paths: list[str] = []
    for item in inputs:
        if os.path.isdir(item):
            for pattern in ("*.log", "*.txt", "*.csv", "*.json"):
                paths.extend(sorted(glob.glob(os.path.join(item, pattern))))
        else:
            paths.extend(sorted(glob.glob(item)) or [item])
    return [p for p in paths if os.path.isfile(p)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="LogHunt command-line investigation")
    ap.add_argument("inputs", nargs="+", help="log files, globs, or directories")
    ap.add_argument("--out", help="write Markdown here instead of stdout")
    ap.add_argument("--incident", help="report on one incident id only")
    ap.add_argument("--min-risk", type=int, default=0,
                    help="only report incidents at or above this risk score")
    ap.add_argument("--quiet", action="store_true", help="suppress the summary")
    args = ap.parse_args(argv)

    paths = collect_paths(args.inputs)
    if not paths:
        print("no log files matched", file=sys.stderr)
        return 2

    result = parser.parse_files(paths)
    if result.events.empty:
        print("no events parsed from the supplied files", file=sys.stderr)
        return 2

    config = DetectionConfig()
    alerts = risk_scoring.score_alerts(run_all(result.events, config), config)
    incidents = correlate(alerts, result.events, config)
    incidents = [i for i in incidents if i.risk >= args.min_risk]

    if args.incident:
        match = [i for i in incidents if i.incident_id == args.incident]
        if not match:
            print(f"incident {args.incident} not found", file=sys.stderr)
            return 2
        report = incident_report(match[0], result.events, config)
    else:
        report = investigation_report(incidents, alerts, result.events,
                                      result.summary(), config)

    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(report)
    else:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(report)

    if not args.quiet:
        critical = [i for i in incidents if i.risk_band == "CRITICAL"]
        summary = (f"{len(result.events):,} events -> {len(alerts)} alerts -> "
                   f"{len(incidents)} incidents ({len(critical)} critical)")
        print(summary, file=sys.stderr)
        for incident in incidents[:5]:
            print(f"  {incident.incident_id}  {incident.risk:3d}/100 "
                  f"{incident.risk_band:8} {incident.title}", file=sys.stderr)
        if args.out:
            print(f"  report written to {args.out}", file=sys.stderr)
        return 1 if critical else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
