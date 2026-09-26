import argparse
import json
import logging

from app.ingestion.runner import run_sync


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel OSS ingestion jobs")
    parser.add_argument(
        "command", choices=["ingest"], help="Run checkpointed external-source ingestion"
    )
    parser.add_argument(
        "--sources",
        default="all",
        help="Comma-separated: gharchive,advisories,osv or all",
    )
    parser.add_argument("--lookback-hours", type=int, default=2)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    sources = {value.strip() for value in args.sources.split(",") if value.strip()}
    print(json.dumps(run_sync(sources, max(1, args.lookback_hours)), sort_keys=True))


if __name__ == "__main__":
    main()
