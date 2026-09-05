"""Command-line interface for the OpenCanary analytics sidecar.

The CLI deliberately keeps secrets out of configuration files.  Event
processing commands read the HMAC key from an environment variable (by
default ``OPENCANARY_HMAC_KEY``), while database-only commands do not need it.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .correlation import CorrelationEngine
from .ingest import FileTailer, parse_result
from .pipeline import AnalyticsPipeline, PipelineStats
from .rules import RiskEngine
from .storage import SQLiteStore


DEFAULT_DB = "opencanary-analytics.sqlite3"
DEFAULT_HMAC_ENV = "OPENCANARY_ANALYTICS_HMAC_KEY"
DEFAULT_RETENTION_DAYS = 30

# Exit status 2 is reserved for argparse's usage errors.
EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_DATABASE = 4
EXIT_VERIFY = 5


class CLIError(Exception):
    """An expected command-line/configuration error."""


class ConfigError(CLIError):
    """The supplied configuration or required environment is invalid."""


def _json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ConfigError("configuration must be a JSON object")
    return dict(value)


def load_config(path: str | Path | None) -> dict[str, Any]:
    """Load an optional JSON config file.

    A JSON object may also be supplied directly (useful for embedding and
    tests), although normal CLI use passes a file path.
    """
    if path is None or str(path).strip() == "":
        return {}
    text = str(path)
    try:
        if text.lstrip().startswith("{"):
            return _json_object(json.loads(text))
        with open(text, "r", encoding="utf-8") as handle:
            return _json_object(json.load(handle))
    except FileNotFoundError as exc:
        raise ConfigError(f"configuration file not found: {text}") from exc
    except PermissionError as exc:
        raise ConfigError(f"cannot read configuration file: {text}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON configuration: {text}: {exc.msg}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read configuration file: {text}: {exc}") from exc


def _section(config: Mapping[str, Any]) -> dict[str, Any]:
    """Accept either a flat config or an ``analytics`` section."""
    section = config.get("analytics")
    if isinstance(section, Mapping):
        merged = dict(config)
        merged.update(section)
        return merged
    return dict(config)


def _value(args: argparse.Namespace, config: Mapping[str, Any], name: str,
           default: Any, *aliases: str) -> Any:
    for candidate in (name, *aliases):
        value = getattr(args, candidate, argparse.SUPPRESS)
        if value is not argparse.SUPPRESS:
            return value
    for candidate in (name, *aliases):
        if candidate in config:
            return config[candidate]
    return default


def _database_path(args: argparse.Namespace, config: Mapping[str, Any]) -> str:
    value = _value(args, config, "db", DEFAULT_DB, "database", "db_path")
    if value is None or not str(value).strip():
        raise ConfigError("database path must not be empty")
    return str(value)


def hmac_key_from_environment(
    environ: Mapping[str, str] | None = None, env_name: str = DEFAULT_HMAC_ENV
) -> bytes:
    """Return the required HMAC key, without providing an insecure default."""
    values = os.environ if environ is None else environ
    value = values.get(env_name)
    if value is None or not value.strip():
        raise ConfigError(
            f"required HMAC key environment variable {env_name} is not set"
        )
    return value.encode("utf-8")


def _hmac_key(args: argparse.Namespace, config: Mapping[str, Any]) -> bytes:
    env_name = _value(args, config, "hmac_env", DEFAULT_HMAC_ENV)
    if not isinstance(env_name, str) or not env_name.strip():
        raise ConfigError("hmac_env must be a non-empty environment variable name")
    return hmac_key_from_environment(env_name=env_name)


def _as_iterable_config(value: Any, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, (list, tuple, set)):
        raise ConfigError(f"{name} must be a JSON array")
    return tuple(str(item) for item in value)


def _integer(value: Any, name: str, minimum: int = 0) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if result < minimum:
        raise ConfigError(f"{name} must be at least {minimum}")
    return result


def make_pipeline(store: SQLiteStore, key: bytes,
                  config: Mapping[str, Any]) -> AnalyticsPipeline:
    """Build the current pipeline using optional JSON risk settings."""
    config = _section(config)
    risk_config = config.get("risk")
    if not isinstance(risk_config, Mapping):
        risk_config = config.get("risk_engine", {})
    if not isinstance(risk_config, Mapping):
        raise ConfigError("risk/risk_engine must be a JSON object")

    def setting(name: str, default: Any, *aliases: str) -> Any:
        if name in risk_config:
            return risk_config[name]
        for alias in aliases:
            if alias in risk_config:
                return risk_config[alias]
        return _value(argparse.Namespace(), config, name, default, *aliases)

    whitelist = _as_iterable_config(setting("whitelist", ()), "whitelist")
    sensitive = _as_iterable_config(
        setting("sensitive_paths", ("/admin", "/login", "/wp-login", "/.env")),
        "sensitive_paths",
    )
    threats = _as_iterable_config(
        setting("threat_ips", ()), "threat_ips"
    )
    risk = RiskEngine(
        whitelist=whitelist,
        sensitive_paths=sensitive,
        threat_ips=threats,
        connection_threshold=_integer(setting("connection_threshold", 20), "connection_threshold", 1),
        brute_force_threshold=_integer(setting("brute_force_threshold", 5), "brute_force_threshold", 1),
    )
    correlation = CorrelationEngine(
        risk_engine=risk,
        window_seconds=_integer(setting("window_seconds", 300), "window_seconds", 1),
        alert_threshold=_integer(setting("alert_threshold", 30), "alert_threshold", 0),
    )
    return AnalyticsPipeline(store, key, correlation=correlation)


def _input_path(args: argparse.Namespace, config: Mapping[str, Any]) -> str:
    positional = getattr(args, "path", None)
    option = getattr(args, "input_path", argparse.SUPPRESS)
    if option is not argparse.SUPPRESS and option:
        return str(option)
    if positional:
        return str(positional)
    value = _value(args, config, "input", "", "log_path", "path")
    if not value:
        raise ConfigError("an input JSONL file is required")
    return str(value)


def _stats_dict(stats: PipelineStats) -> dict[str, int]:
    return {
        "lines": stats.lines,
        "parsed": stats.parsed,
        "accepted": stats.accepted,
        "duplicates": stats.duplicates,
        "malformed": stats.malformed,
        "filtered": stats.filtered,
        "alerts": stats.alerts,
    }


def _record_stats(stats: PipelineStats, outcome: Any) -> None:
    stats.lines += 1
    if outcome.error:
        stats.malformed += 1
    elif outcome.duplicate:
        stats.duplicates += 1
    else:
        stats.parsed += 1
        stats.accepted += 1
        stats.filtered += int(outcome.filtered)
        stats.alerts += int(outcome.alert is not None)


def _process_records(tailer: FileTailer, pipeline: AnalyticsPipeline) -> PipelineStats:
    """Process records before advancing their durable source checkpoint."""
    stats = PipelineStats()
    for record in tailer.read_records():
        outcome = pipeline.process_line(record.line)
        _record_stats(stats, outcome)
        # Malformed input is a permanent error and is safely consumed; storage
        # errors propagate before this acknowledgement and are retried later.
        tailer.acknowledge(record)
    return stats


def _process_once(path: str, pipeline: AnalyticsPipeline,
                  store: SQLiteStore) -> PipelineStats:
    if not Path(path).is_file():
        raise CLIError(f"input file not found: {path}")
    return _process_records(FileTailer(path, store), pipeline)


def run_ingest(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    path = _input_path(args, config)
    key = _hmac_key(args, config)
    store = SQLiteStore(_database_path(args, config))
    try:
        stats = _process_once(path, make_pipeline(store, key, config), store)
        print(json.dumps(_stats_dict(stats), sort_keys=True))
    finally:
        store.close()
    return EXIT_OK


def run_follow(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    path = _input_path(args, config)
    key = _hmac_key(args, config)
    interval = _value(args, config, "interval", 0.5, "poll_interval")
    try:
        interval = float(interval)
    except (TypeError, ValueError) as exc:
        raise ConfigError("interval must be a number") from exc
    if interval < 0:
        raise ConfigError("interval must not be negative")

    store = SQLiteStore(_database_path(args, config))
    stats = PipelineStats()
    try:
        tailer = FileTailer(path, store)
        pipeline = make_pipeline(store, key, config)
        try:
            while True:
                records = tailer.read_records()
                if not records:
                    time.sleep(interval)
                    continue
                for record in records:
                    outcome = pipeline.process_line(record.line)
                    _record_stats(stats, outcome)
                    tailer.acknowledge(record)
        except KeyboardInterrupt:
            pass
        print(json.dumps(_stats_dict(stats), sort_keys=True))
    finally:
        store.close()
    return EXIT_OK


def _row_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {key: row[key] for key in row.keys()}


def _decode_payloads(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        item = _row_dict(row)
        payload = item.get("payload")
        if isinstance(payload, str):
            try:
                item["payload"] = json.loads(payload)
            except json.JSONDecodeError:
                pass
        result.append(item)
    return result


def run_report(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    store = SQLiteStore(_database_path(args, config))
    try:
        limit = _integer(_value(args, config, "limit", 20), "limit", 1)
        since = _value(args, config, "since", None)
        where = ""
        params: tuple[Any, ...] = ()
        if since is not None:
            days = _integer(since, "since", 0)
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            where = " WHERE timestamp >= ?"
            params = (cutoff,)
        events = store.query_all(f"SELECT COUNT(*) AS count FROM events{where}", params)[0][0]
        aggregate_count = store.query_all("SELECT COUNT(*) AS count FROM aggregates")[0][0]
        alert_where = ""
        alert_params: tuple[Any, ...] = ()
        if since is not None:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=_integer(since, "since", 0))).isoformat()
            alert_where = " WHERE created_at >= ?"
            alert_params = (cutoff,)
        alerts_count = store.query_all(f"SELECT COUNT(*) AS count FROM alerts{alert_where}", alert_params)[0][0]
        recent = store.query_all(
            f"SELECT * FROM alerts{alert_where} ORDER BY created_at DESC LIMIT ?",
            alert_params + (limit,),
        )
        top_sources = store.query_all(
            f"SELECT src_ip, COUNT(*) AS event_count FROM events{where} GROUP BY src_ip ORDER BY event_count DESC LIMIT ?",
            params + (limit,),
        )
        metrics = {
            row["name"]: int(row["value"])
            for row in store.query_all("SELECT name,value FROM metrics ORDER BY name")
        }
        report = {
            "events": int(events),
            "aggregates": int(aggregate_count),
            "alerts": int(alerts_count),
            "metrics": metrics,
            "top_sources": [_row_dict(row) for row in top_sources],
            "recent_alerts": _decode_payloads(recent),
        }
        output_format = _value(args, config, "output_format", "json", "format")
        if output_format == "json":
            print(json.dumps(report, ensure_ascii=False, sort_keys=True))
        elif output_format == "text":
            print(f"events: {report['events']}")
            print(f"aggregates: {report['aggregates']}")
            print(f"alerts: {report['alerts']}")
            if report["top_sources"]:
                print("top sources:")
                for source in report["top_sources"]:
                    print(f"  {source['src_ip']}: {source['event_count']}")
        else:
            raise ConfigError("format must be json or text")
    finally:
        store.close()
    return EXIT_OK


def run_prune(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    days = _integer(_value(args, config, "days", DEFAULT_RETENTION_DAYS), "days", 1)
    store = SQLiteStore(_database_path(args, config))
    try:
        before = {
            table: int(store.query_all(f"SELECT COUNT(*) FROM {table}")[0][0])
            for table in ("events", "aggregates", "alerts")
        }
        store.retention(days)
        after = {
            table: int(store.query_all(f"SELECT COUNT(*) FROM {table}")[0][0])
            for table in before
        }
        print(json.dumps({"days": days, "deleted": {
            table: before[table] - after[table] for table in before
        }}, sort_keys=True))
    finally:
        store.close()
    return EXIT_OK


def run_init_db(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    path = _database_path(args, config)
    store = SQLiteStore(path)
    store.close()
    print(json.dumps({"database": path, "initialized": True}, sort_keys=True))
    return EXIT_OK


def run_verify(args: argparse.Namespace, config: Mapping[str, Any]) -> int:
    path = _database_path(args, config)
    store = SQLiteStore(path)
    valid = True
    details: dict[str, Any] = {"database": path}
    try:
        check = store.query_all("PRAGMA integrity_check")[0][0]
        details["integrity_check"] = check
        valid = check == "ok"
        tables = {row["name"] for row in store.query_all(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        required = {"events", "aggregates", "alerts", "metrics", "checkpoints"}
        missing = sorted(required - tables)
        details["missing_tables"] = missing
        valid = valid and not missing

        input_path = getattr(args, "path", None)
        if input_path:
            key = _hmac_key(args, config)
            checked = malformed = 0
            with open(input_path, "rb") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    checked += 1
                    if parse_result(line, key).event is None:
                        malformed += 1
            details["records_checked"] = checked
            details["malformed_records"] = malformed
            valid = valid and malformed == 0
        print(json.dumps(details, sort_keys=True))
    finally:
        store.close()
    return EXIT_OK if valid else EXIT_VERIFY


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    # SUPPRESS permits a value supplied before the subcommand to survive when
    # the same option is supplied after it (both forms are intentionally valid).
    parser.add_argument("--config", metavar="FILE", default=argparse.SUPPRESS,
                        help="optional JSON configuration file")
    parser.add_argument("--db", "--database", dest="db", default=argparse.SUPPRESS,
                        help=f"SQLite database (default: {DEFAULT_DB})")
    parser.add_argument("--hmac-env", dest="hmac_env", default=argparse.SUPPRESS,
                        help=f"environment variable containing HMAC key (default: {DEFAULT_HMAC_ENV})")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opencanary-analytics",
        description="Ingest and report on OpenCanary JSONL events.",
    )
    _add_common_options(parser)
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="ingest a JSONL file once")
    ingest.add_argument("path", nargs="?", help="JSONL input file")
    ingest.add_argument("--file", dest="input_path", default=argparse.SUPPRESS)
    _add_common_options(ingest)

    follow = subparsers.add_parser("follow", help="follow a JSONL file")
    follow.add_argument("path", nargs="?", help="JSONL input file")
    follow.add_argument("--file", dest="input_path", default=argparse.SUPPRESS)
    follow.add_argument("--interval", "--poll-interval", dest="interval", default=argparse.SUPPRESS, type=float)
    _add_common_options(follow)

    report = subparsers.add_parser("report", help="print an analytics report")
    report.add_argument("--format", "--output-format", dest="output_format", choices=("json", "text"), default=argparse.SUPPRESS)
    report.add_argument("--limit", default=argparse.SUPPRESS, type=int)
    report.add_argument("--since", metavar="DAYS", default=argparse.SUPPRESS, type=int)
    _add_common_options(report)

    prune = subparsers.add_parser("prune", help="remove data older than a retention period")
    prune.add_argument("--days", default=argparse.SUPPRESS, type=int)
    _add_common_options(prune)

    init_db = subparsers.add_parser("init-db", help="create the SQLite schema")
    _add_common_options(init_db)

    verify = subparsers.add_parser("verify", help="verify database integrity, optionally a JSONL file")
    verify.add_argument("path", nargs="?", help="optional JSONL input file to validate")
    _add_common_options(verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit status."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        config = _section(load_config(getattr(args, "config", None)))
        command = args.command
        if command == "ingest":
            return run_ingest(args, config)
        if command == "follow":
            return run_follow(args, config)
        if command == "report":
            return run_report(args, config)
        if command == "prune":
            return run_prune(args, config)
        if command == "init-db":
            return run_init_db(args, config)
        if command == "verify":
            return run_verify(args, config)
        raise ConfigError(f"unknown command: {command}")
    except CLIError as exc:
        print(f"opencanary-analytics: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except (sqlite3.Error, OSError) as exc:
        print(f"opencanary-analytics: {exc}", file=sys.stderr)
        return EXIT_DATABASE


__all__ = [
    "EXIT_CONFIG", "EXIT_DATABASE", "EXIT_OK", "EXIT_PARTIAL", "EXIT_VERIFY",
    "build_parser", "hmac_key_from_environment", "load_config", "main",
    "make_pipeline",
]
