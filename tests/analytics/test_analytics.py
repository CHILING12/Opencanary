import json
from datetime import datetime, timezone

from opencanary_analytics.correlation import CorrelationEngine
from opencanary_analytics.ingest import FileTailer
from opencanary_analytics.normalize import normalize_event, parse_line
from opencanary_analytics.pipeline import AnalyticsPipeline
from opencanary_analytics.storage import SQLiteStore


KEY = b"analytics-test-key"


def event(logtype=4002, src="203.0.113.7", port=22, username="root", password="password"):
    return {
        "utc_time": "2026-01-01T00:00:00Z",
        "node_id": "test-node",
        "src_host": src,
        "dst_host": "192.0.2.10",
        "dst_port": port,
        "logtype": logtype,
        "logdata": {"USERNAME": username, "PASSWORD": password},
    }


def test_normalization_redacts_native_secret_fields():
    raw = event()
    raw["logdata"]["VNC Password"] = "never-store-this"
    normalized = normalize_event(raw, KEY)
    rendered = json.dumps(normalized.raw_event)
    assert "never-store-this" not in rendered
    assert "password" not in rendered.lower() or "hmac-sha256:" in rendered
    assert normalized.password_hash
    assert normalized.weak_credential


def test_long_supplied_ids_do_not_collide():
    first = normalize_event({**event(), "event_id": "a" * 128 + "x"}, KEY)
    second = normalize_event({**event(), "event_id": "a" * 128 + "y"}, KEY)
    assert first.event_id != second.event_id
    assert len(first.event_id) <= 128


def test_cross_protocol_correlation_and_no_secret_storage():
    store = SQLiteStore(":memory:")
    pipeline = AnalyticsPipeline(store, KEY)
    outcomes = [
        pipeline.process_line(json.dumps(event(5001, port=22))),
        pipeline.process_line(json.dumps(event(4002, port=22))),
        pipeline.process_line(json.dumps(event(3001, port=80))),
        pipeline.process_line(json.dumps(event(2000, port=21))),
    ]
    assert outcomes[-1].risk.score >= 75
    assert outcomes[-1].risk.severity == "high"
    persisted = store.query_all("SELECT raw_event FROM events")
    assert all("password\"" not in row["raw_event"].lower() or "hmac-sha256:" in row["raw_event"] for row in persisted)


def test_restart_restores_current_aggregate(tmp_path):
    store = SQLiteStore(tmp_path / "events.sqlite3")
    first = AnalyticsPipeline(store, KEY)
    first.process_line(json.dumps(event(4002, port=22, username="safe", password="safe-value")))
    first.process_line(json.dumps(event(3001, port=80, username="safe", password="safe-value")))
    store.close()

    store = SQLiteStore(tmp_path / "events.sqlite3")
    second = AnalyticsPipeline(store, KEY)
    result = second.process_line(json.dumps(event(2000, port=21, username="safe", password="safe-value")))
    assert result.aggregate.event_count == 3
    assert result.aggregate.unique_protocols == {"ssh", "http", "ftp"}
    assert result.risk.score == 25


def test_tailer_keeps_partial_line_until_complete(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_bytes(b'{"logtype":4002')
    store = SQLiteStore(":memory:")
    tailer = FileTailer(log, store, chunk_size=8)
    assert tailer.read_records() == []
    log.write_bytes(b'{"logtype":4002}\n')
    records = tailer.read_records()
    assert [record.line for record in records] == [b'{"logtype":4002}']
    assert store.checkpoint(str(log))[1] == 0
    tailer.acknowledge(records[0])
    assert store.checkpoint(str(log))[1] == len(b'{"logtype":4002}\n')


def test_extended_logtype_is_a_login_attempt():
    normalized = parse_line(json.dumps(event(6001)), KEY)
    assert (normalized.protocol, normalized.event_type) == ("telnet", "login_attempt")


def test_1000_event_simulation_meets_parse_and_dedup_targets():
    import time

    store = SQLiteStore(":memory:")
    pipeline = AnalyticsPipeline(store, KEY)
    lines = []
    for index in range(1000):
        if index % 10 == 0:
            logtype, port = 5001, 22
        elif index % 3 == 0:
            logtype, port = 3001, 80
        elif index % 3 == 1:
            logtype, port = 4002, 22
        else:
            logtype, port = 2000, 21
        item = event(logtype, src=f"203.0.113.{index % 10 + 1}", port=port)
        item["event_id"] = f"fixture-{index}"
        item["utc_time"] = f"2026-01-01T00:{(index // 60) % 60:02d}:{index % 60:02d}Z"
        lines.append(json.dumps(item))
    started = time.monotonic()
    stats = pipeline.process_lines(lines)
    elapsed = time.monotonic() - started
    assert stats.parsed == 1000
    assert stats.malformed == 0
    assert stats.alerts <= 400  # 60%+ fewer alerts than one per event
    assert elapsed < 5
    assert store.query_all("SELECT COUNT(*) AS count FROM events")[0]["count"] == 1000
    assert all("\"PASSWORD\": \"password\"" not in row["raw_event"]
               for row in store.query_all("SELECT raw_event FROM events"))
