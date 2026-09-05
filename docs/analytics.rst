OpenCanary analytics sidecar
=============================

``opencanary-analytics`` is a separate, SQLite-backed event-analysis sidecar.
It consumes newline-delimited JSON emitted by OpenCanary's existing file logger;
it does not change the network-facing protocol modules or daemon lifecycle.

Security model
--------------

Set ``OPENCANARY_ANALYTICS_HMAC_KEY`` to a non-empty secret before using
``ingest`` or ``follow``.  The sidecar derives a stable HMAC-SHA256 password
fingerprint, redacts password-like fields recursively, and never writes
plaintext credentials to its database or webhook notifications.  Use the
sample configuration at ``analytics/analytics.example.json`` and pass secrets
through the environment, as illustrated by ``analytics/analytics.env.example``.

The source OpenCanary JSON log may still contain plaintext credentials before
the sidecar reads it. Restrict its permissions, use a short rotation/retention
period, and treat it as sensitive. The sidecar database and reports do not
need plaintext credential access.

Commands
--------

Initialize a database::

    opencanary-analytics init-db --db /var/lib/opencanary-analytics/events.sqlite3

Ingest all complete JSON records currently in a log file::

    export OPENCANARY_ANALYTICS_HMAC_KEY='long-random-value'
    opencanary-analytics ingest /var/tmp/opencanary.log \
      --db /var/lib/opencanary-analytics/events.sqlite3

Follow a rotating file continuously::

    opencanary-analytics follow /var/tmp/opencanary.log \
      --config analytics/analytics.example.json

Show database health and optionally validate an input file::

    opencanary-analytics verify /var/tmp/opencanary.log --db events.sqlite3

``report`` prints an operational JSON/text summary; daily Markdown reports can
be produced with ``opencanary_analytics.report.generate_markdown(store, date)``.
``prune --days 30`` enforces the data-retention period.

Behavior and scoring
--------------------

Events are normalized to UTC and deduplicated by deterministic event ID.
The sidecar preserves source/destination, protocol, type, username, user agent,
and a redacted raw-event audit record.  It aggregates each source in fixed
five-minute UTC windows and retains first/last observation time, count, unique
ports, and unique protocols. Correlation state is reconstructed from SQLite
when the worker restarts.

The default explainable rules add these points:

* three or more protocols: +25;
* port scan: +30;
* default account or weak credential: +20;
* sensitive path: +20;
* high event volume: +15;
* threat-intelligence source: +40;
* brute-force threshold: +20;
* whitelist match: -30.

Risk levels are low (0--29), medium (30--59), high (60--79), and critical
(80+). Whitelisted events remain stored for reports but do not create alerts.
Webhook alerts include severity, source, protocols/ports, first/last time,
count, tags, score, and rule explanations. They exclude password, username,
and raw-event content. Webhook sends use bounded retries; failures remain in
SQLite for a later retry through ``AnalyticsPipeline.retry_pending_notifications``.

File rotation
-------------

The tailer tracks inode and byte offset in SQLite, handles normal rename
rotation and size-reducing truncation, buffers incomplete final lines, and
acknowledges a record only after normalization and durable pipeline processing.
A malformed line is recorded as an ingestion error and consumed so it cannot
block later valid records. Mount the log read-only for the sidecar and grant
write access only to its database/report directory.
