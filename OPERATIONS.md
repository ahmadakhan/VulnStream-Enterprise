# Operations

## Configuration and release

Keep `.env.production` out of source control and restrict host access. Protect database backups and the encryption key separately. Use a firewall to expose only 80/443 and your administrative access. Keep Docker, PostgreSQL, Caddy and Node base images patched; rebuild and test releases before rollout. The supplied image runs as a non-root user, with a read-only application filesystem, dropped capabilities and no privilege escalation. Set resource limits and monitoring to match your host and workload.

Release with `docker compose --env-file .env.production up -d --build`. Confirm the migration job exits successfully, `docker compose --env-file .env.production ps` reports healthy services, and sign-in, a pipeline and a test delivery work. Before upgrading, take a backup and test restoration. Do not run older code against a newer schema unless compatibility has been verified. Stop application traffic before a rollback requiring database restoration.

The runtime's `/live` endpoint reports process availability and `/ready` checks PostgreSQL. Neither certifies feed freshness or successful delivery. Monitor authenticated System Health, feed errors, execution failures, queue depth, failed deliveries, database size and worker heartbeat (normally updated every five seconds outside an active run). Alert on heartbeat staleness relative to your maximum ingestion time. Logs are JSON on standard output; retain and restrict access through your platform. Feed/provider error details may contain operational information.

## Back up

Run from the repository directory on the Docker host. Backups are consistent PostgreSQL custom-format dumps. Restrict destination permissions and encrypt off-host copies.

```sh
umask 077
mkdir -p backups
docker compose --env-file .env.production exec -T db pg_dump -U vulnstream_migrator -d vulnstream -Fc > "backups/vulnstream-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Check the command exit status and verify archive contents with `pg_restore --list`. Back up the protected deployment configuration and `ENCRYPTION_KEY` separately. Regularly restore to an isolated environment and verify accounts, inventory, audit history and decryption. A database dump alone cannot recover encrypted secrets without the matching key. Define backup frequency and retention from your recovery objectives.

## Restore

Restore into a fresh, isolated Compose project first. Initialize its database with the same database/role names and new protected database passwords. Keep `app` and `proxy` stopped. For example, with the intended project's environment and dump paths:

```sh
docker compose --env-file .env.production stop app proxy
docker compose --env-file .env.production up -d db
# This replaces data in the selected database. Confirm the target before running.
docker compose --env-file .env.production exec -T db pg_restore -U vulnstream_migrator -d vulnstream --clean --if-exists --exit-on-error < backups/SELECTED.dump
docker compose --env-file .env.production run --rm migrate
docker compose --env-file .env.production up -d app proxy
```

Use the encryption key corresponding to the backup. Restore tests must have external SMTP/webhook/feed egress blocked: restored pending jobs can resume. In a real recovery, reconcile provider receipts before restarting delivery to avoid duplicate messages. Sessions in the backup can be invalidated by an administrator running `DELETE FROM sessions` using the database owner role.

## Credentials and delivery

Rotate database passwords using PostgreSQL role administration and update the protected environment together. Re-enter feed/webhook credentials to rotate them. Changing `ENCRYPTION_KEY` does not automatically re-encrypt existing values: retain the original key, disable scheduling/delivery, and plan a controlled re-encryption migration before rotation. Never discard the old key until backups no longer require it.

SMTP uses TLS (implicit on 465, required STARTTLS otherwise), certificate validation and bounded timeouts. Generic webhooks carry `X-VulnStream-Signature`, `X-VulnStream-Timestamp` and `Idempotency-Key`; verify the HMAC over `timestamp + '.' + exact body` and reject stale timestamps at the receiver. Check the source for exact header casing (HTTP headers are case-insensitive). Slack/Teams payloads use their supported text format.

Jobs retry transient failures up to six attempts with backoff; permanent 4xx responses except 408/429 fail immediately. Failed jobs can be explicitly retried. A crash after remote acceptance and before local commit can duplicate a delivery, even with durable storage. Do not describe `ACCEPTED` as delivered/read. Use provider telemetry for those claims.

## Capacity and audit boundaries

This release uses a complete inventory/CVE snapshot for correlation and the UI, and serializes state-changing transactions. It is intended for a bounded organizational inventory; it has not been load-tested for a full historical NVD mirror or high concurrent operator counts. Measure representative ingestion, memory, response size and transaction latency before setting deployment capacity. The NVD window is bounded to 120 days/50,000 results per run, EPSS to 500,000, and individual responses to 8 MiB. Oversized feeds fail explicitly. Choose an appropriate ingestion window; do not silently assume a partial scan is complete.

The UI retains the latest 500 audit entries while the database retains the full chain. Application-role audit writes are append-only; a database owner can still alter schema/data or truncate history. Export audit records to independently controlled immutable storage if tamper evidence against administrators is required. No automated business-record retention/deletion policy is enabled; monitor storage and define an approved archival policy.

Matching does not implement every vendor version convention or full NIST applicability logic. Review flagged matches and vendor advisories. Live provider compatibility, public TLS issuance, restore objectives, accessibility and deployment load require acceptance testing in the target environment.

### Feed timeout recovery

Threat Sources supports a request timeout (5–120 seconds) and recovery delay (1–60 minutes) per source. Existing sources retain adapter timeout defaults until configured. Failed ingestion schedules recovery after five minutes by default, doubling after repeated failures up to one hour. The enabled worker retries due sources automatically, including when the regular pipeline scheduler is disabled. Recovery runs the pipeline so recovered intelligence is correlated normally. Successful ingestion clears the failure counter and retry deadline; disabling a source prevents automatic recovery. Retry deadlines appear beside failed sources and persist across server restarts. Recovery requires `WORKER_ENABLED=true` and can wait for an active pipeline to finish.

Feed ingestion has a total per-source budget controlled by `FEED_MAX_DURATION_SECONDS` (default 1800; range 1–7200). It includes pagination and retry waits; individual requests are capped to the remaining budget. A source exceeding this budget discards its incomplete response and enters automatic recovery. Empty EPSS scopes clear expired retry state without claiming verified connectivity. Loss of the worker lock connection prevents further source requests and commits. Ingestion phases report warnings when sources return partial parsing warnings.

### MITRE CVE source

The enabled `MITRE CVE — Official CVE List` source is added once on upgrade and on fresh deployments. It reads the official CVE Program repository at `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json`, then fetches CVE JSON 5 records by validated CVE ID. No API key is required. Add `raw.githubusercontent.com` to any custom `EGRESS_ALLOWED_HOSTS`; the bundled defaults already include it. Restart the server to run the source bootstrap. Operator changes and later deletions are preserved.

The adapter filters the rolling change log by the pipeline scope, retrieves each CVE once even if listed repeatedly, and caps a run at 5,000 unique records. Scopes exceeding 30 days report a warning because this incremental feed cannot supply a full historical CVE corpus. Larger windows that exceed the record cap fail explicitly; reduce the ingestion scope rather than importing partial results. Source request timeouts and the overall feed duration budget still apply. The log permits a 64 MiB response, and individual records permit 4 MiB.

Published records participate in the existing correlation engine; rejected records participate in withdrawal handling. CVE JSON version rules may contain exceptions or custom version schemes, so MITRE matches require applicability review and cannot initiate automatic dispatch on their own. CPEs, CNA product descriptions, CVSS metrics, CWE IDs and advisory references are retained. Canonical CVE-ID merging combines source attribution across MITRE, NVD and other feeds, while the existing CVE-and-asset finding identity prevents repeated findings across runs. Newer source revisions retain the existing revision-selection behavior.
