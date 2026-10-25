-- operational_events was created in migration 002 with only the pipeline-event
-- shape (category/code/message/run_id/context), but the correlation telemetry
-- writer (server/correlation/telemetry.ts) persists a different, per-worker
-- shape (sequence/event/tracking_id/latency columns). On a fresh database every
-- advisory ingest therefore failed with "column sequence does not exist" and
-- was dead-lettered — the correlation pipeline had never worked end to end.
--
-- Both shapes are supported additively: the pipeline columns stay, and the
-- telemetry columns are added nullable so existing rows remain valid.

ALTER TABLE operational_events
  ADD COLUMN IF NOT EXISTS sequence integer,
  ADD COLUMN IF NOT EXISTS timestamp timestamptz,
  ADD COLUMN IF NOT EXISTS event text,
  ADD COLUMN IF NOT EXISTS tracking_id uuid,
  ADD COLUMN IF NOT EXISTS ingestion_latency_ms double precision,
  ADD COLUMN IF NOT EXISTS extraction_latency_ms double precision,
  ADD COLUMN IF NOT EXISTS total_database_time_ms double precision,
  ADD COLUMN IF NOT EXISTS count integer,
  ADD COLUMN IF NOT EXISTS attempt integer;

-- Worker-local sequence numbers restart with every process, so uniqueness must
-- be scoped per writer. Dropping duplicates is safe: telemetry is diagnostic.
CREATE INDEX IF NOT EXISTS operational_events_tracking
  ON operational_events (tracking_id) WHERE tracking_id IS NOT NULL;

INSERT INTO schema_migrations(version) VALUES(22) ON CONFLICT DO NOTHING;
