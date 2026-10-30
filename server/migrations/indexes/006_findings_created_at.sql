-- Recent-findings window used by the daily digest (server/dailyDigest.ts).
--
-- The digest selects `kind='findings' AND created_at > now() - interval '24 hours'`.
-- Without an index that is a sequential scan of the whole records table, so the
-- cost of one daily email grows with the entire finding history.
--
-- A plain composite B-tree (kind, created_at) does not help here: `created_at`
-- is not the leading column for a range predicate, and an index on the
-- timestamp alone would be no more selective than the filter. The time window
-- is compared directly against the row's system column, so the index is built
-- on that expression and restricted to the one kind it serves.
--
-- Partial and CONCURRENTLY: records is a live table, the index only covers the
-- `findings` rows (one kind of many), and the build must not hold a table lock
-- that blocks ingestion or delivery.
CREATE INDEX CONCURRENTLY IF NOT EXISTS records_findings_created_at
  ON records (created_at)
  WHERE kind = 'findings';
