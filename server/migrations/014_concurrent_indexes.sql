-- Concurrent index creation utilities for large tables
-- These indexes are created CONCURRENTLY to avoid blocking writes on production tables.
-- Must be run OUTSIDE a transaction block (PostgreSQL requirement for CONCURRENTLY).

-- Assets table: concurrent index on cpe_23 and purl
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_cpe ON assets(cpe_23) WHERE cpe_23 IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_purl ON assets(purl) WHERE purl IS NOT NULL;
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_names ON assets(lower(vendor),lower(product));

-- Unstructured advisories: concurrent index on fingerprint and url
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_fingerprint ON unstructured_advisories(fingerprint);
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_url ON unstructured_advisories(url);

-- GIN index on tsv_content must be created carefully on large tables
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_advisory_search ON unstructured_advisories USING gin(tsv_content);

-- Alias lookup
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_alias_lookup ON vendor_product_aliases(lower(alias));

-- Low confidence review buffer
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_review_created ON low_confidence_review_buffer(created_at);

-- Correlation matches
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_matches_created ON correlation_matches(created_at DESC);

-- Dead letters
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_dead_letters_created ON correlation_dead_letters(created_at);

-- Pending
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_pending_lease ON correlation_pending(lease_until,created_at);

-- Match index tables (created by migration 008, adding concurrent variants)
CREATE INDEX CONCURRENTLY IF NOT EXISTS match_asset_identities ON match_asset_index USING GIN(identities);
CREATE INDEX CONCURRENTLY IF NOT EXISTS match_asset_version ON match_asset_index(version_ordinal);
CREATE INDEX CONCURRENTLY IF NOT EXISTS match_cve_identities ON match_cve_index USING GIN(identities);
CREATE INDEX CONCURRENTLY IF NOT EXISTS match_cve_cve ON match_cve_index(cve_id);

-- Operational events telemetry table
CREATE INDEX CONCURRENTLY IF NOT EXISTS operational_events_timestamp ON operational_events(timestamp DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS operational_events_tracking ON operational_events(tracking_id) WHERE tracking_id IS NOT NULL;

INSERT INTO schema_migrations(version) VALUES(14) ON CONFLICT DO NOTHING;