-- Normalized alias lookup with trigram index for fuzzy matching
-- This replaces exact-match lookup with normalized token matching and pg_trgm

-- Enable pg_trgm extension (requires superuser)
-- CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Add normalized alias column for fuzzy matching
ALTER TABLE vendor_product_aliases 
  ADD COLUMN IF NOT EXISTS normalized_alias TEXT 
  GENERATED ALWAYS AS (regexp_replace(lower(alias), '[^a-z0-9]', '', 'g')) STORED;

-- Trigram index for fuzzy alias matching (Levenshtein distance <= 2)
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_alias_trigram 
  ON vendor_product_aliases USING GIN (normalized_alias gin_trgm_ops);

-- Add normalized columns to assets for fuzzy vendor/product matching
ALTER TABLE assets 
  ADD COLUMN IF NOT EXISTS normalized_vendor TEXT 
  GENERATED ALWAYS AS (regexp_replace(lower(vendor), '[^a-z0-9]', '', 'g')) STORED,
  ADD COLUMN IF NOT EXISTS normalized_product TEXT 
  GENERATED ALWAYS AS (regexp_replace(lower(product), '[^a-z0-9]', '', 'g')) STORED;

-- Trigram indexes for fuzzy asset matching
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_vendor_trigram 
  ON assets USING GIN (normalized_vendor gin_trgm_ops);
CREATE INDEX CONCURRENTLY IF NOT EXISTS correlation_assets_product_trigram 
  ON assets USING GIN (normalized_product gin_trgm_ops);

-- Fuzzy alias lookup function (Levenshtein distance <= 2)
-- Uses pg_trgm similarity with threshold 0.6 (~edit distance <= 2 for typical lengths)
CREATE OR REPLACE FUNCTION fuzzy_alias_lookup(
  input_alias TEXT,
  max_distance INT DEFAULT 2,
  similarity_threshold REAL DEFAULT 0.6
)
RETURNS TABLE (
  alias TEXT,
  vendor TEXT,
  product TEXT,
  similarity REAL
) LANGUAGE plpgsql STABLE AS $$
DECLARE
  normalized_input TEXT;
BEGIN
  normalized_input := regexp_replace(lower(input_alias), '[^a-z0-9]', '', 'g');
  RETURN QUERY
  SELECT a.alias, a.vendor, a.product,
         similarity(normalized_input, a.normalized_alias) AS sim
  FROM vendor_product_aliases a
  WHERE similarity(normalized_input, a.normalized_alias) >= similarity_threshold
  ORDER BY similarity(normalized_input, a.normalized_alias) DESC
  LIMIT 5;
END;
$$;

-- Fuzzy asset lookup function
CREATE OR REPLACE FUNCTION fuzzy_asset_lookup(
  input_vendor TEXT,
  input_product TEXT,
  similarity_threshold REAL DEFAULT 0.6
)
RETURNS TABLE (
  id UUID,
  vendor TEXT,
  product TEXT,
  version TEXT,
  vendor_similarity REAL,
  product_similarity REAL
) LANGUAGE plpgsql STABLE AS $$
DECLARE
  norm_vendor TEXT;
  norm_product TEXT;
BEGIN
  norm_vendor := regexp_replace(lower(input_vendor), '[^a-z0-9]', '', 'g');
  norm_product := regexp_replace(lower(input_product), '[^a-z0-9]', '', 'g');
  RETURN QUERY
  SELECT a.id, a.vendor, a.product, a.version,
         similarity(norm_vendor, a.normalized_vendor) AS vendor_sim,
         similarity(norm_product, a.normalized_product) AS product_sim
  FROM assets a
  WHERE similarity(norm_vendor, a.normalized_vendor) >= similarity_threshold
     OR similarity(norm_product, a.normalized_product) >= similarity_threshold
  ORDER BY GREATEST(similarity(norm_vendor, a.normalized_vendor), similarity(norm_product, a.normalized_product)) DESC
  LIMIT 20;
END;
$$;

-- Grant execute permissions
GRANT EXECUTE ON FUNCTION fuzzy_alias_lookup(TEXT, INT, REAL) TO PUBLIC;
GRANT EXECUTE ON FUNCTION fuzzy_asset_lookup(TEXT, TEXT, REAL) TO PUBLIC;

-- Populate normalized columns for existing data
UPDATE vendor_product_aliases 
SET normalized_alias = regexp_replace(lower(alias), '[^a-z0-9]', '', 'g')
WHERE normalized_alias IS NULL;

UPDATE assets 
SET normalized_vendor = regexp_replace(lower(vendor), '[^a-z0-9]', '', 'g'),
    normalized_product = regexp_replace(lower(product), '[^a-z0-9]', '', 'g')
WHERE normalized_vendor IS NULL OR normalized_product IS NULL;

INSERT INTO schema_migrations(version) VALUES(16) ON CONFLICT DO NOTHING;