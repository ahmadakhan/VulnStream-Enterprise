ALTER TABLE outbox ADD COLUMN IF NOT EXISTS priority smallint NOT NULL DEFAULT 0;
COMMENT ON COLUMN outbox.priority IS 'Higher values are delivered first: CISA_KEV=100, zero-day=50, routine=0';
