ALTER TABLE outbox DROP CONSTRAINT IF EXISTS outbox_status_check;
ALTER TABLE outbox ADD CONSTRAINT outbox_status_check
  CHECK(status IN ('REVIEW','QUEUED','SENDING','ACCEPTED','FAILED','REJECTED'));
ALTER TABLE outbox ADD COLUMN IF NOT EXISTS review_approved boolean NOT NULL DEFAULT false;
INSERT INTO schema_migrations(version) VALUES(4) ON CONFLICT DO NOTHING;
