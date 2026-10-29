--
-- 031 — Review-time edits for EVERYONE-distribution advisory emails
--
-- When an advisory is queued to a recipient in the EVERYONE delivery group, the
-- job enters REVIEW status. Operators need to edit the rendered email body and
-- inject additional fields (e.g. an audience notice, a reviewer comment) before
-- the broader distribution is authorised. The edits are stored per-job so they
-- survive review re-opens and are applied to both the email HTML body and the
-- PDF attachment at delivery time.
--
ALTER TABLE outbox
  ADD COLUMN IF NOT EXISTS edits jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Index for fast lookups of jobs that have pending edits while in review.
CREATE INDEX IF NOT EXISTS outbox_edits_review
  ON outbox(created_at)
  WHERE status='REVIEW' AND edits != '{}'::jsonb;

INSERT INTO schema_migrations(version) VALUES(31) ON CONFLICT DO NOTHING;
