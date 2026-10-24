ALTER TABLE scheduler_state ADD COLUMN IF NOT EXISTS next_catchup_run timestamptz;
