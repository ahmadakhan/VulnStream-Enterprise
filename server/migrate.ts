import { createPool, migrate } from './db';
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const pool = createPool(process.env.DATABASE_URL);
try {
  await migrate(pool);
  // The runtime role cannot alter the schema or rewrite audit history.
  if (process.env.GRANT_RUNTIME_ROLE === 'true') {
    await pool.query(`GRANT USAGE ON SCHEMA public TO vulnstream_app;
      GRANT SELECT,INSERT,UPDATE,DELETE ON users,sessions,login_attempts,records,outbox,scheduler_state TO vulnstream_app;
      GRANT SELECT,INSERT ON audit TO vulnstream_app;
      GRANT SELECT,INSERT ON operational_events TO vulnstream_app;
      GRANT SELECT ON schema_migrations TO vulnstream_app;
      GRANT USAGE,SELECT ON SEQUENCE audit_seq_seq,operational_events_id_seq TO vulnstream_app;`);
  }
  console.log('Migrations applied.');
} finally {
  await pool.end();
}
