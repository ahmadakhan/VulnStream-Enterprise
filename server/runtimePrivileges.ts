import type { Db } from './db.ts';
/** Shared by migration bootstrap and restricted-role integration checks. */
export async function grantRuntimePrivileges(db: Db, role = 'vulnstream_app'): Promise<void> {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(role)) throw new Error('INVALID_RUNTIME_ROLE');
  const schema = (await db.query<{ schema: string }>('SELECT current_schema() AS schema')).rows[0].schema;
  const quotedSchema = '"' + schema.replaceAll('"', '""') + '"';
  const target = '"' + role + '"';
  await db.query(`GRANT USAGE ON SCHEMA ${quotedSchema} TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON users,sessions,login_attempts,records,outbox,scheduler_state,rate_limit_buckets TO ${target};
    GRANT SELECT,INSERT ON audit,operational_events TO ${target};
    GRANT SELECT ON assets,vendor_product_aliases,correlation_asset_inventory,schema_migrations TO ${target};
    GRANT SELECT,INSERT,UPDATE ON unstructured_advisories TO ${target};
    GRANT SELECT,INSERT,DELETE ON correlation_matches,correlation_dead_letters,low_confidence_review_buffer TO ${target};
    GRANT SELECT,INSERT,UPDATE,DELETE ON correlation_pending,correlation_managed_assets,correlation_match_evidence,
      correlation_review_decisions,correlation_dead_letter_actions,correlation_notifications TO ${target};
    GRANT SELECT,UPDATE ON correlation_policy TO ${target};
    GRANT USAGE,SELECT ON SEQUENCE audit_seq_seq,operational_events_id_seq TO ${target};
    GRANT EXECUTE ON FUNCTION consume_rate_limit_token(text,double precision,double precision) TO ${target};`);
}
