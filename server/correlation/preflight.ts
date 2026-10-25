import type { Db } from '../db.ts';
const contracts: Record<string, Record<string, readonly string[]>> = {
  assets: {
    id: ['uuid'],
    vendor: ['text', 'character varying'],
    product: ['text', 'character varying'],
    version: ['text', 'character varying'],
    cpe_23: ['text', 'character varying'],
    purl: ['text', 'character varying'],
  },
  unstructured_advisories: {
    id: ['uuid'],
    title: ['text', 'character varying'],
    content: ['text', 'character varying'],
    url: ['text', 'character varying'],
    fingerprint: ['text', 'character', 'character varying'],
    tsv_content: ['tsvector'],
    processed_at: ['timestamp with time zone', 'timestamp without time zone'],
  },
  vendor_product_aliases: {
    alias: ['text', 'character varying'],
    vendor: ['text', 'character varying'],
    product: ['text', 'character varying'],
  },
};
export interface SchemaPreflight {
  compatible: boolean;
  tablesToCreate: string[];
  issues: string[];
}
/** Read-only. Reports identifiers/types only, never row contents or connection details. */
export async function correlationPreflight(db: Db): Promise<SchemaPreflight> {
  const columns = await db.query<{ table_name: string; column_name: string; data_type: string }>(
    `SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema=current_schema()
    AND table_name=ANY($1::text[])`,
    [Object.keys(contracts)],
  );
  const tablesToCreate: string[] = [],
    issues: string[] = [];
  for (const [table, fields] of Object.entries(contracts)) {
    const actual = columns.rows.filter((row) => row.table_name === table);
    if (!actual.length) {
      tablesToCreate.push(table);
      continue;
    }
    for (const [field, types] of Object.entries(fields)) {
      const column = actual.find((row) => row.column_name === field);
      if (!column) issues.push(`${table}.${field}: required column missing`);
      else if (!types.includes(column.data_type))
        issues.push(`${table}.${field}: incompatible type ${column.data_type}`);
    }
  }
  return { compatible: issues.length === 0, tablesToCreate, issues };
}
