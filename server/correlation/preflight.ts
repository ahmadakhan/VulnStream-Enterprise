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
    fingerprint: ['character', 'character varying'],
    tsv_content: ['tsvector'],
    processed_at: ['timestamp with time zone', 'timestamp without time zone'],
  },
  vendor_product_aliases: {
    alias: ['text', 'character varying'],
    vendor: ['text', 'character varying'],
    product: ['text', 'character varying'],
  },
};

const uniqueIndexes: Record<string, readonly string[]> = {
  unstructured_advisories: ['fingerprint', 'url'],
  vendor_product_aliases: ['alias'],
};

const generatedColumns: Record<string, readonly string[]> = {
  unstructured_advisories: ['tsv_content'],
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

  const existingTables = Array.from(
    new Set(columns.rows.filter((row) => row.column_name === 'id').map((row) => row.table_name)),
  );

  if (existingTables.length) {
    // --- Unique index verification ---
    // ON CONFLICT clauses require backing UNIQUE indexes. A missing index on
    // fingerprint or url turns a race condition into a hard 23505 error that
    // dead-letters the advisory instead of merging it.
    const indexRows = await db.query<{
      tablename: string;
      indexname: string;
      indexdef: string;
    }>(
      `SELECT tablename,indexname,indexdef FROM pg_indexes WHERE schemaname=current_schema() AND tablename=ANY($1)`,
      [existingTables],
    );

    const uniqueByTable = new Map<string, Set<string>>();
    for (const row of indexRows.rows) {
      const def = row.indexdef;
      const uniqueMatch = def.match(/CREATE UNIQUE INDEX \w+ ON \w+\.(\w+) (?:USING \w+ )?\(([^)]+)\)/);
      if (uniqueMatch) {
        const tbl = uniqueMatch[1];
        const colList = uniqueMatch[2]
          .split(',')
          .map((c) => c.trim().replace(/^.*\((.+)\)$/, '$1'))
          .join(',')
          .toLowerCase();
        uniqueByTable.set(tbl, (uniqueByTable.get(tbl) ?? new Set()).add(colList));
      }
    }

    for (const [table, cols] of Object.entries(uniqueIndexes)) {
      const actual = uniqueByTable.get(table);
      if (actual) {
        for (const col of cols) {
          if (!actual.has(col.toLowerCase()))
            issues.push(`${table}: missing unique index on ${col}`);
        }
      }
    }

    // --- Index validity verification ---
    // pg_index.indisvalid catches incomplete indexes from a crashed CREATE INDEX
    // CONCURRENTLY. An invalid index is never used for constraint enforcement.
    const invalidIndexRows = await db.query<{ indexname: string }>(
      `SELECT index.relname AS indexname
       FROM pg_index index
       JOIN pg_class cls ON cls.oid = index.indexrelid
       JOIN pg_namespace ns ON ns.oid = cls.relnamespace
       WHERE ns.nspname = current_schema()
         AND index.indisunique IS TRUE
         AND index.indisvalid IS FALSE`,
    );
    for (const row of invalidIndexRows.rows)
      issues.push(`Unique index ${row.indexname}: not valid (incomplete CREATE INDEX CONCURRENTLY?)`);

    // --- Generated column verification ---
    // tsv_content must be GENERATED ALWAYS AS (...) STORED. A plain column or
    // a generated column in a different mode breaks the full-text search contract.
    const genColumnRows = await db.query<{
      table_name: string;
      column_name: string;
      attgenerated: string;
    }>(
      `SELECT c.relname AS table_name, a.attname AS column_name, a.attgenerated
       FROM pg_attribute a
       JOIN pg_class c ON c.oid = a.attrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = current_schema()
         AND a.attname = ANY($1)
         AND a.attnum > 0 AND a.attisdropped IS FALSE`,
      [Array.from(new Set(Object.values(generatedColumns).flat()))],
    );
    const genColumns = new Set(genColumnRows.rows.map((r) => `${r.table_name}.${r.column_name}`));
    for (const [table, cols] of Object.entries(generatedColumns))
      for (const col of cols)
        if (!genColumns.has(`${table}.${col}`))
          issues.push(`${table}.${col}: expected generated column, found plain column`);

    // --- CHECK constraint verification ---
    const checkRows = await db.query<{
      table_name: string;
      check_clause: string;
    }>(
      `SELECT c.relname AS table_name,
              regexp_replace(pg_get_constraintdef(con.oid), '^CHECK\\(|\\)$', '', 'g') AS check_clause
       FROM pg_constraint con
       JOIN pg_class c ON c.oid = con.conrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = current_schema()
         AND con.contype = 'c'
         AND c.relname = ANY($1)`,
      [existingTables],
    );
    const checkSet = new Set(
      checkRows.rows.map((r) => `${r.table_name}:${r.check_clause.replace(/\s+/g, ' ')}`),
    );
    const requiredChecks: Record<string, string[]> = {
      correlation_matches: ["confidence IN ('HIGH', 'MEDIUM')"],
      low_confidence_review_buffer: ["confidence='LOW'"],
    };
    for (const [table, clauses] of Object.entries(requiredChecks))
      for (const clause of clauses)
        if (!checkSet.has(`${table}:${clause}`))
          issues.push(`${table}: missing CHECK constraint for ${clause}`);
  }

  return { compatible: issues.length === 0, tablesToCreate, issues };
}
