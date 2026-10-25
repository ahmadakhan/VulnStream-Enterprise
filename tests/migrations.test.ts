import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { REQUIRED_SCHEMA_VERSION } from '../server/db.ts';

const migrationsDir = fileURLToPath(new URL('../server/migrations/', import.meta.url));

async function migrationFiles(): Promise<string[]> {
  return (await readdir(migrationsDir)).filter((file) => /^\d+_.*\.sql$/.test(file)).sort();
}

test('every migration records its own schema version', async () => {
  for (const file of await migrationFiles()) {
    const version = Number(file.slice(0, 3));
    const sql = await readFile(path.join(migrationsDir, file), 'utf8');
    // Without this marker the migration is re-applied on every startup and the
    // production gate cannot distinguish an upgraded database from a stale one.
    assert.match(
      sql,
      new RegExp(`INSERT INTO schema_migrations\\s*\\(version\\)\\s*VALUES\\s*\\(\\s*${version}\\s*\\)`),
      `${file} must record schema version ${version}`,
    );
  }
});

test('the production schema gate tracks the newest migration', async () => {
  const versions = (await migrationFiles()).map((file) => Number(file.slice(0, 3)));
  assert.equal(REQUIRED_SCHEMA_VERSION, Math.max(...versions));
});
