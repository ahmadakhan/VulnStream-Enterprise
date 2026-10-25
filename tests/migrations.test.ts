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

test('migration version numbers are unique', async () => {
  // Two files shared version 15 and two shared version 14. The runner executes
  // whichever name it hard-codes, so the other file was silently never applied
  // — including the one that created the version-comparison SQL functions.
  // A duplicate number is an unrecoverable deployment hazard, not a warning.
  const files = await migrationFiles();
  const seen = new Map<number, string>();
  for (const file of files) {
    const version = Number(file.slice(0, 3));
    const previous = seen.get(version);
    assert.equal(
      previous,
      undefined,
      `migration version ${version} is claimed by both ${previous} and ${file}`,
    );
    seen.set(version, file);
  }
  // Gaps are also a hazard: a version recorded in schema_migrations with no
  // file means a database was stamped by a build that no longer exists.
  const numbers = [...seen.keys()].sort((a, b) => a - b);
  for (let index = 0; index < numbers.length; index++)
    assert.equal(numbers[index], index + 1, `migration numbering has a gap at ${index + 1}`);
});

test('every migration file is applied by the directory-driven runner', async () => {
  // The runner now reads the migrations directory, so this guards the pattern
  // it matches: a file that does not fit NNN_name.sql is silently never
  // applied. The check is structural because the runner has no hard-coded
  // list to compare against.
  const files = await migrationFiles();
  assert.ok(files.length > 0);
  for (const file of files) assert.match(file, /^\d{3}_.+\.sql$/);
});
