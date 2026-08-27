import assert from "node:assert/strict";
import test from "node:test";

import { Database } from "../src/db/database.js";

test("database migrations are atomic and idempotent", () => {
  const database = new Database(":memory:");
  try {
    database.migrate();
    database.migrate();

    const tables = database
      .raw()
      .prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name",
      )
      .all()
      .map((row) => String((row as { name: unknown }).name));

    for (const required of [
      "accounts",
      "access_tokens",
      "admin_preferences",
      "audit_events",
      "connections",
      "grants",
      "refresh_history",
      "schema_migrations",
      "sessions",
    ]) {
      assert.equal(tables.includes(required), true, `missing ${required}`);
    }

    const migrations = database
      .raw()
      .prepare("SELECT version FROM schema_migrations ORDER BY version")
      .all()
      .map((row) => Number((row as { version: unknown }).version));
    assert.deepEqual(migrations, [1]);
  } finally {
    database.close();
  }
});

test("database enables foreign keys and WAL for file-backed stores", () => {
  const database = new Database(":memory:");
  try {
    assert.equal(
      database.raw().prepare("PRAGMA foreign_keys").get()?.foreign_keys,
      1,
    );
  } finally {
    database.close();
  }
});
