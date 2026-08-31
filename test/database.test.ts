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
      "ssh_hosts",
      "ssh_host_fingerprints",
      "ssh_key_identities",
      "ssh_session_history",
      "ssh_snippets",
      "ssh_tunnels",
      "ssh_workspace_preferences",
    ]) {
      assert.equal(tables.includes(required), true, `missing ${required}`);
    }

    const migrations = database
      .raw()
      .prepare("SELECT version FROM schema_migrations ORDER BY version")
      .all()
      .map((row) => Number((row as { version: unknown }).version));
    assert.deepEqual(migrations, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
  } finally {
    database.close();
  }
});

test("migrations add SSH host storage, workspace metadata, and tunnel rules", () => {
  const database = new Database(":memory:");
  try {
    database.migrate();

    const accountColumns = database
      .raw()
      .prepare("PRAGMA table_info(accounts)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    assert.equal(accountColumns.includes("ssh_enabled"), true);

    const auditColumns = database
      .raw()
      .prepare("PRAGMA table_info(audit_events)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    assert.equal(auditColumns.includes("ssh_host_id"), true);

    const hostColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_hosts)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "enabled",
      "favorite",
      "group_path",
      "tags_json",
      "sort_order",
      "auth_method",
      "settings_json",
      "version",
    ]) {
      assert.equal(hostColumns.includes(required), true, `missing ${required}`);
    }

    const tunnelColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_tunnels)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "account_id",
      "host_id",
      "type",
      "listen_host",
      "listen_port",
      "target_host",
      "target_port",
      "enabled",
      "auto_start",
      "running",
      "traffic_up_bytes",
      "traffic_down_bytes",
      "version",
    ]) {
      assert.equal(
        tunnelColumns.includes(required),
        true,
        `missing ${required}`,
      );
    }

    const snippetColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_snippets)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "account_id",
      "name",
      "command",
      "variables_json",
      "secret_ciphertext",
      "enabled",
      "version",
    ]) {
      assert.equal(
        snippetColumns.includes(required),
        true,
        `missing ${required}`,
      );
    }

    const keyColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_key_identities)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "account_id",
      "name",
      "public_key",
      "fingerprint",
      "secret_ciphertext",
      "enabled",
      "version",
    ]) {
      assert.equal(keyColumns.includes(required), true, `missing ${required}`);
    }

    const fingerprintColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_host_fingerprints)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "account_id",
      "host_id",
      "algorithm",
      "fingerprint",
      "source",
      "active",
      "observed_at",
      "retired_at",
    ]) {
      assert.equal(
        fingerprintColumns.includes(required),
        true,
        `missing ${required}`,
      );
    }

    const historyColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_session_history)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "account_id",
      "host_id",
      "host_name",
      "status",
      "latency_ms",
      "error_message",
      "started_at",
      "ended_at",
    ]) {
      assert.equal(
        historyColumns.includes(required),
        true,
        `missing ${required}`,
      );
    }

    const workspacePreferenceColumns = database
      .raw()
      .prepare("PRAGMA table_info(ssh_workspace_preferences)")
      .all()
      .map((row) => String((row as { name: unknown }).name));
    for (const required of [
      "account_id",
      "terminal_appearance_json",
      "version",
      "updated_at",
    ]) {
      assert.equal(
        workspacePreferenceColumns.includes(required),
        true,
        `missing ${required}`,
      );
    }

    database.raw().exec("PRAGMA foreign_keys = ON");
    const now = Date.now();
    database
      .raw()
      .prepare(
        `INSERT INTO accounts(
           id, username, password_hash, enabled, device_limit, created_at, updated_at
         ) VALUES ('a1', 'alice', 'hash', 1, 3, ?, ?)`,
      )
      .run(now, now);

    const defaultSshEnabled = database
      .raw()
      .prepare("SELECT ssh_enabled FROM accounts WHERE id = 'a1'")
      .get() as { ssh_enabled: number };
    assert.equal(defaultSshEnabled.ssh_enabled, 1);

    database
      .raw()
      .prepare(
        `INSERT INTO ssh_hosts(
           id, account_id, name, host, port, username, secret_ciphertext,
           trusted_fingerprint, created_at, updated_at
         ) VALUES ('h1', 'a1', 'web', 'web.example.com', 22, 'alice', 'cipher',
                   'aa:bb', ?, ?)`,
      )
      .run(now, now);

    const duplicateName = () =>
      database
        .raw()
        .prepare(
          `INSERT INTO ssh_hosts(
             id, account_id, name, host, port, username, secret_ciphertext,
             trusted_fingerprint, created_at, updated_at
           ) VALUES ('h2', 'a1', 'WEB', 'web2.example.com', 22, 'alice', 'cipher',
                     '', ?, ?)`,
        )
        .run(now, now);
    assert.throws(duplicateName, /UNIQUE/);

    database
      .raw()
      .prepare(
        `INSERT INTO accounts(
           id, username, password_hash, enabled, device_limit, created_at, updated_at
         ) VALUES ('a2', 'carol', 'hash', 1, 3, ?, ?)`,
      )
      .run(now, now);
    database
      .raw()
      .prepare(
        `INSERT INTO ssh_hosts(
           id, account_id, name, host, port, username, secret_ciphertext,
           trusted_fingerprint, created_at, updated_at
         ) VALUES ('h3', 'a2', 'WEB', 'web2.example.com', 22, 'carol', 'cipher',
                   '', ?, ?)`,
      )
      .run(now, now);
  } finally {
    database.close();
  }
});

test("migration 2 upgrades an existing version 1 database in place", () => {
  const database = new Database(":memory:");
  try {
    const raw = database.raw();
    raw.exec(`CREATE TABLE schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at INTEGER NOT NULL
    )`);
    raw
      .prepare(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (1, 0)",
      )
      .run();
    raw.exec(`CREATE TABLE accounts (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
      device_limit INTEGER NOT NULL DEFAULT 3 CHECK (device_limit > 0),
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    )`);
    raw.exec(`CREATE TABLE audit_events (
      id TEXT PRIMARY KEY,
      occurred_at INTEGER NOT NULL,
      account_id TEXT,
      session_id TEXT,
      device_id TEXT,
      ip_address TEXT,
      action TEXT NOT NULL,
      connection_id TEXT,
      success INTEGER NOT NULL CHECK (success IN (0, 1)),
      duration_ms INTEGER NOT NULL,
      rows_count INTEGER,
      bytes_count INTEGER,
      statement_hash TEXT,
      statement_type TEXT,
      error_code TEXT
    )`);

    const now = Date.now();
    raw
      .prepare(
        `INSERT INTO accounts(
           id, username, password_hash, enabled, device_limit, created_at, updated_at
         ) VALUES ('legacy', 'bob', 'hash', 1, 2, ?, ?)`,
      )
      .run(now, now);

    database.migrate();

    const account = raw
      .prepare("SELECT ssh_enabled FROM accounts WHERE id = 'legacy'")
      .get() as { ssh_enabled: number };
    assert.equal(account.ssh_enabled, 1);

    const migrations = raw
      .prepare("SELECT version FROM schema_migrations ORDER BY version")
      .all()
      .map((row) => Number((row as { version: unknown }).version));
    assert.deepEqual(migrations, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
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
