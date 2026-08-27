import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

interface Migration {
  version: number;
  sql: string;
}

const migrations: Migration[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE accounts (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        device_limit INTEGER NOT NULL DEFAULT 3 CHECK (device_limit > 0),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE connections (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE COLLATE NOCASE,
        kind TEXT NOT NULL CHECK (kind IN ('s3', 'mysql', 'postgres')),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        secret_ciphertext TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );

      CREATE TABLE grants (
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
        operation TEXT NOT NULL CHECK (operation IN (
          's3.read', 's3.write', 's3.delete',
          'sql.tables', 'sql.query', 'sql.exec'
        )),
        created_at INTEGER NOT NULL,
        PRIMARY KEY (account_id, connection_id, operation)
      );

      CREATE TABLE sessions (
        id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        device_id TEXT NOT NULL,
        refresh_hash TEXT NOT NULL UNIQUE,
        refresh_expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER NOT NULL,
        ip_address TEXT NOT NULL,
        user_agent TEXT NOT NULL
      );
      CREATE INDEX sessions_account_active_idx
        ON sessions(account_id, revoked_at, refresh_expires_at);
      CREATE INDEX sessions_family_idx ON sessions(family_id);

      CREATE TABLE refresh_history (
        token_hash TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        family_id TEXT NOT NULL,
        used_at INTEGER NOT NULL
      );

      CREATE TABLE access_tokens (
        token_hash TEXT PRIMARY KEY,
        session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX access_tokens_session_idx ON access_tokens(session_id);

      CREATE TABLE audit_events (
        id TEXT PRIMARY KEY,
        occurred_at INTEGER NOT NULL,
        account_id TEXT REFERENCES accounts(id) ON DELETE SET NULL,
        session_id TEXT REFERENCES sessions(id) ON DELETE SET NULL,
        device_id TEXT,
        ip_address TEXT,
        action TEXT NOT NULL,
        connection_id TEXT REFERENCES connections(id) ON DELETE SET NULL,
        success INTEGER NOT NULL CHECK (success IN (0, 1)),
        duration_ms INTEGER NOT NULL,
        rows_count INTEGER,
        bytes_count INTEGER,
        statement_hash TEXT,
        statement_type TEXT,
        error_code TEXT
      );
      CREATE INDEX audit_events_time_idx ON audit_events(occurred_at);
      CREATE INDEX audit_events_account_idx ON audit_events(account_id, occurred_at);

      CREATE TABLE admin_preferences (
        telegram_user_id TEXT PRIMARY KEY,
        language TEXT NOT NULL CHECK (language IN ('en', 'zh-TW')),
        updated_at INTEGER NOT NULL
      );
    `,
  },
];

export class Database {
  readonly #database: DatabaseSync;

  constructor(path: string) {
    if (path !== ":memory:") {
      const absolutePath = resolve(path);
      mkdirSync(dirname(absolutePath), { recursive: true, mode: 0o700 });
      this.#database = new DatabaseSync(absolutePath);
      this.#database.exec("PRAGMA journal_mode = WAL");
    } else {
      this.#database = new DatabaseSync(path);
    }
    this.#database.exec("PRAGMA foreign_keys = ON");
    this.#database.exec("PRAGMA busy_timeout = 5000");
  }

  raw(): DatabaseSync {
    return this.#database;
  }

  migrate(): void {
    this.#database.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      )
    `);

    const appliedRows = this.#database
      .prepare("SELECT version FROM schema_migrations")
      .all() as Array<{ version: number }>;
    const applied = new Set(appliedRows.map((row) => row.version));

    for (const migration of migrations) {
      if (applied.has(migration.version)) {
        continue;
      }
      this.#database.exec("BEGIN IMMEDIATE");
      try {
        this.#database.exec(migration.sql);
        this.#database
          .prepare(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
          )
          .run(migration.version, Date.now());
        this.#database.exec("COMMIT");
      } catch (error) {
        this.#database.exec("ROLLBACK");
        throw error;
      }
    }
  }

  close(): void {
    this.#database.close();
  }
}
