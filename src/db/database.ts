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
  {
    version: 2,
    sql: `
      ALTER TABLE accounts
        ADD COLUMN ssh_enabled INTEGER NOT NULL DEFAULT 1
        CHECK (ssh_enabled IN (0, 1));

      CREATE TABLE ssh_hosts (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
        username TEXT NOT NULL,
        secret_ciphertext TEXT NOT NULL,
        trusted_fingerprint TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE (account_id, name COLLATE NOCASE)
      );
      CREATE INDEX ssh_hosts_account_idx ON ssh_hosts(account_id);

      ALTER TABLE audit_events
        ADD COLUMN ssh_host_id TEXT REFERENCES ssh_hosts(id) ON DELETE SET NULL;
    `,
  },
  {
    version: 3,
    sql: `
      ALTER TABLE ssh_hosts ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1
        CHECK (enabled IN (0, 1));
      ALTER TABLE ssh_hosts ADD COLUMN favorite INTEGER NOT NULL DEFAULT 0
        CHECK (favorite IN (0, 1));
      ALTER TABLE ssh_hosts ADD COLUMN group_path TEXT NOT NULL DEFAULT '';
      ALTER TABLE ssh_hosts ADD COLUMN tags_json TEXT NOT NULL DEFAULT '[]';
      ALTER TABLE ssh_hosts ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 0
        CHECK (sort_order >= 0);
      ALTER TABLE ssh_hosts ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'password'
        CHECK (auth_method IN ('password', 'private_key'));
      ALTER TABLE ssh_hosts ADD COLUMN settings_json TEXT NOT NULL DEFAULT '{}';
      ALTER TABLE ssh_hosts ADD COLUMN version INTEGER NOT NULL DEFAULT 1
        CHECK (version > 0);
    `,
  },
  {
    version: 4,
    sql: `
      CREATE TABLE ssh_tunnels (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        host_id TEXT NOT NULL REFERENCES ssh_hosts(id) ON DELETE CASCADE,
        type TEXT NOT NULL CHECK (type IN ('local', 'remote', 'dynamic_socks')),
        listen_host TEXT NOT NULL,
        listen_port INTEGER NOT NULL CHECK (listen_port BETWEEN 1 AND 65535),
        target_host TEXT NOT NULL DEFAULT '',
        target_port INTEGER NOT NULL DEFAULT 0 CHECK (target_port BETWEEN 0 AND 65535),
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        auto_start INTEGER NOT NULL DEFAULT 0 CHECK (auto_start IN (0, 1)),
        running INTEGER NOT NULL DEFAULT 0 CHECK (running IN (0, 1)),
        traffic_up_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_up_bytes >= 0),
        traffic_down_bytes INTEGER NOT NULL DEFAULT 0 CHECK (traffic_down_bytes >= 0),
        version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE (account_id, name COLLATE NOCASE)
      );
      CREATE INDEX ssh_tunnels_account_idx ON ssh_tunnels(account_id);
      CREATE INDEX ssh_tunnels_host_idx ON ssh_tunnels(host_id);
    `,
  },
  {
    version: 5,
    sql: `
      CREATE TABLE ssh_snippets (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        command TEXT NOT NULL,
        variables_json TEXT NOT NULL DEFAULT '[]',
        secret_ciphertext TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE (account_id, name COLLATE NOCASE)
      );
      CREATE INDEX ssh_snippets_account_idx ON ssh_snippets(account_id);
    `,
  },
  {
    version: 6,
    sql: `
      CREATE TABLE ssh_key_identities (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL DEFAULT '',
        fingerprint TEXT NOT NULL DEFAULT '',
        secret_ciphertext TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
        version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        UNIQUE (account_id, name COLLATE NOCASE)
      );
      CREATE INDEX ssh_key_identities_account_idx ON ssh_key_identities(account_id);
    `,
  },
  {
    version: 7,
    sql: `
      CREATE TABLE ssh_host_fingerprints (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        host_id TEXT NOT NULL REFERENCES ssh_hosts(id) ON DELETE CASCADE,
        algorithm TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        source TEXT NOT NULL CHECK (source IN ('tofu', 'manual')),
        active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
        observed_at INTEGER NOT NULL,
        retired_at INTEGER,
        CHECK ((active = 1 AND retired_at IS NULL) OR active = 0)
      );
      CREATE INDEX ssh_host_fingerprints_account_idx
        ON ssh_host_fingerprints(account_id, observed_at DESC);
      CREATE INDEX ssh_host_fingerprints_host_idx
        ON ssh_host_fingerprints(host_id, observed_at DESC);
      CREATE UNIQUE INDEX ssh_host_fingerprints_active_idx
        ON ssh_host_fingerprints(host_id) WHERE active = 1;
    `,
  },
  {
    version: 8,
    sql: `
      CREATE TABLE ssh_session_history (
        id TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        host_id TEXT REFERENCES ssh_hosts(id) ON DELETE SET NULL,
        host_name TEXT NOT NULL,
        status TEXT NOT NULL
          CHECK (status IN ('connecting', 'connected', 'failed', 'closed')),
        latency_ms INTEGER NOT NULL DEFAULT 0 CHECK (latency_ms >= 0),
        error_message TEXT NOT NULL DEFAULT '',
        started_at INTEGER NOT NULL,
        ended_at INTEGER,
        CHECK (
          (status IN ('connecting', 'connected') AND ended_at IS NULL) OR
          (status IN ('failed', 'closed') AND ended_at IS NOT NULL)
        )
      );
      CREATE INDEX ssh_session_history_account_idx
        ON ssh_session_history(account_id, started_at DESC);
      CREATE INDEX ssh_session_history_host_idx
        ON ssh_session_history(host_id, started_at DESC);
    `,
  },
  {
    version: 9,
    sql: `
      CREATE TABLE ssh_workspace_preferences (
        account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
        terminal_appearance_json TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
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
