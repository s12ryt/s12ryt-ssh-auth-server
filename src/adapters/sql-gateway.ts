import {
  createConnection,
  type ConnectionOptions,
  type FieldPacket,
  type QueryOptions,
} from "mysql2/promise";
import {
  Client,
  type ClientConfig,
  type QueryArrayConfig,
  type QueryConfig,
} from "pg";

import type {
  MySQLConnectionSecret,
  PostgresConnectionSecret,
} from "../domain/models.js";
import type {
  SQLConnectionSecret,
  SQLExecResult,
  SQLGateway,
  SQLOptions,
  SQLQueryResult,
} from "../proxy/gateways.js";

export interface MySQLConnectionLike {
  ping(): Promise<void>;
  query(
    statement: string | QueryOptions,
    values?: unknown[],
  ): Promise<[unknown, unknown]>;
  end(): Promise<void>;
}

export interface PostgresClientLike {
  connect(): Promise<void>;
  query(
    config: string | QueryConfig<unknown[]> | QueryArrayConfig<unknown[]>,
  ): Promise<{
    fields: Array<{ name: string }>;
    rows: unknown[];
    rowCount: number | null;
  }>;
  end(): Promise<void>;
}

interface DriverFactories {
  mysqlFactory?: (config: ConnectionOptions) => Promise<MySQLConnectionLike>;
  postgresFactory?: (config: ClientConfig) => PostgresClientLike;
}

export class DriverSQLGateway implements SQLGateway {
  private readonly mysqlFactory: NonNullable<DriverFactories["mysqlFactory"]>;
  private readonly postgresFactory: NonNullable<
    DriverFactories["postgresFactory"]
  >;

  constructor(factories: DriverFactories = {}) {
    this.mysqlFactory =
      factories.mysqlFactory ?? (async (config) => createConnection(config));
    this.postgresFactory = factories.postgresFactory ?? createPostgresClient;
  }

  async test(secret: SQLConnectionSecret, signal: AbortSignal): Promise<void> {
    signal.throwIfAborted();
    if (secret.kind === "mysql") {
      const connection = await this.mysqlFactory(mysqlConfig(secret));
      try {
        await connection.ping();
      } finally {
        await connection.end();
      }
      return;
    }
    const client = this.postgresFactory(postgresConfig(secret));
    try {
      await client.connect();
      signal.throwIfAborted();
      await client.query("SELECT 1");
    } finally {
      await client.end();
    }
  }

  async tables(
    secret: SQLConnectionSecret,
    signal: AbortSignal,
  ): Promise<string[]> {
    const statement =
      secret.kind === "mysql"
        ? "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() ORDER BY table_name"
        : "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name";
    const result = await this.query(secret, statement, [], {
      timeoutMs: 30_000,
      rowLimit: 10_000,
      signal,
    });
    return result.rows.map((row) => String(row[0]));
  }

  async query(
    secret: SQLConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: SQLOptions,
  ): Promise<SQLQueryResult> {
    options.signal.throwIfAborted();
    return secret.kind === "mysql"
      ? this.queryMySQL(secret, statement, parameters, options)
      : this.queryPostgres(secret, statement, parameters, options);
  }

  async exec(
    secret: SQLConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: Omit<SQLOptions, "rowLimit">,
  ): Promise<SQLExecResult> {
    options.signal.throwIfAborted();
    return secret.kind === "mysql"
      ? this.execMySQL(secret, statement, parameters, options)
      : this.execPostgres(secret, statement, parameters, options);
  }

  private async queryMySQL(
    secret: MySQLConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: SQLOptions,
  ): Promise<SQLQueryResult> {
    const connection = await this.mysqlFactory(mysqlConfig(secret));
    let transaction = false;
    try {
      await connection.query("SET SESSION MAX_EXECUTION_TIME = ?", [
        options.timeoutMs,
      ]);
      await connection.query("START TRANSACTION READ ONLY");
      transaction = true;
      const [rawRows, rawFields] = await connection.query(
        { sql: statement, timeout: options.timeoutMs, rowsAsArray: true },
        parameters,
      );
      options.signal.throwIfAborted();
      const rows = normalizeRows(rawRows);
      const columns = normalizeMySQLFields(rawFields);
      return truncateRows(columns, rows, options.rowLimit);
    } finally {
      if (transaction) await connection.query("ROLLBACK");
      await connection.end();
    }
  }

  private async queryPostgres(
    secret: PostgresConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: SQLOptions,
  ): Promise<SQLQueryResult> {
    const client = this.postgresFactory(postgresConfig(secret));
    let transaction = false;
    try {
      await client.connect();
      await client.query("BEGIN READ ONLY");
      transaction = true;
      await client.query(
        `SET LOCAL statement_timeout = ${positiveInteger(options.timeoutMs)}`,
      );
      const result = await client.query({
        text: statement,
        values: parameters,
        rowMode: "array",
      });
      options.signal.throwIfAborted();
      return truncateRows(
        result.fields.map((field) => field.name),
        normalizeRows(result.rows),
        options.rowLimit,
      );
    } finally {
      if (transaction) await client.query("ROLLBACK");
      await client.end();
    }
  }

  private async execMySQL(
    secret: MySQLConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: Omit<SQLOptions, "rowLimit">,
  ): Promise<SQLExecResult> {
    const connection = await this.mysqlFactory(mysqlConfig(secret));
    let transaction = false;
    try {
      await connection.query("SET SESSION MAX_EXECUTION_TIME = ?", [
        options.timeoutMs,
      ]);
      await connection.query("START TRANSACTION");
      transaction = true;
      const [result] = await connection.query(
        { sql: statement, timeout: options.timeoutMs },
        parameters,
      );
      options.signal.throwIfAborted();
      await connection.query("COMMIT");
      transaction = false;
      const header = result as {
        affectedRows?: number;
        insertId?: number | string;
      };
      const output: SQLExecResult = { rowsAffected: header.affectedRows ?? 0 };
      if (header.insertId !== undefined && String(header.insertId) !== "0") {
        output.lastInsertId = String(header.insertId);
      }
      return output;
    } finally {
      if (transaction) await connection.query("ROLLBACK");
      await connection.end();
    }
  }

  private async execPostgres(
    secret: PostgresConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: Omit<SQLOptions, "rowLimit">,
  ): Promise<SQLExecResult> {
    const client = this.postgresFactory(postgresConfig(secret));
    let transaction = false;
    try {
      await client.connect();
      await client.query("BEGIN");
      transaction = true;
      await client.query(
        `SET LOCAL statement_timeout = ${positiveInteger(options.timeoutMs)}`,
      );
      const result = await client.query({
        text: statement,
        values: parameters,
      });
      options.signal.throwIfAborted();
      await client.query("COMMIT");
      transaction = false;
      return { rowsAffected: result.rowCount ?? 0 };
    } finally {
      if (transaction) await client.query("ROLLBACK");
      await client.end();
    }
  }
}

function mysqlConfig(secret: MySQLConnectionSecret): ConnectionOptions {
  const tlsMode = secret.tlsMode.trim().toLowerCase();
  const config: ConnectionOptions = {
    host: secret.host,
    port: secret.port,
    user: secret.user,
    password: secret.password,
    database: secret.database,
    supportBigNumbers: true,
    dateStrings: true,
  };
  if (tlsMode !== "false" && tlsMode !== "disable") {
    config.ssl = { rejectUnauthorized: tlsMode !== "skip-verify" };
  }
  return config;
}

function postgresConfig(secret: PostgresConnectionSecret): ClientConfig {
  const url = new URL("postgresql://localhost");
  url.hostname = secret.host;
  url.port = String(secret.port);
  url.username = secret.user;
  url.password = secret.password;
  url.pathname = `/${encodeURIComponent(secret.database)}`;
  url.searchParams.set("sslmode", secret.sslMode || "require");
  return { connectionString: url.toString() };
}

function createPostgresClient(config: ClientConfig): PostgresClientLike {
  const client = new Client(config);
  return {
    connect: async () => {
      await client.connect();
    },
    query: async (query) => {
      const result = await client.query(query as QueryArrayConfig<unknown[]>);
      return {
        fields: result.fields.map((field) => ({ name: field.name })),
        rows: result.rows as unknown[],
        rowCount: result.rowCount,
      };
    },
    end: async () => {
      await client.end();
    },
  };
}

function normalizeMySQLFields(fields: unknown): string[] {
  if (!Array.isArray(fields)) return [];
  return fields.map((field) => String((field as FieldPacket).name));
}

function normalizeRows(rows: unknown): unknown[][] {
  if (!Array.isArray(rows)) return [];
  return rows.map((row) => {
    if (Array.isArray(row)) {
      const values: unknown[] = [];
      for (const value of row as unknown[]) values.push(value);
      return values;
    }
    return Object.values(row as Record<string, unknown>);
  });
}

function truncateRows(
  columns: string[],
  rows: unknown[][],
  rowLimit: number,
): SQLQueryResult {
  const limit = positiveInteger(rowLimit);
  return {
    columns,
    rows: rows.slice(0, limit),
    truncated: rows.length > limit,
  };
}

function positiveInteger(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0)
    throw new Error("limit must be positive");
  return value;
}
