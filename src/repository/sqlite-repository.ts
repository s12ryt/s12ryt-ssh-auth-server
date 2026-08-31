import type { DatabaseSync, SQLOutputValue } from "node:sqlite";

import type {
  Account,
  AssignedConnection,
  AuditEvent,
  Connection,
  ConnectionKind,
  LoginSessionRecord,
  Operation,
  Principal,
  SessionSummary,
  SessionWithAccount,
  SSHHostFingerprintRecord,
  SSHHostRecord,
  SSHCommandSnippetRecord,
  SSHKeyIdentityRecord,
  SSHSessionHistoryRecord,
  SSHTunnelRecord,
  SSHWorkspacePreferencesRecord,
  StoredAccount,
} from "../domain/models.js";
import {
  ConflictError,
  DeviceLimitError,
  InvalidTokenError,
  NotFoundError,
} from "../errors.js";

function requiredValue(value: SQLOutputValue | undefined): SQLOutputValue {
  if (value === undefined) {
    throw new Error("SQLite row is missing an expected column");
  }
  return value;
}

function stringValue(value: SQLOutputValue | undefined): string {
  value = requiredValue(value);
  return String(value);
}

function numberValue(value: SQLOutputValue | undefined): number {
  value = requiredValue(value);
  return Number(value);
}

function optionalNumber(value: SQLOutputValue | undefined): number | null {
  value = requiredValue(value);
  return value === null ? null : Number(value);
}

function accountFromRow(row: Record<string, SQLOutputValue>): StoredAccount {
  return {
    id: stringValue(row.id),
    username: stringValue(row.username),
    passwordHash: stringValue(row.password_hash),
    enabled: numberValue(row.enabled) === 1,
    sshEnabled: numberValue(row.ssh_enabled) === 1,
    deviceLimit: numberValue(row.device_limit),
    createdAt: numberValue(row.created_at),
    updatedAt: numberValue(row.updated_at),
  };
}

function publicAccount(account: StoredAccount): Account {
  return {
    id: account.id,
    username: account.username,
    enabled: account.enabled,
    sshEnabled: account.sshEnabled,
    deviceLimit: account.deviceLimit,
    createdAt: account.createdAt,
    updatedAt: account.updatedAt,
  };
}

function sshHostFromRow(row: Record<string, SQLOutputValue>): SSHHostRecord {
  const settings = JSON.parse(
    stringValue(row.settings_json),
  ) as SSHHostRecord["settings"];
  const tags = JSON.parse(stringValue(row.tags_json)) as string[];
  return {
    id: stringValue(row.id),
    accountId: stringValue(row.account_id),
    name: stringValue(row.name),
    host: stringValue(row.host),
    port: numberValue(row.port),
    username: stringValue(row.username),
    secretCiphertext: stringValue(row.secret_ciphertext),
    trustedFingerprint: stringValue(row.trusted_fingerprint),
    enabled: numberValue(row.enabled) === 1,
    favorite: numberValue(row.favorite) === 1,
    groupPath: stringValue(row.group_path),
    tags,
    sortOrder: numberValue(row.sort_order),
    authMethod: stringValue(row.auth_method) as SSHHostRecord["authMethod"],
    settings,
    version: numberValue(row.version),
    createdAt: numberValue(row.created_at),
    updatedAt: numberValue(row.updated_at),
  };
}

function sshWorkspacePreferencesFromRow(
  row: Record<string, SQLOutputValue>,
): SSHWorkspacePreferencesRecord {
  return {
    accountId: stringValue(row.account_id),
    terminalAppearance: JSON.parse(
      stringValue(row.terminal_appearance_json),
    ) as SSHWorkspacePreferencesRecord["terminalAppearance"],
    version: numberValue(row.version),
    updatedAt: numberValue(row.updated_at),
  };
}

function sshHostFingerprintFromRow(
  row: Record<string, SQLOutputValue>,
): SSHHostFingerprintRecord {
  return {
    id: stringValue(row.id),
    accountId: stringValue(row.account_id),
    hostId: stringValue(row.host_id),
    algorithm: stringValue(row.algorithm),
    fingerprint: stringValue(row.fingerprint),
    source: stringValue(row.source) as SSHHostFingerprintRecord["source"],
    active: numberValue(row.active) === 1,
    observedAt: numberValue(row.observed_at),
    retiredAt: optionalNumber(row.retired_at),
  };
}

function sshTunnelFromRow(
  row: Record<string, SQLOutputValue>,
): SSHTunnelRecord {
  return {
    id: stringValue(row.id),
    accountId: stringValue(row.account_id),
    name: stringValue(row.name),
    hostId: stringValue(row.host_id),
    type: stringValue(row.type) as SSHTunnelRecord["type"],
    listenHost: stringValue(row.listen_host),
    listenPort: numberValue(row.listen_port),
    targetHost: stringValue(row.target_host),
    targetPort: numberValue(row.target_port),
    enabled: numberValue(row.enabled) === 1,
    autoStart: numberValue(row.auto_start) === 1,
    running: numberValue(row.running) === 1,
    trafficUpBytes: numberValue(row.traffic_up_bytes),
    trafficDownBytes: numberValue(row.traffic_down_bytes),
    version: numberValue(row.version),
    createdAt: numberValue(row.created_at),
    updatedAt: numberValue(row.updated_at),
  };
}

function sshSnippetFromRow(
  row: Record<string, SQLOutputValue>,
): SSHCommandSnippetRecord {
  return {
    id: stringValue(row.id),
    accountId: stringValue(row.account_id),
    name: stringValue(row.name),
    command: stringValue(row.command),
    variables: JSON.parse(stringValue(row.variables_json)) as string[],
    secretCiphertext: stringValue(row.secret_ciphertext),
    enabled: numberValue(row.enabled) === 1,
    version: numberValue(row.version),
    createdAt: numberValue(row.created_at),
    updatedAt: numberValue(row.updated_at),
  };
}

function sshKeyIdentityFromRow(
  row: Record<string, SQLOutputValue>,
): SSHKeyIdentityRecord {
  return {
    id: stringValue(row.id),
    accountId: stringValue(row.account_id),
    name: stringValue(row.name),
    publicKey: stringValue(row.public_key),
    fingerprint: stringValue(row.fingerprint),
    secretCiphertext: stringValue(row.secret_ciphertext),
    enabled: numberValue(row.enabled) === 1,
    version: numberValue(row.version),
    createdAt: numberValue(row.created_at),
    updatedAt: numberValue(row.updated_at),
  };
}

function sshSessionHistoryFromRow(
  row: Record<string, SQLOutputValue>,
): SSHSessionHistoryRecord {
  return {
    id: stringValue(row.id),
    accountId: stringValue(row.account_id),
    hostId: row.host_id === null ? null : stringValue(row.host_id),
    hostName: stringValue(row.host_name),
    status: stringValue(row.status) as SSHSessionHistoryRecord["status"],
    latencyMs: numberValue(row.latency_ms),
    errorMessage: stringValue(row.error_message),
    startedAt: numberValue(row.started_at),
    endedAt: optionalNumber(row.ended_at),
  };
}

function connectionFromRow(row: Record<string, SQLOutputValue>): Connection {
  return {
    id: stringValue(row.id),
    name: stringValue(row.name),
    kind: stringValue(row.kind) as ConnectionKind,
    enabled: numberValue(row.enabled) === 1,
    secretCiphertext: stringValue(row.secret_ciphertext),
    createdAt: numberValue(row.created_at),
    updatedAt: numberValue(row.updated_at),
  };
}

export interface CreateSessionInput {
  session: LoginSessionRecord;
  accessTokenHash: string;
  accessExpiresAt: number;
  deviceLimit: number;
  now: number;
}

export interface RotateSessionInput {
  sessionId: string;
  currentRefreshHash: string;
  nextRefreshHash: string;
  nextRefreshExpiresAt: number;
  accessTokenHash: string;
  accessExpiresAt: number;
  now: number;
}

export class SqliteRepository {
  private transactionDepth = 0;
  private transactionSerial = 0;

  constructor(private readonly database: DatabaseSync) {}

  transaction<T>(operation: () => T): T {
    const outermost = this.transactionDepth === 0;
    const savepoint = `s12ryt_repository_${++this.transactionSerial}`;
    this.database.exec(
      outermost ? "BEGIN IMMEDIATE" : `SAVEPOINT ${savepoint}`,
    );
    this.transactionDepth += 1;
    try {
      const result = operation();
      this.transactionDepth -= 1;
      this.database.exec(outermost ? "COMMIT" : `RELEASE ${savepoint}`);
      return result;
    } catch (error) {
      this.transactionDepth -= 1;
      if (outermost) {
        this.database.exec("ROLLBACK");
      } else {
        this.database.exec(`ROLLBACK TO ${savepoint}`);
        this.database.exec(`RELEASE ${savepoint}`);
      }
      throw error;
    }
  }

  createAccount(account: StoredAccount): Account {
    try {
      this.database
        .prepare(
          `INSERT INTO accounts(
            id, username, password_hash, enabled, ssh_enabled, device_limit,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          account.id,
          account.username,
          account.passwordHash,
          account.enabled ? 1 : 0,
          account.sshEnabled ? 1 : 0,
          account.deviceLimit,
          account.createdAt,
          account.updatedAt,
        );
      return publicAccount(account);
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        throw new ConflictError("account username already exists");
      }
      throw error;
    }
  }

  findAccountByUsername(username: string): StoredAccount | undefined {
    const row = this.database
      .prepare("SELECT * FROM accounts WHERE username = ? COLLATE NOCASE")
      .get(username);
    return row ? accountFromRow(row) : undefined;
  }

  findAccountById(id: string): StoredAccount | undefined {
    const row = this.database
      .prepare("SELECT * FROM accounts WHERE id = ?")
      .get(id);
    return row ? accountFromRow(row) : undefined;
  }

  listAccounts(): Account[] {
    return this.database
      .prepare("SELECT * FROM accounts ORDER BY username")
      .all()
      .map((row) => publicAccount(accountFromRow(row)));
  }

  setAccountEnabled(id: string, enabled: boolean, now: number): void {
    const result = this.database
      .prepare("UPDATE accounts SET enabled = ?, updated_at = ? WHERE id = ?")
      .run(enabled ? 1 : 0, now, id);
    if (result.changes === 0) {
      throw new NotFoundError("account");
    }
  }

  setAccountPassword(id: string, passwordHash: string, now: number): void {
    const result = this.database
      .prepare(
        "UPDATE accounts SET password_hash = ?, updated_at = ? WHERE id = ?",
      )
      .run(passwordHash, now, id);
    if (result.changes === 0) {
      throw new NotFoundError("account");
    }
  }

  setAccountDeviceLimit(id: string, deviceLimit: number, now: number): void {
    const result = this.database
      .prepare(
        "UPDATE accounts SET device_limit = ?, updated_at = ? WHERE id = ?",
      )
      .run(deviceLimit, now, id);
    if (result.changes === 0) {
      throw new NotFoundError("account");
    }
  }

  setAccountSSHEnabled(id: string, sshEnabled: boolean, now: number): void {
    const result = this.database
      .prepare(
        "UPDATE accounts SET ssh_enabled = ?, updated_at = ? WHERE id = ?",
      )
      .run(sshEnabled ? 1 : 0, now, id);
    if (result.changes === 0) {
      throw new NotFoundError("account");
    }
  }

  deleteAccount(id: string): void {
    const result = this.database
      .prepare("DELETE FROM accounts WHERE id = ?")
      .run(id);
    if (result.changes === 0) {
      throw new NotFoundError("account");
    }
  }

  findSSHWorkspacePreferences(
    accountId: string,
  ): SSHWorkspacePreferencesRecord | undefined {
    const row = this.database
      .prepare("SELECT * FROM ssh_workspace_preferences WHERE account_id = ?")
      .get(accountId);
    return row ? sshWorkspacePreferencesFromRow(row) : undefined;
  }

  saveSSHWorkspacePreferences(
    record: SSHWorkspacePreferencesRecord,
  ): SSHWorkspacePreferencesRecord {
    this.database
      .prepare(
        `INSERT INTO ssh_workspace_preferences(
           account_id, terminal_appearance_json, version, updated_at
         ) VALUES (?, ?, ?, ?)
         ON CONFLICT(account_id) DO UPDATE SET
           terminal_appearance_json = excluded.terminal_appearance_json,
           version = excluded.version,
           updated_at = excluded.updated_at`,
      )
      .run(
        record.accountId,
        JSON.stringify(record.terminalAppearance),
        record.version,
        record.updatedAt,
      );
    return { ...record, terminalAppearance: { ...record.terminalAppearance } };
  }

  createConnection(connection: Connection): Connection {
    try {
      this.database
        .prepare(
          `INSERT INTO connections(
            id, name, kind, enabled, secret_ciphertext, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          connection.id,
          connection.name,
          connection.kind,
          connection.enabled ? 1 : 0,
          connection.secretCiphertext,
          connection.createdAt,
          connection.updatedAt,
        );
      return connection;
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        throw new ConflictError("connection name already exists");
      }
      throw error;
    }
  }

  updateConnection(connection: Connection): void {
    const result = this.database
      .prepare(
        `UPDATE connections
         SET name = ?, kind = ?, enabled = ?, secret_ciphertext = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        connection.name,
        connection.kind,
        connection.enabled ? 1 : 0,
        connection.secretCiphertext,
        connection.updatedAt,
        connection.id,
      );
    if (result.changes === 0) {
      throw new NotFoundError("connection");
    }
  }

  findConnection(id: string): Connection | undefined {
    const row = this.database
      .prepare("SELECT * FROM connections WHERE id = ?")
      .get(id);
    return row ? connectionFromRow(row) : undefined;
  }

  listConnections(): Omit<Connection, "secretCiphertext">[] {
    return this.database
      .prepare("SELECT * FROM connections ORDER BY name")
      .all()
      .map((row) => {
        const { secretCiphertext: _secretCiphertext, ...visible } =
          connectionFromRow(row);
        return visible;
      });
  }

  setConnectionEnabled(id: string, enabled: boolean, now: number): void {
    const result = this.database
      .prepare(
        "UPDATE connections SET enabled = ?, updated_at = ? WHERE id = ?",
      )
      .run(enabled ? 1 : 0, now, id);
    if (result.changes === 0) {
      throw new NotFoundError("connection");
    }
  }

  deleteConnection(id: string): void {
    const result = this.database
      .prepare("DELETE FROM connections WHERE id = ?")
      .run(id);
    if (result.changes === 0) {
      throw new NotFoundError("connection");
    }
  }

  createSSHHost(record: SSHHostRecord): SSHHostRecord {
    try {
      this.database
        .prepare(
          `INSERT INTO ssh_hosts(
            id, account_id, name, host, port, username, secret_ciphertext,
            trusted_fingerprint, enabled, favorite, group_path, tags_json,
            sort_order, auth_method, settings_json, version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          record.id,
          record.accountId,
          record.name,
          record.host,
          record.port,
          record.username,
          record.secretCiphertext,
          record.trustedFingerprint,
          record.enabled ? 1 : 0,
          record.favorite ? 1 : 0,
          record.groupPath,
          JSON.stringify(record.tags),
          record.sortOrder,
          record.authMethod,
          JSON.stringify(record.settings),
          record.version,
          record.createdAt,
          record.updatedAt,
        );
      return record;
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        throw new ConflictError("ssh host name already exists");
      }
      throw error;
    }
  }

  updateSSHHost(record: SSHHostRecord): SSHHostRecord {
    const result = this.database
      .prepare(
        `UPDATE ssh_hosts
         SET name = ?, host = ?, port = ?, username = ?, secret_ciphertext = ?,
             trusted_fingerprint = ?, enabled = ?, favorite = ?, group_path = ?,
             tags_json = ?, sort_order = ?, auth_method = ?, settings_json = ?,
             version = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        record.name,
        record.host,
        record.port,
        record.username,
        record.secretCiphertext,
        record.trustedFingerprint,
        record.enabled ? 1 : 0,
        record.favorite ? 1 : 0,
        record.groupPath,
        JSON.stringify(record.tags),
        record.sortOrder,
        record.authMethod,
        JSON.stringify(record.settings),
        record.version,
        record.updatedAt,
        record.id,
      );
    if (result.changes === 0) {
      throw new NotFoundError("ssh host");
    }
    return record;
  }

  createSSHHostWithFingerprint(
    record: SSHHostRecord,
    fingerprint?: SSHHostFingerprintRecord,
  ): SSHHostRecord {
    return this.transaction(() => {
      const created = this.createSSHHost(record);
      if (fingerprint) {
        this.insertSSHHostFingerprint(fingerprint);
      }
      return created;
    });
  }

  replaceSSHHostFingerprint(
    record: SSHHostRecord,
    fingerprint?: SSHHostFingerprintRecord,
  ): SSHHostRecord {
    return this.transaction(() => {
      const saved = this.updateSSHHost(record);
      this.database
        .prepare(
          `UPDATE ssh_host_fingerprints
           SET active = 0, retired_at = ?
           WHERE host_id = ? AND active = 1`,
        )
        .run(record.updatedAt, record.id);
      if (fingerprint) {
        this.insertSSHHostFingerprint(fingerprint);
      }
      return saved;
    });
  }

  listSSHHostFingerprints(
    accountId: string,
    hostId: string,
  ): SSHHostFingerprintRecord[] {
    return this.database
      .prepare(
        `SELECT * FROM ssh_host_fingerprints
         WHERE account_id = ? AND host_id = ?
         ORDER BY observed_at DESC, id DESC`,
      )
      .all(accountId, hostId)
      .map((row) => sshHostFingerprintFromRow(row));
  }

  private insertSSHHostFingerprint(record: SSHHostFingerprintRecord): void {
    this.database
      .prepare(
        `INSERT INTO ssh_host_fingerprints(
          id, account_id, host_id, algorithm, fingerprint, source,
          active, observed_at, retired_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.id,
        record.accountId,
        record.hostId,
        record.algorithm,
        record.fingerprint,
        record.source,
        record.active ? 1 : 0,
        record.observedAt,
        record.retiredAt,
      );
  }

  findSSHHost(id: string): SSHHostRecord | undefined {
    const row = this.database
      .prepare("SELECT * FROM ssh_hosts WHERE id = ?")
      .get(id);
    return row ? sshHostFromRow(row) : undefined;
  }

  listSSHHosts(accountId: string): SSHHostRecord[] {
    return this.database
      .prepare("SELECT * FROM ssh_hosts WHERE account_id = ? ORDER BY name")
      .all(accountId)
      .map((row) => sshHostFromRow(row));
  }

  countSSHHosts(accountId: string): number {
    const row = this.database
      .prepare("SELECT COUNT(*) AS count FROM ssh_hosts WHERE account_id = ?")
      .get(accountId) as { count: number };
    return Number(row.count);
  }

  setSSHHostFingerprint(id: string, fingerprint: string, now: number): void {
    const result = this.database
      .prepare(
        "UPDATE ssh_hosts SET trusted_fingerprint = ?, updated_at = ? WHERE id = ?",
      )
      .run(fingerprint, now, id);
    if (result.changes === 0) {
      throw new NotFoundError("ssh host");
    }
  }

  deleteSSHHost(id: string): void {
    const result = this.database
      .prepare("DELETE FROM ssh_hosts WHERE id = ?")
      .run(id);
    if (result.changes === 0) {
      throw new NotFoundError("ssh host");
    }
  }

  createSSHTunnel(record: SSHTunnelRecord): SSHTunnelRecord {
    try {
      this.database
        .prepare(
          `INSERT INTO ssh_tunnels(
            id, account_id, name, host_id, type, listen_host, listen_port,
            target_host, target_port, enabled, auto_start, running,
            traffic_up_bytes, traffic_down_bytes, version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          record.id,
          record.accountId,
          record.name,
          record.hostId,
          record.type,
          record.listenHost,
          record.listenPort,
          record.targetHost,
          record.targetPort,
          record.enabled ? 1 : 0,
          record.autoStart ? 1 : 0,
          record.running ? 1 : 0,
          record.trafficUpBytes,
          record.trafficDownBytes,
          record.version,
          record.createdAt,
          record.updatedAt,
        );
      return record;
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        throw new ConflictError("ssh tunnel name already exists");
      }
      throw error;
    }
  }

  updateSSHTunnel(record: SSHTunnelRecord): SSHTunnelRecord {
    const result = this.database
      .prepare(
        `UPDATE ssh_tunnels
         SET name = ?, host_id = ?, type = ?, listen_host = ?, listen_port = ?,
             target_host = ?, target_port = ?, enabled = ?, auto_start = ?,
             running = ?, traffic_up_bytes = ?, traffic_down_bytes = ?,
             version = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        record.name,
        record.hostId,
        record.type,
        record.listenHost,
        record.listenPort,
        record.targetHost,
        record.targetPort,
        record.enabled ? 1 : 0,
        record.autoStart ? 1 : 0,
        record.running ? 1 : 0,
        record.trafficUpBytes,
        record.trafficDownBytes,
        record.version,
        record.updatedAt,
        record.id,
      );
    if (result.changes === 0) {
      throw new NotFoundError("ssh tunnel");
    }
    return record;
  }

  findSSHTunnel(id: string): SSHTunnelRecord | undefined {
    const row = this.database
      .prepare("SELECT * FROM ssh_tunnels WHERE id = ?")
      .get(id);
    return row ? sshTunnelFromRow(row) : undefined;
  }

  listSSHTunnels(accountId: string): SSHTunnelRecord[] {
    return this.database
      .prepare("SELECT * FROM ssh_tunnels WHERE account_id = ? ORDER BY name")
      .all(accountId)
      .map((row) => sshTunnelFromRow(row));
  }

  deleteSSHTunnel(id: string): void {
    const result = this.database
      .prepare("DELETE FROM ssh_tunnels WHERE id = ?")
      .run(id);
    if (result.changes === 0) {
      throw new NotFoundError("ssh tunnel");
    }
  }

  createSSHSnippet(record: SSHCommandSnippetRecord): SSHCommandSnippetRecord {
    try {
      this.database
        .prepare(
          `INSERT INTO ssh_snippets(
            id, account_id, name, command, variables_json, secret_ciphertext,
            enabled, version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          record.id,
          record.accountId,
          record.name,
          record.command,
          JSON.stringify(record.variables),
          record.secretCiphertext,
          record.enabled ? 1 : 0,
          record.version,
          record.createdAt,
          record.updatedAt,
        );
      return record;
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        throw new ConflictError("ssh snippet name already exists");
      }
      throw error;
    }
  }

  updateSSHSnippet(record: SSHCommandSnippetRecord): SSHCommandSnippetRecord {
    const result = this.database
      .prepare(
        `UPDATE ssh_snippets
         SET name = ?, command = ?, variables_json = ?, secret_ciphertext = ?,
             enabled = ?, version = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        record.name,
        record.command,
        JSON.stringify(record.variables),
        record.secretCiphertext,
        record.enabled ? 1 : 0,
        record.version,
        record.updatedAt,
        record.id,
      );
    if (result.changes === 0) {
      throw new NotFoundError("ssh snippet");
    }
    return record;
  }

  findSSHSnippet(id: string): SSHCommandSnippetRecord | undefined {
    const row = this.database
      .prepare("SELECT * FROM ssh_snippets WHERE id = ?")
      .get(id);
    return row ? sshSnippetFromRow(row) : undefined;
  }

  listSSHSnippets(accountId: string): SSHCommandSnippetRecord[] {
    return this.database
      .prepare("SELECT * FROM ssh_snippets WHERE account_id = ? ORDER BY name")
      .all(accountId)
      .map((row) => sshSnippetFromRow(row));
  }

  deleteSSHSnippet(id: string): void {
    const result = this.database
      .prepare("DELETE FROM ssh_snippets WHERE id = ?")
      .run(id);
    if (result.changes === 0) {
      throw new NotFoundError("ssh snippet");
    }
  }

  createSSHKeyIdentity(record: SSHKeyIdentityRecord): SSHKeyIdentityRecord {
    try {
      this.database
        .prepare(
          `INSERT INTO ssh_key_identities(
            id, account_id, name, public_key, fingerprint, secret_ciphertext,
            enabled, version, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          record.id,
          record.accountId,
          record.name,
          record.publicKey,
          record.fingerprint,
          record.secretCiphertext,
          record.enabled ? 1 : 0,
          record.version,
          record.createdAt,
          record.updatedAt,
        );
      return record;
    } catch (error) {
      if (String(error).includes("UNIQUE")) {
        throw new ConflictError("ssh key identity name already exists");
      }
      throw error;
    }
  }

  updateSSHKeyIdentity(record: SSHKeyIdentityRecord): SSHKeyIdentityRecord {
    const result = this.database
      .prepare(
        `UPDATE ssh_key_identities
         SET name = ?, public_key = ?, fingerprint = ?, secret_ciphertext = ?,
             enabled = ?, version = ?, updated_at = ?
         WHERE id = ?`,
      )
      .run(
        record.name,
        record.publicKey,
        record.fingerprint,
        record.secretCiphertext,
        record.enabled ? 1 : 0,
        record.version,
        record.updatedAt,
        record.id,
      );
    if (result.changes === 0) {
      throw new NotFoundError("ssh key identity");
    }
    return record;
  }

  findSSHKeyIdentity(id: string): SSHKeyIdentityRecord | undefined {
    const row = this.database
      .prepare("SELECT * FROM ssh_key_identities WHERE id = ?")
      .get(id);
    return row ? sshKeyIdentityFromRow(row) : undefined;
  }

  listSSHKeyIdentities(accountId: string): SSHKeyIdentityRecord[] {
    return this.database
      .prepare(
        "SELECT * FROM ssh_key_identities WHERE account_id = ? ORDER BY name",
      )
      .all(accountId)
      .map((row) => sshKeyIdentityFromRow(row));
  }

  deleteSSHKeyIdentity(id: string): void {
    const result = this.database
      .prepare("DELETE FROM ssh_key_identities WHERE id = ?")
      .run(id);
    if (result.changes === 0) {
      throw new NotFoundError("ssh key identity");
    }
  }

  createSSHSessionHistory(
    record: SSHSessionHistoryRecord,
  ): SSHSessionHistoryRecord {
    this.database
      .prepare(
        `INSERT INTO ssh_session_history(
          id, account_id, host_id, host_name, status, latency_ms,
          error_message, started_at, ended_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        record.id,
        record.accountId,
        record.hostId,
        record.hostName,
        record.status,
        record.latencyMs,
        record.errorMessage,
        record.startedAt,
        record.endedAt,
      );
    return record;
  }

  updateSSHSessionHistory(
    record: SSHSessionHistoryRecord,
  ): SSHSessionHistoryRecord {
    const result = this.database
      .prepare(
        `UPDATE ssh_session_history
         SET status = ?, latency_ms = ?, error_message = ?, ended_at = ?
         WHERE id = ? AND account_id = ?`,
      )
      .run(
        record.status,
        record.latencyMs,
        record.errorMessage,
        record.endedAt,
        record.id,
        record.accountId,
      );
    if (result.changes === 0) {
      throw new NotFoundError("ssh session history");
    }
    return record;
  }

  findSSHSessionHistory(id: string): SSHSessionHistoryRecord | undefined {
    const row = this.database
      .prepare("SELECT * FROM ssh_session_history WHERE id = ?")
      .get(id);
    return row ? sshSessionHistoryFromRow(row) : undefined;
  }

  listSSHSessionHistory(
    accountId: string,
    limit = 200,
  ): SSHSessionHistoryRecord[] {
    return this.database
      .prepare(
        `SELECT * FROM ssh_session_history
         WHERE account_id = ?
         ORDER BY started_at DESC, rowid DESC
         LIMIT ?`,
      )
      .all(accountId, limit)
      .map((row) => sshSessionHistoryFromRow(row));
  }

  replaceGrants(
    accountId: string,
    connectionId: string,
    operations: Operation[],
    now: number,
  ): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          "DELETE FROM grants WHERE account_id = ? AND connection_id = ?",
        )
        .run(accountId, connectionId);
      const insert = this.database.prepare(
        "INSERT INTO grants(account_id, connection_id, operation, created_at) VALUES (?, ?, ?, ?)",
      );
      for (const operation of operations) {
        insert.run(accountId, connectionId, operation, now);
      }
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  listAssignedConnections(accountId: string): AssignedConnection[] {
    const rows = this.database
      .prepare(
        `SELECT c.id, c.name, c.kind, c.enabled, g.operation
         FROM connections c
         JOIN grants g ON g.connection_id = c.id
         WHERE g.account_id = ?
         ORDER BY c.name, g.operation`,
      )
      .all(accountId);
    const result = new Map<string, AssignedConnection>();
    for (const row of rows) {
      const id = stringValue(row.id);
      const current = result.get(id) ?? {
        id,
        name: stringValue(row.name),
        kind: stringValue(row.kind) as ConnectionKind,
        enabled: numberValue(row.enabled) === 1,
        operations: [],
      };
      current.operations.push(stringValue(row.operation) as Operation);
      result.set(id, current);
    }
    return [...result.values()];
  }

  hasGrant(
    accountId: string,
    connectionId: string,
    operation: Operation,
  ): boolean {
    return Boolean(
      this.database
        .prepare(
          `SELECT 1 FROM grants
           WHERE account_id = ? AND connection_id = ? AND operation = ?`,
        )
        .get(accountId, connectionId, operation),
    );
  }

  createLoginSession(input: CreateSessionInput): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      this.database
        .prepare(
          `UPDATE sessions SET revoked_at = ?
           WHERE account_id = ? AND device_id = ? AND revoked_at IS NULL`,
        )
        .run(input.now, input.session.accountId, input.session.deviceId);
      const active = this.database
        .prepare(
          `SELECT COUNT(*) AS count FROM sessions
           WHERE account_id = ? AND revoked_at IS NULL AND refresh_expires_at > ?`,
        )
        .get(input.session.accountId, input.now) as { count: number };
      if (Number(active.count) >= input.deviceLimit) {
        throw new DeviceLimitError();
      }
      this.database
        .prepare(
          `INSERT INTO sessions(
            id, family_id, account_id, device_id, refresh_hash, refresh_expires_at,
            revoked_at, created_at, last_used_at, ip_address, user_agent
          ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)`,
        )
        .run(
          input.session.id,
          input.session.familyId,
          input.session.accountId,
          input.session.deviceId,
          input.session.refreshHash,
          input.session.refreshExpiresAt,
          input.session.createdAt,
          input.session.lastUsedAt,
          input.session.ipAddress,
          input.session.userAgent,
        );
      this.database
        .prepare(
          `INSERT INTO access_tokens(token_hash, session_id, account_id, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?)`,
        )
        .run(
          input.accessTokenHash,
          input.session.id,
          input.session.accountId,
          input.accessExpiresAt,
          input.now,
        );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  findSessionByRefreshHash(
    refreshHash: string,
  ): SessionWithAccount | undefined {
    const row = this.database
      .prepare(
        `SELECT s.*, a.username, a.enabled AS account_enabled, a.device_limit
         FROM sessions s JOIN accounts a ON a.id = s.account_id
         WHERE s.refresh_hash = ?`,
      )
      .get(refreshHash);
    if (!row) {
      return undefined;
    }
    return {
      id: stringValue(row.id),
      familyId: stringValue(row.family_id),
      accountId: stringValue(row.account_id),
      username: stringValue(row.username),
      accountEnabled: numberValue(row.account_enabled) === 1,
      deviceLimit: numberValue(row.device_limit),
      deviceId: stringValue(row.device_id),
      refreshHash: stringValue(row.refresh_hash),
      refreshExpiresAt: numberValue(row.refresh_expires_at),
      revokedAt: optionalNumber(row.revoked_at),
      createdAt: numberValue(row.created_at),
      lastUsedAt: numberValue(row.last_used_at),
      ipAddress: stringValue(row.ip_address),
      userAgent: stringValue(row.user_agent),
    };
  }

  findRefreshFamily(refreshHash: string): string | undefined {
    const row = this.database
      .prepare("SELECT family_id FROM refresh_history WHERE token_hash = ?")
      .get(refreshHash) as { family_id: string } | undefined;
    return row?.family_id;
  }

  rotateSession(input: RotateSessionInput): void {
    this.database.exec("BEGIN IMMEDIATE");
    try {
      const current = this.database
        .prepare(
          "SELECT family_id FROM sessions WHERE id = ? AND refresh_hash = ?",
        )
        .get(input.sessionId, input.currentRefreshHash) as
        { family_id: string } | undefined;
      if (!current) {
        throw new InvalidTokenError();
      }
      this.database
        .prepare(
          "INSERT INTO refresh_history(token_hash, session_id, family_id, used_at) VALUES (?, ?, ?, ?)",
        )
        .run(
          input.currentRefreshHash,
          input.sessionId,
          current.family_id,
          input.now,
        );
      this.database
        .prepare(
          `UPDATE sessions
           SET refresh_hash = ?, refresh_expires_at = ?, last_used_at = ?
           WHERE id = ?`,
        )
        .run(
          input.nextRefreshHash,
          input.nextRefreshExpiresAt,
          input.now,
          input.sessionId,
        );
      this.database
        .prepare(
          `INSERT INTO access_tokens(token_hash, session_id, account_id, expires_at, created_at)
           SELECT ?, id, account_id, ?, ? FROM sessions WHERE id = ?`,
        )
        .run(
          input.accessTokenHash,
          input.accessExpiresAt,
          input.now,
          input.sessionId,
        );
      this.database.exec("COMMIT");
    } catch (error) {
      this.database.exec("ROLLBACK");
      throw error;
    }
  }

  authenticateAccess(accessHash: string, now: number): Principal | undefined {
    const row = this.database
      .prepare(
        `SELECT a.id AS account_id, a.username, a.enabled, s.id AS session_id,
                s.device_id, s.revoked_at, t.expires_at
         FROM access_tokens t
         JOIN sessions s ON s.id = t.session_id
         JOIN accounts a ON a.id = t.account_id
         WHERE t.token_hash = ?`,
      )
      .get(accessHash);
    if (
      !row ||
      numberValue(row.enabled) !== 1 ||
      row.revoked_at !== null ||
      numberValue(row.expires_at) <= now
    ) {
      return undefined;
    }
    return {
      accountId: stringValue(row.account_id),
      username: stringValue(row.username),
      sessionId: stringValue(row.session_id),
      deviceId: stringValue(row.device_id),
    };
  }

  revokeFamily(familyId: string, now: number): void {
    this.database
      .prepare(
        "UPDATE sessions SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL",
      )
      .run(now, familyId);
  }

  revokeSession(sessionId: string, now: number): void {
    this.database
      .prepare(
        "UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
      )
      .run(now, sessionId);
  }

  revokeAccountSessions(accountId: string, now: number): void {
    this.database
      .prepare(
        "UPDATE sessions SET revoked_at = ? WHERE account_id = ? AND revoked_at IS NULL",
      )
      .run(now, accountId);
  }

  listSessions(accountId: string, now: number): SessionSummary[] {
    return this.database
      .prepare(
        `SELECT id, device_id, ip_address, user_agent, created_at, last_used_at,
                refresh_expires_at, revoked_at
         FROM sessions WHERE account_id = ? ORDER BY created_at DESC`,
      )
      .all(accountId)
      .map((row) => ({
        id: stringValue(row.id),
        deviceId: stringValue(row.device_id),
        ipAddress: stringValue(row.ip_address),
        userAgent: stringValue(row.user_agent),
        createdAt: numberValue(row.created_at),
        lastUsedAt: numberValue(row.last_used_at),
        expiresAt: numberValue(row.refresh_expires_at),
        revoked:
          row.revoked_at !== null || numberValue(row.refresh_expires_at) <= now,
      }));
  }

  appendAudit(event: AuditEvent): void {
    this.database
      .prepare(
        `INSERT INTO audit_events(
          id, occurred_at, account_id, session_id, device_id, ip_address, action,
          connection_id, ssh_host_id, success, duration_ms, rows_count, bytes_count,
          statement_hash, statement_type, error_code
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        event.id,
        event.occurredAt,
        event.accountId ?? null,
        event.sessionId ?? null,
        event.deviceId ?? null,
        event.ipAddress ?? null,
        event.action,
        event.connectionId ?? null,
        event.sshHostId ?? null,
        event.success ? 1 : 0,
        event.durationMs,
        event.rowsCount ?? null,
        event.bytesCount ?? null,
        event.statementHash ?? null,
        event.statementType ?? null,
        event.errorCode ?? null,
      );
  }

  listAudit(limit: number): Array<Record<string, SQLOutputValue>> {
    return this.database
      .prepare("SELECT * FROM audit_events ORDER BY occurred_at DESC LIMIT ?")
      .all(limit);
  }

  deleteAuditBefore(cutoff: number): number {
    return Number(
      this.database
        .prepare("DELETE FROM audit_events WHERE occurred_at < ?")
        .run(cutoff).changes,
    );
  }

  setAdminLanguage(
    telegramUserId: number,
    language: "en" | "zh-TW",
    now: number,
  ): void {
    this.database
      .prepare(
        `INSERT INTO admin_preferences(telegram_user_id, language, updated_at)
         VALUES (?, ?, ?)
         ON CONFLICT(telegram_user_id)
         DO UPDATE SET language = excluded.language, updated_at = excluded.updated_at`,
      )
      .run(String(telegramUserId), language, now);
  }

  getAdminLanguage(telegramUserId: number): "en" | "zh-TW" | undefined {
    const row = this.database
      .prepare(
        "SELECT language FROM admin_preferences WHERE telegram_user_id = ?",
      )
      .get(String(telegramUserId)) as { language: "en" | "zh-TW" } | undefined;
    return row?.language;
  }
}
