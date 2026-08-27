import { randomUUID } from "node:crypto";

import type {
  Account,
  AssignedConnection,
  Connection,
  ConnectionSecret,
  Operation,
  SessionSummary,
} from "../domain/models.js";
import { ForbiddenError, NotFoundError } from "../errors.js";
import { SqliteRepository } from "../repository/sqlite-repository.js";
import {
  decryptSecret,
  encryptSecret,
  generatePassword,
  hashPassword,
} from "../security/crypto.js";

interface AdminServiceOptions {
  defaultDeviceLimit: number;
  clock?: () => number;
}

const operationsByKind: Record<
  ConnectionSecret["kind"],
  ReadonlySet<Operation>
> = {
  s3: new Set(["s3.read", "s3.write", "s3.delete"]),
  mysql: new Set(["sql.tables", "sql.query", "sql.exec"]),
  postgres: new Set(["sql.tables", "sql.query", "sql.exec"]),
};

export class AdminService {
  readonly #clock: () => number;

  constructor(
    private readonly repository: SqliteRepository,
    private readonly masterKey: Buffer,
    private readonly options: AdminServiceOptions,
  ) {
    this.#clock = options.clock ?? Date.now;
  }

  async createAccount(
    username: string,
    deviceLimit = this.options.defaultDeviceLimit,
  ): Promise<{ account: Account; password: string }> {
    const normalizedUsername = username.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$/.test(normalizedUsername)) {
      throw new Error("username must contain 3-64 safe characters");
    }
    if (
      !Number.isInteger(deviceLimit) ||
      deviceLimit < 1 ||
      deviceLimit > 100
    ) {
      throw new Error("device limit must be between 1 and 100");
    }
    const password = generatePassword();
    const now = this.#clock();
    const account = this.repository.createAccount({
      id: randomUUID(),
      username: normalizedUsername,
      passwordHash: await hashPassword(password),
      enabled: true,
      deviceLimit,
      createdAt: now,
      updatedAt: now,
    });
    return { account, password };
  }

  listAccounts(): Account[] {
    return this.repository.listAccounts();
  }

  async resetPassword(accountId: string): Promise<string> {
    const password = generatePassword();
    this.repository.setAccountPassword(
      accountId,
      await hashPassword(password),
      this.#clock(),
    );
    this.repository.revokeAccountSessions(accountId, this.#clock());
    return password;
  }

  setAccountEnabled(accountId: string, enabled: boolean): void {
    const now = this.#clock();
    this.repository.setAccountEnabled(accountId, enabled, now);
    if (!enabled) {
      this.repository.revokeAccountSessions(accountId, now);
    }
  }

  setAccountDeviceLimit(accountId: string, limit: number): void {
    if (!Number.isInteger(limit) || limit < 1 || limit > 100) {
      throw new Error("device limit must be between 1 and 100");
    }
    this.repository.setAccountDeviceLimit(accountId, limit, this.#clock());
  }

  deleteAccount(accountId: string): void {
    this.repository.deleteAccount(accountId);
  }

  listSessions(accountId: string): SessionSummary[] {
    return this.repository.listSessions(accountId, this.#clock());
  }

  revokeSession(sessionId: string): void {
    this.repository.revokeSession(sessionId, this.#clock());
  }

  revokeAllSessions(accountId: string): void {
    this.repository.revokeAccountSessions(accountId, this.#clock());
  }

  createConnection(input: {
    name: string;
    secret: ConnectionSecret;
  }): Connection {
    const now = this.#clock();
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100) {
      throw new Error("connection name is required");
    }
    return this.repository.createConnection({
      id: randomUUID(),
      name,
      kind: input.secret.kind,
      enabled: true,
      secretCiphertext: encryptSecret(
        this.masterKey,
        JSON.stringify(input.secret),
      ),
      createdAt: now,
      updatedAt: now,
    });
  }

  updateConnection(
    id: string,
    input: { name: string; secret: ConnectionSecret },
  ): void {
    const current = this.repository.findConnection(id);
    if (!current) {
      throw new NotFoundError("connection");
    }
    this.repository.updateConnection({
      ...current,
      name: input.name.trim(),
      kind: input.secret.kind,
      secretCiphertext: encryptSecret(
        this.masterKey,
        JSON.stringify(input.secret),
      ),
      updatedAt: this.#clock(),
    });
  }

  listConnections(): Array<Omit<Connection, "secretCiphertext">> {
    return this.repository.listConnections();
  }

  setConnectionEnabled(connectionId: string, enabled: boolean): void {
    this.repository.setConnectionEnabled(connectionId, enabled, this.#clock());
  }

  deleteConnection(connectionId: string): void {
    this.repository.deleteConnection(connectionId);
  }

  getConnectionSecret(connectionId: string): ConnectionSecret {
    const connection = this.repository.findConnection(connectionId);
    if (!connection) {
      throw new NotFoundError("connection");
    }
    return JSON.parse(
      decryptSecret(this.masterKey, connection.secretCiphertext),
    ) as ConnectionSecret;
  }

  setGrants(
    accountId: string,
    connectionId: string,
    operations: Operation[],
  ): void {
    if (!this.repository.findAccountById(accountId)) {
      throw new NotFoundError("account");
    }
    const connection = this.repository.findConnection(connectionId);
    if (!connection) {
      throw new NotFoundError("connection");
    }
    const allowed = operationsByKind[connection.kind];
    const unique = [...new Set(operations)].sort();
    if (unique.some((operation) => !allowed.has(operation))) {
      throw new ForbiddenError("operation does not match connection kind");
    }
    this.repository.replaceGrants(
      accountId,
      connectionId,
      unique,
      this.#clock(),
    );
  }

  listAssignedConnections(accountId: string): AssignedConnection[] {
    return this.repository.listAssignedConnections(accountId);
  }

  listAudit(limit = 50): ReturnType<SqliteRepository["listAudit"]> {
    return this.repository.listAudit(Math.min(Math.max(limit, 1), 500));
  }

  setAdminLanguage(telegramUserId: number, language: "en" | "zh-TW"): void {
    this.repository.setAdminLanguage(telegramUserId, language, this.#clock());
  }

  getAdminLanguage(telegramUserId: number): "en" | "zh-TW" | undefined {
    return this.repository.getAdminLanguage(telegramUserId);
  }
}
