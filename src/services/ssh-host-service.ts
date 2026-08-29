import { randomUUID } from "node:crypto";

import type {
  AuditEvent,
  Principal,
  SSHHostRecord,
  SSHHostSecret,
} from "../domain/models.js";
import { NotFoundError, ServiceError } from "../errors.js";
import { SqliteRepository } from "../repository/sqlite-repository.js";
import { decryptSecret, encryptSecret } from "../security/crypto.js";

interface SSHHostServiceOptions {
  maxHosts: number;
  clock?: () => number;
}

export interface SSHHostContext {
  principal: Principal;
  ipAddress?: string;
}

export interface SSHHostInput {
  name: string;
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  keyPassphrase?: string;
  trustedFingerprint?: string;
}

export interface SSHHostView {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  hasPassword: boolean;
  hasPrivateKey: boolean;
  hasKeyPassphrase: boolean;
  trustedFingerprint: string;
  createdAt: number;
  updatedAt: number;
}

export interface SSHHostCredentials {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  password: string;
  privateKey: string;
  keyPassphrase: string;
  trustedFingerprint: string;
}

interface ValidatedFields {
  name: string;
  host: string;
  port: number;
  username: string;
}

function invalid(detail: string): ServiceError {
  return new ServiceError("invalid_ssh_host", detail, 400);
}

export class SSHHostService {
  readonly #clock: () => number;

  constructor(
    private readonly repository: SqliteRepository,
    private readonly masterKey: Buffer,
    private readonly options: SSHHostServiceOptions,
  ) {
    this.#clock = options.clock ?? Date.now;
  }

  accessEnabled(accountId: string): boolean {
    return this.repository.findAccountById(accountId)?.sshEnabled === true;
  }

  listHosts(accountId: string): SSHHostView[] {
    this.requireAccess(accountId);
    return this.repository
      .listSSHHosts(accountId)
      .map((record) => this.toView(record));
  }

  createHost(context: SSHHostContext, input: SSHHostInput): SSHHostView {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const fields = this.validateFields(input);
      const password = input.password ?? "";
      const privateKey = input.privateKey ?? "";
      if (!password && !privateKey) {
        throw invalid("password or private key is required");
      }
      const keyPassphrase = input.keyPassphrase ?? "";
      if (this.repository.countSSHHosts(accountId) >= this.options.maxHosts) {
        throw new ServiceError(
          "ssh_host_limit",
          "ssh host limit reached for this account",
          403,
        );
      }
      const now = this.#clock();
      const record: SSHHostRecord = {
        id: randomUUID(),
        accountId,
        ...fields,
        secretCiphertext: encryptSecret(
          this.masterKey,
          JSON.stringify({
            password,
            privateKey,
            keyPassphrase,
          } satisfies SSHHostSecret),
        ),
        trustedFingerprint: this.normalizeFingerprint(input.trustedFingerprint),
        createdAt: now,
        updatedAt: now,
      };
      const created = this.repository.createSSHHost(record);
      this.appendAudit(context, "ssh.host.create", started, true, created.id);
      return this.toView(created);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.create",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  updateHost(
    context: SSHHostContext,
    id: string,
    input: SSHHostInput,
  ): SSHHostView {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.loadHost(accountId, id);
      hostId = current.id;
      const fields = this.validateFields(input);
      const previous = this.decryptSecretOf(current);
      const secret: SSHHostSecret = {
        password: input.password ? input.password : previous.password,
        privateKey: input.privateKey ? input.privateKey : previous.privateKey,
        keyPassphrase: input.keyPassphrase
          ? input.keyPassphrase
          : previous.keyPassphrase,
      };
      if (!secret.password && !secret.privateKey) {
        throw invalid("password or private key is required");
      }
      const hostChanged =
        fields.host !== current.host || fields.port !== current.port;
      const trustedFingerprint = hostChanged
        ? this.normalizeFingerprint(input.trustedFingerprint)
        : current.trustedFingerprint;
      const saved = this.repository.updateSSHHost({
        ...current,
        ...fields,
        secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secret)),
        trustedFingerprint,
        updatedAt: this.#clock(),
      });
      this.appendAudit(context, "ssh.host.update", started, true, saved.id);
      return this.toView(saved);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.update",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  deleteHost(context: SSHHostContext, id: string): void {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      this.repository.deleteSSHHost(id);
      // The host row is gone, so the audit cannot reference it (foreign key).
      this.appendAudit(context, "ssh.host.delete", started, true, undefined);
    } catch (error) {
      // On failure the host row still exists, so referencing it is safe.
      this.appendAudit(
        context,
        "ssh.host.delete",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  getCredentials(context: SSHHostContext, id: string): SSHHostCredentials {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      const secret = this.decryptSecretOf(record);
      this.appendAudit(context, "ssh.host.credentials", started, true, hostId);
      return {
        id: record.id,
        name: record.name,
        host: record.host,
        port: record.port,
        username: record.username,
        password: secret.password,
        privateKey: secret.privateKey,
        keyPassphrase: secret.keyPassphrase,
        trustedFingerprint: record.trustedFingerprint,
      };
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.credentials",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  setFingerprint(
    context: SSHHostContext,
    id: string,
    fingerprint: string,
  ): void {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      const normalized = fingerprint.trim();
      if (normalized.length < 1 || normalized.length > 128) {
        throw invalid("fingerprint must be 1-128 characters");
      }
      this.repository.setSSHHostFingerprint(
        record.id,
        normalized,
        this.#clock(),
      );
      this.appendAudit(context, "ssh.host.fingerprint", started, true, hostId);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.fingerprint",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  private requireAccess(accountId: string): void {
    const account = this.repository.findAccountById(accountId);
    if (!account) {
      throw new NotFoundError("account");
    }
    if (!account.sshEnabled) {
      throw new ServiceError(
        "ssh_disabled",
        "SSH access is disabled for this account",
        403,
      );
    }
  }

  private loadHost(accountId: string, id: string): SSHHostRecord {
    const record = this.repository.findSSHHost(id);
    if (!record || record.accountId !== accountId) {
      throw new NotFoundError("ssh host");
    }
    return record;
  }

  private validateFields(input: SSHHostInput): ValidatedFields {
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100) {
      throw invalid("name must be 1-100 characters");
    }
    const host = input.host.trim();
    if (host.length < 1 || host.length > 255) {
      throw invalid("host must be 1-255 characters");
    }
    const port = input.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw invalid("port must be between 1 and 65535");
    }
    const username = input.username.trim();
    if (username.length < 1 || username.length > 64) {
      throw invalid("username must be 1-64 characters");
    }
    if ((input.password?.length ?? 0) > 512) {
      throw invalid("password is too long");
    }
    if ((input.privateKey?.length ?? 0) > 65536) {
      throw invalid("private key is too long");
    }
    if ((input.keyPassphrase?.length ?? 0) > 512) {
      throw invalid("key passphrase is too long");
    }
    return { name, host, port, username };
  }

  private normalizeFingerprint(value: string | undefined): string {
    const normalized = (value ?? "").trim();
    if (normalized.length > 128) {
      throw invalid("trusted fingerprint is too long");
    }
    return normalized;
  }

  private decryptSecretOf(record: SSHHostRecord): SSHHostSecret {
    return JSON.parse(
      decryptSecret(this.masterKey, record.secretCiphertext),
    ) as SSHHostSecret;
  }

  private toView(record: SSHHostRecord): SSHHostView {
    const secret = this.decryptSecretOf(record);
    return {
      id: record.id,
      name: record.name,
      host: record.host,
      port: record.port,
      username: record.username,
      hasPassword: Boolean(secret.password),
      hasPrivateKey: Boolean(secret.privateKey),
      hasKeyPassphrase: Boolean(secret.keyPassphrase),
      trustedFingerprint: record.trustedFingerprint,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  private appendAudit(
    context: SSHHostContext,
    action: string,
    started: number,
    success: boolean,
    sshHostId: string | undefined,
    error?: unknown,
  ): void {
    const now = this.#clock();
    const event: AuditEvent = {
      id: randomUUID(),
      occurredAt: now,
      accountId: context.principal.accountId,
      sessionId: context.principal.sessionId,
      deviceId: context.principal.deviceId,
      action,
      success,
      durationMs: Math.max(0, now - started),
    };
    if (context.ipAddress) event.ipAddress = context.ipAddress;
    if (sshHostId) event.sshHostId = sshHostId;
    if (error instanceof ServiceError) event.errorCode = error.code;
    this.repository.appendAudit(event);
  }
}
