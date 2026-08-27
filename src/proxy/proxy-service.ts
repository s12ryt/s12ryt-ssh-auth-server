import { createHash, randomUUID } from "node:crypto";
import { Readable } from "node:stream";

import type {
  AuditEvent,
  Operation,
  Principal,
  S3ConnectionSecret,
} from "../domain/models.js";
import { ForbiddenError, NotFoundError, ServiceError } from "../errors.js";
import { SqliteRepository } from "../repository/sqlite-repository.js";
import { AdminService } from "../services/admin-service.js";
import type {
  S3Download,
  S3Gateway,
  S3Object,
  SQLExecResult,
  SQLGateway,
  SQLQueryResult,
} from "./gateways.js";

interface ProxyOptions {
  sqlTimeoutMs: number;
  sqlRowLimit: number;
  s3MaxBytes: number;
  clock?: () => number;
}

interface Gateways {
  s3: S3Gateway;
  sql: SQLGateway;
}

interface OperationContext {
  principal: Principal;
  connectionId: string;
  ipAddress?: string;
}

function normalizeRelativeKey(value: string, allowEmpty: boolean): string {
  const normalized = value.trim().replaceAll("\\", "/").replace(/^\/+/, "");
  if ((!allowEmpty && !normalized) || normalized.split("/").includes("..")) {
    throw new ServiceError("invalid_key", "invalid object key", 400);
  }
  return normalized;
}

function basePrefix(secret: S3ConnectionSecret): string {
  const normalized = normalizeRelativeKey(secret.prefix, true).replace(
    /\/+$/,
    "",
  );
  return normalized ? `${normalized}/` : "";
}

function statementType(statement: string): string {
  const withoutLeadingComments = statement
    .replace(/^\s*(?:--[^\n]*(?:\n|$)|\/\*[\s\S]*?\*\/\s*)*/u, "")
    .trim();
  return withoutLeadingComments.split(/\s+/, 1)[0]?.toUpperCase() || "UNKNOWN";
}

function statementHash(statement: string): string {
  return createHash("sha256").update(statement, "utf8").digest("hex");
}

export async function* limitBytes(
  body: AsyncIterable<Uint8Array>,
  maximumBytes: number,
): AsyncGenerator<Uint8Array> {
  let total = 0;
  for await (const chunk of body) {
    total += chunk.byteLength;
    if (total > maximumBytes) {
      throw new ServiceError(
        "payload_too_large",
        "object exceeds the configured byte limit",
        413,
      );
    }
    yield chunk;
  }
}

export class ProxyService {
  readonly #clock: () => number;

  constructor(
    private readonly repository: SqliteRepository,
    private readonly admin: AdminService,
    private readonly gateways: Gateways,
    private readonly options: ProxyOptions,
  ) {
    this.#clock = options.clock ?? Date.now;
  }

  async testConnection(
    connectionId: string,
    signal: AbortSignal,
  ): Promise<void> {
    const secret = this.admin.getConnectionSecret(connectionId);
    if (secret.kind === "s3") {
      await this.gateways.s3.test(secret, signal);
      return;
    }
    await this.gateways.sql.test(secret, signal);
  }

  async listS3(
    context: OperationContext,
    prefix: string,
    signal: AbortSignal,
  ): Promise<S3Object[]> {
    return this.withAudit(context, "s3.read", undefined, async () => {
      const secret = this.authorizedS3(context, "s3.read");
      const configuredPrefix = basePrefix(secret);
      const requestedPrefix = normalizeRelativeKey(prefix, true);
      const objects = await this.gateways.s3.list(
        secret,
        `${configuredPrefix}${requestedPrefix}`,
        signal,
      );
      return objects
        .filter((object) => object.key.startsWith(configuredPrefix))
        .map((object) => ({
          ...object,
          key: object.key.slice(configuredPrefix.length),
        }));
    });
  }

  async uploadS3(
    context: OperationContext,
    key: string,
    body: AsyncIterable<Uint8Array>,
    contentLength: number | undefined,
    signal: AbortSignal,
  ): Promise<{ bytes: number }> {
    if (
      contentLength !== undefined &&
      contentLength > this.options.s3MaxBytes
    ) {
      throw new ServiceError(
        "payload_too_large",
        "object exceeds the configured byte limit",
        413,
      );
    }
    return this.withAudit(context, "s3.write", undefined, async () => {
      const secret = this.authorizedS3(context, "s3.write");
      const objectKey = `${basePrefix(secret)}${normalizeRelativeKey(key, false)}`;
      const bytes = await this.gateways.s3.upload(
        secret,
        objectKey,
        limitBytes(body, this.options.s3MaxBytes),
        signal,
      );
      return { bytes };
    });
  }

  async downloadS3(
    context: OperationContext,
    key: string,
    signal: AbortSignal,
  ): Promise<S3Download> {
    return this.withAudit(context, "s3.read", undefined, async () => {
      const secret = this.authorizedS3(context, "s3.read");
      const download = await this.gateways.s3.download(
        secret,
        `${basePrefix(secret)}${normalizeRelativeKey(key, false)}`,
        signal,
      );
      if (
        download.contentLength !== undefined &&
        download.contentLength > this.options.s3MaxBytes
      ) {
        download.body.destroy();
        throw new ServiceError(
          "payload_too_large",
          "object exceeds the configured byte limit",
          413,
        );
      }
      download.body = Readable.from(
        limitBytes(download.body, this.options.s3MaxBytes),
      );
      return download;
    });
  }

  async deleteS3(
    context: OperationContext,
    key: string,
    signal: AbortSignal,
  ): Promise<void> {
    return this.withAudit(context, "s3.delete", undefined, async () => {
      const secret = this.authorizedS3(context, "s3.delete");
      await this.gateways.s3.delete(
        secret,
        `${basePrefix(secret)}${normalizeRelativeKey(key, false)}`,
        signal,
      );
    });
  }

  async tables(
    context: OperationContext,
    signal: AbortSignal,
  ): Promise<string[]> {
    return this.withAudit(context, "sql.tables", undefined, async () => {
      const secret = this.authorizedSQL(context, "sql.tables");
      return this.gateways.sql.tables(secret, signal);
    });
  }

  async query(
    context: OperationContext,
    statement: string,
    parameters: unknown[],
    signal: AbortSignal,
  ): Promise<SQLQueryResult> {
    const metadata = {
      statementHash: statementHash(statement),
      statementType: statementType(statement),
    };
    return this.withAudit(context, "sql.query", metadata, async () => {
      const secret = this.authorizedSQL(context, "sql.query");
      return this.gateways.sql.query(secret, statement, parameters, {
        timeoutMs: this.options.sqlTimeoutMs,
        rowLimit: this.options.sqlRowLimit,
        signal,
      });
    });
  }

  async exec(
    context: OperationContext,
    statement: string,
    parameters: unknown[],
    signal: AbortSignal,
  ): Promise<SQLExecResult> {
    const metadata = {
      statementHash: statementHash(statement),
      statementType: statementType(statement),
    };
    return this.withAudit(context, "sql.exec", metadata, async () => {
      const secret = this.authorizedSQL(context, "sql.exec");
      return this.gateways.sql.exec(secret, statement, parameters, {
        timeoutMs: this.options.sqlTimeoutMs,
        signal,
      });
    });
  }

  private authorizedS3(
    context: OperationContext,
    operation: Operation,
  ): S3ConnectionSecret {
    this.authorize(context, operation);
    const secret = this.admin.getConnectionSecret(context.connectionId);
    if (secret.kind !== "s3") {
      throw new NotFoundError("S3 connection");
    }
    return secret;
  }

  private authorizedSQL(
    context: OperationContext,
    operation: Operation,
  ): Exclude<
    ReturnType<AdminService["getConnectionSecret"]>,
    S3ConnectionSecret
  > {
    this.authorize(context, operation);
    const secret = this.admin.getConnectionSecret(context.connectionId);
    if (secret.kind === "s3") {
      throw new NotFoundError("SQL connection");
    }
    return secret;
  }

  private authorize(context: OperationContext, operation: Operation): void {
    const connection = this.repository.findConnection(context.connectionId);
    if (!connection || !connection.enabled) {
      throw new NotFoundError("connection");
    }
    if (
      !this.repository.hasGrant(
        context.principal.accountId,
        context.connectionId,
        operation,
      )
    ) {
      throw new ForbiddenError();
    }
  }

  private async withAudit<T>(
    context: OperationContext,
    action: string,
    statement: { statementHash: string; statementType: string } | undefined,
    operation: () => Promise<T>,
  ): Promise<T> {
    const started = this.#clock();
    try {
      const result = await operation();
      this.appendAudit(context, action, started, true, statement, result);
      return result;
    } catch (error) {
      this.appendAudit(
        context,
        action,
        started,
        false,
        statement,
        undefined,
        error,
      );
      throw error;
    }
  }

  private appendAudit(
    context: OperationContext,
    action: string,
    started: number,
    success: boolean,
    statement: { statementHash: string; statementType: string } | undefined,
    result?: unknown,
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
      connectionId: context.connectionId,
      success,
      durationMs: Math.max(0, now - started),
    };
    if (context.ipAddress) event.ipAddress = context.ipAddress;
    if (statement) {
      event.statementHash = statement.statementHash;
      event.statementType = statement.statementType;
    }
    if (result && typeof result === "object") {
      if ("rows" in result && Array.isArray(result.rows))
        event.rowsCount = result.rows.length;
      if ("rowsAffected" in result && typeof result.rowsAffected === "number") {
        event.rowsCount = result.rowsAffected;
      }
      if ("bytes" in result && typeof result.bytes === "number")
        event.bytesCount = result.bytes;
    }
    if (error instanceof ServiceError) event.errorCode = error.code;
    this.repository.appendAudit(event);
  }
}
