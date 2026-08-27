import type { FastifyInstance } from "fastify";

import type { Config } from "./config.js";
import { Database } from "./db/database.js";
import { BotController } from "./bot/controller.js";
import { createTelegramBot } from "./bot/telegram.js";
import { AwsS3Gateway } from "./adapters/s3-gateway.js";
import { DriverSQLGateway } from "./adapters/sql-gateway.js";
import type { S3Gateway, SQLGateway } from "./proxy/gateways.js";
import { buildHttpApp, type HttpAppOptions } from "./http/app.js";
import { ProxyService } from "./proxy/proxy-service.js";
import { SqliteRepository } from "./repository/sqlite-repository.js";
import { AdminService } from "./services/admin-service.js";
import { AuthService } from "./services/auth-service.js";

const dayInMilliseconds = 24 * 60 * 60 * 1000;
const defaultAuditIntervalMilliseconds = dayInMilliseconds;

export interface BotRunner {
  start(): Promise<void>;
  stop(): Promise<void>;
}

export interface RuntimeOptions {
  database?: Database;
  databaseFactory?: (path: string) => Database;
  s3Gateway?: S3Gateway;
  s3GatewayFactory?: () => S3Gateway;
  sqlGateway?: SQLGateway;
  sqlGatewayFactory?: () => SQLGateway;
  httpBuilder?: (options: HttpAppOptions) => Promise<FastifyInstance>;
  botFactory?: (token: string, controller: BotController) => BotRunner;
  auditIntervalMs?: number;
  setInterval?: (callback: () => void, delay: number) => unknown;
  clearInterval?: (handle: unknown) => void;
  clock?: () => number;
  onBotError?: (error: unknown) => void | Promise<void>;
}

export interface RuntimeDependencies {
  database: Database;
  repository: SqliteRepository;
  admin: AdminService;
  auth: AuthService;
  proxy: ProxyService;
  http: FastifyInstance;
  bot: BotRunner;
}

export class Runtime implements RuntimeDependencies {
  readonly database: Database;
  readonly repository: SqliteRepository;
  readonly admin: AdminService;
  readonly auth: AuthService;
  readonly proxy: ProxyService;
  readonly http: FastifyInstance;
  readonly bot: BotRunner;

  readonly #config: Config;
  readonly #clock: () => number;
  readonly #auditIntervalMs: number;
  readonly #setInterval: (callback: () => void, delay: number) => unknown;
  readonly #clearInterval: (handle: unknown) => void;
  readonly #onBotError: (error: unknown) => void | Promise<void>;
  #auditTimer: unknown;
  #startPromise: Promise<void> | undefined;
  #closePromise: Promise<void> | undefined;
  #started = false;
  #closed = false;

  constructor(
    config: Config,
    dependencies: RuntimeDependencies,
    options: RuntimeOptions,
  ) {
    this.#config = config;
    this.#clock = options.clock ?? Date.now;
    this.#auditIntervalMs =
      options.auditIntervalMs ?? defaultAuditIntervalMilliseconds;
    this.#setInterval =
      options.setInterval ??
      ((callback, delay) => globalThis.setInterval(callback, delay));
    this.#clearInterval =
      options.clearInterval ??
      ((handle) =>
        globalThis.clearInterval(
          handle as ReturnType<typeof globalThis.setInterval>,
        ));
    this.#onBotError = options.onBotError ?? (() => undefined);
    this.database = dependencies.database;
    this.repository = dependencies.repository;
    this.admin = dependencies.admin;
    this.auth = dependencies.auth;
    this.proxy = dependencies.proxy;
    this.http = dependencies.http;
    this.bot = dependencies.bot;
  }

  cleanupAudit(
    cutoff = this.#clock() -
      this.#config.auditRetentionDays * dayInMilliseconds,
  ): number {
    return this.repository.deleteAuditBefore(cutoff);
  }

  async start(): Promise<void> {
    if (this.#closed) throw new Error("runtime is closed");
    if (this.#startPromise) return this.#startPromise;

    this.#startPromise = this.startInternal();
    try {
      await this.#startPromise;
    } catch (error) {
      this.#startPromise = undefined;
      throw error;
    }
  }

  async close(): Promise<void> {
    if (this.#closePromise) return this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.closeInternal();
    return this.#closePromise;
  }

  private async startInternal(): Promise<void> {
    if (this.#started) return;

    await this.http.listen({
      host: this.#config.host,
      port: this.#config.port,
    });
    this.#started = true;
    this.#auditTimer = this.#setInterval(() => {
      try {
        void this.cleanupAudit();
      } catch (error) {
        this.reportBotError(error);
      }
    }, this.#auditIntervalMs);

    let botTask: Promise<void>;
    try {
      botTask = this.bot.start();
    } catch (error) {
      this.reportBotError(error);
      return;
    }
    void botTask.catch((error: unknown) => {
      this.reportBotError(error);
    });
  }

  private async closeInternal(): Promise<void> {
    const errors: unknown[] = [];
    if (this.#auditTimer !== undefined) {
      try {
        this.#clearInterval(this.#auditTimer);
      } catch (error) {
        errors.push(error);
      }
      this.#auditTimer = undefined;
    }

    if (this.#startPromise) {
      try {
        await this.#startPromise;
      } catch (error) {
        errors.push(error);
      }
    }

    try {
      await this.bot.stop();
    } catch (error) {
      errors.push(error);
    }
    try {
      await this.http.close();
    } catch (error) {
      errors.push(error);
    }
    try {
      this.database.close();
    } catch (error) {
      errors.push(error);
    }

    if (errors.length > 0)
      throw new AggregateError(errors, "runtime close failed");
  }

  private reportBotError(error: unknown): void {
    try {
      void Promise.resolve(this.#onBotError(error)).catch(() => undefined);
    } catch {
      // An error handler must not create an unhandled rejection.
    }
  }
}

export async function createRuntime(
  config: Config,
  options: RuntimeOptions = {},
): Promise<Runtime> {
  const database =
    options.database ??
    (options.databaseFactory ?? ((path: string) => new Database(path)))(
      config.sqlitePath,
    );

  try {
    database.migrate();
    const repository = new SqliteRepository(database.raw());
    const clock = options.clock ?? Date.now;
    const admin = new AdminService(repository, config.masterKey, {
      defaultDeviceLimit: config.defaultDeviceLimit,
      clock,
    });
    const auth = new AuthService(repository, {
      accessTokenTtlMs: config.accessTokenTtlMs,
      refreshTokenTtlMs: config.refreshTokenTtlMs,
      clock,
    });
    const s3Gateway =
      options.s3Gateway ??
      (options.s3GatewayFactory ?? (() => new AwsS3Gateway()))();
    const sqlGateway =
      options.sqlGateway ??
      (options.sqlGatewayFactory ?? (() => new DriverSQLGateway()))();
    const proxy = new ProxyService(
      repository,
      admin,
      { s3: s3Gateway, sql: sqlGateway },
      {
        sqlTimeoutMs: config.sqlTimeoutMs,
        sqlRowLimit: config.sqlRowLimit,
        s3MaxBytes: config.s3MaxBytes,
        clock,
      },
    );
    const http = await (options.httpBuilder ?? buildHttpApp)({
      auth,
      admin,
      proxy,
      allowInsecureHttp: config.allowInsecureHttp,
      trustedProxies: config.trustedProxies,
      loginRateLimit: config.loginRateLimit,
      apiRateLimit: config.apiRateLimit,
    });
    const controller = new BotController({
      admin,
      administratorIds: config.telegramAdminIds,
      connectionTester: proxy,
    });
    const bot = (options.botFactory ?? createTelegramBot)(
      config.botToken,
      controller,
    );
    return new Runtime(
      config,
      { database, repository, admin, auth, proxy, http, bot },
      options,
    );
  } catch (error) {
    try {
      database.close();
    } catch {
      // Preserve the initialization error; cleanup is best effort.
    }
    throw error;
  }
}
