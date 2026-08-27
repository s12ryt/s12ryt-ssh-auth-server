import { isIP } from "node:net";

export interface Config {
  botToken: string;
  telegramAdminIds: number[];
  masterKey: Buffer;
  sqlitePath: string;
  host: string;
  port: number;
  trustedProxies: string[];
  allowInsecureHttp: boolean;
  accessTokenTtlMs: number;
  refreshTokenTtlMs: number;
  defaultDeviceLimit: number;
  sqlTimeoutMs: number;
  sqlRowLimit: number;
  s3MaxBytes: number;
  auditRetentionDays: number;
  loginRateLimit: number;
  apiRateLimit: number;
}

function required(environment: NodeJS.ProcessEnv, key: string): string {
  const value = environment[key]?.trim();
  if (!value) {
    throw new Error(`missing required environment variable ${key}`);
  }
  return value;
}

function positiveInteger(
  environment: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
): number {
  const source = environment[key]?.trim();
  if (!source) {
    return fallback;
  }
  const value = Number(source);
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${key} must be a positive integer`);
  }
  return value;
}

function booleanValue(
  environment: NodeJS.ProcessEnv,
  key: string,
  fallback: boolean,
): boolean {
  const source = environment[key]?.trim().toLowerCase();
  if (!source) {
    return fallback;
  }
  if (source === "true" || source === "1") {
    return true;
  }
  if (source === "false" || source === "0") {
    return false;
  }
  throw new Error(`${key} must be true or false`);
}

function parseAdministrators(value: string): number[] {
  const administrators = [
    ...new Set(value.split(",").map((entry) => Number(entry.trim()))),
  ];
  if (
    administrators.length === 0 ||
    administrators.some((entry) => !Number.isSafeInteger(entry) || entry <= 0)
  ) {
    throw new Error(
      "TELEGRAM_ADMIN_IDS must contain positive numeric user IDs",
    );
  }
  return administrators;
}

function parseMasterKey(value: string): Buffer {
  const key = Buffer.from(value, "base64");
  if (key.length !== 32) {
    throw new Error("MASTER_KEY_BASE64 must decode to exactly 32 bytes");
  }
  return key;
}

function parseTrustedProxies(value: string | undefined): string[] {
  if (!value?.trim()) {
    return [];
  }
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      if (isIP(entry) === 0 && !entry.includes("/")) {
        throw new Error(`invalid trusted proxy ${entry}`);
      }
      return entry;
    });
}

export function loadConfig(
  environment: NodeJS.ProcessEnv = process.env,
): Config {
  return {
    botToken: required(environment, "BOT_TOKEN"),
    telegramAdminIds: parseAdministrators(
      required(environment, "TELEGRAM_ADMIN_IDS"),
    ),
    masterKey: parseMasterKey(required(environment, "MASTER_KEY_BASE64")),
    sqlitePath: environment.SQLITE_PATH?.trim() || "./data/auth.db",
    host: environment.HOST?.trim() || "127.0.0.1",
    port: positiveInteger(environment, "PORT", 8787),
    trustedProxies: parseTrustedProxies(environment.TRUSTED_PROXIES),
    allowInsecureHttp: booleanValue(environment, "ALLOW_INSECURE_HTTP", false),
    accessTokenTtlMs:
      positiveInteger(environment, "ACCESS_TOKEN_TTL_SECONDS", 900) * 1000,
    refreshTokenTtlMs:
      positiveInteger(
        environment,
        "REFRESH_TOKEN_TTL_SECONDS",
        30 * 24 * 60 * 60,
      ) * 1000,
    defaultDeviceLimit: positiveInteger(environment, "DEFAULT_DEVICE_LIMIT", 3),
    sqlTimeoutMs: positiveInteger(environment, "SQL_TIMEOUT_MS", 30_000),
    sqlRowLimit: positiveInteger(environment, "SQL_ROW_LIMIT", 1_000),
    s3MaxBytes: positiveInteger(environment, "S3_MAX_BYTES", 100 * 1024 * 1024),
    auditRetentionDays: positiveInteger(
      environment,
      "AUDIT_RETENTION_DAYS",
      90,
    ),
    loginRateLimit: positiveInteger(environment, "LOGIN_RATE_LIMIT", 10),
    apiRateLimit: positiveInteger(environment, "API_RATE_LIMIT", 120),
  };
}
