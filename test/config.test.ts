import assert from "node:assert/strict";
import test from "node:test";

import { loadConfig } from "../src/config.js";

function validEnvironment(): NodeJS.ProcessEnv {
  return {
    BOT_TOKEN: "123456:test-token",
    TELEGRAM_ADMIN_IDS: "123,456",
    MASTER_KEY_BASE64: Buffer.alloc(32, 7).toString("base64"),
  };
}

test("loadConfig applies conservative defaults", () => {
  const config = loadConfig(validEnvironment());

  assert.deepEqual(config.telegramAdminIds, [123, 456]);
  assert.equal(config.host, "127.0.0.1");
  assert.equal(config.port, 8787);
  assert.equal(config.accessTokenTtlMs, 15 * 60 * 1000);
  assert.equal(config.refreshTokenTtlMs, 30 * 24 * 60 * 60 * 1000);
  assert.equal(config.defaultDeviceLimit, 3);
  assert.equal(config.sqlTimeoutMs, 30_000);
  assert.equal(config.sqlRowLimit, 1_000);
  assert.equal(config.s3MaxBytes, 100 * 1024 * 1024);
  assert.equal(config.auditRetentionDays, 90);
  assert.equal(config.allowInsecureHttp, false);
});

test("loadConfig rejects an invalid master key", () => {
  const environment = validEnvironment();
  environment.MASTER_KEY_BASE64 = Buffer.alloc(16).toString("base64");

  assert.throws(() => loadConfig(environment), /32 bytes/);
});

test("loadConfig rejects missing Telegram administrators", () => {
  const environment = validEnvironment();
  delete environment.TELEGRAM_ADMIN_IDS;

  assert.throws(() => loadConfig(environment), /TELEGRAM_ADMIN_IDS/);
});

test("loadConfig only enables trusted proxies explicitly", () => {
  const environment = validEnvironment();
  environment.TRUSTED_PROXIES = "127.0.0.1,10.0.0.5";

  assert.deepEqual(loadConfig(environment).trustedProxies, [
    "127.0.0.1",
    "10.0.0.5",
  ]);
  assert.deepEqual(loadConfig(validEnvironment()).trustedProxies, []);
});
