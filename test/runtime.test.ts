import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";
import type { FastifyInstance } from "fastify";

import type { Config } from "../src/config.js";
import { Database } from "../src/db/database.js";
import type {
  S3Download,
  S3Gateway,
  S3Object,
  SQLExecResult,
  SQLGateway,
  SQLQueryResult,
} from "../src/proxy/gateways.js";
import { createRuntime, type Runtime } from "../src/runtime.js";

class FakeS3Gateway implements S3Gateway {
  async test(): Promise<void> {}

  async list(): Promise<S3Object[]> {
    return [];
  }

  async upload(): Promise<number> {
    return 0;
  }

  async download(): Promise<S3Download> {
    return { body: Readable.from([]) };
  }

  async delete(): Promise<void> {}
}

class FakeSQLGateway implements SQLGateway {
  async test(): Promise<void> {}

  async tables(): Promise<string[]> {
    return [];
  }

  async query(): Promise<SQLQueryResult> {
    return { columns: [], rows: [], truncated: false };
  }

  async exec(): Promise<SQLExecResult> {
    return { rowsAffected: 0 };
  }
}

class FakeBot {
  startCount = 0;
  stopCount = 0;
  startFailure: Error | undefined;
  stopFailure: Error | undefined;

  async start(): Promise<void> {
    this.startCount += 1;
    if (this.startFailure) throw this.startFailure;
  }

  async stop(): Promise<void> {
    this.stopCount += 1;
    if (this.stopFailure) throw this.stopFailure;
  }
}

function config(): Config {
  return {
    botToken: "test-token",
    telegramAdminIds: [123456789],
    masterKey: Buffer.alloc(32, 7),
    sqlitePath: ":memory:",
    host: "127.0.0.1",
    port: 0,
    trustedProxies: [],
    allowInsecureHttp: true,
    accessTokenTtlMs: 15 * 60 * 1000,
    refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000,
    defaultDeviceLimit: 3,
    sqlTimeoutMs: 30_000,
    sqlRowLimit: 1_000,
    s3MaxBytes: 1024,
    auditRetentionDays: 90,
    loginRateLimit: 10,
    apiRateLimit: 120,
  };
}

function auditEvent(id: string, occurredAt: number) {
  return {
    id,
    occurredAt,
    action: "test",
    success: true,
    durationMs: 1,
  };
}

async function createTestRuntime(database: Database): Promise<{
  runtime: Runtime;
  bot: FakeBot;
}> {
  const bot = new FakeBot();
  const runtime = await createRuntime(config(), {
    database,
    s3Gateway: new FakeS3Gateway(),
    sqlGateway: new FakeSQLGateway(),
    botFactory: () => bot,
  });
  return { runtime, bot };
}

test("runtime composes the service graph and exposes healthz", async () => {
  const database = new Database(":memory:");
  const { runtime, bot } = await createTestRuntime(database);
  try {
    const response = await runtime.http.inject({
      method: "GET",
      url: "/healthz",
    });
    assert.equal(response.statusCode, 200);
    assert.deepEqual(response.json(), { status: "ok" });
    assert.equal(bot.startCount, 0);
    assert.ok(runtime.repository);
    assert.ok(runtime.admin);
    assert.ok(runtime.auth);
    assert.ok(runtime.proxy);
  } finally {
    await runtime.close();
  }
});

test("runtime cleanup removes audit events older than the retention window", async () => {
  const database = new Database(":memory:");
  const { runtime } = await createTestRuntime(database);
  try {
    runtime.repository.appendAudit(auditEvent("old", 1));
    runtime.repository.appendAudit(auditEvent("new", Date.now()));

    const deleted = runtime.cleanupAudit(Date.now() - 90 * 24 * 60 * 60 * 1000);

    assert.equal(deleted, 1);
    assert.equal(runtime.repository.listAudit(10).length, 1);
    assert.equal(runtime.repository.listAudit(10)[0]?.id, "new");
  } finally {
    await runtime.close();
  }
});

test("runtime starts HTTP before bot polling and closes all resources idempotently", async () => {
  const database = new Database(":memory:");
  const bot = new FakeBot();
  const callbacks: Array<() => void> = [];
  const cleared: unknown[] = [];
  const runtime = await createRuntime(config(), {
    database,
    s3Gateway: new FakeS3Gateway(),
    sqlGateway: new FakeSQLGateway(),
    botFactory: () => bot,
    auditIntervalMs: 60_000,
    setInterval: (callback: () => void) => {
      callbacks.push(callback);
      return "timer";
    },
    clearInterval: (handle: unknown) => {
      cleared.push(handle);
    },
  });

  await runtime.start();
  assert.equal(bot.startCount, 1);
  assert.equal(callbacks.length, 1);

  await runtime.close();
  await runtime.close();

  assert.equal(bot.stopCount, 1);
  assert.deepEqual(cleared, ["timer"]);
});

test("runtime reports rejected bot polling without an unhandled rejection", async () => {
  const database = new Database(":memory:");
  const bot = new FakeBot();
  const pollingError = new Error("polling failed");
  const errors: unknown[] = [];
  const runtime = await createRuntime(config(), {
    database,
    s3Gateway: new FakeS3Gateway(),
    sqlGateway: new FakeSQLGateway(),
    botFactory: () => ({
      start: async () => Promise.reject(pollingError),
      stop: async () => {
        bot.stopCount += 1;
      },
    }),
    onBotError: (error) => {
      errors.push(error);
    },
  });

  try {
    await runtime.start();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(errors, [pollingError]);
  } finally {
    await runtime.close();
  }
});

test("runtime reports a synchronous bot start failure", async () => {
  const database = new Database(":memory:");
  const startError = new Error("bot start failed");
  const errors: unknown[] = [];
  const bot = new FakeBot();
  const runtime = await createRuntime(config(), {
    database,
    s3Gateway: new FakeS3Gateway(),
    sqlGateway: new FakeSQLGateway(),
    botFactory: () => ({
      start: () => {
        throw startError;
      },
      stop: async () => {
        bot.stopCount += 1;
      },
    }),
    onBotError: (error) => {
      errors.push(error);
    },
  });

  try {
    await runtime.start();
    await new Promise((resolve) => setImmediate(resolve));
    assert.deepEqual(errors, [startError]);
  } finally {
    await runtime.close();
  }
});

test("runtime closes HTTP after listen failure", async () => {
  const database = new Database(":memory:");
  const bot = new FakeBot();
  const listenError = new Error("listen failed");
  let closeCount = 0;
  const http = {
    listen: async () => {
      throw listenError;
    },
    close: async () => {
      closeCount += 1;
    },
  } as unknown as FastifyInstance;
  const runtime = await createRuntime(config(), {
    database,
    s3Gateway: new FakeS3Gateway(),
    sqlGateway: new FakeSQLGateway(),
    httpBuilder: async () => http,
    botFactory: () => bot,
  });

  await assert.rejects(runtime.start(), /listen failed/);
  await runtime.close();

  assert.equal(closeCount, 1);
  assert.equal(bot.stopCount, 1);
});

test("runtime attempts every close operation when resources fail", async () => {
  const database = new Database(":memory:");
  const bot = new FakeBot();
  bot.stopFailure = new Error("bot stop failed");
  let httpCloseCount = 0;
  const http = {
    listen: async () => "http://127.0.0.1:0",
    close: async () => {
      httpCloseCount += 1;
      throw new Error("http close failed");
    },
  } as unknown as FastifyInstance;
  const runtime = await createRuntime(config(), {
    database,
    s3Gateway: new FakeS3Gateway(),
    sqlGateway: new FakeSQLGateway(),
    httpBuilder: async () => http,
    botFactory: () => bot,
  });

  await assert.rejects(runtime.close(), AggregateError);
  assert.equal(bot.stopCount, 1);
  assert.equal(httpCloseCount, 1);
});
