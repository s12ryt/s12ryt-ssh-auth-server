import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { buildHttpApp } from "../src/http/app.js";
import type {
  S3Gateway,
  S3Object,
  SQLExecResult,
  SQLGateway,
  SQLQueryResult,
} from "../src/proxy/gateways.js";
import { ProxyService } from "../src/proxy/proxy-service.js";
import { Database } from "../src/db/database.js";
import { SqliteRepository } from "../src/repository/sqlite-repository.js";
import { AdminService } from "../src/services/admin-service.js";
import { AuthService } from "../src/services/auth-service.js";

class FakeS3Gateway implements S3Gateway {
  listedPrefixes: string[] = [];
  deletedKeys: string[] = [];
  uploaded = new Map<string, Buffer>();
  downloadPayload = Buffer.from("downloaded");
  omitDownloadLength = false;

  async test(): Promise<void> {}

  async list(_secret: never, prefix: string): Promise<S3Object[]> {
    this.listedPrefixes.push(prefix);
    return [
      { key: `${prefix}one.txt`, size: 3 },
      { key: `${prefix}nested/two.txt`, size: 5 },
    ];
  }

  async upload(
    _secret: never,
    key: string,
    body: AsyncIterable<Uint8Array>,
  ): Promise<number> {
    const chunks: Buffer[] = [];
    for await (const chunk of body) {
      chunks.push(Buffer.from(chunk));
    }
    const payload = Buffer.concat(chunks);
    this.uploaded.set(key, payload);
    return payload.length;
  }

  async download(): Promise<{
    body: Readable;
    contentLength?: number;
    contentType: string;
  }> {
    const result: {
      body: Readable;
      contentLength?: number;
      contentType: string;
    } = {
      body: Readable.from(this.downloadPayload),
      contentType: "text/plain",
    };
    if (!this.omitDownloadLength)
      result.contentLength = this.downloadPayload.length;
    return result;
  }

  async delete(_secret: never, key: string): Promise<void> {
    this.deletedKeys.push(key);
  }
}

class FakeSQLGateway implements SQLGateway {
  queries: string[] = [];
  executions: string[] = [];

  async test(): Promise<void> {}

  async tables(): Promise<string[]> {
    return ["users", "jobs"];
  }

  async query(
    _secret: never,
    statement: string,
    _parameters: unknown[],
    _options: { timeoutMs: number; rowLimit: number; signal: AbortSignal },
  ): Promise<SQLQueryResult> {
    this.queries.push(statement);
    return { columns: ["id"], rows: [[1]], truncated: false };
  }

  async exec(): Promise<SQLExecResult> {
    this.executions.push("exec");
    return { rowsAffected: 2, lastInsertId: "7" };
  }
}

async function createFixture() {
  const database = new Database(":memory:");
  database.migrate();
  const repository = new SqliteRepository(database.raw());
  const admin = new AdminService(repository, Buffer.alloc(32, 8), {
    defaultDeviceLimit: 3,
  });
  const auth = new AuthService(repository, {
    accessTokenTtlMs: 15 * 60 * 1000,
    refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000,
  });
  const s3 = new FakeS3Gateway();
  const sql = new FakeSQLGateway();
  const proxy = new ProxyService(
    repository,
    admin,
    { s3, sql },
    {
      sqlTimeoutMs: 30_000,
      sqlRowLimit: 1_000,
      s3MaxBytes: 1024,
    },
  );
  const app = await buildHttpApp({
    auth,
    admin,
    proxy,
    allowInsecureHttp: false,
    trustedProxies: [],
    loginRateLimit: 100,
    apiRateLimit: 1000,
  });
  const account = await admin.createAccount("api-user");
  const s3Connection = admin.createConnection({
    name: "assigned-storage",
    secret: {
      kind: "s3",
      endpoint: "https://storage.example.com",
      region: "auto",
      bucket: "bucket",
      prefix: "tenant-a/",
      usePathStyle: true,
      accessKeyId: "access-key",
      secretAccessKey: "secret-key",
    },
  });
  const sqlConnection = admin.createConnection({
    name: "assigned-db",
    secret: {
      kind: "postgres",
      host: "db.example.com",
      port: 5432,
      user: "proxy",
      password: "db-secret",
      database: "app",
      sslMode: "verify-full",
    },
  });
  admin.setGrants(account.account.id, s3Connection.id, ["s3.read", "s3.write"]);
  admin.setGrants(account.account.id, sqlConnection.id, [
    "sql.tables",
    "sql.query",
  ]);
  const login = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    payload: {
      username: account.account.username,
      password: account.password,
      deviceId: "desktop-a",
    },
  });
  assert.equal(login.statusCode, 200, login.body);
  const tokens = login.json<{ accessToken: string; refreshToken: string }>();
  return {
    database,
    repository,
    admin,
    auth,
    proxy,
    app,
    account,
    s3Connection,
    sqlConnection,
    s3,
    sql,
    tokens,
  };
}

test("login rejects insecure non-loopback requests", async () => {
  const fixture = await createFixture();
  try {
    const response = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      remoteAddress: "203.0.113.10",
      payload: {
        username: "api-user",
        password: "not-relevant",
        deviceId: "remote",
      },
    });
    assert.equal(response.statusCode, 400);
    assert.equal(
      response.json<{ error: { code: string } }>().error.code,
      "https_required",
    );
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("resources require bearer authentication and never expose credentials", async () => {
  const fixture = await createFixture();
  try {
    assert.equal(
      (await fixture.app.inject({ method: "GET", url: "/api/v1/resources" }))
        .statusCode,
      401,
    );
    const response = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/resources",
      headers: { authorization: `Bearer ${fixture.tokens.accessToken}` },
    });
    assert.equal(response.statusCode, 200, response.body);
    assert.equal(response.body.includes("secret-key"), false);
    assert.equal(response.body.includes("db-secret"), false);
    assert.deepEqual(
      response
        .json<{ resources: Array<{ name: string }> }>()
        .resources.map((item) => item.name),
      ["assigned-db", "assigned-storage"],
    );
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("S3 routes enforce operation grants and the configured base prefix", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.tokens.accessToken}` };
    const listed = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/resources/${fixture.s3Connection.id}/s3/objects?prefix=docs/`,
      headers,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    assert.deepEqual(fixture.s3.listedPrefixes, ["tenant-a/docs/"]);
    assert.deepEqual(
      listed.json<{ objects: S3Object[] }>().objects.map((item) => item.key),
      ["docs/one.txt", "docs/nested/two.txt"],
    );

    const uploaded = await fixture.app.inject({
      method: "PUT",
      url: `/api/v1/resources/${fixture.s3Connection.id}/s3/objects/docs/new.txt`,
      headers: { ...headers, "content-type": "application/octet-stream" },
      payload: Buffer.from("payload"),
    });
    assert.equal(uploaded.statusCode, 200, uploaded.body);
    assert.equal(
      fixture.s3.uploaded.get("tenant-a/docs/new.txt")?.toString(),
      "payload",
    );

    const denied = await fixture.app.inject({
      method: "DELETE",
      url: `/api/v1/resources/${fixture.s3Connection.id}/s3/objects/docs/new.txt`,
      headers,
    });
    assert.equal(denied.statusCode, 403);
    assert.deepEqual(fixture.s3.deletedKeys, []);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("S3 downloads enforce configured byte limit when content length is absent", async () => {
  const fixture = await createFixture();
  try {
    fixture.s3.downloadPayload = Buffer.alloc(1025, 1);
    fixture.s3.omitDownloadLength = true;
    const identity = await fixture.auth.authenticate(
      fixture.tokens.accessToken,
    );
    const download = await fixture.proxy.downloadS3(
      {
        principal: identity,
        connectionId: fixture.s3Connection.id,
        ipAddress: "127.0.0.1",
      },
      "large.bin",
      new AbortController().signal,
    );
    await assert.rejects(
      async () => download.body.toArray(),
      /configured byte limit/,
    );
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("SQL routes separate query and exec permissions and audit only a statement hash", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.tokens.accessToken}` };
    const statement = "SELECT id FROM users";
    const queried = await fixture.app.inject({
      method: "POST",
      url: `/api/v1/resources/${fixture.sqlConnection.id}/sql/query`,
      headers,
      payload: { statement, parameters: [] },
    });
    assert.equal(queried.statusCode, 200, queried.body);
    assert.deepEqual(queried.json<SQLQueryResult>().rows, [[1]]);

    const denied = await fixture.app.inject({
      method: "POST",
      url: `/api/v1/resources/${fixture.sqlConnection.id}/sql/exec`,
      headers,
      payload: { statement: "DELETE FROM users", parameters: [] },
    });
    assert.equal(denied.statusCode, 403);
    assert.deepEqual(fixture.sql.executions, []);

    const audits = fixture.repository.listAudit(20);
    const queryAudit = audits.find((row) => row.action === "sql.query");
    assert.equal(typeof queryAudit?.statement_hash, "string");
    assert.equal(JSON.stringify(audits).includes(statement), false);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("refresh and logout endpoints rotate refresh state and revoke the session", async () => {
  const fixture = await createFixture();
  try {
    const refreshed = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/auth/refresh",
      payload: {
        refreshToken: fixture.tokens.refreshToken,
        deviceId: "desktop-a",
      },
    });
    assert.equal(refreshed.statusCode, 200, refreshed.body);
    const next = refreshed.json<{
      accessToken: string;
      refreshToken: string;
    }>();
    assert.notEqual(next.refreshToken, fixture.tokens.refreshToken);

    const loggedOut = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/auth/logout",
      headers: { authorization: `Bearer ${next.accessToken}` },
    });
    assert.equal(loggedOut.statusCode, 204, loggedOut.body);
    const resources = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/resources",
      headers: { authorization: `Bearer ${next.accessToken}` },
    });
    assert.equal(resources.statusCode, 401);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});
