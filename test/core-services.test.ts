import assert from "node:assert/strict";
import test from "node:test";

import { Database } from "../src/db/database.js";
import { SqliteRepository } from "../src/repository/sqlite-repository.js";
import { AdminService } from "../src/services/admin-service.js";
import { AuthService } from "../src/services/auth-service.js";

function createFixture(deviceLimit = 3) {
  const database = new Database(":memory:");
  database.migrate();
  const repository = new SqliteRepository(database.raw());
  let now = 1_700_000_000_000;
  const clock = () => now;
  const admin = new AdminService(repository, Buffer.alloc(32, 4), {
    defaultDeviceLimit: deviceLimit,
    clock,
  });
  const auth = new AuthService(repository, {
    accessTokenTtlMs: 15 * 60 * 1000,
    refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000,
    clock,
  });
  return {
    database,
    repository,
    admin,
    auth,
    advance(milliseconds: number) {
      now += milliseconds;
    },
  };
}

test("account passwords are generated once and only hashes are stored", async () => {
  const fixture = createFixture();
  try {
    const created = await fixture.admin.createAccount("operator");

    assert.match(created.password, /^[A-Za-z0-9_-]{24,}$/);
    assert.equal(created.account.username, "operator");
    const stored = fixture.database
      .raw()
      .prepare("SELECT password_hash FROM accounts WHERE id = ?")
      .get(created.account.id) as { password_hash: string };
    assert.equal(stored.password_hash.includes(created.password), false);

    const tokens = await fixture.auth.login({
      username: "operator",
      password: created.password,
      deviceId: "desktop-a",
      ipAddress: "127.0.0.1",
      userAgent: "test-client",
    });
    assert.equal(tokens.account.username, "operator");
    assert.equal(
      (await fixture.auth.authenticate(tokens.accessToken)).accountId,
      created.account.id,
    );
  } finally {
    fixture.database.close();
  }
});

test("device limits apply to independent active refresh sessions", async () => {
  const fixture = createFixture(1);
  try {
    const created = await fixture.admin.createAccount("single-device");
    await fixture.auth.login({
      username: created.account.username,
      password: created.password,
      deviceId: "desktop-a",
      ipAddress: "127.0.0.1",
      userAgent: "test-client",
    });

    await assert.rejects(
      fixture.auth.login({
        username: created.account.username,
        password: created.password,
        deviceId: "desktop-b",
        ipAddress: "127.0.0.1",
        userAgent: "test-client",
      }),
      /device limit/i,
    );
  } finally {
    fixture.database.close();
  }
});

test("refresh tokens rotate and reuse revokes the token family", async () => {
  const fixture = createFixture();
  try {
    const created = await fixture.admin.createAccount("rotating-user");
    const first = await fixture.auth.login({
      username: created.account.username,
      password: created.password,
      deviceId: "desktop-a",
      ipAddress: "127.0.0.1",
      userAgent: "test-client",
    });
    const second = await fixture.auth.refresh(first.refreshToken, "desktop-a");

    assert.notEqual(first.refreshToken, second.refreshToken);
    assert.notEqual(first.accessToken, second.accessToken);
    await assert.rejects(
      fixture.auth.refresh(first.refreshToken, "desktop-a"),
      /reuse/i,
    );
    await assert.rejects(
      fixture.auth.authenticate(second.accessToken),
      /invalid|revoked/i,
    );
  } finally {
    fixture.database.close();
  }
});

test("connection credentials are encrypted and grants expose only summaries", async () => {
  const fixture = createFixture();
  try {
    const created = await fixture.admin.createAccount("resource-user");
    const connection = fixture.admin.createConnection({
      name: "private-r2",
      secret: {
        kind: "s3",
        endpoint: "https://example.r2.cloudflarestorage.com",
        region: "auto",
        bucket: "private-bucket",
        prefix: "assigned/",
        usePathStyle: true,
        accessKeyId: "access-secret",
        secretAccessKey: "storage-secret",
      },
    });
    fixture.admin.setGrants(created.account.id, connection.id, [
      "s3.read",
      "s3.write",
    ]);

    const row = fixture.database
      .raw()
      .prepare("SELECT secret_ciphertext FROM connections WHERE id = ?")
      .get(connection.id) as { secret_ciphertext: string };
    assert.equal(row.secret_ciphertext.includes("access-secret"), false);
    assert.equal(row.secret_ciphertext.includes("storage-secret"), false);

    const assigned = fixture.admin.listAssignedConnections(created.account.id);
    assert.deepEqual(assigned, [
      {
        id: connection.id,
        name: "private-r2",
        kind: "s3",
        enabled: true,
        operations: ["s3.read", "s3.write"],
      },
    ]);
    assert.equal(JSON.stringify(assigned).includes("storage-secret"), false);
    const secret = fixture.admin.getConnectionSecret(connection.id);
    assert.equal(secret.kind, "s3");
    if (secret.kind === "s3") {
      assert.equal(secret.secretAccessKey, "storage-secret");
    }
  } finally {
    fixture.database.close();
  }
});

test("grant operations must match the connection kind", async () => {
  const fixture = createFixture();
  try {
    const created = await fixture.admin.createAccount("grant-user");
    const connection = fixture.admin.createConnection({
      name: "database",
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

    assert.throws(
      () =>
        fixture.admin.setGrants(created.account.id, connection.id, ["s3.read"]),
      /operation/i,
    );
    fixture.admin.setGrants(created.account.id, connection.id, [
      "sql.tables",
      "sql.query",
    ]);
    assert.deepEqual(
      fixture.admin.listAssignedConnections(created.account.id)[0]?.operations,
      ["sql.query", "sql.tables"],
    );
  } finally {
    fixture.database.close();
  }
});

test("disabling an account revokes existing access immediately", async () => {
  const fixture = createFixture();
  try {
    const created = await fixture.admin.createAccount("disabled-user");
    const tokens = await fixture.auth.login({
      username: created.account.username,
      password: created.password,
      deviceId: "desktop-a",
      ipAddress: "127.0.0.1",
      userAgent: "test-client",
    });

    fixture.admin.setAccountEnabled(created.account.id, false);
    await assert.rejects(
      fixture.auth.authenticate(tokens.accessToken),
      /disabled|invalid|revoked/i,
    );
    await assert.rejects(
      fixture.auth.login({
        username: created.account.username,
        password: created.password,
        deviceId: "desktop-a",
        ipAddress: "127.0.0.1",
        userAgent: "test-client",
      }),
      /disabled/i,
    );
  } finally {
    fixture.database.close();
  }
});
