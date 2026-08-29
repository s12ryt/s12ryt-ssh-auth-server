import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { buildHttpApp } from "../src/http/app.js";
import type { S3Gateway, SQLGateway } from "../src/proxy/gateways.js";
import { ProxyService } from "../src/proxy/proxy-service.js";
import { Database } from "../src/db/database.js";
import { SqliteRepository } from "../src/repository/sqlite-repository.js";
import { AdminService } from "../src/services/admin-service.js";
import { AuthService } from "../src/services/auth-service.js";
import { SSHHostService } from "../src/services/ssh-host-service.js";

class FakeS3Gateway implements S3Gateway {
  async test(): Promise<void> {}
  async list(): Promise<never[]> {
    return [];
  }
  async upload(): Promise<number> {
    return 0;
  }
  async download(): Promise<{
    body: Readable;
    contentLength?: number;
    contentType: string;
  }> {
    return { body: Readable.from([]), contentType: "text/plain" };
  }
  async delete(): Promise<void> {}
}

class FakeSQLGateway implements SQLGateway {
  async test(): Promise<void> {}
  async tables(): Promise<string[]> {
    return [];
  }
  async query(): Promise<never> {
    throw new Error("not used");
  }
  async exec(): Promise<never> {
    throw new Error("not used");
  }
}

interface Fixture {
  database: Database;
  repository: SqliteRepository;
  admin: AdminService;
  ssh: SSHHostService;
  app: Awaited<ReturnType<typeof buildHttpApp>>;
  aliceToken: string;
  bobToken: string;
  aliceAccountId: string;
  bobAccountId: string;
}

async function createFixture(): Promise<Fixture> {
  const database = new Database(":memory:");
  database.migrate();
  const repository = new SqliteRepository(database.raw());
  const masterKey = Buffer.alloc(32, 8);
  const admin = new AdminService(repository, masterKey, {
    defaultDeviceLimit: 3,
  });
  const auth = new AuthService(repository, {
    accessTokenTtlMs: 15 * 60 * 1000,
    refreshTokenTtlMs: 30 * 24 * 60 * 60 * 1000,
  });
  const proxy = new ProxyService(
    repository,
    admin,
    { s3: new FakeS3Gateway(), sql: new FakeSQLGateway() },
    { sqlTimeoutMs: 30_000, sqlRowLimit: 1000, s3MaxBytes: 1024 },
  );
  const ssh = new SSHHostService(repository, masterKey, { maxHosts: 50 });
  const app = await buildHttpApp({
    auth,
    admin,
    proxy,
    ssh,
    allowInsecureHttp: false,
    trustedProxies: [],
    loginRateLimit: 100,
    apiRateLimit: 1000,
  });
  const alice = await admin.createAccount("alice");
  const bob = await admin.createAccount("bob");
  async function login(username: string, password: string): Promise<string> {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/auth/login",
      payload: { username, password, deviceId: "device-a" },
    });
    assert.equal(response.statusCode, 200, response.body);
    return response.json<{ accessToken: string }>().accessToken;
  }
  const aliceToken = await login("alice", alice.password);
  const bobToken = await login("bob", bob.password);
  return {
    database,
    repository,
    admin,
    ssh,
    app,
    aliceToken,
    bobToken,
    aliceAccountId: alice.account.id,
    bobAccountId: bob.account.id,
  };
}

function hostPayload(overrides: Record<string, unknown> = {}) {
  return {
    name: "web",
    host: "web.example.com",
    port: 22,
    username: "deploy",
    password: "hunter2hunter2",
    ...overrides,
  };
}

test("ssh host routes require bearer authentication", async () => {
  const fixture = await createFixture();
  try {
    const endpoints: Array<{
      method: "GET" | "POST" | "PATCH" | "DELETE" | "PUT";
      url: string;
      payload?: Record<string, unknown>;
    }> = [
      { method: "GET", url: "/api/v1/ssh/hosts" },
      { method: "POST", url: "/api/v1/ssh/hosts", payload: hostPayload() },
      {
        method: "PATCH",
        url: "/api/v1/ssh/hosts/host-1",
        payload: hostPayload({ name: "x" }),
      },
      { method: "DELETE", url: "/api/v1/ssh/hosts/host-1" },
      {
        method: "GET",
        url: "/api/v1/ssh/hosts/host-1/credentials",
      },
      {
        method: "PUT",
        url: "/api/v1/ssh/hosts/host-1/fingerprint",
        payload: { fingerprint: "SHA256:abc" },
      },
    ];
    for (const endpoint of endpoints) {
      const response = await fixture.app.inject({
        method: endpoint.method,
        url: endpoint.url,
        ...(endpoint.payload === undefined
          ? {}
          : { payload: endpoint.payload }),
      });
      assert.equal(
        response.statusCode,
        401,
        `${endpoint.method} ${endpoint.url}`,
      );
    }
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh host lifecycle creates, lists, updates, and deletes hosts", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const empty = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/hosts",
      headers,
    });
    assert.equal(empty.statusCode, 200, empty.body);
    assert.deepEqual(empty.json<{ hosts: unknown[] }>().hosts, []);

    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(created.statusCode, 201, created.body);
    const host = created.json<{
      id: string;
      name: string;
      host: string;
      port: number;
      username: string;
      hasPassword: boolean;
      hasPrivateKey: boolean;
      hasKeyPassphrase: boolean;
      trustedFingerprint: string;
    }>();
    assert.equal(host.name, "web");
    assert.equal(host.host, "web.example.com");
    assert.equal(host.port, 22);
    assert.equal(host.username, "deploy");
    assert.equal(host.hasPassword, true);
    assert.equal(host.hasPrivateKey, false);
    assert.equal(host.hasKeyPassphrase, false);
    assert.equal(host.trustedFingerprint, "");
    assert.equal(created.body.includes("hunter2hunter2"), false);

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/hosts",
      headers,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    assert.equal(listed.json<{ hosts: unknown[] }>().hosts.length, 1);
    assert.equal(listed.body.includes("hunter2hunter2"), false);

    const updated = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/hosts/${host.id}`,
      headers,
      payload: hostPayload({ name: "web-2", host: "web2.example.com" }),
    });
    assert.equal(updated.statusCode, 200, updated.body);
    const updatedHost = updated.json<{ name: string; host: string }>();
    assert.equal(updatedHost.name, "web-2");
    assert.equal(updatedHost.host, "web2.example.com");

    const deleted = await fixture.app.inject({
      method: "DELETE",
      url: `/api/v1/ssh/hosts/${host.id}`,
      headers,
    });
    assert.equal(deleted.statusCode, 204, deleted.body);
    const afterDelete = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/hosts",
      headers,
    });
    assert.deepEqual(afterDelete.json<{ hosts: unknown[] }>().hosts, []);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh host credentials are issued to the owning account only", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(created.statusCode, 201, created.body);
    const hostId = created.json<{ id: string }>().id;

    const credentials = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${hostId}/credentials`,
      headers,
    });
    assert.equal(credentials.statusCode, 200, credentials.body);
    const issued = credentials.json<{
      id: string;
      name: string;
      host: string;
      port: number;
      username: string;
      password: string;
      privateKey: string;
      keyPassphrase: string;
      trustedFingerprint: string;
    }>();
    assert.equal(issued.host, "web.example.com");
    assert.equal(issued.port, 22);
    assert.equal(issued.username, "deploy");
    assert.equal(issued.password, "hunter2hunter2");
    assert.equal(issued.privateKey, "");
    assert.equal(issued.keyPassphrase, "");
    assert.equal(issued.trustedFingerprint, "");

    const otherHeaders = { authorization: `Bearer ${fixture.bobToken}` };
    const crossAccount = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${hostId}/credentials`,
      headers: otherHeaders,
    });
    assert.equal(crossAccount.statusCode, 404, crossAccount.body);

    const audit = fixture.admin.listAudit(10);
    const credentialEvents = audit.filter(
      (event) => event.action === "ssh.host.credentials" && event.success === 1,
    );
    assert.equal(credentialEvents.length, 1);
    assert.equal(credentialEvents[0]?.ssh_host_id, hostId);
    assert.equal(credentialEvents[0]?.account_id, fixture.aliceAccountId);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh host fingerprint is stored through the dedicated route", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(created.statusCode, 201, created.body);
    const hostId = created.json<{ id: string }>().id;

    const stored = await fixture.app.inject({
      method: "PUT",
      url: `/api/v1/ssh/hosts/${hostId}/fingerprint`,
      headers,
      payload: { fingerprint: "SHA256:abc123" },
    });
    assert.equal(stored.statusCode, 204, stored.body);

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/hosts",
      headers,
    });
    const hosts = listed.json<{
      hosts: Array<{ trustedFingerprint: string }>;
    }>().hosts;
    assert.equal(hosts.length, 1);
    assert.equal(hosts[0]?.trustedFingerprint, "SHA256:abc123");
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh host validation errors map to 400 responses", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const missingCredentials = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload({ password: "", privateKey: "" }),
    });
    assert.equal(missingCredentials.statusCode, 400, missingCredentials.body);
    assert.equal(
      missingCredentials.json<{ error: { code: string } }>().error.code,
      "invalid_ssh_host",
    );

    const badPort = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload({ port: 70000 }),
    });
    assert.equal(badPort.statusCode, 400, badPort.body);

    const duplicate = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(duplicate.statusCode, 201, duplicate.body);
    const conflict = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(conflict.statusCode, 409, conflict.body);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh host routes reject accounts with ssh disabled", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(created.statusCode, 201, created.body);
    const hostId = created.json<{ id: string }>().id;

    fixture.admin.setAccountSSHEnabled(fixture.aliceAccountId, false);

    const endpoints: Array<{
      method: "GET" | "POST" | "PATCH" | "DELETE" | "PUT";
      url: string;
      payload?: Record<string, unknown>;
    }> = [
      { method: "GET", url: "/api/v1/ssh/hosts" },
      {
        method: "POST",
        url: "/api/v1/ssh/hosts",
        payload: hostPayload({ name: "x" }),
      },
      {
        method: "PATCH",
        url: `/api/v1/ssh/hosts/${hostId}`,
        payload: hostPayload({ name: "x" }),
      },
      { method: "DELETE", url: `/api/v1/ssh/hosts/${hostId}` },
      { method: "GET", url: `/api/v1/ssh/hosts/${hostId}/credentials` },
      {
        method: "PUT",
        url: `/api/v1/ssh/hosts/${hostId}/fingerprint`,
        payload: { fingerprint: "SHA256:abc" },
      },
    ];
    for (const endpoint of endpoints) {
      const response = await fixture.app.inject({
        method: endpoint.method,
        url: endpoint.url,
        headers,
        ...(endpoint.payload === undefined
          ? {}
          : { payload: endpoint.payload }),
      });
      assert.equal(
        response.statusCode,
        403,
        `${endpoint.method} ${endpoint.url}`,
      );
      assert.equal(
        response.json<{ error: { code: string } }>().error.code,
        "ssh_disabled",
      );
    }

    fixture.admin.setAccountSSHEnabled(fixture.aliceAccountId, true);
    const restored = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/hosts",
      headers,
    });
    assert.equal(restored.statusCode, 200, restored.body);
    assert.equal(restored.json<{ hosts: unknown[] }>().hosts.length, 1);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("resources response reports the account ssh enabled flag", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const enabled = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/resources",
      headers,
    });
    assert.equal(enabled.statusCode, 200, enabled.body);
    assert.equal(enabled.json<{ sshEnabled: boolean }>().sshEnabled, true);

    fixture.admin.setAccountSSHEnabled(fixture.aliceAccountId, false);
    const disabled = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/resources",
      headers,
    });
    assert.equal(disabled.statusCode, 200, disabled.body);
    assert.equal(disabled.json<{ sshEnabled: boolean }>().sshEnabled, false);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});
