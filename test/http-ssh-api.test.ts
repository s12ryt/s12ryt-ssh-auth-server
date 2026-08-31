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
      { method: "GET", url: "/api/v1/ssh/preferences" },
      {
        method: "PATCH",
        url: "/api/v1/ssh/preferences",
        payload: {
          terminalAppearance: {
            font: "builtin-mono",
            fontSize: 13,
            foreground: "#d7e6e2",
            background: "#101c1b",
          },
        },
      },
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
      {
        method: "GET",
        url: "/api/v1/ssh/hosts/host-1/fingerprints",
      },
      {
        method: "DELETE",
        url: "/api/v1/ssh/hosts/host-1/fingerprint",
      },
      { method: "GET", url: "/api/v1/ssh/tunnels" },
      {
        method: "POST",
        url: "/api/v1/ssh/tunnels",
        payload: {
          name: "local",
          hostId: "host-1",
          type: "local",
          listenHost: "127.0.0.1",
          listenPort: 18080,
          targetHost: "127.0.0.1",
          targetPort: 80,
        },
      },
      {
        method: "PATCH",
        url: "/api/v1/ssh/tunnels/tunnel-1",
        payload: {
          name: "local",
          hostId: "host-1",
          type: "local",
          listenHost: "127.0.0.1",
          listenPort: 18080,
          targetHost: "127.0.0.1",
          targetPort: 80,
        },
      },
      {
        method: "PATCH",
        url: "/api/v1/ssh/tunnels/tunnel-1/runtime",
        payload: {
          running: true,
          trafficUpBytes: 1,
          trafficDownBytes: 2,
        },
      },
      { method: "DELETE", url: "/api/v1/ssh/tunnels/tunnel-1" },
      { method: "GET", url: "/api/v1/ssh/snippets" },
      {
        method: "POST",
        url: "/api/v1/ssh/snippets",
        payload: { name: "deploy", command: "echo ${TOKEN}" },
      },
      {
        method: "PATCH",
        url: "/api/v1/ssh/snippets/snippet-1",
        payload: { name: "deploy", command: "echo ${TOKEN}" },
      },
      { method: "DELETE", url: "/api/v1/ssh/snippets/snippet-1" },
      { method: "GET", url: "/api/v1/ssh/snippets/snippet-1/secrets" },
      { method: "GET", url: "/api/v1/ssh/keys" },
      {
        method: "POST",
        url: "/api/v1/ssh/keys",
        payload: { name: "deploy", privateKey: "private-key" },
      },
      {
        method: "PATCH",
        url: "/api/v1/ssh/keys/key-1",
        payload: { name: "deploy", privateKey: "private-key" },
      },
      { method: "DELETE", url: "/api/v1/ssh/keys/key-1" },
      { method: "GET", url: "/api/v1/ssh/keys/key-1/secrets" },
      { method: "GET", url: "/api/v1/ssh/session-history" },
      {
        method: "POST",
        url: "/api/v1/ssh/session-history",
        payload: { hostId: "host-1", status: "connecting" },
      },
      {
        method: "PATCH",
        url: "/api/v1/ssh/session-history/history-1",
        payload: { status: "connected", latencyMs: 42 },
      },
      {
        method: "POST",
        url: "/api/v1/ssh/workspace/export",
        payload: { includeSecrets: false },
      },
      {
        method: "POST",
        url: "/api/v1/ssh/workspace/import/preview",
        payload: { package: "{}" },
      },
      {
        method: "POST",
        url: "/api/v1/ssh/workspace/import/apply",
        payload: { package: "{}", resolutions: [] },
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

test("ssh workspace preferences persist terminal appearance per account", async () => {
  const fixture = await createFixture();
  try {
    const update = await fixture.app.inject({
      method: "PATCH",
      url: "/api/v1/ssh/preferences",
      headers: { authorization: `Bearer ${fixture.aliceToken}` },
      payload: {
        terminalAppearance: {
          font: "system-mono",
          fontSize: 17,
          foreground: "#f0f0f0",
          background: "#080808",
        },
      },
    });
    assert.equal(update.statusCode, 200, update.body);
    assert.equal(
      update.json<{ terminalAppearance: { fontSize: number } }>()
        .terminalAppearance.fontSize,
      17,
    );

    const alice = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/preferences",
      headers: { authorization: `Bearer ${fixture.aliceToken}` },
    });
    assert.equal(alice.statusCode, 200, alice.body);
    assert.equal(
      alice.json<{ terminalAppearance: { background: string } }>()
        .terminalAppearance.background,
      "#080808",
    );

    const bob = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/preferences",
      headers: { authorization: `Bearer ${fixture.bobToken}` },
    });
    assert.equal(bob.statusCode, 200, bob.body);
    assert.equal(
      bob.json<{ terminalAppearance: { font: string }; version: number }>()
        .terminalAppearance.font,
      "builtin-mono",
    );
    assert.equal(bob.json<{ version: number }>().version, 1);

    const host = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers: { authorization: `Bearer ${fixture.aliceToken}` },
      payload: hostPayload({
        settings: { terminalAppearance: { fontSize: 18 } },
      }),
    });
    assert.equal(host.statusCode, 201, host.body);
    assert.equal(
      host.json<{ settings: { terminalAppearance: { fontSize: number } } }>()
        .settings.terminalAppearance.fontSize,
      18,
    );

    const inherited = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/hosts/${host.json<{ id: string }>().id}`,
      headers: { authorization: `Bearer ${fixture.aliceToken}` },
      payload: hostPayload({
        settings: { compression: true },
        clearTerminalAppearance: true,
      }),
    });
    assert.equal(inherited.statusCode, 200, inherited.body);
    const inheritedBody = inherited.json<{
      settings: { terminalAppearance?: unknown; compression: boolean };
    }>();
    assert.equal(inheritedBody.settings.terminalAppearance, undefined);
    assert.equal(inheritedBody.settings.compression, true);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh tunnel routes persist rules and enforce account ownership", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const host = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(host.statusCode, 201, host.body);
    const hostID = host.json<{ id: string }>().id;

    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/tunnels",
      headers,
      payload: {
        name: "socks",
        hostId: hostID,
        type: "dynamic_socks",
        listenHost: "127.0.0.1",
        listenPort: 1080,
        enabled: true,
        autoStart: false,
      },
    });
    assert.equal(created.statusCode, 201, created.body);
    const tunnelID = created.json<{ id: string }>().id;

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/tunnels",
      headers,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    assert.equal(listed.json<{ tunnels: unknown[] }>().tunnels.length, 1);

    const runtime = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/tunnels/${tunnelID}/runtime`,
      headers,
      payload: {
        running: true,
        trafficUpBytes: 4096,
        trafficDownBytes: 8192,
      },
    });
    assert.equal(runtime.statusCode, 200, runtime.body);
    assert.deepEqual(
      runtime.json<{
        running: boolean;
        trafficUpBytes: number;
        trafficDownBytes: number;
        version: number;
      }>(),
      {
        ...runtime.json(),
        running: true,
        trafficUpBytes: 4096,
        trafficDownBytes: 8192,
        version: 1,
      },
    );

    const bobRuntime = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/tunnels/${tunnelID}/runtime`,
      headers: { authorization: `Bearer ${fixture.bobToken}` },
      payload: {
        running: false,
        trafficUpBytes: 0,
        trafficDownBytes: 0,
      },
    });
    assert.equal(bobRuntime.statusCode, 404, bobRuntime.body);

    const bobUpdate = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/tunnels/${tunnelID}`,
      headers: { authorization: `Bearer ${fixture.bobToken}` },
      payload: {
        name: "stolen",
        hostId: hostID,
        type: "local",
        listenHost: "127.0.0.1",
        listenPort: 18080,
        targetHost: "127.0.0.1",
        targetPort: 80,
      },
    });
    assert.equal(bobUpdate.statusCode, 404, bobUpdate.body);

    const removed = await fixture.app.inject({
      method: "DELETE",
      url: `/api/v1/ssh/tunnels/${tunnelID}`,
      headers,
    });
    assert.equal(removed.statusCode, 204, removed.body);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh snippet routes persist metadata, protect secrets, and enforce ownership", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/snippets",
      headers,
      payload: {
        name: "deploy",
        command: "echo ${ENV} ${TOKEN}",
        variables: ["ENV"],
        secrets: { TOKEN: "top-secret" },
        enabled: true,
      },
    });
    assert.equal(created.statusCode, 201, created.body);
    const snippet = created.json<{
      id: string;
      name: string;
      command: string;
      variables: string[];
      secretNames: string[];
      version: number;
    }>();
    assert.equal(snippet.name, "deploy");
    assert.deepEqual(snippet.variables, ["ENV"]);
    assert.deepEqual(snippet.secretNames, ["TOKEN"]);
    assert.equal(snippet.version, 1);
    assert.equal(created.body.includes("top-secret"), false);

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/snippets",
      headers,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    assert.equal(listed.body.includes("top-secret"), false);

    const secrets = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/snippets/${snippet.id}/secrets`,
      headers,
    });
    assert.equal(secrets.statusCode, 200, secrets.body);
    assert.deepEqual(secrets.json(), { TOKEN: "top-secret" });

    const crossAccount = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/snippets/${snippet.id}/secrets`,
      headers: { authorization: `Bearer ${fixture.bobToken}` },
    });
    assert.equal(crossAccount.statusCode, 404, crossAccount.body);

    const updated = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/snippets/${snippet.id}`,
      headers,
      payload: {
        name: "deploy-prod",
        command: "${TOKEN}",
        variables: [],
        secrets: { TOKEN: "rotated" },
        enabled: false,
      },
    });
    assert.equal(updated.statusCode, 200, updated.body);
    assert.equal(
      updated.json<{ version: number; enabled: boolean }>().version,
      2,
    );
    assert.equal(
      updated.json<{ version: number; enabled: boolean }>().enabled,
      false,
    );

    const deleted = await fixture.app.inject({
      method: "DELETE",
      url: `/api/v1/ssh/snippets/${snippet.id}`,
      headers,
    });
    assert.equal(deleted.statusCode, 204, deleted.body);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh key routes persist metadata, protect private material, and enforce ownership", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/keys",
      headers,
      payload: {
        name: "deploy",
        publicKey: "ssh-ed25519 public",
        fingerprint: "SHA256:key",
        privateKey: "private-material",
        keyPassphrase: "passphrase",
        enabled: true,
      },
    });
    assert.equal(created.statusCode, 201, created.body);
    const key = created.json<{
      id: string;
      name: string;
      publicKey: string;
      fingerprint: string;
      hasPassphrase: boolean;
      enabled: boolean;
      version: number;
    }>();
    assert.equal(key.name, "deploy");
    assert.equal(key.publicKey, "ssh-ed25519 public");
    assert.equal(key.fingerprint, "SHA256:key");
    assert.equal(key.hasPassphrase, true);
    assert.equal(key.version, 1);
    assert.equal(created.body.includes("private-material"), false);
    assert.equal(created.body.includes("passphrase"), false);

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/keys",
      headers,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    assert.equal(listed.body.includes("private-material"), false);

    const secrets = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/keys/${key.id}/secrets`,
      headers,
    });
    assert.equal(secrets.statusCode, 200, secrets.body);
    assert.deepEqual(secrets.json(), {
      privateKey: "private-material",
      keyPassphrase: "passphrase",
    });

    const crossAccount = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/keys/${key.id}/secrets`,
      headers: { authorization: `Bearer ${fixture.bobToken}` },
    });
    assert.equal(crossAccount.statusCode, 404, crossAccount.body);

    const updated = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/keys/${key.id}`,
      headers,
      payload: {
        name: "deploy-disabled",
        publicKey: "ssh-ed25519 updated",
        fingerprint: "SHA256:updated",
        enabled: false,
      },
    });
    assert.equal(updated.statusCode, 200, updated.body);
    assert.equal(
      updated.json<{ version: number; enabled: boolean }>().version,
      2,
    );
    assert.equal(
      updated.json<{ version: number; enabled: boolean }>().enabled,
      false,
    );

    const preservedSecrets = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/keys/${key.id}/secrets`,
      headers,
    });
    assert.equal(preservedSecrets.statusCode, 200, preservedSecrets.body);
    assert.deepEqual(preservedSecrets.json(), {
      privateKey: "private-material",
      keyPassphrase: "passphrase",
    });

    const cleared = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/keys/${key.id}`,
      headers,
      payload: {
        name: "deploy-cleared",
        clearSecretMaterial: true,
        enabled: true,
      },
    });
    assert.equal(cleared.statusCode, 200, cleared.body);
    assert.equal(
      cleared.json<{ hasPassphrase: boolean; version: number }>().hasPassphrase,
      false,
    );
    assert.equal(
      cleared.json<{ hasPassphrase: boolean; version: number }>().version,
      3,
    );

    const clearedSecrets = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/keys/${key.id}/secrets`,
      headers,
    });
    assert.equal(clearedSecrets.statusCode, 200, clearedSecrets.body);
    assert.deepEqual(clearedSecrets.json(), {
      privateKey: "",
      keyPassphrase: "",
    });

    const deleted = await fixture.app.inject({
      method: "DELETE",
      url: `/api/v1/ssh/keys/${key.id}`,
      headers,
    });
    assert.equal(deleted.statusCode, 204, deleted.body);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh session history routes store only connection metadata and enforce ownership", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const hostResponse = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload(),
    });
    assert.equal(hostResponse.statusCode, 201, hostResponse.body);
    const host = hostResponse.json<{ id: string; name: string }>();

    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/session-history",
      headers,
      payload: { hostId: host.id, status: "connecting" },
    });
    assert.equal(created.statusCode, 201, created.body);
    const history = created.json<{
      id: string;
      hostId: string;
      hostName: string;
      status: string;
      latencyMs: number;
      errorMessage: string;
      endedAt: number | null;
    }>();
    assert.equal(history.hostId, host.id);
    assert.equal(history.hostName, host.name);
    assert.equal(history.status, "connecting");
    assert.equal(history.endedAt, null);
    assert.equal(created.body.includes("terminalOutput"), false);
    assert.equal(created.body.includes("command"), false);

    const connected = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/session-history/${history.id}`,
      headers,
      payload: { status: "connected", latencyMs: 42 },
    });
    assert.equal(connected.statusCode, 200, connected.body);
    assert.equal(connected.json<{ latencyMs: number }>().latencyMs, 42);

    const otherHeaders = { authorization: `Bearer ${fixture.bobToken}` };
    const crossAccountList = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/session-history",
      headers: otherHeaders,
    });
    assert.equal(crossAccountList.statusCode, 200, crossAccountList.body);
    assert.deepEqual(crossAccountList.json(), { history: [] });

    const crossAccountUpdate = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/session-history/${history.id}`,
      headers: otherHeaders,
      payload: { status: "failed", errorMessage: "stolen" },
    });
    assert.equal(crossAccountUpdate.statusCode, 404, crossAccountUpdate.body);

    const crossAccountCreate = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/session-history",
      headers: otherHeaders,
      payload: { hostId: host.id, status: "connecting" },
    });
    assert.equal(crossAccountCreate.statusCode, 404, crossAccountCreate.body);

    const closed = await fixture.app.inject({
      method: "PATCH",
      url: `/api/v1/ssh/session-history/${history.id}`,
      headers,
      payload: { status: "closed" },
    });
    assert.equal(closed.statusCode, 200, closed.body);
    assert.equal(closed.json<{ status: string }>().status, "closed");
    assert.equal(typeof closed.json<{ endedAt: number }>().endedAt, "number");

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/session-history",
      headers,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    const records = listed.json<{ history: Array<{ id: string }> }>().history;
    assert.deepEqual(
      records.map((record) => record.id),
      [history.id],
    );
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh workspace export routes protect secret packages and preview conflicts", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const hostResponse = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload({ password: "workspace-export-password" }),
    });
    assert.equal(hostResponse.statusCode, 201, hostResponse.body);

    const plain = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/workspace/export",
      headers,
      payload: { includeSecrets: false },
    });
    assert.equal(plain.statusCode, 200, plain.body);
    const plainPackage = plain.json<{ package: string }>().package;
    assert.equal(plainPackage.includes("workspace-export-password"), false);

    const encrypted = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/workspace/export",
      headers,
      payload: {
        includeSecrets: true,
        password: "correct horse battery staple",
      },
    });
    assert.equal(encrypted.statusCode, 200, encrypted.body);
    const encryptedPackage = encrypted.json<{ package: string }>().package;
    assert.equal(encryptedPackage.includes("workspace-export-password"), false);

    const preview = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/workspace/import/preview",
      headers,
      payload: {
        package: encryptedPackage,
        password: "correct horse battery staple",
      },
    });
    assert.equal(preview.statusCode, 200, preview.body);
    assert.equal(preview.body.includes("workspace-export-password"), false);
    const result = preview.json<{
      includesSecrets: boolean;
      counts: { hosts: number };
      conflicts: Array<{ kind: string; name: string; conflict: boolean }>;
    }>();
    assert.equal(result.includesSecrets, true);
    assert.equal(result.counts.hosts, 1);
    assert.deepEqual(result.conflicts, [
      { kind: "host", name: "web", conflict: true },
    ]);

    const wrongPassword = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/workspace/import/preview",
      headers,
      payload: {
        package: encryptedPackage,
        password: "wrong password value",
      },
    });
    assert.equal(wrongPassword.statusCode, 400, wrongPassword.body);
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});

test("ssh workspace import apply persists encrypted resources without returning secrets", async () => {
  const fixture = await createFixture();
  try {
    const aliceHeaders = { authorization: `Bearer ${fixture.aliceToken}` };
    const bobHeaders = { authorization: `Bearer ${fixture.bobToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers: aliceHeaders,
      payload: hostPayload({
        name: "imported-web",
        password: "workspace-import-password",
      }),
    });
    assert.equal(created.statusCode, 201, created.body);
    const exported = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/workspace/export",
      headers: aliceHeaders,
      payload: {
        includeSecrets: true,
        password: "correct horse battery staple",
      },
    });
    assert.equal(exported.statusCode, 200, exported.body);
    const encoded = exported.json<{ package: string }>().package;

    const applied = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/workspace/import/apply",
      headers: bobHeaders,
      payload: {
        package: encoded,
        password: "correct horse battery staple",
        resolutions: [],
      },
    });
    assert.equal(applied.statusCode, 200, applied.body);
    assert.equal(applied.body.includes("workspace-import-password"), false);
    assert.equal(applied.body.includes("payload"), false);
    assert.deepEqual(applied.json<{ counts: unknown }>().counts, {
      created: 1,
      overwritten: 0,
      copied: 0,
      skipped: 0,
    });

    const listed = await fixture.app.inject({
      method: "GET",
      url: "/api/v1/ssh/hosts",
      headers: bobHeaders,
    });
    assert.equal(listed.statusCode, 200, listed.body);
    const hosts = listed.json<{ hosts: Array<{ id: string; name: string }> }>()
      .hosts;
    assert.equal(hosts[0]?.name, "imported-web");
    const credentials = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${hosts[0]?.id}/credentials`,
      headers: bobHeaders,
    });
    assert.equal(credentials.statusCode, 200, credentials.body);
    assert.equal(
      credentials.json<{ password: string }>().password,
      "workspace-import-password",
    );
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

test("ssh host fingerprint routes preserve history and enforce ownership", async () => {
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
      payload: { fingerprint: "SHA256:abc123", source: "manual" },
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

    const history = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${hostId}/fingerprints`,
      headers,
    });
    assert.equal(history.statusCode, 200, history.body);
    const entries = history.json<{
      fingerprints: Array<{
        algorithm: string;
        fingerprint: string;
        source: string;
        active: boolean;
        retiredAt: number | null;
      }>;
    }>().fingerprints;
    assert.equal(entries.length, 1);
    assert.deepEqual(entries[0], {
      ...entries[0],
      algorithm: "SHA256",
      fingerprint: "SHA256:abc123",
      source: "manual",
      active: true,
      retiredAt: null,
    });

    const crossAccount = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${hostId}/fingerprints`,
      headers: { authorization: `Bearer ${fixture.bobToken}` },
    });
    assert.equal(crossAccount.statusCode, 404, crossAccount.body);

    const cleared = await fixture.app.inject({
      method: "DELETE",
      url: `/api/v1/ssh/hosts/${hostId}/fingerprint`,
      headers,
    });
    assert.equal(cleared.statusCode, 204, cleared.body);

    const retired = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${hostId}/fingerprints`,
      headers,
    });
    const retiredEntries = retired.json<{
      fingerprints: Array<{ active: boolean; retiredAt: number | null }>;
    }>().fingerprints;
    assert.equal(retiredEntries[0]?.active, false);
    assert.equal(typeof retiredEntries[0]?.retiredAt, "number");
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

test("ssh host clone route copies secrets without returning them in metadata", async () => {
  const fixture = await createFixture();
  try {
    const headers = { authorization: `Bearer ${fixture.aliceToken}` };
    const created = await fixture.app.inject({
      method: "POST",
      url: "/api/v1/ssh/hosts",
      headers,
      payload: hostPayload({ name: "source", password: "source-password" }),
    });
    assert.equal(created.statusCode, 201, created.body);
    const sourceId = created.json<{ id: string }>().id;

    const cloned = await fixture.app.inject({
      method: "POST",
      url: `/api/v1/ssh/hosts/${sourceId}/clone`,
      headers,
      payload: { name: "source copy" },
    });
    assert.equal(cloned.statusCode, 201, cloned.body);
    const metadata = cloned.json<Record<string, unknown>>();
    assert.equal(metadata.name, "source copy");
    assert.equal("password" in metadata, false);
    assert.equal("privateKey" in metadata, false);

    const credentials = await fixture.app.inject({
      method: "GET",
      url: `/api/v1/ssh/hosts/${String(metadata.id)}/credentials`,
      headers,
    });
    assert.equal(credentials.statusCode, 200, credentials.body);
    assert.equal(
      credentials.json<{ password: string }>().password,
      "source-password",
    );
  } finally {
    await fixture.app.close();
    fixture.database.close();
  }
});
