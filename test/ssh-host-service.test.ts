import assert from "node:assert/strict";
import test from "node:test";

import { Database } from "../src/db/database.js";
import { SqliteRepository } from "../src/repository/sqlite-repository.js";
import {
  createSSHWorkspaceExport,
  readSSHWorkspaceExport,
  type SSHWorkspaceImportResolution,
} from "../src/security/ssh-export-package.js";
import { AdminService } from "../src/services/admin-service.js";
import { SSHHostService } from "../src/services/ssh-host-service.js";
import type { Principal } from "../src/domain/models.js";

const masterKey = Buffer.alloc(32, 8);

interface Fixture {
  database: Database;
  repository: SqliteRepository;
  admin: AdminService;
  ssh: SSHHostService;
  accountId: string;
  otherAccountId: string;
  principal: Principal;
}

async function createFixture(): Promise<Fixture> {
  const database = new Database(":memory:");
  database.migrate();
  const repository = new SqliteRepository(database.raw());
  const admin = new AdminService(repository, masterKey, {
    defaultDeviceLimit: 3,
  });
  const ssh = new SSHHostService(repository, masterKey, { maxHosts: 50 });
  const account = await admin.createAccount("alice");
  const other = await admin.createAccount("bob");
  // audit_events.session_id has a foreign key to sessions, so the fake
  // principals need matching session rows like the authenticated flow.
  const now = Date.now();
  const insertSession = database.raw().prepare(
    `INSERT INTO sessions(
        id, family_id, account_id, device_id, refresh_hash, refresh_expires_at,
        revoked_at, created_at, last_used_at, ip_address, user_agent
      ) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?)`,
  );
  insertSession.run(
    "session-1",
    "family-1",
    account.account.id,
    "device-1",
    "refresh-1",
    now + 60_000,
    now,
    now,
    "127.0.0.1",
    "node:test",
  );
  insertSession.run(
    "session-2",
    "family-2",
    other.account.id,
    "device-2",
    "refresh-2",
    now + 60_000,
    now,
    now,
    "127.0.0.1",
    "node:test",
  );
  return {
    database,
    repository,
    admin,
    ssh,
    accountId: account.account.id,
    otherAccountId: other.account.id,
    principal: {
      accountId: account.account.id,
      username: "alice",
      sessionId: "session-1",
      deviceId: "device-1",
    },
  };
}

function context(fixture: Fixture) {
  return { principal: fixture.principal, ipAddress: "127.0.0.1" };
}

function otherContext(fixture: Fixture) {
  return {
    principal: {
      accountId: fixture.otherAccountId,
      username: "bob",
      sessionId: "session-2",
      deviceId: "device-2",
    },
    ipAddress: "127.0.0.1",
  };
}

function hostInput(overrides: Record<string, unknown> = {}) {
  return {
    name: "web",
    host: "web.example.com",
    port: 22,
    username: "deploy",
    password: "hunter2hunter2",
    ...overrides,
  };
}

test("ssh host service creates hosts and lists metadata without secrets", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    assert.equal(created.name, "web");
    assert.equal(created.host, "web.example.com");
    assert.equal(created.port, 22);
    assert.equal(created.username, "deploy");
    assert.equal(created.hasPassword, true);
    assert.equal(created.hasPrivateKey, false);
    assert.equal(created.trustedFingerprint, "");

    const keyHost = fixture.ssh.createHost(
      context(fixture),
      hostInput({
        name: "key-host",
        password: "",
        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
        keyPassphrase: "unlock",
      }),
    );
    assert.equal(keyHost.hasPassword, false);
    assert.equal(keyHost.hasPrivateKey, true);
    assert.equal(keyHost.hasKeyPassphrase, true);

    const hosts = fixture.ssh.listHosts(fixture.accountId);
    assert.equal(hosts.length, 2);
    assert.equal(
      hosts.some((host) => host.name === "web"),
      true,
    );
    for (const host of hosts) {
      assert.equal("secretCiphertext" in host, false);
      assert.equal("password" in host, false);
      assert.equal("privateKey" in host, false);
    }
  } finally {
    fixture.database.close();
  }
});

test("ssh tunnel service persists forwarding rules and runtime metadata", async () => {
  const fixture = await createFixture();
  try {
    const host = fixture.ssh.createHost(context(fixture), hostInput());
    const created = fixture.ssh.createTunnel(context(fixture), {
      name: "web-local",
      hostId: host.id,
      type: "local",
      listenHost: "127.0.0.1",
      listenPort: 18080,
      targetHost: "web.internal",
      targetPort: 8080,
      enabled: true,
      autoStart: true,
    });
    assert.equal(created.type, "local");
    assert.equal(created.hostId, host.id);
    assert.equal(created.listenPort, 18080);
    assert.equal(created.targetPort, 8080);
    assert.equal(created.running, false);
    assert.equal(created.trafficUpBytes, 0);
    assert.equal(created.trafficDownBytes, 0);
    assert.equal(created.version, 1);

    const listed = fixture.ssh.listTunnels(fixture.accountId);
    assert.equal(listed.length, 1);
    assert.equal(listed[0]?.id, created.id);

    const updated = fixture.ssh.updateTunnel(context(fixture), created.id, {
      name: "web-remote",
      hostId: host.id,
      type: "remote",
      listenHost: "0.0.0.0",
      listenPort: 19090,
      targetHost: "127.0.0.1",
      targetPort: 9090,
      enabled: true,
      autoStart: false,
    });
    assert.equal(updated.type, "remote");
    assert.equal(updated.version, 2);

    fixture.ssh.deleteTunnel(context(fixture), created.id);
    assert.deepEqual(fixture.ssh.listTunnels(fixture.accountId), []);
  } finally {
    fixture.database.close();
  }
});

test("ssh tunnel runtime updates preserve configuration versions and ownership", async () => {
  const fixture = await createFixture();
  try {
    const host = fixture.ssh.createHost(context(fixture), hostInput());
    const tunnel = fixture.ssh.createTunnel(context(fixture), {
      name: "runtime-local",
      hostId: host.id,
      type: "local",
      listenHost: "127.0.0.1",
      listenPort: 18081,
      targetHost: "web.internal",
      targetPort: 8080,
    });

    const running = fixture.ssh.updateTunnelRuntime(
      context(fixture),
      tunnel.id,
      {
        running: true,
        trafficUpBytes: 128,
        trafficDownBytes: 256,
      },
    );
    assert.equal(running.running, true);
    assert.equal(running.trafficUpBytes, 128);
    assert.equal(running.trafficDownBytes, 256);
    assert.equal(running.version, tunnel.version);

    assert.throws(
      () =>
        fixture.ssh.updateTunnelRuntime(otherContext(fixture), tunnel.id, {
          running: false,
          trafficUpBytes: 0,
          trafficDownBytes: 0,
        }),
      /ssh tunnel not found/,
    );
    assert.throws(
      () =>
        fixture.ssh.updateTunnelRuntime(context(fixture), tunnel.id, {
          running: true,
          trafficUpBytes: -1,
          trafficDownBytes: 0,
        }),
      /trafficUpBytes must be a non-negative integer/,
    );

    const stopped = fixture.ssh.updateTunnelRuntime(
      context(fixture),
      tunnel.id,
      {
        running: false,
        trafficUpBytes: 512,
        trafficDownBytes: 1024,
      },
    );
    assert.equal(stopped.running, false);
    assert.equal(stopped.trafficUpBytes, 512);
    assert.equal(stopped.trafficDownBytes, 1024);
    assert.equal(stopped.version, tunnel.version);
  } finally {
    fixture.database.close();
  }
});

test("ssh snippet service persists variables and keeps secrets encrypted", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createSnippet(context(fixture), {
      name: "deploy",
      command: "echo ${ENV} ${TOKEN}",
      variables: ["ENV"],
      secrets: { TOKEN: "secret-value" },
      enabled: true,
    });
    assert.equal(created.name, "deploy");
    assert.equal(created.command, "echo ${ENV} ${TOKEN}");
    assert.deepEqual(created.variables, ["ENV"]);
    assert.deepEqual(created.secretNames, ["TOKEN"]);
    assert.equal(created.enabled, true);
    assert.equal("secrets" in created, false);

    const stored = fixture.database
      .raw()
      .prepare("SELECT secret_ciphertext FROM ssh_snippets WHERE id = ?")
      .get(created.id) as { secret_ciphertext: string };
    assert.notEqual(stored.secret_ciphertext, "secret-value");

    const secrets = fixture.ssh.getSnippetSecrets(context(fixture), created.id);
    assert.deepEqual(secrets, { TOKEN: "secret-value" });

    const updated = fixture.ssh.updateSnippet(context(fixture), created.id, {
      name: "deploy-prod",
      command: "${TOKEN}",
      variables: [],
      secrets: { TOKEN: "rotated-secret" },
      enabled: false,
    });
    assert.equal(updated.version, 2);
    assert.equal(updated.enabled, false);
    assert.deepEqual(
      fixture.ssh.getSnippetSecrets(context(fixture), created.id),
      { TOKEN: "rotated-secret" },
    );

    fixture.ssh.deleteSnippet(context(fixture), created.id);
    assert.deepEqual(fixture.ssh.listSnippets(fixture.accountId), []);
  } finally {
    fixture.database.close();
  }
});

test("ssh key identity service persists metadata and keeps private material encrypted", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createKeyIdentity(context(fixture), {
      name: "production-deploy",
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAexample",
      fingerprint: "SHA256:key-fingerprint",
      privateKey: "private-key-material",
      keyPassphrase: "key-passphrase",
      enabled: true,
    });
    assert.equal(created.name, "production-deploy");
    assert.equal(
      created.publicKey,
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAexample",
    );
    assert.equal(created.fingerprint, "SHA256:key-fingerprint");
    assert.equal(created.hasPassphrase, true);
    assert.equal(created.enabled, true);
    assert.equal(created.version, 1);
    assert.equal("privateKey" in created, false);
    assert.equal("keyPassphrase" in created, false);

    const stored = fixture.database
      .raw()
      .prepare("SELECT secret_ciphertext FROM ssh_key_identities WHERE id = ?")
      .get(created.id) as { secret_ciphertext: string };
    assert.notEqual(stored.secret_ciphertext, "private-key-material");
    assert.equal(stored.secret_ciphertext.includes("key-passphrase"), false);

    assert.deepEqual(
      fixture.ssh.getKeyIdentitySecrets(context(fixture), created.id),
      { privateKey: "private-key-material", keyPassphrase: "key-passphrase" },
    );
    assert.equal(fixture.ssh.listKeyIdentities(fixture.accountId).length, 1);

    const updated = fixture.ssh.updateKeyIdentity(
      context(fixture),
      created.id,
      {
        name: "production-deploy-disabled",
        publicKey: "ssh-ed25519 updated",
        fingerprint: "SHA256:updated",
        enabled: false,
      },
    );
    assert.equal(updated.version, 2);
    assert.equal(updated.enabled, false);
    assert.equal(updated.hasPassphrase, true);
    assert.deepEqual(
      fixture.ssh.getKeyIdentitySecrets(context(fixture), created.id),
      { privateKey: "private-key-material", keyPassphrase: "key-passphrase" },
    );

    const cleared = fixture.ssh.updateKeyIdentity(
      context(fixture),
      created.id,
      {
        name: "production-deploy-cleared",
        clearSecretMaterial: true,
        enabled: true,
      },
    );
    assert.equal(cleared.hasPassphrase, false);
    assert.deepEqual(
      fixture.ssh.getKeyIdentitySecrets(context(fixture), created.id),
      { privateKey: "", keyPassphrase: "" },
    );

    fixture.ssh.deleteKeyIdentity(context(fixture), created.id);
    assert.deepEqual(fixture.ssh.listKeyIdentities(fixture.accountId), []);
  } finally {
    fixture.database.close();
  }
});

test("ssh session history records connection metadata without terminal content", async () => {
  const fixture = await createFixture();
  try {
    const host = fixture.ssh.createHost(context(fixture), hostInput());
    const started = fixture.ssh.createSessionHistory(context(fixture), {
      hostId: host.id,
      status: "connecting",
    });
    assert.equal(started.hostId, host.id);
    assert.equal(started.hostName, host.name);
    assert.equal(started.status, "connecting");
    assert.equal(started.latencyMs, 0);
    assert.equal(started.errorMessage, "");
    assert.equal(started.endedAt, null);
    assert.equal("terminalOutput" in started, false);
    assert.equal("command" in started, false);

    const connected = fixture.ssh.updateSessionHistory(
      context(fixture),
      started.id,
      { status: "connected", latencyMs: 42 },
    );
    assert.equal(connected.status, "connected");
    assert.equal(connected.latencyMs, 42);
    assert.equal(connected.endedAt, null);

    const closed = fixture.ssh.updateSessionHistory(
      context(fixture),
      started.id,
      { status: "closed" },
    );
    assert.equal(closed.status, "closed");
    assert.equal(closed.latencyMs, 42);
    assert.equal(typeof closed.endedAt, "number");

    const failed = fixture.ssh.createSessionHistory(context(fixture), {
      hostId: host.id,
      status: "failed",
      latencyMs: 125,
      errorMessage: "handshake failed",
    });
    assert.equal(failed.status, "failed");
    assert.equal(failed.errorMessage, "handshake failed");
    assert.equal(typeof failed.endedAt, "number");

    const listed = fixture.ssh.listSessionHistory(fixture.accountId);
    assert.deepEqual(
      listed.map((entry) => entry.id),
      [failed.id, started.id],
    );
    assert.deepEqual(
      fixture.ssh.listSessionHistory(fixture.otherAccountId),
      [],
    );

    const otherContext = {
      principal: {
        accountId: fixture.otherAccountId,
        username: "bob",
        sessionId: "session-2",
        deviceId: "device-2",
      },
      ipAddress: "127.0.0.1",
    };
    assert.throws(
      () =>
        fixture.ssh.updateSessionHistory(otherContext, started.id, {
          status: "failed",
          errorMessage: "stolen",
        }),
      /not found/,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service rejects a host without any credential", async () => {
  const fixture = await createFixture();
  try {
    assert.throws(
      () =>
        fixture.ssh.createHost(
          context(fixture),
          hostInput({ password: "", privateKey: "" }),
        ),
      /password or private key/,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service enforces the per-account host limit", async () => {
  const fixture = await createFixture();
  try {
    for (let index = 0; index < 50; index += 1) {
      fixture.ssh.createHost(
        context(fixture),
        hostInput({ name: `host-${index}` }),
      );
    }
    assert.throws(
      () =>
        fixture.ssh.createHost(context(fixture), hostInput({ name: "extra" })),
      /limit/,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service rejects duplicate names per account but not across accounts", async () => {
  const fixture = await createFixture();
  try {
    fixture.ssh.createHost(context(fixture), hostInput());
    assert.throws(
      () => fixture.ssh.createHost(context(fixture), hostInput()),
      /already exists/,
    );
    fixture.ssh.createHost(
      {
        principal: {
          accountId: fixture.otherAccountId,
          username: "bob",
          sessionId: "session-2",
          deviceId: "device-2",
        },
        ipAddress: "127.0.0.1",
      },
      hostInput(),
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service validates host fields", async () => {
  const fixture = await createFixture();
  try {
    assert.throws(
      () => fixture.ssh.createHost(context(fixture), hostInput({ name: "" })),
      /name/,
    );
    assert.throws(
      () => fixture.ssh.createHost(context(fixture), hostInput({ host: "" })),
      /host/,
    );
    assert.throws(
      () => fixture.ssh.createHost(context(fixture), hostInput({ port: 0 })),
      /port/,
    );
    assert.throws(
      () =>
        fixture.ssh.createHost(context(fixture), hostInput({ port: 65536 })),
      /port/,
    );
    assert.throws(
      () =>
        fixture.ssh.createHost(context(fixture), hostInput({ username: "" })),
      /username/,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service update keeps secrets when fields are blank", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(
      context(fixture),
      hostInput({
        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----",
        password: "",
      }),
    );
    const updated = fixture.ssh.updateHost(context(fixture), created.id, {
      name: "renamed",
      host: "web.example.com",
      port: 22,
      username: "deploy",
      password: "",
      privateKey: "",
    });
    assert.equal(updated.name, "renamed");
    assert.equal(updated.hasPrivateKey, true);

    const credentials = fixture.ssh.getCredentials(
      context(fixture),
      created.id,
    );
    assert.equal(credentials.privateKey, "-----BEGIN OPENSSH PRIVATE KEY-----");
    assert.equal(credentials.password, "");
  } finally {
    fixture.database.close();
  }
});

test("ssh host service update replaces only provided credentials", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(
      context(fixture),
      hostInput({
        privateKey: "old-key",
        password: "old-password-old-password",
      }),
    );
    fixture.ssh.updateHost(context(fixture), created.id, {
      name: "web",
      host: "web.example.com",
      port: 22,
      username: "deploy",
      password: "new-password-new-password",
    });
    const credentials = fixture.ssh.getCredentials(
      context(fixture),
      created.id,
    );
    assert.equal(credentials.password, "new-password-new-password");
    assert.equal(credentials.privateKey, "old-key");
  } finally {
    fixture.database.close();
  }
});

test("ssh host service clears the fingerprint when host or port changes", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    fixture.ssh.setFingerprint(context(fixture), created.id, "SHA256:abc123");
    assert.equal(
      fixture.ssh.listHosts(fixture.accountId)[0]?.trustedFingerprint,
      "SHA256:abc123",
    );
    const trustedCredentials = fixture.ssh.getCredentials(
      context(fixture),
      created.id,
    );
    assert.equal(trustedCredentials.version, created.version + 1);

    const moved = fixture.ssh.updateHost(context(fixture), created.id, {
      name: "web",
      host: "web2.example.com",
      port: 22,
      username: "deploy",
      password: "",
      privateKey: "",
    });
    assert.equal(moved.trustedFingerprint, "");

    fixture.ssh.setFingerprint(context(fixture), created.id, "SHA256:def456");
    const portChanged = fixture.ssh.updateHost(context(fixture), created.id, {
      name: "web",
      host: "web2.example.com",
      port: 2222,
      username: "deploy",
      password: "",
      privateKey: "",
    });
    assert.equal(portChanged.trustedFingerprint, "");

    const withNewFingerprint = fixture.ssh.updateHost(
      context(fixture),
      created.id,
      {
        name: "web",
        host: "web3.example.com",
        port: 22,
        username: "deploy",
        password: "",
        privateKey: "",
        trustedFingerprint: "SHA256:xyz789",
      },
    );
    assert.equal(withNewFingerprint.trustedFingerprint, "SHA256:xyz789");
  } finally {
    fixture.database.close();
  }
});

test("ssh host fingerprint history records replacements and explicit clearing", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    fixture.ssh.setFingerprint(
      context(fixture),
      created.id,
      "SHA256:first",
      "tofu",
    );
    fixture.ssh.setFingerprint(
      context(fixture),
      created.id,
      "MD5:aa:bb:cc",
      "manual",
    );

    const history = fixture.ssh.listHostFingerprints(
      context(fixture),
      created.id,
    );
    assert.equal(history.length, 2);
    const first = history.find((entry) => entry.fingerprint === "SHA256:first");
    const current = history.find(
      (entry) => entry.fingerprint === "MD5:aa:bb:cc",
    );
    assert.equal(first?.algorithm, "SHA256");
    assert.equal(first?.source, "tofu");
    assert.equal(first?.active, false);
    assert.equal(typeof first?.retiredAt, "number");
    assert.equal(current?.algorithm, "MD5");
    assert.equal(current?.source, "manual");
    assert.equal(current?.active, true);
    assert.equal(current?.retiredAt, null);

    fixture.ssh.clearFingerprint(context(fixture), created.id);
    const clearedHost = fixture.ssh.listHosts(fixture.accountId)[0];
    assert.equal(clearedHost?.trustedFingerprint, "");
    assert.equal(clearedHost?.version, created.version + 3);
    const clearedHistory = fixture.ssh.listHostFingerprints(
      context(fixture),
      created.id,
    );
    assert.equal(
      clearedHistory.every((entry) => !entry.active),
      true,
    );
    assert.equal(
      clearedHistory.every((entry) => typeof entry.retiredAt === "number"),
      true,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service isolates hosts between accounts", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    const otherContext = {
      principal: {
        accountId: fixture.otherAccountId,
        username: "bob",
        sessionId: "session-2",
        deviceId: "device-2",
      },
      ipAddress: "127.0.0.1",
    };
    assert.equal(fixture.ssh.listHosts(fixture.otherAccountId).length, 0);
    assert.throws(
      () => fixture.ssh.getCredentials(otherContext, created.id),
      /not found/,
    );
    assert.throws(
      () =>
        fixture.ssh.updateHost(otherContext, created.id, {
          name: "stolen",
          host: "evil.example.com",
          port: 22,
          username: "deploy",
        }),
      /not found/,
    );
    assert.throws(
      () => fixture.ssh.deleteHost(otherContext, created.id),
      /not found/,
    );
    assert.equal(fixture.ssh.listHosts(fixture.accountId).length, 1);
  } finally {
    fixture.database.close();
  }
});

test("ssh host service deletes hosts", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    fixture.ssh.deleteHost(context(fixture), created.id);
    assert.equal(fixture.ssh.listHosts(fixture.accountId).length, 0);
    assert.throws(
      () => fixture.ssh.getCredentials(context(fixture), created.id),
      /not found/,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service blocks access when ssh is disabled for the account", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    fixture.admin.setAccountSSHEnabled(fixture.accountId, false);

    assert.equal(fixture.ssh.accessEnabled(fixture.accountId), false);
    assert.throws(() => fixture.ssh.listHosts(fixture.accountId), /disabled/);
    assert.throws(
      () =>
        fixture.ssh.createHost(context(fixture), hostInput({ name: "next" })),
      /disabled/,
    );
    assert.throws(
      () => fixture.ssh.getCredentials(context(fixture), created.id),
      /disabled/,
    );
    assert.throws(
      () => fixture.ssh.setFingerprint(context(fixture), created.id, "fp"),
      /disabled/,
    );
    assert.throws(
      () => fixture.ssh.deleteHost(context(fixture), created.id),
      /disabled/,
    );

    fixture.admin.setAccountSSHEnabled(fixture.accountId, true);
    assert.equal(fixture.ssh.listHosts(fixture.accountId).length, 1);
  } finally {
    fixture.database.close();
  }
});

test("ssh host service returns decrypted credentials and audits issuance", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(
      context(fixture),
      hostInput({
        privateKey: "-----BEGIN KEY-----",
        keyPassphrase: "unlock",
        password: "",
      }),
    );
    fixture.ssh.setFingerprint(context(fixture), created.id, "SHA256:abc");
    const credentials = fixture.ssh.getCredentials(
      context(fixture),
      created.id,
    );
    assert.equal(credentials.host, "web.example.com");
    assert.equal(credentials.port, 22);
    assert.equal(credentials.username, "deploy");
    assert.equal(credentials.privateKey, "-----BEGIN KEY-----");
    assert.equal(credentials.keyPassphrase, "unlock");
    assert.equal(credentials.trustedFingerprint, "SHA256:abc");

    const events = fixture.repository.listAudit(20).map((row) => ({
      action: String(row.action),
      sshHostId: row.ssh_host_id ?? null,
      accountId: row.account_id ?? null,
      sessionId: row.session_id ?? null,
      success: Number(row.success),
    }));
    const issuance = events.find(
      (event) => event.action === "ssh.host.credentials",
    );
    assert.ok(issuance, "credentials issuance is audited");
    assert.equal(issuance.sshHostId, created.id);
    assert.equal(issuance.accountId, fixture.accountId);
    assert.equal(issuance.sessionId, "session-1");
    assert.equal(issuance.success, 1);
  } finally {
    fixture.database.close();
  }
});

test("ssh host service audits host lifecycle actions", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), hostInput());
    fixture.ssh.updateHost(context(fixture), created.id, {
      name: "web",
      host: "web.example.com",
      port: 22,
      username: "deploy",
      password: "rotated-rotated",
    });
    fixture.ssh.setFingerprint(context(fixture), created.id, "SHA256:abc");
    fixture.ssh.deleteHost(context(fixture), created.id);

    const actions = fixture.repository
      .listAudit(20)
      .map((row) => String(row.action));
    for (const expected of [
      "ssh.host.create",
      "ssh.host.update",
      "ssh.host.fingerprint",
      "ssh.host.delete",
    ]) {
      assert.equal(actions.includes(expected), true, `missing ${expected}`);
    }
  } finally {
    fixture.database.close();
  }
});

test("ssh host service audits failed operations", async () => {
  const fixture = await createFixture();
  try {
    assert.throws(() =>
      fixture.ssh.createHost(
        context(fixture),
        hostInput({ password: "", privateKey: "" }),
      ),
    );
    const events = fixture.repository.listAudit(5).map((row) => ({
      action: String(row.action),
      success: Number(row.success),
      errorCode: row.error_code ?? null,
    }));
    const failure = events.find(
      (event) => event.action === "ssh.host.create" && event.success === 0,
    );
    assert.ok(failure, "failed create is audited");
    assert.ok(failure.errorCode);
  } finally {
    fixture.database.close();
  }
});

test("ssh host service persists host workspace metadata and connection settings", async () => {
  const fixture = await createFixture();
  try {
    const created = fixture.ssh.createHost(context(fixture), {
      ...hostInput(),
      authMethod: "password",
      enabled: false,
      favorite: true,
      groupPath: "vps/production",
      tags: ["prod", "web"],
      sortOrder: 7,
      settings: {
        tcpTimeoutMs: 5000,
        sshHandshakeTimeoutMs: 12000,
        ptyTimeoutMs: 9000,
        keepaliveIntervalMs: 30000,
        failureCount: 3,
        idleTimeoutMs: 600000,
        compression: true,
        startupCommand: "cd /srv/app",
        initialDirectory: "/srv/app",
        environment: { APP_ENV: "production" },
        autoReconnect: true,
      },
    });

    assert.equal(created.enabled, false);
    assert.equal(created.favorite, true);
    assert.equal(created.groupPath, "vps/production");
    assert.deepEqual(created.tags, ["prod", "web"]);
    assert.equal(created.sortOrder, 7);
    assert.equal(created.authMethod, "password");
    assert.equal(created.settings.compression, true);
    assert.equal(created.settings.environment.APP_ENV, "production");

    const listed = fixture.ssh.listHosts(fixture.accountId);
    assert.deepEqual(listed[0]?.tags, ["prod", "web"]);
    assert.equal(listed[0]?.settings.initialDirectory, "/srv/app");
  } finally {
    fixture.database.close();
  }
});

test("ssh workspace terminal appearance persists account defaults and host overrides", async () => {
  const fixture = await createFixture();
  try {
    const defaults = fixture.ssh.getWorkspacePreferences(fixture.accountId);
    assert.equal(defaults.terminalAppearance.font, "builtin-mono");
    assert.equal(defaults.terminalAppearance.fontSize, 13);
    assert.equal(defaults.version, 1);

    const updated = fixture.ssh.updateWorkspacePreferences(context(fixture), {
      terminalAppearance: {
        font: "system-mono",
        fontSize: 16,
        foreground: "#e0e0e0",
        background: "#080c0b",
      },
    });
    assert.equal(updated.version, 2);
    assert.equal(updated.terminalAppearance.font, "system-mono");

    const host = fixture.ssh.createHost(context(fixture), {
      ...hostInput(),
      settings: {
        terminalAppearance: {
          fontSize: 18,
          foreground: "#ffcc00",
        },
      },
    });
    assert.deepEqual(host.settings.terminalAppearance, {
      fontSize: 18,
      foreground: "#ffcc00",
    });

    const inherited = fixture.ssh.updateHost(context(fixture), host.id, {
      ...hostInput(),
      settings: { compression: true },
      clearTerminalAppearance: true,
    });
    assert.equal(inherited.settings.terminalAppearance, undefined);
    assert.equal(inherited.settings.compression, true);

    assert.throws(
      () =>
        fixture.ssh.updateWorkspacePreferences(context(fixture), {
          terminalAppearance: {
            font: "system-mono",
            fontSize: 99,
            foreground: "invalid",
            background: "#000000",
          },
        }),
      /terminal appearance/i,
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh host service clones a host with its complete encrypted configuration", async () => {
  const fixture = await createFixture();
  try {
    const source = fixture.ssh.createHost(context(fixture), {
      ...hostInput(),
      name: "source",
      password: "source-password",
      favorite: true,
      groupPath: "vps",
      tags: ["important"],
      settings: { compression: true, startupCommand: "uptime" },
    });

    const clone = fixture.ssh.cloneHost(
      context(fixture),
      source.id,
      "source copy",
    );
    assert.notEqual(clone.id, source.id);
    assert.equal(clone.name, "source copy");
    assert.equal(clone.favorite, true);
    assert.equal(clone.groupPath, "vps");
    assert.deepEqual(clone.tags, ["important"]);

    const credentials = fixture.ssh.getCredentials(context(fixture), clone.id);
    assert.equal(credentials.password, "source-password");
    assert.equal(credentials.settings.startupCommand, "uptime");
    assert.equal(credentials.version, clone.version);
  } finally {
    fixture.database.close();
  }
});

test("ssh workspace export assembles account resources and previews conflicts", async () => {
  const fixture = await createFixture();
  try {
    const host = fixture.ssh.createHost(context(fixture), {
      ...hostInput(),
      password: "export-host-password",
      trustedFingerprint: "SHA256:export-host",
      groupPath: "production/web",
      tags: ["production"],
    });
    fixture.ssh.createTunnel(context(fixture), {
      name: "export-tunnel",
      hostId: host.id,
      type: "local",
      listenHost: "127.0.0.1",
      listenPort: 18080,
      targetHost: "web.internal",
      targetPort: 8080,
      enabled: true,
      autoStart: false,
    });
    fixture.ssh.createSnippet(context(fixture), {
      name: "export-snippet",
      command: "deploy ${TOKEN}",
      secrets: { TOKEN: "export-snippet-token" },
      enabled: true,
    });
    fixture.ssh.createKeyIdentity(context(fixture), {
      name: "export-key",
      publicKey: "ssh-ed25519 AAAAexport",
      fingerprint: "SHA256:export-key",
      privateKey: "EXPORT PRIVATE KEY",
      keyPassphrase: "export-key-passphrase",
      enabled: true,
    });

    const plain = await fixture.ssh.exportWorkspace(context(fixture), {
      includeSecrets: false,
    });
    const plainPayload = await readSSHWorkspaceExport(plain);
    assert.equal(plainPayload.hosts.length, 1);
    assert.equal(plainPayload.tunnels[0]?.hostRef, `host:${host.id}`);
    assert.equal(plainPayload.hosts[0]?.secret, undefined);
    assert.equal(plainPayload.snippets[0]?.secrets, undefined);
    assert.equal(plainPayload.keys[0]?.secret, undefined);

    const encrypted = await fixture.ssh.exportWorkspace(context(fixture), {
      includeSecrets: true,
      password: "correct horse battery staple",
    });
    const secretPayload = await readSSHWorkspaceExport(
      encrypted,
      "correct horse battery staple",
    );
    assert.equal(
      secretPayload.hosts[0]?.secret?.password,
      "export-host-password",
    );
    assert.deepEqual(secretPayload.snippets[0]?.secrets, {
      TOKEN: "export-snippet-token",
    });
    assert.equal(
      secretPayload.keys[0]?.secret?.privateKey,
      "EXPORT PRIVATE KEY",
    );

    const preview = await fixture.ssh.previewWorkspaceImport(
      context(fixture),
      encrypted,
      "correct horse battery staple",
    );
    assert.equal(preview.includesSecrets, true);
    assert.deepEqual(preview.counts, {
      hosts: 1,
      tunnels: 1,
      snippets: 1,
      keys: 1,
    });
    assert.deepEqual(
      preview.conflicts.map(({ kind, name, conflict }) => ({
        kind,
        name,
        conflict,
      })),
      [
        { kind: "host", name: "web", conflict: true },
        { kind: "tunnel", name: "export-tunnel", conflict: true },
        { kind: "snippet", name: "export-snippet", conflict: true },
        { kind: "key", name: "export-key", conflict: true },
      ],
    );
    assert.equal("payload" in preview, false);
    assert.equal("secrets" in preview, false);
  } finally {
    fixture.database.close();
  }
});

test("ssh workspace import applies encrypted resources and every conflict decision", async () => {
  const fixture = await createFixture();
  try {
    const sourceHost = fixture.ssh.createHost(context(fixture), {
      ...hostInput(),
      password: "import-host-password",
      groupPath: "production/web",
      tags: ["production"],
    });
    fixture.ssh.createTunnel(context(fixture), {
      name: "import-tunnel",
      hostId: sourceHost.id,
      type: "local",
      listenHost: "127.0.0.1",
      listenPort: 18080,
      targetHost: "web.internal",
      targetPort: 8080,
      enabled: true,
      autoStart: false,
    });
    fixture.ssh.createSnippet(context(fixture), {
      name: "import-snippet",
      command: "deploy ${TOKEN}",
      secrets: { TOKEN: "import-snippet-token" },
      enabled: true,
    });
    fixture.ssh.createKeyIdentity(context(fixture), {
      name: "import-key",
      publicKey: "ssh-ed25519 AAAAimport",
      fingerprint: "SHA256:import-key",
      privateKey: "IMPORT PRIVATE KEY",
      keyPassphrase: "import-key-passphrase",
      enabled: true,
    });
    const password = "correct horse battery staple";
    const encoded = await fixture.ssh.exportWorkspace(context(fixture), {
      includeSecrets: true,
      password,
    });

    const first = await fixture.ssh.applyWorkspaceImport(
      otherContext(fixture),
      encoded,
      password,
      [],
    );
    assert.deepEqual(first.counts, {
      created: 4,
      overwritten: 0,
      copied: 0,
      skipped: 0,
    });
    const importedHost = fixture.ssh.listHosts(fixture.otherAccountId)[0];
    assert.ok(importedHost);
    assert.equal(importedHost.groupPath, "production/web");
    assert.equal(
      fixture.ssh.getCredentials(otherContext(fixture), importedHost.id)
        .password,
      "import-host-password",
    );
    assert.equal(
      fixture.ssh.listTunnels(fixture.otherAccountId)[0]?.hostId,
      importedHost.id,
    );
    const importedSnippet = fixture.ssh.listSnippets(fixture.otherAccountId)[0];
    assert.ok(importedSnippet);
    assert.deepEqual(
      fixture.ssh.getSnippetSecrets(otherContext(fixture), importedSnippet.id),
      { TOKEN: "import-snippet-token" },
    );
    const importedKey = fixture.ssh.listKeyIdentities(
      fixture.otherAccountId,
    )[0];
    assert.ok(importedKey);
    assert.equal(
      fixture.ssh.getKeyIdentitySecrets(otherContext(fixture), importedKey.id)
        .privateKey,
      "IMPORT PRIVATE KEY",
    );

    const resolutions: SSHWorkspaceImportResolution[] = [
      { kind: "host", name: "web", action: "copy" },
      { kind: "tunnel", name: "import-tunnel", action: "skip" },
      { kind: "snippet", name: "import-snippet", action: "overwrite" },
      { kind: "key", name: "import-key", action: "copy" },
    ];
    const second = await fixture.ssh.applyWorkspaceImport(
      otherContext(fixture),
      encoded,
      password,
      resolutions,
    );
    assert.deepEqual(second.counts, {
      created: 0,
      overwritten: 1,
      copied: 2,
      skipped: 1,
    });
    const copiedHost = fixture.ssh
      .listHosts(fixture.otherAccountId)
      .find((host) => host.name === "web (2)");
    assert.ok(copiedHost);
    assert.equal(
      fixture.ssh.getCredentials(otherContext(fixture), copiedHost.id).password,
      "import-host-password",
    );
    assert.equal(fixture.ssh.listTunnels(fixture.otherAccountId).length, 1);
    const overwrittenSnippet = fixture.ssh
      .listSnippets(fixture.otherAccountId)
      .find((snippet) => snippet.name === "import-snippet");
    assert.ok(overwrittenSnippet);
    assert.deepEqual(
      fixture.ssh.getSnippetSecrets(
        otherContext(fixture),
        overwrittenSnippet.id,
      ),
      { TOKEN: "import-snippet-token" },
    );
    const copiedKey = fixture.ssh
      .listKeyIdentities(fixture.otherAccountId)
      .find((key) => key.name === "import-key (2)");
    assert.ok(copiedKey);
    assert.equal(
      fixture.ssh.getKeyIdentitySecrets(otherContext(fixture), copiedKey.id)
        .keyPassphrase,
      "import-key-passphrase",
    );
  } finally {
    fixture.database.close();
  }
});

test("ssh workspace import rolls back every resource when a later item is invalid", async () => {
  const fixture = await createFixture();
  try {
    const payload = {
      hosts: [
        {
          ref: "host:rollback",
          name: "rollback-host",
          host: "rollback.example.com",
          port: 22,
          username: "deploy",
          enabled: true,
          favorite: false,
          groupPath: "",
          tags: [],
          sortOrder: 0,
          authMethod: "password" as const,
          settings: {
            tcpTimeoutMs: 10_000,
            sshHandshakeTimeoutMs: 10_000,
            ptyTimeoutMs: 10_000,
            keepaliveIntervalMs: 30_000,
            failureCount: 3,
            idleTimeoutMs: 0,
            compression: false,
            startupCommand: "",
            initialDirectory: "",
            environment: {},
            autoReconnect: false,
          },
          trustedFingerprint: "",
          secret: {
            password: "rollback-password",
            privateKey: "",
            keyPassphrase: "",
          },
        },
      ],
      tunnels: [
        {
          name: "broken-tunnel",
          hostRef: "host:missing",
          type: "local" as const,
          listenHost: "127.0.0.1",
          listenPort: 18080,
          targetHost: "internal.example.com",
          targetPort: 8080,
          enabled: true,
          autoStart: false,
        },
      ],
      snippets: [],
      keys: [],
    };
    const encoded = await createSSHWorkspaceExport(payload, {
      includeSecrets: true,
      password: "correct horse battery staple",
    });

    await assert.rejects(
      fixture.ssh.applyWorkspaceImport(
        otherContext(fixture),
        encoded,
        "correct horse battery staple",
        [],
      ),
      /tunnel host reference is invalid/,
    );
    assert.deepEqual(fixture.ssh.listHosts(fixture.otherAccountId), []);
    assert.deepEqual(fixture.ssh.listTunnels(fixture.otherAccountId), []);
  } finally {
    fixture.database.close();
  }
});
