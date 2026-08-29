import assert from "node:assert/strict";
import test from "node:test";

import { Database } from "../src/db/database.js";
import { SqliteRepository } from "../src/repository/sqlite-repository.js";
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
