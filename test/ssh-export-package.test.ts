import assert from "node:assert/strict";
import test from "node:test";

import {
  createSSHWorkspaceExport,
  planSSHWorkspaceImport,
  previewSSHWorkspaceImport,
  readSSHWorkspaceExport,
  type SSHWorkspaceExportPayload,
} from "../src/security/ssh-export-package.js";

const payload: SSHWorkspaceExportPayload = {
  hosts: [
    {
      ref: "host:web",
      name: "web",
      host: "web.example.com",
      port: 22,
      username: "deploy",
      enabled: true,
      favorite: true,
      groupPath: "production/web",
      tags: ["production"],
      sortOrder: 1,
      authMethod: "password",
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
      trustedFingerprint: "SHA256:trusted",
      secret: {
        password: "host-password",
        privateKey: "",
        keyPassphrase: "",
      },
    },
  ],
  tunnels: [
    {
      name: "web-local",
      hostRef: "host:web",
      type: "local",
      listenHost: "127.0.0.1",
      listenPort: 18080,
      targetHost: "web.internal",
      targetPort: 8080,
      enabled: true,
      autoStart: false,
    },
  ],
  snippets: [
    {
      name: "deploy",
      command: "deploy ${SERVICE} ${TOKEN}",
      variables: ["SERVICE"],
      enabled: true,
      secrets: { TOKEN: "snippet-token" },
    },
  ],
  keys: [
    {
      name: "production-key",
      publicKey: "ssh-ed25519 AAAA",
      fingerprint: "SHA256:key",
      enabled: true,
      secret: {
        privateKey: "PRIVATE KEY MATERIAL",
        keyPassphrase: "key-passphrase",
      },
    },
  ],
};

test("ssh workspace export excludes secrets unless explicitly encrypted", async () => {
  const encoded = await createSSHWorkspaceExport(payload, {
    includeSecrets: false,
    createdAt: 1_700_000_000_000,
  });
  const envelope = JSON.parse(encoded) as Record<string, unknown>;
  assert.equal(envelope.format, "s12ryt-ssh-workspace");
  assert.equal(envelope.version, 1);
  assert.equal(envelope.includesSecrets, false);
  assert.equal(encoded.includes("host-password"), false);
  assert.equal(encoded.includes("snippet-token"), false);
  assert.equal(encoded.includes("PRIVATE KEY MATERIAL"), false);

  const decoded = await readSSHWorkspaceExport(encoded);
  assert.equal(decoded.hosts[0]?.name, "web");
  assert.equal(decoded.hosts[0]?.secret, undefined);
  assert.equal(decoded.snippets[0]?.secrets, undefined);
  assert.equal(decoded.keys[0]?.secret, undefined);
});

test("ssh workspace export encrypts secret payloads and rejects wrong passwords", async () => {
  const encoded = await createSSHWorkspaceExport(payload, {
    includeSecrets: true,
    password: "correct horse battery staple",
    createdAt: 1_700_000_000_000,
  });
  assert.equal(encoded.includes("host-password"), false);
  assert.equal(encoded.includes("snippet-token"), false);
  assert.equal(encoded.includes("PRIVATE KEY MATERIAL"), false);

  const decoded = await readSSHWorkspaceExport(
    encoded,
    "correct horse battery staple",
  );
  assert.deepEqual(decoded, payload);
  await assert.rejects(
    readSSHWorkspaceExport(encoded, "wrong password value"),
    /unable to decrypt SSH workspace export/,
  );
});

test("ssh workspace export rejects authenticated ciphertext tampering", async () => {
  const encoded = await createSSHWorkspaceExport(payload, {
    includeSecrets: true,
    password: "correct horse battery staple",
  });
  const envelope = JSON.parse(encoded) as {
    encryption: { ciphertext: string };
  };
  envelope.encryption.ciphertext = `${
    envelope.encryption.ciphertext[0] === "A" ? "B" : "A"
  }${envelope.encryption.ciphertext.slice(1)}`;
  await assert.rejects(
    readSSHWorkspaceExport(
      JSON.stringify(envelope),
      "correct horse battery staple",
    ),
    /unable to decrypt SSH workspace export/,
  );
});

test("ssh workspace import preview reports deterministic name conflicts", () => {
  assert.deepEqual(
    previewSSHWorkspaceImport(payload, {
      hosts: ["web"],
      tunnels: ["other-tunnel"],
      snippets: ["deploy"],
      keys: ["production-key"],
    }),
    [
      { kind: "host", name: "web", conflict: true },
      { kind: "tunnel", name: "web-local", conflict: false },
      { kind: "snippet", name: "deploy", conflict: true },
      { kind: "key", name: "production-key", conflict: true },
    ],
  );
});

test("ssh workspace import plan requires and applies every conflict decision", () => {
  const existing = {
    hosts: ["web", "web (2)"],
    tunnels: [] as string[],
    snippets: ["deploy"],
    keys: ["production-key"],
  };
  assert.deepEqual(
    planSSHWorkspaceImport(payload, existing, [
      { kind: "host", name: "web", action: "copy" },
      { kind: "snippet", name: "deploy", action: "overwrite" },
      { kind: "key", name: "production-key", action: "skip" },
    ]),
    [
      { kind: "host", name: "web", action: "copy", targetName: "web (3)" },
      {
        kind: "tunnel",
        name: "web-local",
        action: "create",
        targetName: "web-local",
      },
      {
        kind: "snippet",
        name: "deploy",
        action: "overwrite",
        targetName: "deploy",
      },
      {
        kind: "key",
        name: "production-key",
        action: "skip",
        targetName: "production-key",
      },
    ],
  );
  assert.throws(
    () => planSSHWorkspaceImport(payload, existing, []),
    /missing import decision for host web/,
  );
});
