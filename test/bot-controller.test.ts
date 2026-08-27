import assert from "node:assert/strict";
import test from "node:test";

import { BotController } from "../src/bot/controller.js";
import { dispatchTelegramUpdate } from "../src/bot/telegram.js";
import { Database } from "../src/db/database.js";
import { SqliteRepository } from "../src/repository/sqlite-repository.js";
import { AdminService } from "../src/services/admin-service.js";

function createFixture() {
  const database = new Database(":memory:");
  database.migrate();
  const repository = new SqliteRepository(database.raw());
  const admin = new AdminService(repository, Buffer.alloc(32, 8), {
    defaultDeviceLimit: 3,
    clock: () => 1_700_000_000_000,
  });
  const tested: string[] = [];
  const controller = new BotController({
    admin,
    administratorIds: [1001],
    connectionTester: {
      async testConnection(connectionId) {
        tested.push(connectionId);
      },
    },
  });
  return { database, repository, admin, controller, tested };
}

test("Bot controller rejects groups and non-administrators", async () => {
  const fixture = createFixture();
  try {
    assert.deepEqual(
      await fixture.controller.handle({
        telegramUserId: 1001,
        chatType: "group",
        text: "/start",
      }),
      [],
    );
    const replies = await fixture.controller.handle({
      telegramUserId: 2002,
      chatType: "private",
      text: "/start",
    });
    assert.match(replies[0]?.text ?? "", /not authorized/i);
  } finally {
    fixture.database.close();
  }
});

test("Bot language defaults from Telegram and persists explicit changes", async () => {
  const fixture = createFixture();
  try {
    const start = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      languageCode: "zh-hant",
      text: "/start",
    });
    assert.match(start[0]?.text ?? "", /管理/);
    assert.ok(
      start[0]?.keyboard
        ?.flat()
        .some((button) => button.data === "menu:accounts"),
    );

    const changed = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: "/language en",
    });
    assert.match(changed[0]?.text ?? "", /English/);
    assert.equal(fixture.admin.getAdminLanguage(1001), "en");
  } finally {
    fixture.database.close();
  }
});

test("Account commands create a one-time password and manage sessions", async () => {
  const fixture = createFixture();
  try {
    const created = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: "/account_create operator 2",
    });
    assert.match(created[0]?.text ?? "", /operator/);
    assert.match(created[0]?.text ?? "", /password/i);
    assert.equal(fixture.admin.listAccounts()[0]?.deviceLimit, 2);

    const listed = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      callbackData: "menu:accounts",
    });
    assert.match(listed[0]?.text ?? "", /operator/);
    assert.doesNotMatch(listed[0]?.text ?? "", /password:/i);
  } finally {
    fixture.database.close();
  }
});

test("S3 connection wizard deletes credential messages and stores encrypted secret", async () => {
  const fixture = createFixture();
  try {
    const inputs = [
      "/connection_add_s3 archive",
      "https://r2.example.com",
      "auto",
      "bucket",
      "tenant/",
      "on",
      "access-key",
      "secret-key",
    ];
    const replies = [];
    for (const text of inputs) {
      replies.push(
        await fixture.controller.handle({
          telegramUserId: 1001,
          chatType: "private",
          text,
        }),
      );
    }
    assert.equal(replies[6]?.[0]?.deleteIncoming, true);
    assert.equal(replies[7]?.[0]?.deleteIncoming, true);
    const connections = fixture.admin.listConnections();
    assert.equal(connections[0]?.name, "archive");
    assert.equal(connections[0]?.kind, "s3");
    const stored = fixture.database
      .raw()
      .prepare("SELECT secret_ciphertext FROM connections")
      .get() as { secret_ciphertext: string };
    assert.equal(stored.secret_ciphertext.includes("secret-key"), false);
  } finally {
    fixture.database.close();
  }
});

test("Inline connection buttons start the same connection wizard as slash commands", async () => {
  const fixture = createFixture();
  try {
    const menu = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      callbackData: "menu:connections",
    });
    const callbackData = menu[0]?.keyboard?.flat().map((button) => button.data);
    assert.deepEqual(callbackData, [
      "connection:add:s3",
      "connection:add:mysql",
      "connection:add:postgres",
      "menu:home",
    ]);

    const started = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      callbackData: "connection:add:s3",
    });
    assert.match(started[0]?.text ?? "", /connection name/i);

    const inputs = [
      "archive",
      "https://r2.example.com",
      "auto",
      "bucket",
      "tenant/",
      "on",
      "access-key",
      "secret-key",
    ];
    for (const text of inputs) {
      await fixture.controller.handle({
        telegramUserId: 1001,
        chatType: "private",
        text,
      });
    }

    const connection = fixture.admin.listConnections()[0];
    assert.equal(connection?.name, "archive");
    assert.equal(connection?.kind, "s3");
  } finally {
    fixture.database.close();
  }
});

test("Traditional Chinese administration lists localize dynamic labels", async () => {
  const fixture = createFixture();
  try {
    await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      languageCode: "zh-hant",
      text: "/start",
    });
    const created = await fixture.admin.createAccount("operator", 2);
    fixture.admin.setAccountEnabled(created.account.id, false);
    fixture.repository.createLoginSession({
      session: {
        id: "session-1",
        familyId: "family-1",
        accountId: created.account.id,
        deviceId: "desktop-1",
        refreshHash: "refresh-hash",
        refreshExpiresAt: 1_700_000_100_000,
        revokedAt: null,
        createdAt: 1_700_000_000_000,
        lastUsedAt: 1_700_000_000_000,
        ipAddress: "127.0.0.1",
        userAgent: "test",
      },
      accessTokenHash: "access-hash",
      accessExpiresAt: 1_700_000_100_000,
      deviceLimit: 2,
      now: 1_700_000_000_000,
    });
    fixture.repository.revokeSession("session-1", 1_700_000_000_001);
    const connection = fixture.admin.createConnection({
      name: "storage",
      secret: {
        kind: "s3",
        endpoint: "https://r2.example.com",
        region: "auto",
        bucket: "bucket",
        prefix: "",
        usePathStyle: true,
        accessKeyId: "access",
        secretAccessKey: "secret",
      },
    });
    fixture.admin.setConnectionEnabled(connection.id, false);
    fixture.repository.appendAudit({
      id: "audit-1",
      occurredAt: 1_700_000_000_000,
      action: "s3.list",
      connectionId: connection.id,
      success: false,
      durationMs: 12,
    });

    const accounts = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: "/account_list",
    });
    assert.match(accounts[0]?.text ?? "", /已停用/);
    assert.match(accounts[0]?.text ?? "", /裝置上限=2/);
    assert.doesNotMatch(accounts[0]?.text ?? "", /disabled|devices=/i);

    const reset = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: `/account_reset ${created.account.id}`,
    });
    assert.match(reset[0]?.text ?? "", /所有既有工作階段已撤銷/);
    assert.doesNotMatch(reset[0]?.text ?? "", /session/i);

    const sessions = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: `/session_list ${created.account.id}`,
    });
    assert.match(sessions[0]?.text ?? "", /裝置=desktop-1/);
    assert.match(sessions[0]?.text ?? "", /已撤銷/);
    assert.doesNotMatch(sessions[0]?.text ?? "", /device=|revoked/i);

    const connections = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: "/connection_list",
    });
    assert.match(connections[0]?.text ?? "", /已停用/);
    assert.doesNotMatch(connections[0]?.text ?? "", /disabled/i);

    const audit = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: "/audit 1",
    });
    assert.match(audit[0]?.text ?? "", /失敗/);
    assert.match(audit[0]?.text ?? "", /連線=/);
    assert.doesNotMatch(audit[0]?.text ?? "", /failed|connection=/i);
  } finally {
    fixture.database.close();
  }
});

test("Grant and connection test commands use existing services", async () => {
  const fixture = createFixture();
  try {
    const account = await fixture.admin.createAccount("operator");
    const connection = fixture.admin.createConnection({
      name: "storage",
      secret: {
        kind: "s3",
        endpoint: "https://r2.example.com",
        region: "auto",
        bucket: "bucket",
        prefix: "tenant/",
        usePathStyle: true,
        accessKeyId: "access",
        secretAccessKey: "secret",
      },
    });
    const grant = await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: `/grant ${account.account.id} ${connection.id} s3.read,s3.write`,
    });
    assert.match(grant[0]?.text ?? "", /updated/i);
    assert.deepEqual(
      fixture.admin.listAssignedConnections(account.account.id)[0]?.operations,
      ["s3.read", "s3.write"],
    );

    await fixture.controller.handle({
      telegramUserId: 1001,
      chatType: "private",
      text: `/connection_test ${connection.id}`,
    });
    assert.deepEqual(fixture.tested, [connection.id]);
  } finally {
    fixture.database.close();
  }
});

test("Telegram adapter deletes sensitive input and renders inline keyboards", async () => {
  const deleted: number[] = [];
  const sent: Array<{ text: string; options: unknown }> = [];
  const answered: string[] = [];
  const controller = {
    async handle() {
      return [
        {
          text: "done",
          deleteIncoming: true,
          keyboard: [[{ text: "Accounts", data: "menu:accounts" }]],
        },
      ];
    },
  };

  await dispatchTelegramUpdate(
    {
      from: { id: 1001, language_code: "en" },
      chat: { type: "private" },
      message: { message_id: 42, text: "secret" },
      callbackQuery: { id: "callback-id", data: "menu:accounts" },
      async deleteMessage() {
        deleted.push(42);
      },
      async reply(text, options) {
        sent.push({ text, options });
      },
      async answerCallbackQuery() {
        answered.push("callback-id");
      },
    },
    controller,
  );

  assert.deepEqual(deleted, [42]);
  assert.equal(sent[0]?.text, "done");
  assert.match(JSON.stringify(sent[0]?.options), /menu:accounts/);
  assert.deepEqual(answered, ["callback-id"]);
});
