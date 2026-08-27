import type { ConnectionSecret, Operation } from "../domain/models.js";
import { AdminService } from "../services/admin-service.js";

type Language = "en" | "zh-TW";

export interface BotButton {
  text: string;
  data: string;
}

export interface BotReply {
  text: string;
  keyboard?: BotButton[][];
  deleteIncoming?: boolean;
}

export interface BotUpdate {
  telegramUserId: number;
  chatType: string;
  languageCode?: string;
  text?: string;
  callbackData?: string;
}

interface ConnectionTester {
  testConnection(connectionId: string, signal: AbortSignal): Promise<void>;
}

interface BotControllerOptions {
  admin: AdminService;
  administratorIds: number[];
  connectionTester: ConnectionTester;
}

type WizardKind = ConnectionSecret["kind"];

interface ConnectionWizard {
  kind: WizardKind;
  name: string | undefined;
  updateId?: string;
  step: number;
  values: string[];
}

const s3Steps = [
  "endpoint",
  "region",
  "bucket",
  "prefix",
  "pathStyle",
  "accessKeyId",
  "secretAccessKey",
] as const;
const sqlSteps = [
  "host",
  "port",
  "user",
  "password",
  "database",
  "mode",
] as const;

const messages = {
  en: {
    unauthorized: "You are not authorized to use this bot.",
    title: "s12ryt SSH administration",
    choose: "Choose an administration area or use /help.",
    accounts: "Accounts",
    connections: "Connections",
    audit: "Audit",
    language: "Language changed to English.",
    emptyAccounts: "No accounts.",
    emptyConnections: "No connections.",
    emptyAudit: "No audit events.",
    updated: "Updated.",
    deleted: "Deleted.",
    tested: "Connection test passed.",
    cancelled: "Wizard cancelled.",
    error: "Operation failed",
    addS3: "Add S3",
    addMySQL: "Add MySQL",
    addPostgres: "Add PostgreSQL",
    back: "Back",
    connectionName: "Send the connection name.",
    enabled: "enabled",
    disabled: "disabled",
    deviceLimit: "devices",
    device: "device",
    active: "active",
    revoked: "revoked",
    succeeded: "ok",
    failed: "failed",
    connectionLabel: "connection",
    noSessions: "No sessions.",
    noGrants: "No grants.",
  },
  "zh-TW": {
    unauthorized: "你沒有權限使用此 Bot。",
    title: "s12ryt SSH 管理",
    choose: "請選擇管理區域，或使用 /help。",
    accounts: "帳號",
    connections: "連線",
    audit: "稽核",
    language: "語言已切換為繁體中文。",
    emptyAccounts: "沒有帳號。",
    emptyConnections: "沒有連線。",
    emptyAudit: "沒有稽核事件。",
    updated: "已更新。",
    deleted: "已刪除。",
    tested: "連線測試通過。",
    cancelled: "已取消設定精靈。",
    error: "操作失敗",
    addS3: "新增 S3",
    addMySQL: "新增 MySQL",
    addPostgres: "新增 PostgreSQL",
    back: "返回",
    connectionName: "請輸入連線名稱。",
    enabled: "已啟用",
    disabled: "已停用",
    deviceLimit: "裝置上限",
    device: "裝置",
    active: "有效",
    revoked: "已撤銷",
    succeeded: "成功",
    failed: "失敗",
    connectionLabel: "連線",
    noSessions: "沒有工作階段。",
    noGrants: "沒有授權。",
  },
} as const;

export class BotController {
  private readonly administrators: Set<number>;
  private readonly wizards = new Map<number, ConnectionWizard>();

  constructor(private readonly options: BotControllerOptions) {
    this.administrators = new Set(options.administratorIds);
  }

  async handle(update: BotUpdate): Promise<BotReply[]> {
    if (update.chatType !== "private") return [];
    const language = this.languageFor(update);
    if (!this.administrators.has(update.telegramUserId)) {
      return [{ text: messages[language].unauthorized }];
    }

    try {
      if (update.callbackData) {
        return this.handleCallback(
          update.telegramUserId,
          update.callbackData,
          language,
        );
      }
      const source = update.text?.trim();
      if (!source) return [];
      if (!source.startsWith("/")) {
        const wizard = this.wizards.get(update.telegramUserId);
        return wizard
          ? [
              this.advanceWizard(
                update.telegramUserId,
                wizard,
                source,
                language,
              ),
            ]
          : [{ text: this.help(language) }];
      }
      return await this.handleCommand(update.telegramUserId, source, language);
    } catch (error) {
      return [{ text: `${messages[language].error}: ${errorMessage(error)}` }];
    }
  }

  private languageFor(update: BotUpdate): Language {
    const saved = this.options.admin.getAdminLanguage(update.telegramUserId);
    if (saved) return saved;
    const detected: Language = update.languageCode
      ?.toLowerCase()
      .startsWith("zh")
      ? "zh-TW"
      : "en";
    if (this.administrators.has(update.telegramUserId)) {
      this.options.admin.setAdminLanguage(update.telegramUserId, detected);
    }
    return detected;
  }

  private async handleCommand(
    userId: number,
    source: string,
    language: Language,
  ): Promise<BotReply[]> {
    const [commandWithBot, ...args] = splitArguments(source);
    const command = commandWithBot?.split("@")[0]?.toLowerCase();
    switch (command) {
      case "/start":
        return [this.menu(language)];
      case "/help":
        return [
          { text: this.help(language), keyboard: this.menuKeyboard(language) },
        ];
      case "/cancel":
        this.wizards.delete(userId);
        return [{ text: messages[language].cancelled }];
      case "/language":
        return [this.changeLanguage(userId, args[0])];
      case "/account_create":
        return [await this.createAccount(args, language)];
      case "/account_list":
        return [this.listAccounts(language)];
      case "/account_enable":
        this.options.admin.setAccountEnabled(
          requiredArg(args, 0, "account id"),
          true,
        );
        return [{ text: messages[language].updated }];
      case "/account_disable":
        this.options.admin.setAccountEnabled(
          requiredArg(args, 0, "account id"),
          false,
        );
        return [{ text: messages[language].updated }];
      case "/account_delete":
        this.options.admin.deleteAccount(requiredArg(args, 0, "account id"));
        return [{ text: messages[language].deleted }];
      case "/account_reset":
        return [await this.resetPassword(args, language)];
      case "/account_devices":
        this.options.admin.setAccountDeviceLimit(
          requiredArg(args, 0, "account id"),
          positiveInteger(requiredArg(args, 1, "device limit")),
        );
        return [{ text: messages[language].updated }];
      case "/session_list":
        return [this.listSessions(args, language)];
      case "/session_revoke":
        this.options.admin.revokeSession(requiredArg(args, 0, "session id"));
        return [{ text: messages[language].updated }];
      case "/session_revoke_all":
        this.options.admin.revokeAllSessions(
          requiredArg(args, 0, "account id"),
        );
        return [{ text: messages[language].updated }];
      case "/connection_add_s3":
        return [this.startWizard(userId, "s3", args, language)];
      case "/connection_add_mysql":
        return [this.startWizard(userId, "mysql", args, language)];
      case "/connection_add_postgres":
        return [this.startWizard(userId, "postgres", args, language)];
      case "/connection_edit":
        return [this.editConnection(userId, args, language)];
      case "/connection_list":
        return [this.listConnections(language)];
      case "/connection_enable":
        this.options.admin.setConnectionEnabled(
          requiredArg(args, 0, "connection id"),
          true,
        );
        return [{ text: messages[language].updated }];
      case "/connection_disable":
        this.options.admin.setConnectionEnabled(
          requiredArg(args, 0, "connection id"),
          false,
        );
        return [{ text: messages[language].updated }];
      case "/connection_delete":
        this.options.admin.deleteConnection(
          requiredArg(args, 0, "connection id"),
        );
        return [{ text: messages[language].deleted }];
      case "/connection_test": {
        const id = requiredArg(args, 0, "connection id");
        await this.options.connectionTester.testConnection(
          id,
          new AbortController().signal,
        );
        return [{ text: messages[language].tested }];
      }
      case "/grant":
        return [this.setGrant(args, language)];
      case "/grant_list":
        return [this.listGrants(args, language)];
      case "/audit":
        return [this.listAudit(args, language)];
      default:
        return [
          { text: this.help(language), keyboard: this.menuKeyboard(language) },
        ];
    }
  }

  private handleCallback(
    userId: number,
    data: string,
    language: Language,
  ): BotReply[] {
    if (data === "menu:accounts") return [this.listAccounts(language)];
    if (data === "menu:connections") return [this.listConnections(language)];
    if (data === "menu:audit") return [this.listAudit([], language)];
    if (data === "menu:home") return [this.menu(language)];
    if (
      data === "connection:add:s3" ||
      data === "connection:add:mysql" ||
      data === "connection:add:postgres"
    ) {
      return [
        this.startInlineConnectionWizard(
          userId,
          data.slice("connection:add:".length) as WizardKind,
          language,
        ),
      ];
    }
    if (data === "language:en" || data === "language:zh-TW") {
      return [this.changeLanguage(userId, data.slice("language:".length))];
    }
    return [this.menu(language)];
  }

  private menu(language: Language): BotReply {
    return {
      text: `${messages[language].title}\n${messages[language].choose}`,
      keyboard: this.menuKeyboard(language),
    };
  }

  private menuKeyboard(language: Language): BotButton[][] {
    return [
      [
        { text: messages[language].accounts, data: "menu:accounts" },
        { text: messages[language].connections, data: "menu:connections" },
      ],
      [
        { text: messages[language].audit, data: "menu:audit" },
        {
          text: language === "en" ? "繁中" : "EN",
          data: `language:${language === "en" ? "zh-TW" : "en"}`,
        },
      ],
    ];
  }

  private changeLanguage(userId: number, value: string | undefined): BotReply {
    const language: Language = value?.toLowerCase() === "en" ? "en" : "zh-TW";
    this.options.admin.setAdminLanguage(userId, language);
    return {
      text: messages[language].language,
      keyboard: this.menuKeyboard(language),
    };
  }

  private async createAccount(
    args: string[],
    language: Language,
  ): Promise<BotReply> {
    const username = requiredArg(args, 0, "username");
    const limit = args[1] ? positiveInteger(args[1]) : undefined;
    const created = await this.options.admin.createAccount(username, limit);
    return {
      text:
        language === "zh-TW"
          ? `帳號：${created.account.username}\nID：${created.account.id}\n一次性密碼：${created.password}\n請立即安全保存，Bot 不會再次顯示。`
          : `Account: ${created.account.username}\nID: ${created.account.id}\nOne-time password: ${created.password}\nStore it securely now; the bot will not show it again.`,
    };
  }

  private async resetPassword(
    args: string[],
    language: Language,
  ): Promise<BotReply> {
    const password = await this.options.admin.resetPassword(
      requiredArg(args, 0, "account id"),
    );
    return {
      text:
        language === "zh-TW"
          ? `新的一次性密碼：${password}\n所有既有工作階段已撤銷。`
          : `New one-time password: ${password}\nAll existing sessions were revoked.`,
    };
  }

  private listAccounts(language: Language): BotReply {
    const accounts = this.options.admin.listAccounts();
    if (accounts.length === 0)
      return { text: messages[language].emptyAccounts };
    return {
      text: accounts
        .map(
          (account) =>
            `${account.username} | ${account.id} | ${account.enabled ? messages[language].enabled : messages[language].disabled} | ${messages[language].deviceLimit}=${account.deviceLimit}`,
        )
        .join("\n"),
    };
  }

  private listSessions(args: string[], language: Language): BotReply {
    const sessions = this.options.admin.listSessions(
      requiredArg(args, 0, "account id"),
    );
    if (sessions.length === 0) {
      return { text: messages[language].noSessions };
    }
    return {
      text: sessions
        .map(
          (session) =>
            `${session.id} | ${messages[language].device}=${session.deviceId} | ${session.revoked ? messages[language].revoked : messages[language].active} | ${session.ipAddress}`,
        )
        .join("\n"),
    };
  }

  private listConnections(language: Language): BotReply {
    const connections = this.options.admin.listConnections();
    if (connections.length === 0) {
      return {
        text: messages[language].emptyConnections,
        keyboard: this.connectionKeyboard(language),
      };
    }
    return {
      text: connections
        .map(
          (connection) =>
            `${connection.name} | ${connection.id} | ${connection.kind} | ${connection.enabled ? messages[language].enabled : messages[language].disabled}`,
        )
        .join("\n"),
      keyboard: this.connectionKeyboard(language),
    };
  }

  private connectionKeyboard(language: Language): BotButton[][] {
    return [
      [
        { text: messages[language].addS3, data: "connection:add:s3" },
        { text: messages[language].addMySQL, data: "connection:add:mysql" },
      ],
      [
        {
          text: messages[language].addPostgres,
          data: "connection:add:postgres",
        },
      ],
      [{ text: messages[language].back, data: "menu:home" }],
    ];
  }

  private setGrant(args: string[], language: Language): BotReply {
    const operations = requiredArg(args, 2, "operations")
      .split(",")
      .map((operation) => operation.trim()) as Operation[];
    this.options.admin.setGrants(
      requiredArg(args, 0, "account id"),
      requiredArg(args, 1, "connection id"),
      operations,
    );
    return { text: messages[language].updated };
  }

  private listGrants(args: string[], language: Language): BotReply {
    const assigned = this.options.admin.listAssignedConnections(
      requiredArg(args, 0, "account id"),
    );
    if (assigned.length === 0) {
      return { text: messages[language].noGrants };
    }
    return {
      text: assigned
        .map(
          (connection) =>
            `${connection.name} | ${connection.id} | ${connection.operations.join(",")}`,
        )
        .join("\n"),
    };
  }

  private listAudit(args: string[], language: Language): BotReply {
    const limit = args[0] ? positiveInteger(args[0]) : 50;
    const events = this.options.admin.listAudit(limit);
    if (events.length === 0) return { text: messages[language].emptyAudit };
    return {
      text: events
        .map(
          (event) =>
            `${String(event.occurred_at)} | ${String(event.action)} | ${Number(event.success) === 1 ? messages[language].succeeded : messages[language].failed} | ${messages[language].connectionLabel}=${String(event.connection_id ?? "-")}`,
        )
        .join("\n"),
    };
  }

  private startWizard(
    userId: number,
    kind: WizardKind,
    args: string[],
    language: Language,
  ): BotReply {
    const name = requiredArg(args, 0, "connection name");
    const wizard: ConnectionWizard = { kind, name, step: 0, values: [] };
    this.wizards.set(userId, wizard);
    return { text: this.wizardPrompt(wizard, language) };
  }

  private startInlineConnectionWizard(
    userId: number,
    kind: WizardKind,
    language: Language,
  ): BotReply {
    const wizard: ConnectionWizard = {
      kind,
      name: undefined,
      step: 0,
      values: [],
    };
    this.wizards.set(userId, wizard);
    return { text: this.wizardPrompt(wizard, language) };
  }

  private editConnection(
    userId: number,
    args: string[],
    language: Language,
  ): BotReply {
    const updateId = requiredArg(args, 0, "connection id");
    const name = requiredArg(args, 1, "connection name");
    const kind = this.options.admin.getConnectionSecret(updateId).kind;
    const wizard: ConnectionWizard = {
      kind,
      name,
      updateId,
      step: 0,
      values: [],
    };
    this.wizards.set(userId, wizard);
    return { text: this.wizardPrompt(wizard, language) };
  }

  private advanceWizard(
    userId: number,
    wizard: ConnectionWizard,
    value: string,
    language: Language,
  ): BotReply {
    if (!wizard.name) {
      wizard.name = requiredValue(value, "connection name");
      return { text: this.wizardPrompt(wizard, language) };
    }
    const steps = wizard.kind === "s3" ? s3Steps : sqlSteps;
    const field = steps[wizard.step];
    if (!field) throw new Error("wizard is complete");
    wizard.values.push(value.trim());
    wizard.step += 1;
    const sensitive =
      field === "accessKeyId" ||
      field === "secretAccessKey" ||
      field === "password";
    if (wizard.step < steps.length) {
      return {
        text: this.wizardPrompt(wizard, language),
        ...(sensitive ? { deleteIncoming: true } : {}),
      };
    }
    const secret = buildSecret(wizard);
    if (wizard.updateId) {
      this.options.admin.updateConnection(wizard.updateId, {
        name: requiredValue(wizard.name, "connection name"),
        secret,
      });
    } else {
      this.options.admin.createConnection({
        name: requiredValue(wizard.name, "connection name"),
        secret,
      });
    }
    this.wizards.delete(userId);
    return {
      text: messages[language].updated,
      ...(sensitive ? { deleteIncoming: true } : {}),
    };
  }

  private wizardPrompt(wizard: ConnectionWizard, language: Language): string {
    if (!wizard.name) return messages[language].connectionName;
    const steps = wizard.kind === "s3" ? s3Steps : sqlSteps;
    const field = steps[wizard.step] ?? "complete";
    const descriptions: Record<string, [string, string]> = {
      endpoint: [
        "Send the S3 API endpoint URL.",
        "請輸入 S3 API endpoint URL。",
      ],
      region: ["Send the region (R2: auto).", "請輸入 region（R2：auto）。"],
      bucket: ["Send the bucket name.", "請輸入 bucket 名稱。"],
      prefix: [
        "Send the base prefix, or - for none.",
        "請輸入 base prefix；沒有則輸入 -。",
      ],
      pathStyle: [
        "Send on or off for path-style.",
        "Path-style 請輸入 on 或 off。",
      ],
      accessKeyId: [
        "Send the access key. The message will be deleted.",
        "請輸入 access key；訊息會被刪除。",
      ],
      secretAccessKey: [
        "Send the secret key. The message will be deleted.",
        "請輸入 secret key；訊息會被刪除。",
      ],
      host: ["Send the database host.", "請輸入資料庫 host。"],
      port: ["Send the database port.", "請輸入資料庫 port。"],
      user: ["Send the database user.", "請輸入資料庫 user。"],
      password: [
        "Send the database password. The message will be deleted.",
        "請輸入資料庫密碼；訊息會被刪除。",
      ],
      database: ["Send the database name.", "請輸入 database 名稱。"],
      mode: [
        wizard.kind === "mysql"
          ? "Send MySQL TLS mode."
          : "Send PostgreSQL SSL mode.",
        wizard.kind === "mysql"
          ? "請輸入 MySQL TLS mode。"
          : "請輸入 PostgreSQL SSL mode。",
      ],
    };
    const pair = descriptions[field];
    return pair?.[language === "en" ? 0 : 1] ?? field;
  }

  private help(language: Language): string {
    const commands = [
      "/account_create <username> [device-limit]",
      "/account_list | /account_enable | /account_disable | /account_delete | /account_reset",
      "/account_devices <account-id> <limit>",
      "/session_list <account-id> | /session_revoke <session-id> | /session_revoke_all <account-id>",
      "/connection_add_s3|mysql|postgres <name> | /connection_edit <id> <name>",
      "/connection_list | /connection_test | /connection_enable | /connection_disable | /connection_delete",
      "/grant <account-id> <connection-id> <operations> | /grant_list <account-id>",
      "/audit [limit] | /language en|zh-TW | /cancel",
    ];
    return `${language === "zh-TW" ? "管理命令" : "Administration commands"}\n${commands.join("\n")}`;
  }
}

function buildSecret(wizard: ConnectionWizard): ConnectionSecret {
  if (wizard.kind === "s3") {
    const [
      endpoint,
      region,
      bucket,
      prefix,
      pathStyle,
      accessKeyId,
      secretAccessKey,
    ] = wizard.values;
    return {
      kind: "s3",
      endpoint: requiredValue(endpoint, "endpoint"),
      region: requiredValue(region, "region"),
      bucket: requiredValue(bucket, "bucket"),
      prefix: prefix === "-" ? "" : (prefix ?? ""),
      usePathStyle: pathStyle?.toLowerCase() === "on",
      accessKeyId: requiredValue(accessKeyId, "access key"),
      secretAccessKey: requiredValue(secretAccessKey, "secret key"),
    };
  }
  const [host, port, user, password, database, mode] = wizard.values;
  const common = {
    host: requiredValue(host, "host"),
    port: positiveInteger(requiredValue(port, "port")),
    user: requiredValue(user, "user"),
    password: requiredValue(password, "password"),
    database: requiredValue(database, "database"),
  };
  return wizard.kind === "mysql"
    ? { kind: "mysql", ...common, tlsMode: requiredValue(mode, "TLS mode") }
    : { kind: "postgres", ...common, sslMode: requiredValue(mode, "SSL mode") };
}

function splitArguments(source: string): string[] {
  return (
    source
      .match(/"[^"]*"|'[^']*'|\S+/g)
      ?.map((part) => part.replace(/^['"]|['"]$/g, "")) ?? []
  );
}

function requiredArg(args: string[], index: number, name: string): string {
  return requiredValue(args[index], name);
}

function requiredValue(value: string | undefined, name: string): string {
  if (!value?.trim()) throw new Error(`${name} is required`);
  return value.trim();
}

function positiveInteger(value: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0)
    throw new Error("value must be a positive integer");
  return parsed;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
