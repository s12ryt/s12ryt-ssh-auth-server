import { randomUUID } from "node:crypto";

import type {
  AuditEvent,
  Principal,
  SSHCommandSnippetRecord,
  SSHAuthMethod,
  SSHConnectionSettings,
  SSHHostFingerprintRecord,
  SSHHostFingerprintSource,
  SSHHostRecord,
  SSHHostSecret,
  SSHKeyIdentityRecord,
  SSHSessionHistoryRecord,
  SSHSessionHistoryStatus,
  SSHTerminalAppearance,
  SSHTunnelRecord,
  SSHTunnelType,
  SSHWorkspacePreferencesRecord,
} from "../domain/models.js";
import { NotFoundError, ServiceError } from "../errors.js";
import { SqliteRepository } from "../repository/sqlite-repository.js";
import { decryptSecret, encryptSecret } from "../security/crypto.js";
import {
  createSSHWorkspaceExport,
  inspectSSHWorkspaceExport,
  planSSHWorkspaceImport,
  previewSSHWorkspaceImport,
  readSSHWorkspaceExport,
  type SSHWorkspaceExportHost,
  type SSHWorkspaceExportKey,
  type SSHWorkspaceExportPayload,
  type SSHWorkspaceExportSnippet,
  type SSHWorkspaceExportTunnel,
  type SSHWorkspaceImportConflict,
  type SSHWorkspaceImportPlanItem,
  type SSHWorkspaceImportResolution,
} from "../security/ssh-export-package.js";

interface SSHHostServiceOptions {
  maxHosts: number;
  clock?: () => number;
}

export interface SSHHostContext {
  principal: Principal;
  ipAddress?: string;
}

export interface SSHHostInput {
  name: string;
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  keyPassphrase?: string;
  trustedFingerprint?: string;
  enabled?: boolean;
  favorite?: boolean;
  groupPath?: string;
  tags?: string[];
  sortOrder?: number;
  authMethod?: SSHAuthMethod;
  settings?: Partial<SSHConnectionSettings>;
  clearTerminalAppearance?: boolean;
}

export interface SSHHostView {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  hasPassword: boolean;
  hasPrivateKey: boolean;
  hasKeyPassphrase: boolean;
  trustedFingerprint: string;
  enabled: boolean;
  favorite: boolean;
  groupPath: string;
  tags: string[];
  sortOrder: number;
  authMethod: SSHAuthMethod;
  settings: SSHConnectionSettings;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface SSHHostCredentials {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  password: string;
  privateKey: string;
  keyPassphrase: string;
  trustedFingerprint: string;
  authMethod: SSHAuthMethod;
  settings: SSHConnectionSettings;
  version: number;
}

export interface SSHWorkspacePreferencesInput {
  terminalAppearance: SSHTerminalAppearance;
}

export interface SSHHostFingerprintView {
  id: string;
  hostId: string;
  algorithm: string;
  fingerprint: string;
  source: SSHHostFingerprintSource;
  active: boolean;
  observedAt: number;
  retiredAt: number | null;
}

export interface SSHTunnelInput {
  name: string;
  hostId: string;
  type: SSHTunnelType;
  listenHost: string;
  listenPort: number;
  targetHost?: string;
  targetPort?: number;
  enabled?: boolean;
  autoStart?: boolean;
}

export interface SSHTunnelRuntimeUpdate {
  running: boolean;
  trafficUpBytes: number;
  trafficDownBytes: number;
}

export interface SSHSnippetInput {
  name: string;
  command: string;
  variables?: string[];
  secrets?: Record<string, string>;
  enabled?: boolean;
}

export interface SSHSnippetView {
  id: string;
  name: string;
  command: string;
  variables: string[];
  secretNames: string[];
  enabled: boolean;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface SSHKeyIdentityInput {
  name: string;
  publicKey?: string;
  fingerprint?: string;
  privateKey?: string;
  keyPassphrase?: string;
  clearSecretMaterial?: boolean;
  enabled?: boolean;
}

export interface SSHKeyIdentityView {
  id: string;
  name: string;
  publicKey: string;
  fingerprint: string;
  hasPassphrase: boolean;
  enabled: boolean;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface SSHSessionHistoryInput {
  hostId: string;
  status: SSHSessionHistoryStatus;
  latencyMs?: number;
  errorMessage?: string;
}

export interface SSHSessionHistoryUpdate {
  status: SSHSessionHistoryStatus;
  latencyMs?: number;
  errorMessage?: string;
}

export interface SSHWorkspaceExportRequest {
  includeSecrets: boolean;
  password?: string;
}

export interface SSHWorkspaceImportPreview {
  includesSecrets: boolean;
  counts: {
    hosts: number;
    tunnels: number;
    snippets: number;
    keys: number;
  };
  conflicts: SSHWorkspaceImportConflict[];
}

export interface SSHWorkspaceImportResult {
  includesSecrets: boolean;
  counts: {
    created: number;
    overwritten: number;
    copied: number;
    skipped: number;
  };
  items: SSHWorkspaceImportPlanItem[];
}

interface ValidatedFields {
  name: string;
  host: string;
  port: number;
  username: string;
}

function invalid(detail: string): ServiceError {
  return new ServiceError("invalid_ssh_host", detail, 400);
}

const defaultSSHConnectionSettings: SSHConnectionSettings = {
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
};

const defaultSSHTerminalAppearance: SSHTerminalAppearance = {
  font: "builtin-mono",
  fontSize: 13,
  foreground: "#d7e6e2",
  background: "#101c1b",
};

export class SSHHostService {
  readonly #clock: () => number;

  constructor(
    private readonly repository: SqliteRepository,
    private readonly masterKey: Buffer,
    private readonly options: SSHHostServiceOptions,
  ) {
    this.#clock = options.clock ?? Date.now;
  }

  accessEnabled(accountId: string): boolean {
    return this.repository.findAccountById(accountId)?.sshEnabled === true;
  }

  listHosts(accountId: string): SSHHostView[] {
    this.requireAccess(accountId);
    return this.repository
      .listSSHHosts(accountId)
      .map((record) => this.toView(record));
  }

  getWorkspacePreferences(accountId: string): SSHWorkspacePreferencesRecord {
    this.requireAccess(accountId);
    const stored = this.repository.findSSHWorkspacePreferences(accountId);
    if (stored) return stored;
    return {
      accountId,
      terminalAppearance: { ...defaultSSHTerminalAppearance },
      version: 1,
      updatedAt: 0,
    };
  }

  updateWorkspacePreferences(
    context: SSHHostContext,
    input: SSHWorkspacePreferencesInput,
  ): SSHWorkspacePreferencesRecord {
    const accountId = context.principal.accountId;
    this.requireAccess(accountId);
    const current = this.repository.findSSHWorkspacePreferences(accountId);
    return this.repository.saveSSHWorkspacePreferences({
      accountId,
      terminalAppearance: this.validateTerminalAppearance(
        input.terminalAppearance,
        false,
      ) as SSHTerminalAppearance,
      version: (current?.version ?? 1) + 1,
      updatedAt: this.#clock(),
    });
  }

  async exportWorkspace(
    context: SSHHostContext,
    request: SSHWorkspaceExportRequest,
  ): Promise<string> {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const payload = this.workspaceExportPayload(
        accountId,
        request.includeSecrets,
      );
      let encoded: string;
      try {
        encoded = await createSSHWorkspaceExport(payload, {
          includeSecrets: request.includeSecrets,
          createdAt: this.#clock(),
          ...(request.password === undefined
            ? {}
            : { password: request.password }),
        });
      } catch (error) {
        throw this.workspacePackageError(error);
      }
      this.appendAudit(
        context,
        "ssh.workspace.export",
        started,
        true,
        undefined,
      );
      return encoded;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.workspace.export",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  async previewWorkspaceImport(
    context: SSHHostContext,
    encoded: string,
    password?: string,
  ): Promise<SSHWorkspaceImportPreview> {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      let info: ReturnType<typeof inspectSSHWorkspaceExport>;
      let payload: SSHWorkspaceExportPayload;
      try {
        info = inspectSSHWorkspaceExport(encoded);
        payload = await readSSHWorkspaceExport(encoded, password);
      } catch (error) {
        throw this.workspacePackageError(error);
      }
      const conflicts = previewSSHWorkspaceImport(payload, {
        hosts: this.repository.listSSHHosts(accountId).map((item) => item.name),
        tunnels: this.repository
          .listSSHTunnels(accountId)
          .map((item) => item.name),
        snippets: this.repository
          .listSSHSnippets(accountId)
          .map((item) => item.name),
        keys: this.repository
          .listSSHKeyIdentities(accountId)
          .map((item) => item.name),
      });
      const preview: SSHWorkspaceImportPreview = {
        includesSecrets: info.includesSecrets,
        counts: {
          hosts: payload.hosts.length,
          tunnels: payload.tunnels.length,
          snippets: payload.snippets.length,
          keys: payload.keys.length,
        },
        conflicts,
      };
      this.appendAudit(
        context,
        "ssh.workspace.import_preview",
        started,
        true,
        undefined,
      );
      return preview;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.workspace.import_preview",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  async applyWorkspaceImport(
    context: SSHHostContext,
    encoded: string,
    password: string | undefined,
    resolutions: SSHWorkspaceImportResolution[],
  ): Promise<SSHWorkspaceImportResult> {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      let includesSecrets: boolean;
      let payload: SSHWorkspaceExportPayload;
      let plan: SSHWorkspaceImportPlanItem[];
      try {
        includesSecrets = inspectSSHWorkspaceExport(encoded).includesSecrets;
        payload = await readSSHWorkspaceExport(encoded, password);
        plan = planSSHWorkspaceImport(
          payload,
          this.workspaceExistingNames(accountId),
          resolutions,
        );
      } catch (error) {
        throw this.workspacePackageError(error);
      }
      const counts = this.repository.transaction(() =>
        this.applyWorkspaceImportPlan(accountId, payload, plan),
      );
      const result: SSHWorkspaceImportResult = {
        includesSecrets,
        counts,
        items: plan.map((item) => ({ ...item })),
      };
      this.appendAudit(
        context,
        "ssh.workspace.import_apply",
        started,
        true,
        undefined,
      );
      return result;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.workspace.import_apply",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  createHost(context: SSHHostContext, input: SSHHostInput): SSHHostView {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const fields = this.validateFields(input);
      const password = input.password ?? "";
      const privateKey = input.privateKey ?? "";
      if (!password && !privateKey) {
        throw invalid("password or private key is required");
      }
      const keyPassphrase = input.keyPassphrase ?? "";
      const metadata = this.normalizeMetadata(input, password, privateKey);
      if (this.repository.countSSHHosts(accountId) >= this.options.maxHosts) {
        throw new ServiceError(
          "ssh_host_limit",
          "ssh host limit reached for this account",
          403,
        );
      }
      const now = this.#clock();
      const record: SSHHostRecord = {
        id: randomUUID(),
        accountId,
        ...fields,
        secretCiphertext: encryptSecret(
          this.masterKey,
          JSON.stringify({
            password,
            privateKey,
            keyPassphrase,
          } satisfies SSHHostSecret),
        ),
        trustedFingerprint: this.normalizeFingerprint(input.trustedFingerprint),
        ...metadata,
        version: 1,
        createdAt: now,
        updatedAt: now,
      };
      const created = this.repository.createSSHHostWithFingerprint(
        record,
        record.trustedFingerprint
          ? this.newFingerprintRecord(
              record,
              record.trustedFingerprint,
              "manual",
              now,
            )
          : undefined,
      );
      this.appendAudit(context, "ssh.host.create", started, true, created.id);
      return this.toView(created);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.create",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  updateHost(
    context: SSHHostContext,
    id: string,
    input: SSHHostInput,
  ): SSHHostView {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.loadHost(accountId, id);
      hostId = current.id;
      const fields = this.validateFields(input);
      const previous = this.decryptSecretOf(current);
      const secret: SSHHostSecret = {
        password: input.password ? input.password : previous.password,
        privateKey: input.privateKey ? input.privateKey : previous.privateKey,
        keyPassphrase: input.keyPassphrase
          ? input.keyPassphrase
          : previous.keyPassphrase,
      };
      if (!secret.password && !secret.privateKey) {
        throw invalid("password or private key is required");
      }
      const metadata = this.normalizeMetadata(
        input,
        secret.password,
        secret.privateKey,
        current,
      );
      const hostChanged =
        fields.host !== current.host || fields.port !== current.port;
      const trustedFingerprint = hostChanged
        ? this.normalizeFingerprint(input.trustedFingerprint)
        : current.trustedFingerprint;
      const next: SSHHostRecord = {
        ...current,
        ...fields,
        secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secret)),
        trustedFingerprint,
        ...metadata,
        version: current.version + 1,
        updatedAt: this.#clock(),
      };
      const saved =
        trustedFingerprint === current.trustedFingerprint
          ? this.repository.updateSSHHost(next)
          : this.repository.replaceSSHHostFingerprint(
              next,
              trustedFingerprint
                ? this.newFingerprintRecord(
                    next,
                    trustedFingerprint,
                    "manual",
                    next.updatedAt,
                  )
                : undefined,
            );
      this.appendAudit(context, "ssh.host.update", started, true, saved.id);
      return this.toView(saved);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.update",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  cloneHost(context: SSHHostContext, id: string, name: string): SSHHostView {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const source = this.loadHost(accountId, id);
      hostId = source.id;
      const cloneName = this.validateCloneName(name);
      const secret = this.decryptSecretOf(source);
      const now = this.#clock();
      const clone: SSHHostRecord = {
        ...source,
        id: randomUUID(),
        name: cloneName,
        secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secret)),
        version: 1,
        createdAt: now,
        updatedAt: now,
      };
      const created = this.repository.createSSHHostWithFingerprint(
        clone,
        clone.trustedFingerprint
          ? this.newFingerprintRecord(
              clone,
              clone.trustedFingerprint,
              "manual",
              now,
            )
          : undefined,
      );
      this.appendAudit(context, "ssh.host.clone", started, true, created.id);
      return this.toView(created);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.clone",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  deleteHost(context: SSHHostContext, id: string): void {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      this.repository.deleteSSHHost(id);
      // The host row is gone, so the audit cannot reference it (foreign key).
      this.appendAudit(context, "ssh.host.delete", started, true, undefined);
    } catch (error) {
      // On failure the host row still exists, so referencing it is safe.
      this.appendAudit(
        context,
        "ssh.host.delete",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  getCredentials(context: SSHHostContext, id: string): SSHHostCredentials {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      const secret = this.decryptSecretOf(record);
      this.appendAudit(context, "ssh.host.credentials", started, true, hostId);
      return {
        id: record.id,
        name: record.name,
        host: record.host,
        port: record.port,
        username: record.username,
        password: secret.password,
        privateKey: secret.privateKey,
        keyPassphrase: secret.keyPassphrase,
        trustedFingerprint: record.trustedFingerprint,
        authMethod: record.authMethod,
        settings: record.settings,
        version: record.version,
      };
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.credentials",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  setFingerprint(
    context: SSHHostContext,
    id: string,
    fingerprint: string,
    source: SSHHostFingerprintSource = "tofu",
  ): void {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      const parsed = this.parseFingerprint(fingerprint);
      if (source !== "tofu" && source !== "manual") {
        throw invalid("fingerprint source is invalid");
      }
      if (record.trustedFingerprint === parsed.fingerprint) {
        this.appendAudit(
          context,
          "ssh.host.fingerprint",
          started,
          true,
          hostId,
        );
        return;
      }
      const now = this.#clock();
      const updated = {
        ...record,
        trustedFingerprint: parsed.fingerprint,
        version: record.version + 1,
        updatedAt: now,
      };
      this.repository.replaceSSHHostFingerprint(
        updated,
        this.newFingerprintRecord(updated, parsed.fingerprint, source, now),
      );
      this.appendAudit(context, "ssh.host.fingerprint", started, true, hostId);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.fingerprint",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  listHostFingerprints(
    context: SSHHostContext,
    id: string,
  ): SSHHostFingerprintView[] {
    const accountId = context.principal.accountId;
    this.requireAccess(accountId);
    this.loadHost(accountId, id);
    return this.repository
      .listSSHHostFingerprints(accountId, id)
      .map((record) => this.fingerprintView(record));
  }

  clearFingerprint(context: SSHHostContext, id: string): void {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.loadHost(accountId, id);
      hostId = record.id;
      if (record.trustedFingerprint) {
        this.repository.replaceSSHHostFingerprint({
          ...record,
          trustedFingerprint: "",
          version: record.version + 1,
          updatedAt: this.#clock(),
        });
      }
      this.appendAudit(
        context,
        "ssh.host.fingerprint.clear",
        started,
        true,
        hostId,
      );
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.host.fingerprint.clear",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  listTunnels(accountId: string): SSHTunnelRecord[] {
    this.requireAccess(accountId);
    return this.repository
      .listSSHTunnels(accountId)
      .map((tunnel) => ({ ...tunnel }));
  }

  createTunnel(
    context: SSHHostContext,
    input: SSHTunnelInput,
  ): SSHTunnelRecord {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const fields = this.validateTunnel(input);
      this.loadHost(accountId, fields.hostId);
      const now = this.#clock();
      const record: SSHTunnelRecord = {
        id: randomUUID(),
        accountId,
        ...fields,
        enabled: input.enabled ?? true,
        autoStart: input.autoStart ?? false,
        running: false,
        trafficUpBytes: 0,
        trafficDownBytes: 0,
        version: 1,
        createdAt: now,
        updatedAt: now,
      };
      const created = this.repository.createSSHTunnel(record);
      this.appendAudit(context, "ssh.tunnel.create", started, true, undefined);
      return created;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.tunnel.create",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  updateTunnel(
    context: SSHHostContext,
    id: string,
    input: SSHTunnelInput,
  ): SSHTunnelRecord {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHTunnel(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh tunnel");
      }
      const fields = this.validateTunnel(input);
      this.loadHost(accountId, fields.hostId);
      const saved = this.repository.updateSSHTunnel({
        ...current,
        ...fields,
        enabled: input.enabled ?? current.enabled,
        autoStart: input.autoStart ?? current.autoStart,
        version: current.version + 1,
        updatedAt: this.#clock(),
      });
      this.appendAudit(context, "ssh.tunnel.update", started, true, undefined);
      return saved;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.tunnel.update",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  updateTunnelRuntime(
    context: SSHHostContext,
    id: string,
    input: SSHTunnelRuntimeUpdate,
  ): SSHTunnelRecord {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHTunnel(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh tunnel");
      }
      const trafficUpBytes = this.validateTunnelTraffic(
        "trafficUpBytes",
        input.trafficUpBytes,
      );
      const trafficDownBytes = this.validateTunnelTraffic(
        "trafficDownBytes",
        input.trafficDownBytes,
      );
      const saved = this.repository.updateSSHTunnel({
        ...current,
        running: input.running,
        trafficUpBytes,
        trafficDownBytes,
        updatedAt: this.#clock(),
      });
      this.appendAudit(
        context,
        "ssh.tunnel.runtime.update",
        started,
        true,
        undefined,
      );
      return saved;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.tunnel.runtime.update",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  deleteTunnel(context: SSHHostContext, id: string): void {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHTunnel(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh tunnel");
      }
      this.repository.deleteSSHTunnel(id);
      this.appendAudit(context, "ssh.tunnel.delete", started, true, undefined);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.tunnel.delete",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  listSnippets(accountId: string): SSHSnippetView[] {
    this.requireAccess(accountId);
    return this.repository
      .listSSHSnippets(accountId)
      .map((record) => this.snippetView(record));
  }

  createSnippet(
    context: SSHHostContext,
    input: SSHSnippetInput,
  ): SSHSnippetView {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const fields = this.validateSnippet(input);
      const record: SSHCommandSnippetRecord = {
        id: randomUUID(),
        accountId,
        ...fields,
        secretCiphertext: encryptSecret(
          this.masterKey,
          JSON.stringify(input.secrets ?? {}),
        ),
        version: 1,
        createdAt: this.#clock(),
        updatedAt: this.#clock(),
      };
      const created = this.repository.createSSHSnippet(record);
      this.appendAudit(context, "ssh.snippet.create", started, true, undefined);
      return this.snippetView(created);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.snippet.create",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  updateSnippet(
    context: SSHHostContext,
    id: string,
    input: SSHSnippetInput,
  ): SSHSnippetView {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHSnippet(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh snippet");
      }
      const fields = this.validateSnippet(input);
      const secrets =
        input.secrets === undefined
          ? this.decryptSnippetSecrets(current)
          : this.validateSnippetSecrets(input.secrets);
      const saved = this.repository.updateSSHSnippet({
        ...current,
        ...fields,
        secretCiphertext: encryptSecret(
          this.masterKey,
          JSON.stringify(secrets),
        ),
        version: current.version + 1,
        updatedAt: this.#clock(),
      });
      this.appendAudit(context, "ssh.snippet.update", started, true, undefined);
      return this.snippetView(saved);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.snippet.update",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  deleteSnippet(context: SSHHostContext, id: string): void {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHSnippet(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh snippet");
      }
      this.repository.deleteSSHSnippet(id);
      this.appendAudit(context, "ssh.snippet.delete", started, true, undefined);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.snippet.delete",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  getSnippetSecrets(
    context: SSHHostContext,
    id: string,
  ): Record<string, string> {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const record = this.repository.findSSHSnippet(id);
      if (!record || record.accountId !== accountId) {
        throw new NotFoundError("ssh snippet");
      }
      const secrets = this.decryptSnippetSecrets(record);
      this.appendAudit(
        context,
        "ssh.snippet.secrets",
        started,
        true,
        undefined,
      );
      return secrets;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.snippet.secrets",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  listKeyIdentities(accountId: string): SSHKeyIdentityView[] {
    this.requireAccess(accountId);
    return this.repository
      .listSSHKeyIdentities(accountId)
      .map((record) => this.keyIdentityView(record));
  }

  createKeyIdentity(
    context: SSHHostContext,
    input: SSHKeyIdentityInput,
  ): SSHKeyIdentityView {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const fields = this.validateKeyIdentity(input, true);
      const record: SSHKeyIdentityRecord = {
        id: randomUUID(),
        accountId,
        ...fields,
        secretCiphertext: encryptSecret(
          this.masterKey,
          JSON.stringify({
            privateKey: input.privateKey,
            keyPassphrase: input.keyPassphrase ?? "",
          }),
        ),
        version: 1,
        createdAt: this.#clock(),
        updatedAt: this.#clock(),
      };
      const created = this.repository.createSSHKeyIdentity(record);
      this.appendAudit(context, "ssh.key.create", started, true, undefined);
      return this.keyIdentityView(created);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.key.create",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  updateKeyIdentity(
    context: SSHHostContext,
    id: string,
    input: SSHKeyIdentityInput,
  ): SSHKeyIdentityView {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHKeyIdentity(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh key identity");
      }
      const fields = this.validateKeyIdentity(input, false);
      const previous = this.decryptKeyIdentitySecrets(current);
      const secret = {
        privateKey: input.clearSecretMaterial
          ? ""
          : input.privateKey === undefined
            ? previous.privateKey
            : input.privateKey,
        keyPassphrase: input.clearSecretMaterial
          ? ""
          : input.keyPassphrase === undefined
            ? previous.keyPassphrase
            : input.keyPassphrase,
      };
      const saved = this.repository.updateSSHKeyIdentity({
        ...current,
        ...fields,
        secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secret)),
        version: current.version + 1,
        updatedAt: this.#clock(),
      });
      this.appendAudit(context, "ssh.key.update", started, true, undefined);
      return this.keyIdentityView(saved);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.key.update",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  deleteKeyIdentity(context: SSHHostContext, id: string): void {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHKeyIdentity(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh key identity");
      }
      this.repository.deleteSSHKeyIdentity(id);
      this.appendAudit(context, "ssh.key.delete", started, true, undefined);
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.key.delete",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  getKeyIdentitySecrets(
    context: SSHHostContext,
    id: string,
  ): { privateKey: string; keyPassphrase: string } {
    const started = this.#clock();
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHKeyIdentity(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh key identity");
      }
      const secrets = this.decryptKeyIdentitySecrets(current);
      this.appendAudit(context, "ssh.key.secrets", started, true, undefined);
      return secrets;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.key.secrets",
        started,
        false,
        undefined,
        error,
      );
      throw error;
    }
  }

  listSessionHistory(accountId: string): SSHSessionHistoryRecord[] {
    this.requireAccess(accountId);
    return this.repository.listSSHSessionHistory(accountId).map((record) => ({
      ...record,
    }));
  }

  createSessionHistory(
    context: SSHHostContext,
    input: SSHSessionHistoryInput,
  ): SSHSessionHistoryRecord {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const host = this.loadHost(accountId, input.hostId.trim());
      hostId = host.id;
      const fields = this.validateSessionHistory(input);
      const record: SSHSessionHistoryRecord = {
        id: randomUUID(),
        accountId,
        hostId: host.id,
        hostName: host.name,
        ...fields,
        startedAt: this.#clock(),
        endedAt: this.sessionHistoryEndedAt(fields.status),
      };
      const created = this.repository.createSSHSessionHistory(record);
      this.appendAudit(
        context,
        "ssh.session_history.create",
        started,
        true,
        hostId,
      );
      return created;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.session_history.create",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  updateSessionHistory(
    context: SSHHostContext,
    id: string,
    input: SSHSessionHistoryUpdate,
  ): SSHSessionHistoryRecord {
    const started = this.#clock();
    let hostId: string | undefined;
    try {
      const accountId = context.principal.accountId;
      this.requireAccess(accountId);
      const current = this.repository.findSSHSessionHistory(id);
      if (!current || current.accountId !== accountId) {
        throw new NotFoundError("ssh session history");
      }
      hostId = current.hostId ?? undefined;
      const fields = this.validateSessionHistory({
        status: input.status,
        latencyMs: input.latencyMs ?? current.latencyMs,
        errorMessage: input.errorMessage ?? current.errorMessage,
      });
      const saved = this.repository.updateSSHSessionHistory({
        ...current,
        status: fields.status,
        latencyMs: fields.latencyMs,
        errorMessage: fields.errorMessage,
        endedAt: this.sessionHistoryEndedAt(fields.status),
      });
      this.appendAudit(
        context,
        "ssh.session_history.update",
        started,
        true,
        hostId,
      );
      return saved;
    } catch (error) {
      this.appendAudit(
        context,
        "ssh.session_history.update",
        started,
        false,
        hostId,
        error,
      );
      throw error;
    }
  }

  private requireAccess(accountId: string): void {
    const account = this.repository.findAccountById(accountId);
    if (!account) {
      throw new NotFoundError("account");
    }
    if (!account.sshEnabled) {
      throw new ServiceError(
        "ssh_disabled",
        "SSH access is disabled for this account",
        403,
      );
    }
  }

  private validateSessionHistory(input: {
    status: SSHSessionHistoryStatus;
    latencyMs?: number;
    errorMessage?: string;
  }): Pick<SSHSessionHistoryRecord, "status" | "latencyMs" | "errorMessage"> {
    if (
      !["connecting", "connected", "failed", "closed"].includes(input.status)
    ) {
      throw new ServiceError(
        "invalid_ssh_session_history",
        "session history status is invalid",
        400,
      );
    }
    const latencyMs = input.latencyMs ?? 0;
    if (
      !Number.isInteger(latencyMs) ||
      latencyMs < 0 ||
      latencyMs > 86_400_000
    ) {
      throw new ServiceError(
        "invalid_ssh_session_history",
        "session history latency is invalid",
        400,
      );
    }
    const errorMessage = (input.errorMessage ?? "").trim();
    if (errorMessage.length > 4096) {
      throw new ServiceError(
        "invalid_ssh_session_history",
        "session history error is too long",
        400,
      );
    }
    return { status: input.status, latencyMs, errorMessage };
  }

  private sessionHistoryEndedAt(
    status: SSHSessionHistoryStatus,
  ): number | null {
    return status === "failed" || status === "closed" ? this.#clock() : null;
  }

  private loadHost(accountId: string, id: string): SSHHostRecord {
    const record = this.repository.findSSHHost(id);
    if (!record || record.accountId !== accountId) {
      throw new NotFoundError("ssh host");
    }
    return record;
  }

  private validateFields(input: SSHHostInput): ValidatedFields {
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100) {
      throw invalid("name must be 1-100 characters");
    }
    const host = input.host.trim();
    if (host.length < 1 || host.length > 255) {
      throw invalid("host must be 1-255 characters");
    }
    const port = input.port;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw invalid("port must be between 1 and 65535");
    }
    const username = input.username.trim();
    if (username.length < 1 || username.length > 64) {
      throw invalid("username must be 1-64 characters");
    }
    if ((input.password?.length ?? 0) > 512) {
      throw invalid("password is too long");
    }
    if ((input.privateKey?.length ?? 0) > 65536) {
      throw invalid("private key is too long");
    }
    if ((input.keyPassphrase?.length ?? 0) > 512) {
      throw invalid("key passphrase is too long");
    }
    return { name, host, port, username };
  }

  private normalizeFingerprint(value: string | undefined): string {
    const normalized = (value ?? "").trim();
    if (!normalized) {
      return "";
    }
    return this.parseFingerprint(normalized).fingerprint;
  }

  private parseFingerprint(value: string): {
    algorithm: string;
    fingerprint: string;
  } {
    const normalized = value.trim();
    if (normalized.length < 3 || normalized.length > 256) {
      throw invalid("fingerprint must be 3-256 characters");
    }
    const separator = normalized.indexOf(":");
    const algorithm = normalized.slice(0, separator).trim().toUpperCase();
    const digest = normalized.slice(separator + 1).trim();
    if (!/^[A-Z0-9][A-Z0-9._-]{0,31}$/.test(algorithm) || !digest) {
      throw invalid("fingerprint must include an algorithm prefix");
    }
    return { algorithm, fingerprint: `${algorithm}:${digest}` };
  }

  private newFingerprintRecord(
    host: SSHHostRecord,
    fingerprint: string,
    source: SSHHostFingerprintSource,
    observedAt: number,
  ): SSHHostFingerprintRecord {
    const parsed = this.parseFingerprint(fingerprint);
    return {
      id: randomUUID(),
      accountId: host.accountId,
      hostId: host.id,
      algorithm: parsed.algorithm,
      fingerprint: parsed.fingerprint,
      source,
      active: true,
      observedAt,
      retiredAt: null,
    };
  }

  private fingerprintView(
    record: SSHHostFingerprintRecord,
  ): SSHHostFingerprintView {
    return {
      id: record.id,
      hostId: record.hostId,
      algorithm: record.algorithm,
      fingerprint: record.fingerprint,
      source: record.source,
      active: record.active,
      observedAt: record.observedAt,
      retiredAt: record.retiredAt,
    };
  }

  private normalizeMetadata(
    input: SSHHostInput,
    password: string,
    privateKey: string,
    current?: SSHHostRecord,
  ): Pick<
    SSHHostRecord,
    | "enabled"
    | "favorite"
    | "groupPath"
    | "tags"
    | "sortOrder"
    | "authMethod"
    | "settings"
  > {
    const authMethod =
      input.authMethod ??
      current?.authMethod ??
      (password ? "password" : "private_key");
    if (authMethod === "password" && !password) {
      throw invalid("password authentication requires a password");
    }
    if (authMethod === "private_key" && !privateKey) {
      throw invalid("private key authentication requires a private key");
    }
    const tags = input.tags ?? current?.tags ?? [];
    if (
      !Array.isArray(tags) ||
      tags.length > 32 ||
      tags.some(
        (tag) =>
          typeof tag !== "string" ||
          tag.trim().length < 1 ||
          tag.trim().length > 50,
      )
    ) {
      throw invalid(
        "tags must contain at most 32 non-empty values of 50 characters",
      );
    }
    const settings = this.normalizeSettings(
      input.settings,
      current?.settings,
      input.clearTerminalAppearance === true,
    );
    const groupPath = (input.groupPath ?? current?.groupPath ?? "").trim();
    if (groupPath.length > 255) throw invalid("group path is too long");
    const sortOrder = input.sortOrder ?? current?.sortOrder ?? 0;
    if (!Number.isInteger(sortOrder) || sortOrder < 0) {
      throw invalid("sort order must be a non-negative integer");
    }
    return {
      enabled: input.enabled ?? current?.enabled ?? true,
      favorite: input.favorite ?? current?.favorite ?? false,
      groupPath,
      tags: tags.map((tag) => tag.trim()),
      sortOrder,
      authMethod,
      settings,
    };
  }

  private normalizeSettings(
    input: Partial<SSHConnectionSettings> | undefined,
    current: SSHConnectionSettings | undefined,
    clearTerminalAppearance = false,
  ): SSHConnectionSettings {
    const value = {
      ...defaultSSHConnectionSettings,
      ...(current ?? {}),
      ...(input ?? {}),
    };

    const terminalAppearance = clearTerminalAppearance
      ? undefined
      : input?.terminalAppearance === undefined &&
          current?.terminalAppearance === undefined
        ? undefined
        : this.validateTerminalAppearance(
            {
              ...(current?.terminalAppearance ?? {}),
              ...(input?.terminalAppearance ?? {}),
            },
            true,
          );
    for (const [key, numberValue] of Object.entries(value)) {
      if (
        key.endsWith("Ms") &&
        (typeof numberValue !== "number" ||
          !Number.isInteger(numberValue) ||
          numberValue < 0)
      ) {
        throw invalid(`${key} must be a non-negative integer`);
      }
    }
    if (
      !Number.isInteger(value.failureCount) ||
      value.failureCount < 0 ||
      value.failureCount > 20
    ) {
      throw invalid("failure count must be between 0 and 20");
    }
    if (
      typeof value.compression !== "boolean" ||
      typeof value.autoReconnect !== "boolean"
    ) {
      throw invalid("compression and auto reconnect must be boolean");
    }
    if (
      typeof value.startupCommand !== "string" ||
      value.startupCommand.length > 4096
    ) {
      throw invalid("startup command is too long");
    }
    if (
      typeof value.initialDirectory !== "string" ||
      value.initialDirectory.length > 4096
    ) {
      throw invalid("initial directory is too long");
    }
    if (
      typeof value.environment !== "object" ||
      value.environment === null ||
      Object.keys(value.environment).length > 64 ||
      Object.entries(value.environment).some(
        ([key, item]) =>
          key.length < 1 ||
          key.length > 128 ||
          typeof item !== "string" ||
          item.length > 4096,
      )
    ) {
      throw invalid("environment is invalid");
    }
    return {
      tcpTimeoutMs: value.tcpTimeoutMs,
      sshHandshakeTimeoutMs: value.sshHandshakeTimeoutMs,
      ptyTimeoutMs: value.ptyTimeoutMs,
      keepaliveIntervalMs: value.keepaliveIntervalMs,
      failureCount: value.failureCount,
      idleTimeoutMs: value.idleTimeoutMs,
      compression: value.compression,
      startupCommand: value.startupCommand,
      initialDirectory: value.initialDirectory,
      environment: { ...value.environment },
      autoReconnect: value.autoReconnect,
      ...(terminalAppearance === undefined ? {} : { terminalAppearance }),
    };
  }

  private validateTerminalAppearance(
    input: Partial<SSHTerminalAppearance>,
    partial: boolean,
  ): Partial<SSHTerminalAppearance> {
    const value = partial
      ? input
      : { ...defaultSSHTerminalAppearance, ...input };
    if (
      value.font !== undefined &&
      value.font !== "builtin-mono" &&
      value.font !== "system-mono"
    ) {
      throw invalid("terminal appearance font is invalid");
    }
    if (
      value.fontSize !== undefined &&
      (!Number.isFinite(value.fontSize) ||
        value.fontSize < 8 ||
        value.fontSize > 32)
    ) {
      throw invalid("terminal appearance font size must be between 8 and 32");
    }
    for (const color of [value.foreground, value.background]) {
      if (color !== undefined && !/^#[0-9a-fA-F]{6}$/.test(color)) {
        throw invalid("terminal appearance colors must use #RRGGBB");
      }
    }
    return { ...value };
  }

  private validateCloneName(name: string): string {
    const normalized = name.trim();
    if (normalized.length < 1 || normalized.length > 100) {
      throw invalid("name must be 1-100 characters");
    }
    return normalized;
  }

  private validateTunnel(
    input: SSHTunnelInput,
  ): Omit<
    SSHTunnelRecord,
    | "id"
    | "accountId"
    | "name"
    | "enabled"
    | "autoStart"
    | "running"
    | "trafficUpBytes"
    | "trafficDownBytes"
    | "version"
    | "createdAt"
    | "updatedAt"
  > & { name: string } {
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100)
      throw invalid("tunnel name must be 1-100 characters");
    const hostId = input.hostId.trim();
    if (!hostId) throw invalid("tunnel host is required");
    if (!["local", "remote", "dynamic_socks"].includes(input.type))
      throw invalid("tunnel type is invalid");
    const listenHost = input.listenHost.trim();
    if (!listenHost || listenHost.length > 255)
      throw invalid("listen host is invalid");
    if (
      !Number.isInteger(input.listenPort) ||
      input.listenPort < 1 ||
      input.listenPort > 65535
    )
      throw invalid("listen port is invalid");
    const targetHost = (input.targetHost ?? "").trim();
    const targetPort = input.targetPort ?? 0;
    if (
      input.type !== "dynamic_socks" &&
      (!targetHost ||
        !Number.isInteger(targetPort) ||
        targetPort < 1 ||
        targetPort > 65535)
    ) {
      throw invalid("target host and port are required");
    }
    if (
      input.type === "dynamic_socks" &&
      (!Number.isInteger(targetPort) || targetPort < 0 || targetPort > 65535)
    ) {
      throw invalid("target port is invalid");
    }
    return {
      name,
      hostId,
      type: input.type,
      listenHost,
      listenPort: input.listenPort,
      targetHost,
      targetPort,
    };
  }

  private validateTunnelTraffic(name: string, value: number): number {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw invalid(`${name} must be a non-negative integer`);
    }
    return value;
  }

  private validateSnippet(
    input: SSHSnippetInput,
  ): Pick<
    SSHCommandSnippetRecord,
    "name" | "command" | "variables" | "enabled"
  > {
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100) {
      throw invalid("snippet name must be 1-100 characters");
    }
    const command = input.command.trim();
    if (command.length < 1 || command.length > 8192) {
      throw invalid("snippet command must be 1-8192 characters");
    }
    const variables = input.variables ?? [];
    if (
      !Array.isArray(variables) ||
      variables.length > 32 ||
      variables.some((variable) => {
        const value = variable.trim();
        return (
          value.length < 1 ||
          value.length > 64 ||
          !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)
        );
      })
    ) {
      throw invalid("snippet variables are invalid");
    }
    const uniqueVariables = [
      ...new Set(variables.map((variable) => variable.trim())),
    ];
    if (uniqueVariables.length !== variables.length) {
      throw invalid("snippet variables must be unique");
    }
    this.validateSnippetSecrets(input.secrets ?? {});
    return {
      name,
      command,
      variables: uniqueVariables,
      enabled: input.enabled ?? true,
    };
  }

  private validateKeyIdentity(
    input: SSHKeyIdentityInput,
    requirePrivateKey: boolean,
  ): Pick<
    SSHKeyIdentityRecord,
    "name" | "publicKey" | "fingerprint" | "enabled"
  > {
    const name = input.name.trim();
    if (name.length < 1 || name.length > 100) {
      throw new ServiceError(
        "invalid_ssh_key",
        "key identity name is invalid",
        400,
      );
    }
    const publicKey = (input.publicKey ?? "").trim();
    if (publicKey.length > 8192) {
      throw new ServiceError("invalid_ssh_key", "public key is too long", 400);
    }
    const fingerprint = (input.fingerprint ?? "").trim();
    if (fingerprint.length > 256) {
      throw new ServiceError("invalid_ssh_key", "fingerprint is too long", 400);
    }
    if (requirePrivateKey && !input.privateKey) {
      throw new ServiceError("invalid_ssh_key", "private key is required", 400);
    }
    if (input.privateKey !== undefined && input.privateKey.length > 65536) {
      throw new ServiceError("invalid_ssh_key", "private key is too long", 400);
    }
    if (
      input.keyPassphrase !== undefined &&
      input.keyPassphrase.length > 4096
    ) {
      throw new ServiceError(
        "invalid_ssh_key",
        "key passphrase is too long",
        400,
      );
    }
    return {
      name,
      publicKey,
      fingerprint,
      enabled: input.enabled ?? true,
    };
  }

  private validateSnippetSecrets(
    secrets: Record<string, string>,
  ): Record<string, string> {
    if (
      typeof secrets !== "object" ||
      secrets === null ||
      Array.isArray(secrets) ||
      Object.keys(secrets).length > 32
    ) {
      throw invalid("snippet secrets are invalid");
    }
    const normalized: Record<string, string> = {};
    for (const [name, value] of Object.entries(secrets)) {
      if (
        !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) ||
        name.length > 64 ||
        typeof value !== "string" ||
        value.length > 4096
      ) {
        throw invalid("snippet secrets are invalid");
      }
      normalized[name] = value;
    }
    return normalized;
  }

  private decryptSnippetSecrets(
    record: SSHCommandSnippetRecord,
  ): Record<string, string> {
    return this.validateSnippetSecrets(
      JSON.parse(
        decryptSecret(this.masterKey, record.secretCiphertext),
      ) as Record<string, string>,
    );
  }

  private snippetView(record: SSHCommandSnippetRecord): SSHSnippetView {
    const secrets = this.decryptSnippetSecrets(record);
    return {
      id: record.id,
      name: record.name,
      command: record.command,
      variables: [...record.variables],
      secretNames: Object.keys(secrets).sort(),
      enabled: record.enabled,
      version: record.version,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  private decryptKeyIdentitySecrets(record: SSHKeyIdentityRecord): {
    privateKey: string;
    keyPassphrase: string;
  } {
    const secrets = JSON.parse(
      decryptSecret(this.masterKey, record.secretCiphertext),
    ) as Partial<{ privateKey: string; keyPassphrase: string }>;
    return {
      privateKey:
        typeof secrets.privateKey === "string" ? secrets.privateKey : "",
      keyPassphrase:
        typeof secrets.keyPassphrase === "string" ? secrets.keyPassphrase : "",
    };
  }

  private keyIdentityView(record: SSHKeyIdentityRecord): SSHKeyIdentityView {
    const secrets = this.decryptKeyIdentitySecrets(record);
    return {
      id: record.id,
      name: record.name,
      publicKey: record.publicKey,
      fingerprint: record.fingerprint,
      hasPassphrase: Boolean(secrets.keyPassphrase),
      enabled: record.enabled,
      version: record.version,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  private decryptSecretOf(record: SSHHostRecord): SSHHostSecret {
    return JSON.parse(
      decryptSecret(this.masterKey, record.secretCiphertext),
    ) as SSHHostSecret;
  }

  private toView(record: SSHHostRecord): SSHHostView {
    const secret = this.decryptSecretOf(record);
    return {
      id: record.id,
      name: record.name,
      host: record.host,
      port: record.port,
      username: record.username,
      hasPassword: Boolean(secret.password),
      hasPrivateKey: Boolean(secret.privateKey),
      hasKeyPassphrase: Boolean(secret.keyPassphrase),
      trustedFingerprint: record.trustedFingerprint,
      enabled: record.enabled,
      favorite: record.favorite,
      groupPath: record.groupPath,
      tags: [...record.tags],
      sortOrder: record.sortOrder,
      authMethod: record.authMethod,
      settings: {
        ...record.settings,
        environment: { ...record.settings.environment },
      },
      version: record.version,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
    };
  }

  private workspaceExistingNames(accountId: string) {
    return {
      hosts: this.repository.listSSHHosts(accountId).map((item) => item.name),
      tunnels: this.repository
        .listSSHTunnels(accountId)
        .map((item) => item.name),
      snippets: this.repository
        .listSSHSnippets(accountId)
        .map((item) => item.name),
      keys: this.repository
        .listSSHKeyIdentities(accountId)
        .map((item) => item.name),
    };
  }

  private applyWorkspaceImportPlan(
    accountId: string,
    payload: SSHWorkspaceExportPayload,
    plan: SSHWorkspaceImportPlanItem[],
  ): SSHWorkspaceImportResult["counts"] {
    const planByName = new Map(
      plan.map((item) => [this.workspaceImportKey(item.kind, item.name), item]),
    );
    const hostsByName = new Map(
      this.repository
        .listSSHHosts(accountId)
        .map((record) => [this.workspaceImportName(record.name), record]),
    );
    const tunnelsByName = new Map(
      this.repository
        .listSSHTunnels(accountId)
        .map((record) => [this.workspaceImportName(record.name), record]),
    );
    const snippetsByName = new Map(
      this.repository
        .listSSHSnippets(accountId)
        .map((record) => [this.workspaceImportName(record.name), record]),
    );
    const keysByName = new Map(
      this.repository
        .listSSHKeyIdentities(accountId)
        .map((record) => [this.workspaceImportName(record.name), record]),
    );
    const hostIdsByRef = new Map<string, string>();
    for (const host of payload.hosts) {
      if (!host.ref.trim() || hostIdsByRef.has(host.ref)) {
        throw invalid("host reference is invalid");
      }
      const item = this.workspaceImportPlanItem(planByName, "host", host.name);
      const current = hostsByName.get(this.workspaceImportName(host.name));
      if (item.action === "skip") {
        if (!current) throw invalid("host import target is missing");
        hostIdsByRef.set(host.ref, current.id);
        continue;
      }
      if (item.action === "overwrite" && !current) {
        throw invalid("host import target is missing");
      }
      const saved = this.applyWorkspaceHost(
        accountId,
        host,
        item.targetName,
        item.action === "overwrite" ? current : undefined,
      );
      hostsByName.set(this.workspaceImportName(saved.name), saved);
      hostIdsByRef.set(host.ref, saved.id);
    }
    for (const tunnel of payload.tunnels) {
      const hostId = hostIdsByRef.get(tunnel.hostRef);
      if (!hostId) throw invalid("tunnel host reference is invalid");
      const item = this.workspaceImportPlanItem(
        planByName,
        "tunnel",
        tunnel.name,
      );
      const current = tunnelsByName.get(this.workspaceImportName(tunnel.name));
      if (item.action === "skip") {
        if (!current) throw invalid("tunnel import target is missing");
        continue;
      }
      if (item.action === "overwrite" && !current) {
        throw invalid("tunnel import target is missing");
      }
      const saved = this.applyWorkspaceTunnel(
        accountId,
        tunnel,
        hostId,
        item.targetName,
        item.action === "overwrite" ? current : undefined,
      );
      tunnelsByName.set(this.workspaceImportName(saved.name), saved);
    }
    for (const snippet of payload.snippets) {
      const item = this.workspaceImportPlanItem(
        planByName,
        "snippet",
        snippet.name,
      );
      const current = snippetsByName.get(
        this.workspaceImportName(snippet.name),
      );
      if (item.action === "skip") {
        if (!current) throw invalid("snippet import target is missing");
        continue;
      }
      if (item.action === "overwrite" && !current) {
        throw invalid("snippet import target is missing");
      }
      const saved = this.applyWorkspaceSnippet(
        accountId,
        snippet,
        item.targetName,
        item.action === "overwrite" ? current : undefined,
      );
      snippetsByName.set(this.workspaceImportName(saved.name), saved);
    }
    for (const key of payload.keys) {
      const item = this.workspaceImportPlanItem(planByName, "key", key.name);
      const current = keysByName.get(this.workspaceImportName(key.name));
      if (item.action === "skip") {
        if (!current) throw invalid("key import target is missing");
        continue;
      }
      if (item.action === "overwrite" && !current) {
        throw invalid("key import target is missing");
      }
      const saved = this.applyWorkspaceKey(
        accountId,
        key,
        item.targetName,
        item.action === "overwrite" ? current : undefined,
      );
      keysByName.set(this.workspaceImportName(saved.name), saved);
    }
    const counts: SSHWorkspaceImportResult["counts"] = {
      created: 0,
      overwritten: 0,
      copied: 0,
      skipped: 0,
    };
    for (const item of plan) {
      if (item.action === "create") counts.created += 1;
      if (item.action === "overwrite") counts.overwritten += 1;
      if (item.action === "copy") counts.copied += 1;
      if (item.action === "skip") counts.skipped += 1;
    }
    return counts;
  }

  private applyWorkspaceHost(
    accountId: string,
    source: SSHWorkspaceExportHost,
    targetName: string,
    current?: SSHHostRecord,
  ): SSHHostRecord {
    const importedSecret =
      source.secret === undefined
        ? undefined
        : this.validateWorkspaceHostSecret(source.secret);
    const secret =
      importedSecret ??
      (current
        ? this.decryptSecretOf(current)
        : {
            password: "",
            privateKey: "",
            keyPassphrase: "",
          });
    const input: SSHHostInput = {
      name: targetName,
      host: source.host,
      port: source.port,
      username: source.username,
      password: secret.password,
      privateKey: secret.privateKey,
      keyPassphrase: secret.keyPassphrase,
      trustedFingerprint: source.trustedFingerprint,
      enabled: source.enabled,
      favorite: source.favorite,
      groupPath: source.groupPath,
      tags: [...source.tags],
      sortOrder: source.sortOrder,
      authMethod: source.authMethod,
      settings: {
        ...source.settings,
        environment: { ...source.settings.environment },
      },
    };
    const fields = this.validateFields(input);
    const metadata =
      !current && importedSecret === undefined
        ? this.normalizeWorkspacePlaceholderMetadata(input)
        : this.normalizeMetadata(
            input,
            secret.password,
            secret.privateKey,
            current,
          );
    const trustedFingerprint = this.normalizeFingerprint(
      source.trustedFingerprint,
    );
    const now = this.#clock();
    const record: SSHHostRecord = {
      id: current?.id ?? randomUUID(),
      accountId,
      ...fields,
      secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secret)),
      trustedFingerprint,
      ...metadata,
      version: current ? current.version + 1 : 1,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
    };
    if (current) {
      return trustedFingerprint === current.trustedFingerprint
        ? this.repository.updateSSHHost(record)
        : this.repository.replaceSSHHostFingerprint(
            record,
            trustedFingerprint
              ? this.newFingerprintRecord(
                  record,
                  trustedFingerprint,
                  "manual",
                  now,
                )
              : undefined,
          );
    }
    if (this.repository.countSSHHosts(accountId) >= this.options.maxHosts) {
      throw new ServiceError(
        "ssh_host_limit",
        "ssh host limit reached for this account",
        403,
      );
    }
    return this.repository.createSSHHostWithFingerprint(
      record,
      trustedFingerprint
        ? this.newFingerprintRecord(record, trustedFingerprint, "manual", now)
        : undefined,
    );
  }

  private applyWorkspaceTunnel(
    accountId: string,
    source: SSHWorkspaceExportTunnel,
    hostId: string,
    targetName: string,
    current?: SSHTunnelRecord,
  ): SSHTunnelRecord {
    const fields = this.validateTunnel({
      name: targetName,
      hostId,
      type: source.type,
      listenHost: source.listenHost,
      listenPort: source.listenPort,
      targetHost: source.targetHost,
      targetPort: source.targetPort,
      enabled: source.enabled,
      autoStart: source.autoStart,
    });
    const now = this.#clock();
    const record: SSHTunnelRecord = {
      id: current?.id ?? randomUUID(),
      accountId,
      ...fields,
      enabled: source.enabled,
      autoStart: source.autoStart,
      running: false,
      trafficUpBytes: 0,
      trafficDownBytes: 0,
      version: current ? current.version + 1 : 1,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
    };
    return current
      ? this.repository.updateSSHTunnel(record)
      : this.repository.createSSHTunnel(record);
  }

  private applyWorkspaceSnippet(
    accountId: string,
    source: SSHWorkspaceExportSnippet,
    targetName: string,
    current?: SSHCommandSnippetRecord,
  ): SSHCommandSnippetRecord {
    const input: SSHSnippetInput = {
      name: targetName,
      command: source.command,
      variables: [...source.variables],
      enabled: source.enabled,
      ...(source.secrets === undefined ? {} : { secrets: source.secrets }),
    };
    const fields = this.validateSnippet(input);
    const secrets =
      source.secrets === undefined
        ? current
          ? this.decryptSnippetSecrets(current)
          : {}
        : this.validateSnippetSecrets(source.secrets);
    const now = this.#clock();
    const record: SSHCommandSnippetRecord = {
      id: current?.id ?? randomUUID(),
      accountId,
      ...fields,
      secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secrets)),
      version: current ? current.version + 1 : 1,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
    };
    return current
      ? this.repository.updateSSHSnippet(record)
      : this.repository.createSSHSnippet(record);
  }

  private applyWorkspaceKey(
    accountId: string,
    source: SSHWorkspaceExportKey,
    targetName: string,
    current?: SSHKeyIdentityRecord,
  ): SSHKeyIdentityRecord {
    const importedSecret =
      source.secret === undefined
        ? undefined
        : this.validateWorkspaceKeySecret(source.secret);
    const secret =
      importedSecret ??
      (current
        ? this.decryptKeyIdentitySecrets(current)
        : { privateKey: "", keyPassphrase: "" });
    const input: SSHKeyIdentityInput = {
      name: targetName,
      publicKey: source.publicKey,
      fingerprint: source.fingerprint,
      privateKey: secret.privateKey,
      keyPassphrase: secret.keyPassphrase,
      enabled:
        !current && importedSecret === undefined ? false : source.enabled,
    };
    const fields = this.validateKeyIdentity(
      input,
      !current && importedSecret !== undefined,
    );
    const now = this.#clock();
    const record: SSHKeyIdentityRecord = {
      id: current?.id ?? randomUUID(),
      accountId,
      ...fields,
      secretCiphertext: encryptSecret(this.masterKey, JSON.stringify(secret)),
      version: current ? current.version + 1 : 1,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
    };
    return current
      ? this.repository.updateSSHKeyIdentity(record)
      : this.repository.createSSHKeyIdentity(record);
  }

  private normalizeWorkspacePlaceholderMetadata(
    input: SSHHostInput,
  ): ReturnType<SSHHostService["normalizeMetadata"]> {
    if (
      !input.authMethod ||
      !["password", "private_key"].includes(input.authMethod)
    ) {
      throw invalid("authentication method is invalid");
    }
    const metadata = this.normalizeMetadata(
      input,
      input.authMethod === "password" ? "import-placeholder" : "",
      input.authMethod === "private_key" ? "import-placeholder" : "",
    );
    return { ...metadata, enabled: false };
  }

  private validateWorkspaceHostSecret(value: unknown): SSHHostSecret {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw invalid("host secret is invalid");
    }
    const secret = value as Partial<SSHHostSecret>;
    if (
      typeof secret.password !== "string" ||
      typeof secret.privateKey !== "string" ||
      typeof secret.keyPassphrase !== "string" ||
      secret.password.length > 4096 ||
      secret.privateKey.length > 65536 ||
      secret.keyPassphrase.length > 4096
    ) {
      throw invalid("host secret is invalid");
    }
    return {
      password: secret.password,
      privateKey: secret.privateKey,
      keyPassphrase: secret.keyPassphrase,
    };
  }

  private validateWorkspaceKeySecret(value: unknown): {
    privateKey: string;
    keyPassphrase: string;
  } {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      throw new ServiceError("invalid_ssh_key", "key secret is invalid", 400);
    }
    const secret = value as Partial<{
      privateKey: string;
      keyPassphrase: string;
    }>;
    if (
      typeof secret.privateKey !== "string" ||
      typeof secret.keyPassphrase !== "string" ||
      secret.privateKey.length > 65536 ||
      secret.keyPassphrase.length > 4096
    ) {
      throw new ServiceError("invalid_ssh_key", "key secret is invalid", 400);
    }
    return {
      privateKey: secret.privateKey,
      keyPassphrase: secret.keyPassphrase,
    };
  }

  private workspaceImportPlanItem(
    plan: Map<string, SSHWorkspaceImportPlanItem>,
    kind: SSHWorkspaceImportPlanItem["kind"],
    name: string,
  ): SSHWorkspaceImportPlanItem {
    const item = plan.get(this.workspaceImportKey(kind, name));
    if (!item) throw invalid(`missing import plan for ${kind} ${name}`);
    return item;
  }

  private workspaceImportKey(
    kind: SSHWorkspaceImportPlanItem["kind"],
    name: string,
  ): string {
    return `${kind}\u0000${this.workspaceImportName(name)}`;
  }

  private workspaceImportName(name: string): string {
    return name.trim().toLocaleLowerCase("en-US");
  }

  private workspaceExportPayload(
    accountId: string,
    includeSecrets: boolean,
  ): SSHWorkspaceExportPayload {
    const hosts = this.repository.listSSHHosts(accountId).map((record) => {
      const exported: SSHWorkspaceExportHost = {
        ref: `host:${record.id}`,
        name: record.name,
        host: record.host,
        port: record.port,
        username: record.username,
        enabled: record.enabled,
        favorite: record.favorite,
        groupPath: record.groupPath,
        tags: [...record.tags],
        sortOrder: record.sortOrder,
        authMethod: record.authMethod,
        settings: {
          ...record.settings,
          environment: { ...record.settings.environment },
        },
        trustedFingerprint: record.trustedFingerprint,
      };
      if (includeSecrets) exported.secret = this.decryptSecretOf(record);
      return exported;
    });
    const tunnels = this.repository.listSSHTunnels(accountId).map((record) => ({
      name: record.name,
      hostRef: `host:${record.hostId}`,
      type: record.type,
      listenHost: record.listenHost,
      listenPort: record.listenPort,
      targetHost: record.targetHost,
      targetPort: record.targetPort,
      enabled: record.enabled,
      autoStart: record.autoStart,
    }));
    const snippets = this.repository
      .listSSHSnippets(accountId)
      .map((record) => {
        const exported: SSHWorkspaceExportPayload["snippets"][number] = {
          name: record.name,
          command: record.command,
          variables: [...record.variables],
          enabled: record.enabled,
        };
        if (includeSecrets)
          exported.secrets = this.decryptSnippetSecrets(record);
        return exported;
      });
    const keys = this.repository
      .listSSHKeyIdentities(accountId)
      .map((record) => {
        const exported: SSHWorkspaceExportPayload["keys"][number] = {
          name: record.name,
          publicKey: record.publicKey,
          fingerprint: record.fingerprint,
          enabled: record.enabled,
        };
        if (includeSecrets) {
          exported.secret = this.decryptKeyIdentitySecrets(record);
        }
        return exported;
      });
    return { hosts, tunnels, snippets, keys };
  }

  private workspacePackageError(error: unknown): ServiceError {
    if (error instanceof ServiceError) return error;
    return new ServiceError(
      "invalid_ssh_workspace_export",
      error instanceof Error ? error.message : "invalid SSH workspace export",
      400,
    );
  }

  private appendAudit(
    context: SSHHostContext,
    action: string,
    started: number,
    success: boolean,
    sshHostId: string | undefined,
    error?: unknown,
  ): void {
    const now = this.#clock();
    const event: AuditEvent = {
      id: randomUUID(),
      occurredAt: now,
      accountId: context.principal.accountId,
      sessionId: context.principal.sessionId,
      deviceId: context.principal.deviceId,
      action,
      success,
      durationMs: Math.max(0, now - started),
    };
    if (context.ipAddress) event.ipAddress = context.ipAddress;
    if (sshHostId) event.sshHostId = sshHostId;
    if (error instanceof ServiceError) event.errorCode = error.code;
    this.repository.appendAudit(event);
  }
}
