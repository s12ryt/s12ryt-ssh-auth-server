import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scrypt,
} from "node:crypto";

import type {
  SSHAuthMethod,
  SSHConnectionSettings,
  SSHHostSecret,
  SSHTunnelType,
} from "../domain/models.js";

const exportFormat = "s12ryt-ssh-workspace";
const exportVersion = 1;
const exportKeyLength = 32;
const exportScryptCost = 32_768;
const exportScryptBlockSize = 8;
const exportScryptParallelization = 1;
const maxExportBytes = 16 * 1024 * 1024;

export interface SSHWorkspaceExportHost {
  ref: string;
  name: string;
  host: string;
  port: number;
  username: string;
  enabled: boolean;
  favorite: boolean;
  groupPath: string;
  tags: string[];
  sortOrder: number;
  authMethod: SSHAuthMethod;
  settings: SSHConnectionSettings;
  trustedFingerprint: string;
  secret?: SSHHostSecret;
}

export interface SSHWorkspaceExportTunnel {
  name: string;
  hostRef: string;
  type: SSHTunnelType;
  listenHost: string;
  listenPort: number;
  targetHost: string;
  targetPort: number;
  enabled: boolean;
  autoStart: boolean;
}

export interface SSHWorkspaceExportSnippet {
  name: string;
  command: string;
  variables: string[];
  enabled: boolean;
  secrets?: Record<string, string>;
}

export interface SSHWorkspaceExportKey {
  name: string;
  publicKey: string;
  fingerprint: string;
  enabled: boolean;
  secret?: { privateKey: string; keyPassphrase: string };
}

export interface SSHWorkspaceExportPayload {
  hosts: SSHWorkspaceExportHost[];
  tunnels: SSHWorkspaceExportTunnel[];
  snippets: SSHWorkspaceExportSnippet[];
  keys: SSHWorkspaceExportKey[];
}

export interface SSHWorkspaceExportOptions {
  includeSecrets: boolean;
  password?: string;
  createdAt?: number;
}

interface ExportKDF {
  algorithm: "scrypt";
  cost: typeof exportScryptCost;
  blockSize: typeof exportScryptBlockSize;
  parallelization: typeof exportScryptParallelization;
  salt: string;
}

interface ExportEncryption {
  algorithm: "aes-256-gcm";
  kdf: ExportKDF;
  nonce: string;
  tag: string;
  ciphertext: string;
}

interface ExportEnvelope {
  format: typeof exportFormat;
  version: typeof exportVersion;
  createdAt: number;
  includesSecrets: boolean;
  payload?: SSHWorkspaceExportPayload;
  encryption?: ExportEncryption;
}

export type SSHWorkspaceImportKind = "host" | "tunnel" | "snippet" | "key";

export interface SSHWorkspaceImportConflict {
  kind: SSHWorkspaceImportKind;
  name: string;
  conflict: boolean;
}

export type SSHWorkspaceImportDecision = "overwrite" | "skip" | "copy";

export interface SSHWorkspaceImportResolution {
  kind: SSHWorkspaceImportKind;
  name: string;
  action: SSHWorkspaceImportDecision;
}

export interface SSHWorkspaceImportPlanItem {
  kind: SSHWorkspaceImportKind;
  name: string;
  action: SSHWorkspaceImportDecision | "create";
  targetName: string;
}

export interface SSHWorkspaceExistingNames {
  hosts: string[];
  tunnels: string[];
  snippets: string[];
  keys: string[];
}

export interface SSHWorkspaceExportInfo {
  createdAt: number;
  includesSecrets: boolean;
}

function deriveExportKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      password,
      salt,
      exportKeyLength,
      {
        N: exportScryptCost,
        r: exportScryptBlockSize,
        p: exportScryptParallelization,
        maxmem: 128 * 1024 * 1024,
      },
      (error, key) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(key);
      },
    );
  });
}

function clonePayload(
  payload: SSHWorkspaceExportPayload,
  includeSecrets: boolean,
): SSHWorkspaceExportPayload {
  return {
    hosts: payload.hosts.map((host) => {
      const cloned: SSHWorkspaceExportHost = {
        ...host,
        tags: [...host.tags],
        settings: {
          ...host.settings,
          environment: { ...host.settings.environment },
        },
      };
      delete cloned.secret;
      if (includeSecrets && host.secret) cloned.secret = { ...host.secret };
      return cloned;
    }),
    tunnels: payload.tunnels.map((tunnel) => ({ ...tunnel })),
    snippets: payload.snippets.map((snippet) => {
      const cloned: SSHWorkspaceExportSnippet = {
        ...snippet,
        variables: [...snippet.variables],
      };
      delete cloned.secrets;
      if (includeSecrets && snippet.secrets) {
        cloned.secrets = { ...snippet.secrets };
      }
      return cloned;
    }),
    keys: payload.keys.map((key) => {
      const cloned: SSHWorkspaceExportKey = { ...key };
      delete cloned.secret;
      if (includeSecrets && key.secret) cloned.secret = { ...key.secret };
      return cloned;
    }),
  };
}

function encryptionAAD(envelope: ExportEnvelope): Buffer {
  const encryption = envelope.encryption;
  if (!encryption) throw new Error("SSH workspace export is not encrypted");
  return Buffer.from(
    JSON.stringify({
      format: envelope.format,
      version: envelope.version,
      createdAt: envelope.createdAt,
      includesSecrets: envelope.includesSecrets,
      algorithm: encryption.algorithm,
      kdf: encryption.kdf,
    }),
    "utf8",
  );
}

export async function createSSHWorkspaceExport(
  payload: SSHWorkspaceExportPayload,
  options: SSHWorkspaceExportOptions,
): Promise<string> {
  const safePayload = clonePayload(payload, options.includeSecrets);
  validatePayload(safePayload, options.includeSecrets);
  const envelope: ExportEnvelope = {
    format: exportFormat,
    version: exportVersion,
    createdAt: options.createdAt ?? Date.now(),
    includesSecrets: options.includeSecrets,
  };
  if (!options.includeSecrets) {
    envelope.payload = safePayload;
    return JSON.stringify(envelope);
  }
  if ((options.password?.length ?? 0) < 12) {
    throw new Error("export password must contain at least 12 characters");
  }
  const salt = randomBytes(16);
  const nonce = randomBytes(12);
  envelope.encryption = {
    algorithm: "aes-256-gcm",
    kdf: {
      algorithm: "scrypt",
      cost: exportScryptCost,
      blockSize: exportScryptBlockSize,
      parallelization: exportScryptParallelization,
      salt: salt.toString("base64url"),
    },
    nonce: nonce.toString("base64url"),
    tag: "",
    ciphertext: "",
  };
  const key = await deriveExportKey(options.password!, salt);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(encryptionAAD(envelope));
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(safePayload), "utf8"),
    cipher.final(),
  ]);
  envelope.encryption.tag = cipher.getAuthTag().toString("base64url");
  envelope.encryption.ciphertext = ciphertext.toString("base64url");
  return JSON.stringify(envelope);
}

export async function readSSHWorkspaceExport(
  encoded: string,
  password?: string,
): Promise<SSHWorkspaceExportPayload> {
  if (Buffer.byteLength(encoded, "utf8") > maxExportBytes) {
    throw new Error("SSH workspace export exceeds the 16 MiB limit");
  }
  const envelope = parseEnvelope(encoded);
  if (!envelope.includesSecrets) {
    if (!envelope.payload || envelope.encryption) {
      throw new Error("invalid SSH workspace export envelope");
    }
    validatePayload(envelope.payload, false);
    return clonePayload(envelope.payload, false);
  }
  if (!password || !envelope.encryption || envelope.payload) {
    throw new Error("export password is required");
  }
  try {
    validateEncryption(envelope.encryption);
    const salt = Buffer.from(envelope.encryption.kdf.salt, "base64url");
    const nonce = Buffer.from(envelope.encryption.nonce, "base64url");
    if (salt.length !== 16 || nonce.length !== 12) {
      throw new Error("invalid encryption parameters");
    }
    const key = await deriveExportKey(password, salt);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAAD(encryptionAAD(envelope));
    decipher.setAuthTag(Buffer.from(envelope.encryption.tag, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(envelope.encryption.ciphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8");
    const payload = JSON.parse(plaintext) as SSHWorkspaceExportPayload;
    validatePayload(payload, true);
    return clonePayload(payload, true);
  } catch {
    throw new Error("unable to decrypt SSH workspace export");
  }
}

export function inspectSSHWorkspaceExport(
  encoded: string,
): SSHWorkspaceExportInfo {
  if (Buffer.byteLength(encoded, "utf8") > maxExportBytes) {
    throw new Error("SSH workspace export exceeds the 16 MiB limit");
  }
  const envelope = parseEnvelope(encoded);
  return {
    createdAt: envelope.createdAt,
    includesSecrets: envelope.includesSecrets,
  };
}

export function previewSSHWorkspaceImport(
  payload: SSHWorkspaceExportPayload,
  existing: SSHWorkspaceExistingNames,
): SSHWorkspaceImportConflict[] {
  validatePayload(payload, true);
  const conflicts: SSHWorkspaceImportConflict[] = [];
  appendConflicts(conflicts, "host", payload.hosts, existing.hosts);
  appendConflicts(conflicts, "tunnel", payload.tunnels, existing.tunnels);
  appendConflicts(conflicts, "snippet", payload.snippets, existing.snippets);
  appendConflicts(conflicts, "key", payload.keys, existing.keys);
  return conflicts;
}

export function planSSHWorkspaceImport(
  payload: SSHWorkspaceExportPayload,
  existing: SSHWorkspaceExistingNames,
  resolutions: SSHWorkspaceImportResolution[],
): SSHWorkspaceImportPlanItem[] {
  validatePayload(payload, true);
  const resolutionMap = new Map<string, SSHWorkspaceImportDecision>();
  for (const resolution of resolutions) {
    if (!["host", "tunnel", "snippet", "key"].includes(resolution.kind)) {
      throw new Error(`invalid import decision kind ${resolution.kind}`);
    }
    if (!["overwrite", "skip", "copy"].includes(resolution.action)) {
      throw new Error(
        `invalid import decision for ${resolution.kind} ${resolution.name}`,
      );
    }
    const key = importNameKey(resolution.kind, resolution.name);
    if (resolutionMap.has(key)) {
      throw new Error(
        `duplicate import decision for ${resolution.kind} ${resolution.name}`,
      );
    }
    resolutionMap.set(key, resolution.action);
  }
  const output: SSHWorkspaceImportPlanItem[] = [];
  appendPlan(output, "host", payload.hosts, existing.hosts, resolutionMap);
  appendPlan(
    output,
    "tunnel",
    payload.tunnels,
    existing.tunnels,
    resolutionMap,
  );
  appendPlan(
    output,
    "snippet",
    payload.snippets,
    existing.snippets,
    resolutionMap,
  );
  appendPlan(output, "key", payload.keys, existing.keys, resolutionMap);
  const consumed = new Set(
    output.map((item) => importNameKey(item.kind, item.name)),
  );
  for (const resolution of resolutions) {
    if (!consumed.has(importNameKey(resolution.kind, resolution.name))) {
      throw new Error(
        `unused import decision for ${resolution.kind} ${resolution.name}`,
      );
    }
  }
  return output;
}

function appendConflicts(
  output: SSHWorkspaceImportConflict[],
  kind: SSHWorkspaceImportKind,
  values: Array<{ name: string }>,
  existingNames: string[],
): void {
  const names = new Set(existingNames.map(normalizeName));
  for (const value of values) {
    const normalized = normalizeName(value.name);
    output.push({ kind, name: value.name, conflict: names.has(normalized) });
    names.add(normalized);
  }
}

function appendPlan(
  output: SSHWorkspaceImportPlanItem[],
  kind: SSHWorkspaceImportKind,
  values: Array<{ name: string }>,
  existingNames: string[],
  resolutions: Map<string, SSHWorkspaceImportDecision>,
): void {
  const names = new Set(existingNames.map(normalizeName));
  for (const value of values) {
    const normalized = normalizeName(value.name);
    if (!names.has(normalized)) {
      names.add(normalized);
      output.push({
        kind,
        name: value.name,
        action: "create",
        targetName: value.name,
      });
      continue;
    }
    const action = resolutions.get(importNameKey(kind, value.name));
    if (!action)
      throw new Error(`missing import decision for ${kind} ${value.name}`);
    let targetName = value.name;
    if (action === "copy") {
      targetName = uniqueCopyName(value.name, names);
      names.add(normalizeName(targetName));
    }
    output.push({ kind, name: value.name, action, targetName });
  }
}

function uniqueCopyName(name: string, names: Set<string>): string {
  for (let suffix = 2; suffix <= 10_000; suffix += 1) {
    const candidate = `${name} (${suffix})`;
    if (!names.has(normalizeName(candidate))) return candidate;
  }
  throw new Error(`unable to create a unique copy name for ${name}`);
}

function importNameKey(kind: SSHWorkspaceImportKind, name: string): string {
  return `${kind}\u0000${normalizeName(name)}`;
}

function normalizeName(value: string): string {
  return value.trim().toLocaleLowerCase("en-US");
}

function parseEnvelope(encoded: string): ExportEnvelope {
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error("invalid SSH workspace export JSON");
  }
  if (!isRecord(value))
    throw new Error("invalid SSH workspace export envelope");
  if (value.format !== exportFormat || value.version !== exportVersion) {
    throw new Error("unsupported SSH workspace export version");
  }
  if (
    !Number.isSafeInteger(value.createdAt) ||
    typeof value.includesSecrets !== "boolean"
  ) {
    throw new Error("invalid SSH workspace export envelope");
  }
  return value as unknown as ExportEnvelope;
}

function validateEncryption(value: ExportEncryption): void {
  if (
    value.algorithm !== "aes-256-gcm" ||
    value.kdf?.algorithm !== "scrypt" ||
    value.kdf.cost !== exportScryptCost ||
    value.kdf.blockSize !== exportScryptBlockSize ||
    value.kdf.parallelization !== exportScryptParallelization ||
    typeof value.kdf.salt !== "string" ||
    typeof value.nonce !== "string" ||
    typeof value.tag !== "string" ||
    typeof value.ciphertext !== "string"
  ) {
    throw new Error("invalid encryption parameters");
  }
}

function validatePayload(value: unknown, allowSecrets: boolean): void {
  if (!isRecord(value)) throw new Error("invalid SSH workspace payload");
  for (const key of ["hosts", "tunnels", "snippets", "keys"] as const) {
    if (!Array.isArray(value[key])) {
      throw new Error(`invalid SSH workspace ${key}`);
    }
    const names = new Set<string>();
    for (const item of value[key]) {
      if (
        !isRecord(item) ||
        typeof item.name !== "string" ||
        !item.name.trim()
      ) {
        throw new Error(`invalid SSH workspace ${key} item`);
      }
      const normalized = normalizeName(item.name);
      if (names.has(normalized)) {
        throw new Error(`duplicate SSH workspace ${key} name ${item.name}`);
      }
      names.add(normalized);
    }
  }
  if (!allowSecrets) {
    const secretPresent = [
      ...(value.hosts as Array<Record<string, unknown>>),
      ...(value.keys as Array<Record<string, unknown>>),
    ].some((item) => item.secret !== undefined);
    const snippetSecretPresent = (
      value.snippets as Array<Record<string, unknown>>
    ).some((item) => item.secrets !== undefined);
    if (secretPresent || snippetSecretPresent) {
      throw new Error("plaintext SSH workspace export contains secrets");
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
