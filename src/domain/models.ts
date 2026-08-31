export type ConnectionKind = "s3" | "mysql" | "postgres";

export type Operation =
  | "s3.read"
  | "s3.write"
  | "s3.delete"
  | "sql.tables"
  | "sql.query"
  | "sql.exec";

export interface Account {
  id: string;
  username: string;
  enabled: boolean;
  sshEnabled: boolean;
  deviceLimit: number;
  createdAt: number;
  updatedAt: number;
}

export interface StoredAccount extends Account {
  passwordHash: string;
}

export interface S3ConnectionSecret {
  kind: "s3";
  endpoint: string;
  region: string;
  bucket: string;
  prefix: string;
  usePathStyle: boolean;
  accessKeyId: string;
  secretAccessKey: string;
}

export interface MySQLConnectionSecret {
  kind: "mysql";
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  tlsMode: string;
}

export interface PostgresConnectionSecret {
  kind: "postgres";
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  sslMode: string;
}

export type ConnectionSecret =
  S3ConnectionSecret | MySQLConnectionSecret | PostgresConnectionSecret;

export interface Connection {
  id: string;
  name: string;
  kind: ConnectionKind;
  enabled: boolean;
  secretCiphertext: string;
  createdAt: number;
  updatedAt: number;
}

export interface AssignedConnection {
  id: string;
  name: string;
  kind: ConnectionKind;
  enabled: boolean;
  operations: Operation[];
}

export interface LoginSessionRecord {
  id: string;
  familyId: string;
  accountId: string;
  deviceId: string;
  refreshHash: string;
  refreshExpiresAt: number;
  revokedAt: number | null;
  createdAt: number;
  lastUsedAt: number;
  ipAddress: string;
  userAgent: string;
}

export interface SessionWithAccount extends LoginSessionRecord {
  username: string;
  accountEnabled: boolean;
  deviceLimit: number;
}

export interface Principal {
  accountId: string;
  username: string;
  sessionId: string;
  deviceId: string;
}

export interface SessionSummary {
  id: string;
  deviceId: string;
  ipAddress: string;
  userAgent: string;
  createdAt: number;
  lastUsedAt: number;
  expiresAt: number;
  revoked: boolean;
}

export interface AuditEvent {
  id: string;
  occurredAt: number;
  accountId?: string;
  sessionId?: string;
  deviceId?: string;
  ipAddress?: string;
  action: string;
  connectionId?: string;
  sshHostId?: string;
  success: boolean;
  durationMs: number;
  rowsCount?: number;
  bytesCount?: number;
  statementHash?: string;
  statementType?: string;
  errorCode?: string;
}

export interface SSHHostSecret {
  password: string;
  privateKey: string;
  keyPassphrase: string;
}

export type SSHAuthMethod = "password" | "private_key";

export type SSHTerminalFont = "builtin-mono" | "system-mono";

export interface SSHTerminalAppearance {
  font: SSHTerminalFont;
  fontSize: number;
  foreground: string;
  background: string;
}

export interface SSHWorkspacePreferencesRecord {
  accountId: string;
  terminalAppearance: SSHTerminalAppearance;
  version: number;
  updatedAt: number;
}

export interface SSHConnectionSettings {
  tcpTimeoutMs: number;
  sshHandshakeTimeoutMs: number;
  ptyTimeoutMs: number;
  keepaliveIntervalMs: number;
  failureCount: number;
  idleTimeoutMs: number;
  compression: boolean;
  startupCommand: string;
  initialDirectory: string;
  environment: Record<string, string>;
  autoReconnect: boolean;
  terminalAppearance?: Partial<SSHTerminalAppearance>;
}

export interface SSHHostRecord {
  id: string;
  accountId: string;
  name: string;
  host: string;
  port: number;
  username: string;
  secretCiphertext: string;
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

export type SSHHostFingerprintSource = "tofu" | "manual";

export interface SSHHostFingerprintRecord {
  id: string;
  accountId: string;
  hostId: string;
  algorithm: string;
  fingerprint: string;
  source: SSHHostFingerprintSource;
  active: boolean;
  observedAt: number;
  retiredAt: number | null;
}

export type SSHTunnelType = "local" | "remote" | "dynamic_socks";

export interface SSHTunnelRecord {
  id: string;
  accountId: string;
  name: string;
  hostId: string;
  type: SSHTunnelType;
  listenHost: string;
  listenPort: number;
  targetHost: string;
  targetPort: number;
  enabled: boolean;
  autoStart: boolean;
  running: boolean;
  trafficUpBytes: number;
  trafficDownBytes: number;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface SSHCommandSnippetRecord {
  id: string;
  accountId: string;
  name: string;
  command: string;
  variables: string[];
  secretCiphertext: string;
  enabled: boolean;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export interface SSHKeyIdentityRecord {
  id: string;
  accountId: string;
  name: string;
  publicKey: string;
  fingerprint: string;
  secretCiphertext: string;
  enabled: boolean;
  version: number;
  createdAt: number;
  updatedAt: number;
}

export type SSHSessionHistoryStatus =
  "connecting" | "connected" | "failed" | "closed";

export interface SSHSessionHistoryRecord {
  id: string;
  accountId: string;
  hostId: string | null;
  hostName: string;
  status: SSHSessionHistoryStatus;
  latencyMs: number;
  errorMessage: string;
  startedAt: number;
  endedAt: number | null;
}
