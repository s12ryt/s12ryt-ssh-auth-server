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
  success: boolean;
  durationMs: number;
  rowsCount?: number;
  bytesCount?: number;
  statementHash?: string;
  statementType?: string;
  errorCode?: string;
}
