import type { Readable } from "node:stream";

import type {
  MySQLConnectionSecret,
  PostgresConnectionSecret,
  S3ConnectionSecret,
} from "../domain/models.js";

export interface S3Object {
  key: string;
  size: number;
  lastModified?: string;
}

export interface S3Download {
  body: Readable;
  contentLength?: number;
  contentType?: string;
}

export interface S3Gateway {
  test(secret: S3ConnectionSecret, signal: AbortSignal): Promise<void>;
  list(
    secret: S3ConnectionSecret,
    prefix: string,
    signal: AbortSignal,
  ): Promise<S3Object[]>;
  upload(
    secret: S3ConnectionSecret,
    key: string,
    body: AsyncIterable<Uint8Array>,
    signal: AbortSignal,
  ): Promise<number>;
  download(
    secret: S3ConnectionSecret,
    key: string,
    signal: AbortSignal,
  ): Promise<S3Download>;
  delete(
    secret: S3ConnectionSecret,
    key: string,
    signal: AbortSignal,
  ): Promise<void>;
}

export interface SQLQueryResult {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
}

export interface SQLExecResult {
  rowsAffected: number;
  lastInsertId?: string;
}

export interface SQLOptions {
  timeoutMs: number;
  rowLimit: number;
  signal: AbortSignal;
}

export type SQLConnectionSecret =
  MySQLConnectionSecret | PostgresConnectionSecret;

export interface SQLGateway {
  test(secret: SQLConnectionSecret, signal: AbortSignal): Promise<void>;
  tables(secret: SQLConnectionSecret, signal: AbortSignal): Promise<string[]>;
  query(
    secret: SQLConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: SQLOptions,
  ): Promise<SQLQueryResult>;
  exec(
    secret: SQLConnectionSecret,
    statement: string,
    parameters: unknown[],
    options: Omit<SQLOptions, "rowLimit">,
  ): Promise<SQLExecResult>;
}
