import assert from "node:assert/strict";
import { Readable } from "node:stream";
import test from "node:test";

import { AwsS3Gateway } from "../src/adapters/s3-gateway.js";
import {
  DriverSQLGateway,
  type MySQLConnectionLike,
  type PostgresClientLike,
} from "../src/adapters/sql-gateway.js";
import type {
  MySQLConnectionSecret,
  PostgresConnectionSecret,
  S3ConnectionSecret,
} from "../src/domain/models.js";

const s3Secret: S3ConnectionSecret = {
  kind: "s3",
  endpoint: "https://storage.example.com",
  region: "auto",
  bucket: "bucket",
  prefix: "tenant/",
  usePathStyle: true,
  accessKeyId: "access",
  secretAccessKey: "secret",
};

test("AWS S3 adapter paginates and streams object operations", async () => {
  const commandNames: string[] = [];
  const client = {
    async send(command: {
      constructor: { name: string };
      input?: Record<string, unknown>;
    }) {
      commandNames.push(command.constructor.name);
      if (command.constructor.name === "ListObjectsV2Command") {
        const token = command.input?.ContinuationToken;
        return token
          ? {
              Contents: [{ Key: "prefix/two.txt", Size: 2 }],
              IsTruncated: false,
            }
          : {
              Contents: [{ Key: "prefix/one.txt", Size: 1 }],
              IsTruncated: true,
              NextContinuationToken: "next",
            };
      }
      if (command.constructor.name === "GetObjectCommand") {
        return {
          Body: Readable.from(Buffer.from("payload")),
          ContentLength: 7,
          ContentType: "text/plain",
        };
      }
      return {};
    },
  };
  const gateway = new AwsS3Gateway(() => client);
  const signal = new AbortController().signal;

  assert.deepEqual(await gateway.list(s3Secret, "prefix/", signal), [
    { key: "prefix/one.txt", size: 1 },
    { key: "prefix/two.txt", size: 2 },
  ]);
  await gateway.upload(
    s3Secret,
    "prefix/new.txt",
    Readable.from(Buffer.from("new")),
    signal,
  );
  const downloaded = await gateway.download(s3Secret, "prefix/new.txt", signal);
  assert.equal((await downloaded.body.toArray()).join(""), "payload");
  await gateway.delete(s3Secret, "prefix/new.txt", signal);
  assert.deepEqual(commandNames, [
    "ListObjectsV2Command",
    "ListObjectsV2Command",
    "PutObjectCommand",
    "GetObjectCommand",
    "DeleteObjectCommand",
  ]);
});

test("MySQL query uses a read-only transaction and truncates rows", async () => {
  const calls: string[] = [];
  const connection: MySQLConnectionLike = {
    async ping() {},
    async query(statement) {
      const sql = typeof statement === "string" ? statement : statement.sql;
      calls.push(sql);
      if (sql === "SELECT id FROM users") {
        return [[{ id: 1 }, { id: 2 }], [{ name: "id" }]];
      }
      return [[], []];
    },
    async end() {
      calls.push("END");
    },
  };
  const gateway = new DriverSQLGateway({
    mysqlFactory: async () => connection,
  });
  const secret: MySQLConnectionSecret = {
    kind: "mysql",
    host: "db.example.com",
    port: 3306,
    user: "proxy",
    password: "secret",
    database: "app",
    tlsMode: "true",
  };

  const result = await gateway.query(secret, "SELECT id FROM users", [], {
    timeoutMs: 5000,
    rowLimit: 1,
    signal: new AbortController().signal,
  });
  assert.deepEqual(result, { columns: ["id"], rows: [[1]], truncated: true });
  assert.deepEqual(calls, [
    "SET SESSION MAX_EXECUTION_TIME = ?",
    "START TRANSACTION READ ONLY",
    "SELECT id FROM users",
    "ROLLBACK",
    "END",
  ]);
});

test("PostgreSQL query uses read-only transaction and statement timeout", async () => {
  const calls: string[] = [];
  const client: PostgresClientLike = {
    async connect() {
      calls.push("CONNECT");
    },
    async query(config) {
      const text = typeof config === "string" ? config : config.text;
      calls.push(text);
      if (text === "SELECT id FROM users") {
        return { fields: [{ name: "id" }], rows: [[1], [2]], rowCount: 2 };
      }
      return { fields: [], rows: [], rowCount: 0 };
    },
    async end() {
      calls.push("END");
    },
  };
  const gateway = new DriverSQLGateway({ postgresFactory: () => client });
  const secret: PostgresConnectionSecret = {
    kind: "postgres",
    host: "db.example.com",
    port: 5432,
    user: "proxy",
    password: "secret",
    database: "app",
    sslMode: "verify-full",
  };

  const result = await gateway.query(secret, "SELECT id FROM users", [], {
    timeoutMs: 5000,
    rowLimit: 1,
    signal: new AbortController().signal,
  });
  assert.deepEqual(result, { columns: ["id"], rows: [[1]], truncated: true });
  assert.deepEqual(calls, [
    "CONNECT",
    "BEGIN READ ONLY",
    "SET LOCAL statement_timeout = 5000",
    "SELECT id FROM users",
    "ROLLBACK",
    "END",
  ]);
});
