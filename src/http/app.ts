import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";

import type { Principal } from "../domain/models.js";
import { InvalidTokenError, ServiceError } from "../errors.js";
import { ProxyService } from "../proxy/proxy-service.js";
import { AdminService } from "../services/admin-service.js";
import { AuthService } from "../services/auth-service.js";
import type { SSHHostInput } from "../services/ssh-host-service.js";
import { SSHHostService } from "../services/ssh-host-service.js";

export interface HttpAppOptions {
  auth: AuthService;
  admin: AdminService;
  proxy: ProxyService;
  ssh: SSHHostService;
  allowInsecureHttp: boolean;
  trustedProxies: string[];
  loginRateLimit: number;
  apiRateLimit: number;
}

const credentialsSchema = {
  type: "object",
  additionalProperties: false,
  required: ["username", "password", "deviceId"],
  properties: {
    username: { type: "string", minLength: 1, maxLength: 64 },
    password: { type: "string", minLength: 1, maxLength: 512 },
    deviceId: { type: "string", minLength: 1, maxLength: 128 },
  },
} as const;

const refreshSchema = {
  type: "object",
  additionalProperties: false,
  required: ["refreshToken", "deviceId"],
  properties: {
    refreshToken: { type: "string", minLength: 32, maxLength: 256 },
    deviceId: { type: "string", minLength: 1, maxLength: 128 },
  },
} as const;

const sqlSchema = {
  type: "object",
  additionalProperties: false,
  required: ["statement"],
  properties: {
    statement: { type: "string", minLength: 1, maxLength: 1_000_000 },
    parameters: { type: "array", maxItems: 10_000 },
  },
} as const;

const sshHostBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["name", "host", "username"],
  properties: {
    name: { type: "string", minLength: 1, maxLength: 100 },
    host: { type: "string", minLength: 1, maxLength: 255 },
    port: { type: "integer", minimum: 1, maximum: 65535, default: 22 },
    username: { type: "string", minLength: 1, maxLength: 64 },
    password: { type: "string", maxLength: 512 },
    privateKey: { type: "string", maxLength: 65536 },
    keyPassphrase: { type: "string", maxLength: 512 },
    trustedFingerprint: { type: "string", maxLength: 128 },
  },
} as const;

const sshFingerprintSchema = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint"],
  properties: {
    fingerprint: { type: "string", minLength: 1, maxLength: 128 },
  },
} as const;

function loopback(address: string): boolean {
  const normalized = address.replace(/^::ffff:/, "");
  return (
    normalized === "::1" ||
    normalized === "localhost" ||
    normalized.startsWith("127.")
  );
}

function requireSecureTransport(
  request: FastifyRequest,
  allowInsecureHttp: boolean,
): void {
  if (
    !allowInsecureHttp &&
    request.protocol !== "https" &&
    !loopback(request.ip)
  ) {
    throw new ServiceError(
      "https_required",
      "HTTPS is required for remote authentication",
      400,
    );
  }
}

function abortSignal(request: FastifyRequest): AbortSignal {
  const controller = new AbortController();
  request.raw.once("close", () => controller.abort());
  return controller.signal;
}

function principal(
  request: FastifyRequest,
  auth: AuthService,
): Promise<Principal> {
  const authorization = request.headers.authorization;
  if (!authorization?.startsWith("Bearer ")) {
    throw new InvalidTokenError();
  }
  return auth.authenticate(authorization.slice("Bearer ".length));
}

function operationContext(
  identity: Principal,
  request: FastifyRequest,
  connectionId: string,
) {
  return { principal: identity, connectionId, ipAddress: request.ip };
}

function sshContext(identity: Principal, request: FastifyRequest) {
  return { principal: identity, ipAddress: request.ip };
}

export async function buildHttpApp(
  options: HttpAppOptions,
): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    trustProxy:
      options.trustedProxies.length > 0 ? options.trustedProxies : false,
    bodyLimit: 1024 * 1024,
  });
  await app.register(rateLimit, {
    global: true,
    max: options.apiRateLimit,
    timeWindow: "1 minute",
  });

  app.addContentTypeParser(
    "application/octet-stream",
    (request, payload, done) => {
      void request;
      done(null, payload);
    },
  );

  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof ServiceError) {
      void reply
        .status(error.statusCode)
        .send({ error: { code: error.code, message: error.message } });
      return;
    }
    if (
      typeof error === "object" &&
      error !== null &&
      "validation" in error &&
      error.validation
    ) {
      const message =
        error instanceof Error ? error.message : "request validation failed";
      void reply
        .status(400)
        .send({ error: { code: "validation_error", message } });
      return;
    }
    void reply.status(500).send({
      error: { code: "internal_error", message: "internal server error" },
    });
  });

  app.get("/healthz", () => ({ status: "ok" }));

  app.post<{ Body: { username: string; password: string; deviceId: string } }>(
    "/api/v1/auth/login",
    {
      schema: { body: credentialsSchema },
      config: {
        rateLimit: { max: options.loginRateLimit, timeWindow: "1 minute" },
      },
    },
    (request) => {
      requireSecureTransport(request, options.allowInsecureHttp);
      return options.auth.login({
        ...request.body,
        ipAddress: request.ip,
        userAgent: request.headers["user-agent"] ?? "unknown",
      });
    },
  );

  app.post<{ Body: { refreshToken: string; deviceId: string } }>(
    "/api/v1/auth/refresh",
    {
      schema: { body: refreshSchema },
      config: {
        rateLimit: { max: options.loginRateLimit, timeWindow: "1 minute" },
      },
    },
    (request) => {
      requireSecureTransport(request, options.allowInsecureHttp);
      return options.auth.refresh(
        request.body.refreshToken,
        request.body.deviceId,
      );
    },
  );

  app.post("/api/v1/auth/logout", async (request, reply) => {
    const identity = await principal(request, options.auth);
    options.auth.logout(identity.sessionId);
    return reply.status(204).send();
  });

  app.get("/api/v1/resources", async (request) => {
    const identity = await principal(request, options.auth);
    return {
      resources: options.admin
        .listAssignedConnections(identity.accountId)
        .filter((item) => item.enabled),
      sshEnabled: options.ssh.accessEnabled(identity.accountId),
    };
  });

  app.get<{
    Params: { connectionId: string };
    Querystring: { prefix?: string };
  }>("/api/v1/resources/:connectionId/s3/objects", async (request) => {
    const identity = await principal(request, options.auth);
    const objects = await options.proxy.listS3(
      operationContext(identity, request, request.params.connectionId),
      request.query.prefix ?? "",
      abortSignal(request),
    );
    return { objects };
  });

  app.put<{ Params: { connectionId: string; "*": string } }>(
    "/api/v1/resources/:connectionId/s3/objects/*",
    async (request) => {
      const identity = await principal(request, options.auth);
      const source = request.body;
      if (
        !source ||
        typeof source !== "object" ||
        !(Symbol.asyncIterator in source)
      ) {
        throw new ServiceError(
          "invalid_body",
          "binary request body is required",
          400,
        );
      }
      const contentLengthSource = request.headers["content-length"];
      const contentLength = contentLengthSource
        ? Number(contentLengthSource)
        : undefined;
      return options.proxy.uploadS3(
        operationContext(identity, request, request.params.connectionId),
        request.params["*"],
        source as AsyncIterable<Uint8Array>,
        Number.isFinite(contentLength) ? contentLength : undefined,
        abortSignal(request),
      );
    },
  );

  app.get<{ Params: { connectionId: string; "*": string } }>(
    "/api/v1/resources/:connectionId/s3/download/*",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const download = await options.proxy.downloadS3(
        operationContext(identity, request, request.params.connectionId),
        request.params["*"],
        abortSignal(request),
      );
      if (download.contentLength !== undefined)
        reply.header("content-length", download.contentLength);
      if (download.contentType) reply.type(download.contentType);
      return reply.send(download.body);
    },
  );

  app.delete<{ Params: { connectionId: string; "*": string } }>(
    "/api/v1/resources/:connectionId/s3/objects/*",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      await options.proxy.deleteS3(
        operationContext(identity, request, request.params.connectionId),
        request.params["*"],
        abortSignal(request),
      );
      return reply.status(204).send();
    },
  );

  app.get<{ Params: { connectionId: string } }>(
    "/api/v1/resources/:connectionId/sql/tables",
    async (request) => {
      const identity = await principal(request, options.auth);
      return {
        tables: await options.proxy.tables(
          operationContext(identity, request, request.params.connectionId),
          abortSignal(request),
        ),
      };
    },
  );

  for (const action of ["query", "exec"] as const) {
    app.post<{
      Params: { connectionId: string };
      Body: { statement: string; parameters?: unknown[] };
    }>(
      `/api/v1/resources/:connectionId/sql/${action}`,
      { schema: { body: sqlSchema } },
      async (request) => {
        const identity = await principal(request, options.auth);
        return options.proxy[action](
          operationContext(identity, request, request.params.connectionId),
          request.body.statement,
          request.body.parameters ?? [],
          abortSignal(request),
        );
      },
    );
  }

  app.get("/api/v1/ssh/hosts", async (request) => {
    const identity = await principal(request, options.auth);
    return { hosts: options.ssh.listHosts(identity.accountId) };
  });

  app.post<{ Body: SSHHostInput }>(
    "/api/v1/ssh/hosts",
    { schema: { body: sshHostBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const host = options.ssh.createHost(
        sshContext(identity, request),
        request.body,
      );
      return reply.status(201).send(host);
    },
  );

  app.patch<{ Params: { hostId: string }; Body: SSHHostInput }>(
    "/api/v1/ssh/hosts/:hostId",
    { schema: { body: sshHostBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const host = options.ssh.updateHost(
        sshContext(identity, request),
        request.params.hostId,
        request.body,
      );
      return reply.status(200).send(host);
    },
  );

  app.delete<{ Params: { hostId: string } }>(
    "/api/v1/ssh/hosts/:hostId",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.deleteHost(
        sshContext(identity, request),
        request.params.hostId,
      );
      return reply.status(204).send();
    },
  );

  app.get<{ Params: { hostId: string } }>(
    "/api/v1/ssh/hosts/:hostId/credentials",
    async (request) => {
      const identity = await principal(request, options.auth);
      return options.ssh.getCredentials(
        sshContext(identity, request),
        request.params.hostId,
      );
    },
  );

  app.put<{ Params: { hostId: string }; Body: { fingerprint: string } }>(
    "/api/v1/ssh/hosts/:hostId/fingerprint",
    { schema: { body: sshFingerprintSchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.setFingerprint(
        sshContext(identity, request),
        request.params.hostId,
        request.body.fingerprint,
      );
      return reply.status(204).send();
    },
  );

  return app;
}
