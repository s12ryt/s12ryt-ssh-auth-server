import rateLimit from "@fastify/rate-limit";
import Fastify, { type FastifyInstance, type FastifyRequest } from "fastify";

import type { Principal } from "../domain/models.js";
import { InvalidTokenError, ServiceError } from "../errors.js";
import { ProxyService } from "../proxy/proxy-service.js";
import type { SSHWorkspaceImportResolution } from "../security/ssh-export-package.js";
import { AdminService } from "../services/admin-service.js";
import { AuthService } from "../services/auth-service.js";
import type {
  SSHHostInput,
  SSHKeyIdentityInput,
  SSHSessionHistoryInput,
  SSHSessionHistoryUpdate,
  SSHSnippetInput,
  SSHTunnelInput,
  SSHTunnelRuntimeUpdate,
  SSHWorkspaceExportRequest,
  SSHWorkspacePreferencesInput,
} from "../services/ssh-host-service.js";
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
    trustedFingerprint: { type: "string", maxLength: 256 },
    enabled: { type: "boolean" },
    favorite: { type: "boolean" },
    groupPath: { type: "string", maxLength: 255 },
    tags: {
      type: "array",
      maxItems: 32,
      items: { type: "string", minLength: 1, maxLength: 50 },
    },
    sortOrder: { type: "integer", minimum: 0 },
    authMethod: { type: "string", enum: ["password", "private_key"] },
    clearTerminalAppearance: { type: "boolean" },
    settings: {
      type: "object",
      additionalProperties: false,
      properties: {
        tcpTimeoutMs: { type: "integer", minimum: 0 },
        sshHandshakeTimeoutMs: { type: "integer", minimum: 0 },
        ptyTimeoutMs: { type: "integer", minimum: 0 },
        keepaliveIntervalMs: { type: "integer", minimum: 0 },
        failureCount: { type: "integer", minimum: 0, maximum: 20 },
        idleTimeoutMs: { type: "integer", minimum: 0 },
        compression: { type: "boolean" },
        startupCommand: { type: "string", maxLength: 4096 },
        initialDirectory: { type: "string", maxLength: 4096 },
        environment: {
          type: "object",
          additionalProperties: { type: "string", maxLength: 4096 },
          maxProperties: 64,
        },
        autoReconnect: { type: "boolean" },
        terminalAppearance: {
          type: "object",
          additionalProperties: false,
          properties: {
            font: { type: "string", enum: ["builtin-mono", "system-mono"] },
            fontSize: { type: "number", minimum: 8, maximum: 32 },
            foreground: { type: "string", pattern: "^#[0-9a-fA-F]{6}$" },
            background: { type: "string", pattern: "^#[0-9a-fA-F]{6}$" },
          },
        },
      },
    },
  },
} as const;

const sshHostCloneSchema = {
  type: "object",
  additionalProperties: false,
  required: ["name"],
  properties: { name: { type: "string", minLength: 1, maxLength: 100 } },
} as const;

const sshWorkspacePreferencesSchema = {
  type: "object",
  additionalProperties: false,
  required: ["terminalAppearance"],
  properties: {
    terminalAppearance: {
      type: "object",
      additionalProperties: false,
      required: ["font", "fontSize", "foreground", "background"],
      properties: {
        font: { type: "string", enum: ["builtin-mono", "system-mono"] },
        fontSize: { type: "number", minimum: 8, maximum: 32 },
        foreground: { type: "string", pattern: "^#[0-9a-fA-F]{6}$" },
        background: { type: "string", pattern: "^#[0-9a-fA-F]{6}$" },
      },
    },
  },
} as const;

const sshFingerprintSchema = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint"],
  properties: {
    fingerprint: { type: "string", minLength: 3, maxLength: 256 },
    source: { type: "string", enum: ["tofu", "manual"] },
  },
} as const;

const sshTunnelBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["name", "hostId", "type", "listenHost", "listenPort"],
  properties: {
    name: { type: "string", minLength: 1, maxLength: 100 },
    hostId: { type: "string", minLength: 1, maxLength: 128 },
    type: { type: "string", enum: ["local", "remote", "dynamic_socks"] },
    listenHost: { type: "string", minLength: 1, maxLength: 255 },
    listenPort: { type: "integer", minimum: 1, maximum: 65535 },
    targetHost: { type: "string", maxLength: 255 },
    targetPort: { type: "integer", minimum: 0, maximum: 65535 },
    enabled: { type: "boolean" },
    autoStart: { type: "boolean" },
  },
} as const;

const sshTunnelRuntimeSchema = {
  type: "object",
  additionalProperties: false,
  required: ["running", "trafficUpBytes", "trafficDownBytes"],
  properties: {
    running: { type: "boolean" },
    trafficUpBytes: {
      type: "integer",
      minimum: 0,
      maximum: Number.MAX_SAFE_INTEGER,
    },
    trafficDownBytes: {
      type: "integer",
      minimum: 0,
      maximum: Number.MAX_SAFE_INTEGER,
    },
  },
} as const;

const sshSnippetBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["name", "command"],
  properties: {
    name: { type: "string", minLength: 1, maxLength: 100 },
    command: { type: "string", minLength: 1, maxLength: 8192 },
    variables: {
      type: "array",
      maxItems: 32,
      items: { type: "string", minLength: 1, maxLength: 64 },
    },
    secrets: {
      type: "object",
      maxProperties: 32,
      additionalProperties: { type: "string", maxLength: 4096 },
    },
    enabled: { type: "boolean" },
  },
} as const;

const sshKeyIdentityBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["name"],
  properties: {
    name: { type: "string", minLength: 1, maxLength: 100 },
    publicKey: { type: "string", maxLength: 8192 },
    fingerprint: { type: "string", maxLength: 256 },
    privateKey: { type: "string", maxLength: 65536 },
    keyPassphrase: { type: "string", maxLength: 4096 },
    clearSecretMaterial: { type: "boolean" },
    enabled: { type: "boolean" },
  },
} as const;

const sshSessionHistoryBodySchema = {
  type: "object",
  additionalProperties: false,
  required: ["hostId", "status"],
  properties: {
    hostId: { type: "string", minLength: 1, maxLength: 128 },
    status: {
      type: "string",
      enum: ["connecting", "connected", "failed", "closed"],
    },
    latencyMs: { type: "integer", minimum: 0, maximum: 86_400_000 },
    errorMessage: { type: "string", maxLength: 4096 },
  },
} as const;

const sshWorkspaceExportSchema = {
  type: "object",
  additionalProperties: false,
  required: ["includeSecrets"],
  properties: {
    includeSecrets: { type: "boolean" },
    password: { type: "string", minLength: 1, maxLength: 4096 },
  },
} as const;

const sshWorkspaceImportPreviewSchema = {
  type: "object",
  additionalProperties: false,
  required: ["package"],
  properties: {
    package: { type: "string", minLength: 1, maxLength: 16 * 1024 * 1024 },
    password: { type: "string", maxLength: 4096 },
  },
} as const;

const sshWorkspaceImportApplySchema = {
  type: "object",
  additionalProperties: false,
  required: ["package", "resolutions"],
  properties: {
    package: { type: "string", minLength: 1, maxLength: 16 * 1024 * 1024 },
    password: { type: "string", maxLength: 4096 },
    resolutions: {
      type: "array",
      maxItems: 10_000,
      items: {
        type: "object",
        additionalProperties: false,
        required: ["kind", "name", "action"],
        properties: {
          kind: {
            type: "string",
            enum: ["host", "tunnel", "snippet", "key"],
          },
          name: { type: "string", minLength: 1, maxLength: 100 },
          action: {
            type: "string",
            enum: ["overwrite", "skip", "copy"],
          },
        },
      },
    },
  },
} as const;

const sshSessionHistoryUpdateSchema = {
  type: "object",
  additionalProperties: false,
  required: ["status"],
  properties: {
    status: {
      type: "string",
      enum: ["connecting", "connected", "failed", "closed"],
    },
    latencyMs: { type: "integer", minimum: 0, maximum: 86_400_000 },
    errorMessage: { type: "string", maxLength: 4096 },
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

  app.get("/api/v1/ssh/preferences", async (request) => {
    const identity = await principal(request, options.auth);
    return options.ssh.getWorkspacePreferences(identity.accountId);
  });

  app.patch<{ Body: SSHWorkspacePreferencesInput }>(
    "/api/v1/ssh/preferences",
    { schema: { body: sshWorkspacePreferencesSchema } },
    async (request) => {
      const identity = await principal(request, options.auth);
      return options.ssh.updateWorkspacePreferences(
        sshContext(identity, request),
        request.body,
      );
    },
  );

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

  app.post<{
    Params: { hostId: string };
    Body: { name: string };
  }>(
    "/api/v1/ssh/hosts/:hostId/clone",
    { schema: { body: sshHostCloneSchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const host = options.ssh.cloneHost(
        sshContext(identity, request),
        request.params.hostId,
        request.body.name,
      );
      return reply.status(201).send(host);
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

  app.put<{
    Params: { hostId: string };
    Body: { fingerprint: string; source?: "tofu" | "manual" };
  }>(
    "/api/v1/ssh/hosts/:hostId/fingerprint",
    { schema: { body: sshFingerprintSchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.setFingerprint(
        sshContext(identity, request),
        request.params.hostId,
        request.body.fingerprint,
        request.body.source,
      );
      return reply.status(204).send();
    },
  );

  app.get<{ Params: { hostId: string } }>(
    "/api/v1/ssh/hosts/:hostId/fingerprints",
    async (request) => {
      const identity = await principal(request, options.auth);
      return {
        fingerprints: options.ssh.listHostFingerprints(
          sshContext(identity, request),
          request.params.hostId,
        ),
      };
    },
  );

  app.delete<{ Params: { hostId: string } }>(
    "/api/v1/ssh/hosts/:hostId/fingerprint",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.clearFingerprint(
        sshContext(identity, request),
        request.params.hostId,
      );
      return reply.status(204).send();
    },
  );

  app.get("/api/v1/ssh/tunnels", async (request) => {
    const identity = await principal(request, options.auth);
    return { tunnels: options.ssh.listTunnels(identity.accountId) };
  });

  app.post<{ Body: SSHTunnelInput }>(
    "/api/v1/ssh/tunnels",
    { schema: { body: sshTunnelBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const tunnel = options.ssh.createTunnel(
        sshContext(identity, request),
        request.body,
      );
      return reply.status(201).send(tunnel);
    },
  );

  app.patch<{ Params: { tunnelId: string }; Body: SSHTunnelInput }>(
    "/api/v1/ssh/tunnels/:tunnelId",
    { schema: { body: sshTunnelBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const tunnel = options.ssh.updateTunnel(
        sshContext(identity, request),
        request.params.tunnelId,
        request.body,
      );
      return reply.status(200).send(tunnel);
    },
  );

  app.patch<{
    Params: { tunnelId: string };
    Body: SSHTunnelRuntimeUpdate;
  }>(
    "/api/v1/ssh/tunnels/:tunnelId/runtime",
    { schema: { body: sshTunnelRuntimeSchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const tunnel = options.ssh.updateTunnelRuntime(
        sshContext(identity, request),
        request.params.tunnelId,
        request.body,
      );
      return reply.status(200).send(tunnel);
    },
  );

  app.delete<{ Params: { tunnelId: string } }>(
    "/api/v1/ssh/tunnels/:tunnelId",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.deleteTunnel(
        sshContext(identity, request),
        request.params.tunnelId,
      );
      return reply.status(204).send();
    },
  );

  app.get("/api/v1/ssh/snippets", async (request) => {
    const identity = await principal(request, options.auth);
    return { snippets: options.ssh.listSnippets(identity.accountId) };
  });

  app.post<{ Body: SSHSnippetInput }>(
    "/api/v1/ssh/snippets",
    { schema: { body: sshSnippetBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const snippet = options.ssh.createSnippet(
        sshContext(identity, request),
        request.body,
      );
      return reply.status(201).send(snippet);
    },
  );

  app.patch<{ Params: { snippetId: string }; Body: SSHSnippetInput }>(
    "/api/v1/ssh/snippets/:snippetId",
    { schema: { body: sshSnippetBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const snippet = options.ssh.updateSnippet(
        sshContext(identity, request),
        request.params.snippetId,
        request.body,
      );
      return reply.status(200).send(snippet);
    },
  );

  app.delete<{ Params: { snippetId: string } }>(
    "/api/v1/ssh/snippets/:snippetId",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.deleteSnippet(
        sshContext(identity, request),
        request.params.snippetId,
      );
      return reply.status(204).send();
    },
  );

  app.get<{ Params: { snippetId: string } }>(
    "/api/v1/ssh/snippets/:snippetId/secrets",
    async (request) => {
      const identity = await principal(request, options.auth);
      return options.ssh.getSnippetSecrets(
        sshContext(identity, request),
        request.params.snippetId,
      );
    },
  );

  app.get("/api/v1/ssh/keys", async (request) => {
    const identity = await principal(request, options.auth);
    return { keys: options.ssh.listKeyIdentities(identity.accountId) };
  });

  app.post<{ Body: SSHKeyIdentityInput }>(
    "/api/v1/ssh/keys",
    { schema: { body: sshKeyIdentityBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const key = options.ssh.createKeyIdentity(
        sshContext(identity, request),
        request.body,
      );
      return reply.status(201).send(key);
    },
  );

  app.patch<{ Params: { keyId: string }; Body: SSHKeyIdentityInput }>(
    "/api/v1/ssh/keys/:keyId",
    { schema: { body: sshKeyIdentityBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const key = options.ssh.updateKeyIdentity(
        sshContext(identity, request),
        request.params.keyId,
        request.body,
      );
      return reply.status(200).send(key);
    },
  );

  app.delete<{ Params: { keyId: string } }>(
    "/api/v1/ssh/keys/:keyId",
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      options.ssh.deleteKeyIdentity(
        sshContext(identity, request),
        request.params.keyId,
      );
      return reply.status(204).send();
    },
  );

  app.get<{ Params: { keyId: string } }>(
    "/api/v1/ssh/keys/:keyId/secrets",
    async (request) => {
      const identity = await principal(request, options.auth);
      return options.ssh.getKeyIdentitySecrets(
        sshContext(identity, request),
        request.params.keyId,
      );
    },
  );

  app.get("/api/v1/ssh/session-history", async (request) => {
    const identity = await principal(request, options.auth);
    return { history: options.ssh.listSessionHistory(identity.accountId) };
  });

  app.post<{ Body: SSHSessionHistoryInput }>(
    "/api/v1/ssh/session-history",
    { schema: { body: sshSessionHistoryBodySchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const history = options.ssh.createSessionHistory(
        sshContext(identity, request),
        request.body,
      );
      return reply.status(201).send(history);
    },
  );

  app.patch<{
    Params: { historyId: string };
    Body: SSHSessionHistoryUpdate;
  }>(
    "/api/v1/ssh/session-history/:historyId",
    { schema: { body: sshSessionHistoryUpdateSchema } },
    async (request, reply) => {
      const identity = await principal(request, options.auth);
      const history = options.ssh.updateSessionHistory(
        sshContext(identity, request),
        request.params.historyId,
        request.body,
      );
      return reply.status(200).send(history);
    },
  );

  app.post<{ Body: SSHWorkspaceExportRequest }>(
    "/api/v1/ssh/workspace/export",
    { schema: { body: sshWorkspaceExportSchema } },
    async (request) => {
      const identity = await principal(request, options.auth);
      return {
        package: await options.ssh.exportWorkspace(
          sshContext(identity, request),
          request.body,
        ),
      };
    },
  );

  app.post<{ Body: { package: string; password?: string } }>(
    "/api/v1/ssh/workspace/import/preview",
    { schema: { body: sshWorkspaceImportPreviewSchema } },
    async (request) => {
      const identity = await principal(request, options.auth);
      return options.ssh.previewWorkspaceImport(
        sshContext(identity, request),
        request.body.package,
        request.body.password,
      );
    },
  );

  app.post<{
    Body: {
      package: string;
      password?: string;
      resolutions: SSHWorkspaceImportResolution[];
    };
  }>(
    "/api/v1/ssh/workspace/import/apply",
    { schema: { body: sshWorkspaceImportApplySchema } },
    async (request) => {
      const identity = await principal(request, options.auth);
      return options.ssh.applyWorkspaceImport(
        sshContext(identity, request),
        request.body.package,
        request.body.password,
        request.body.resolutions,
      );
    },
  );

  return app;
}
