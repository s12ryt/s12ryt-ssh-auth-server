import { randomUUID } from "node:crypto";

import type { Principal } from "../domain/models.js";
import {
  DisabledError,
  InvalidCredentialsError,
  InvalidTokenError,
  RefreshReuseError,
} from "../errors.js";
import { SqliteRepository } from "../repository/sqlite-repository.js";
import {
  generateOpaqueToken,
  hashToken,
  verifyPassword,
} from "../security/crypto.js";

interface AuthServiceOptions {
  accessTokenTtlMs: number;
  refreshTokenTtlMs: number;
  clock?: () => number;
}

interface LoginInput {
  username: string;
  password: string;
  deviceId: string;
  ipAddress: string;
  userAgent: string;
}

export interface TokenPair {
  accessToken: string;
  accessExpiresAt: number;
  refreshToken: string;
  refreshExpiresAt: number;
  account: {
    id: string;
    username: string;
  };
  sessionId: string;
}

export class AuthService {
  readonly #clock: () => number;

  constructor(
    private readonly repository: SqliteRepository,
    private readonly options: AuthServiceOptions,
  ) {
    this.#clock = options.clock ?? Date.now;
  }

  async login(input: LoginInput): Promise<TokenPair> {
    const account = this.repository.findAccountByUsername(
      input.username.trim(),
    );
    if (
      !account ||
      !(await verifyPassword(input.password, account.passwordHash))
    ) {
      throw new InvalidCredentialsError();
    }
    if (!account.enabled) {
      throw new DisabledError();
    }
    if (!input.deviceId.trim()) {
      throw new InvalidCredentialsError("device ID is required");
    }
    const now = this.#clock();
    const accessToken = generateOpaqueToken();
    const refreshToken = generateOpaqueToken();
    const sessionId = randomUUID();
    const accessExpiresAt = now + this.options.accessTokenTtlMs;
    const refreshExpiresAt = now + this.options.refreshTokenTtlMs;
    this.repository.createLoginSession({
      session: {
        id: sessionId,
        familyId: randomUUID(),
        accountId: account.id,
        deviceId: input.deviceId.trim(),
        refreshHash: hashToken(refreshToken),
        refreshExpiresAt,
        revokedAt: null,
        createdAt: now,
        lastUsedAt: now,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
      },
      accessTokenHash: hashToken(accessToken),
      accessExpiresAt,
      deviceLimit: account.deviceLimit,
      now,
    });
    return {
      accessToken,
      accessExpiresAt,
      refreshToken,
      refreshExpiresAt,
      account: { id: account.id, username: account.username },
      sessionId,
    };
  }

  async refresh(refreshToken: string, deviceId: string): Promise<TokenPair> {
    await Promise.resolve();
    const now = this.#clock();
    const currentHash = hashToken(refreshToken);
    const session = this.repository.findSessionByRefreshHash(currentHash);
    if (!session) {
      const reusedFamily = this.repository.findRefreshFamily(currentHash);
      if (reusedFamily) {
        this.repository.revokeFamily(reusedFamily, now);
        throw new RefreshReuseError();
      }
      throw new InvalidTokenError();
    }
    if (!session.accountEnabled) {
      this.repository.revokeFamily(session.familyId, now);
      throw new DisabledError();
    }
    if (
      session.revokedAt !== null ||
      session.refreshExpiresAt <= now ||
      session.deviceId !== deviceId.trim()
    ) {
      throw new InvalidTokenError();
    }

    const accessToken = generateOpaqueToken();
    const nextRefreshToken = generateOpaqueToken();
    const accessExpiresAt = now + this.options.accessTokenTtlMs;
    const refreshExpiresAt = now + this.options.refreshTokenTtlMs;
    this.repository.rotateSession({
      sessionId: session.id,
      currentRefreshHash: currentHash,
      nextRefreshHash: hashToken(nextRefreshToken),
      nextRefreshExpiresAt: refreshExpiresAt,
      accessTokenHash: hashToken(accessToken),
      accessExpiresAt,
      now,
    });
    return {
      accessToken,
      accessExpiresAt,
      refreshToken: nextRefreshToken,
      refreshExpiresAt,
      account: { id: session.accountId, username: session.username },
      sessionId: session.id,
    };
  }

  async authenticate(accessToken: string): Promise<Principal> {
    await Promise.resolve();
    const principal = this.repository.authenticateAccess(
      hashToken(accessToken),
      this.#clock(),
    );
    if (!principal) {
      throw new InvalidTokenError();
    }
    return principal;
  }

  logout(sessionId: string): void {
    this.repository.revokeSession(sessionId, this.#clock());
  }
}
