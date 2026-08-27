export class ServiceError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly statusCode: number,
  ) {
    super(message);
    this.name = "ServiceError";
  }
}

export class InvalidCredentialsError extends ServiceError {
  constructor(message = "invalid username or password") {
    super("invalid_credentials", message, 401);
  }
}

export class DisabledError extends ServiceError {
  constructor(message = "account is disabled") {
    super("disabled", message, 403);
  }
}

export class InvalidTokenError extends ServiceError {
  constructor(message = "invalid or expired token") {
    super("invalid_token", message, 401);
  }
}

export class RefreshReuseError extends ServiceError {
  constructor() {
    super("refresh_reuse", "refresh token reuse detected", 401);
  }
}

export class DeviceLimitError extends ServiceError {
  constructor() {
    super("device_limit", "device limit reached", 403);
  }
}

export class NotFoundError extends ServiceError {
  constructor(resource: string) {
    super("not_found", `${resource} not found`, 404);
  }
}

export class ConflictError extends ServiceError {
  constructor(message: string) {
    super("conflict", message, 409);
  }
}

export class ForbiddenError extends ServiceError {
  constructor(message = "operation is not allowed") {
    super("forbidden", message, 403);
  }
}
