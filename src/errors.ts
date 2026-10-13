/**
 * Иерархия ошибок. Все наследуют {@link SessionError} и несут `code` + `cause`.
 */

export type SessionErrorCode =
  | 'ALREADY_LOGGED_IN'
  | 'NOT_AUTHENTICATED'
  | 'INVALID_TOKEN'
  | 'SESSION_EXPIRED'
  | 'LOGIN_IN_PROGRESS'
  | 'INVALID_ARGUMENT'
  | 'REFRESH_NOT_AVAILABLE'
  | 'REFRESH_FAILED'
  | 'ABORTED'
  | 'DESTROYED';

export class SessionError extends Error {
  public readonly code: SessionErrorCode;
  public override readonly cause?: unknown;

  constructor(code: SessionErrorCode, message: string, cause?: unknown) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    if (cause !== undefined) this.cause = cause;
    Object.setPrototypeOf(this, new.target.prototype);
    const capture = (Error as unknown as { captureStackTrace?: (t: object, c: Function) => void })
      .captureStackTrace;
    if (typeof capture === 'function') capture(this, new.target);
  }
}

export class AlreadyLoggedInError extends SessionError {
  constructor(message = 'Session is already active. Logout first or pass { force: true }.') {
    super('ALREADY_LOGGED_IN', message);
  }
}
export class NotAuthenticatedError extends SessionError {
  constructor(message = 'No active session.') {
    super('NOT_AUTHENTICATED', message);
  }
}
export class InvalidTokenError extends SessionError {
  constructor(message = 'Token is invalid.', cause?: unknown) {
    super('INVALID_TOKEN', message, cause);
  }
}
export class SessionExpiredError extends SessionError {
  constructor(message = 'Session has expired.') {
    super('SESSION_EXPIRED', message);
  }
}
export class InvalidArgumentError extends SessionError {
  constructor(message: string) {
    super('INVALID_ARGUMENT', message);
  }
}
export class RefreshNotAvailableError extends SessionError {
  constructor(message = 'No refresh token or refresher configured.') {
    super('REFRESH_NOT_AVAILABLE', message);
  }
}
export class RefreshFailedError extends SessionError {
  constructor(message = 'Token refresh failed.', cause?: unknown) {
    super('REFRESH_FAILED', message, cause);
  }
}
export class AbortedError extends SessionError {
  constructor(message = 'Operation was aborted.') {
    super('ABORTED', message);
  }
}
export class DestroyedError extends SessionError {
  constructor(message = 'SessionManager has been destroyed.') {
    super('DESTROYED', message);
  }
}
