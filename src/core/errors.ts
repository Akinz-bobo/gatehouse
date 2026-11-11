/** An error the caller can act on, with a stable code and an HTTP status. */
export class AuthError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AuthError';
  }
}

export const errors = {
  // Deliberately vague: the same answer for a wrong password, an unknown
  // email, a locked account and a disabled one, so none can be told apart.
  invalidCredentials: () =>
    new AuthError('invalid_credentials', 'The email or password is incorrect', 401),
  unauthenticated: () => new AuthError('unauthenticated', 'A valid access token is required', 401),
  invalidRefreshToken: () =>
    new AuthError('invalid_refresh_token', 'The refresh token is invalid or has expired', 401),
  refreshTokenReused: () =>
    new AuthError(
      'refresh_token_reused',
      'This refresh token was already used. The session has been ended as a precaution',
      401,
    ),
  forbidden: (permission?: string) =>
    new AuthError('forbidden', 'You do not have permission to do this', 403, {
      ...(permission ? { permission } : {}),
    }),
  emailTaken: () => new AuthError('email_taken', 'An account with this email already exists', 409),
  weakPassword: (reason: string) => new AuthError('weak_password', reason, 422),
  invalidToken: (what: string) =>
    new AuthError('invalid_token', `The ${what} is invalid or has expired`, 400),
  notFound: (what: string) => new AuthError('not_found', `${what} not found`, 404),
  conflict: (code: string, message: string) => new AuthError(code, message, 409),
  invalid: (code: string, message: string) => new AuthError(code, message, 422),
  moduleDisabled: (module: string) =>
    new AuthError('module_disabled', `The ${module} module is not enabled`, 404),
};
