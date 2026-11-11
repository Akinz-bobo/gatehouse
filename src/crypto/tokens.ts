import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** A URL-safe random token with 256 bits of entropy by default. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/**
 * Opaque tokens (refresh tokens, reset tokens, OAuth state) are stored only
 * as SHA-256 digests. They are long random values, so a fast hash is enough:
 * there is nothing to brute-force, unlike a password.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Compares two strings without leaking, through timing, where they differ. */
export function constantTimeEqual(a: string, b: string): boolean {
  const left = createHash('sha256').update(a).digest();
  const right = createHash('sha256').update(b).digest();
  return timingSafeEqual(left, right);
}
