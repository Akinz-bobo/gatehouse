import { errors } from './errors.js';

export const MIN_PASSWORD_LENGTH = 12;
// Argon2 would accept more, but an unbounded input is a denial-of-service lever.
export const MAX_PASSWORD_LENGTH = 128;

const COMMON = new Set([
  'password1234',
  'password12345',
  '123456789012',
  '1234567890123',
  'qwertyuiop12',
  'qwertyuiopas',
  'iloveyou1234',
  'administrator',
  'letmein12345',
  'welcome12345',
  'passwordpassword',
  'changeme1234',
]);

/**
 * Follows NIST SP 800-63B: require length, forbid known-bad choices, and
 * impose no composition rules (forced symbols make passwords worse, not
 * better). Throws when the password is not acceptable.
 */
export function assertAcceptablePassword(password: string, email: string): void {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw errors.weakPassword(`Use at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw errors.weakPassword(`Use at most ${MAX_PASSWORD_LENGTH} characters`);
  }
  const lowered = password.toLowerCase();
  if (COMMON.has(lowered)) throw errors.weakPassword('This password is too common');
  if (new Set(lowered).size < 5) {
    throw errors.weakPassword('This password is too repetitive');
  }
  const localPart = email.split('@')[0]?.toLowerCase() ?? '';
  if (localPart.length >= 4 && lowered.includes(localPart)) {
    throw errors.weakPassword('Do not base your password on your email address');
  }
}
