import { createHmac, randomBytes } from 'node:crypto';
import { constantTimeEqual } from './tokens.js';

// Time-based one-time passwords, RFC 6238, with the parameters every
// authenticator app expects: HMAC-SHA1, 6 digits, 30-second steps.
const STEP_SECONDS = 30;
const DIGITS = 6;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateSecret(bytes = 20): string {
  return base32Encode(randomBytes(bytes));
}

export function base32Encode(data: Buffer): string {
  let bits = '';
  for (const byte of data) bits += byte.toString(2).padStart(8, '0');
  let output = '';
  for (let index = 0; index < bits.length; index += 5) {
    output += BASE32.charAt(parseInt(bits.slice(index, index + 5).padEnd(5, '0'), 2));
  }
  return output;
}

export function base32Decode(value: string): Buffer {
  let bits = '';
  for (const char of value.replace(/=+$/, '').toUpperCase()) {
    const index = BASE32.indexOf(char);
    if (index === -1) throw new Error('Invalid base32 character');
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

export function stepAt(date: Date): bigint {
  return BigInt(Math.floor(date.getTime() / 1000 / STEP_SECONDS));
}

/** The code for one time step (RFC 4226 dynamic truncation). */
export function codeForStep(secret: string, step: bigint, digits = DIGITS): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(step);
  const digest = createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = (digest.at(-1) ?? 0) & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

/**
 * Checks a code against the current step and one step either side, to allow
 * for clock drift. Returns the step that matched, so the caller can refuse a
 * second use of the same code, or null if none did.
 */
export function verifyCode(secret: string, code: string, now = new Date()): bigint | null {
  if (!/^\d{6}$/.test(code)) return null;
  const current = stepAt(now);
  let matched: bigint | null = null;
  // Check every step, without stopping early, so timing reveals nothing.
  for (const step of [current - 1n, current, current + 1n]) {
    if (constantTimeEqual(codeForStep(secret, step), code)) matched = step;
  }
  return matched;
}

/** The URI an authenticator app reads from a QR code. */
export function provisioningUri(secret: string, account: string, issuer: string): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: 'SHA1',
    digits: String(DIGITS),
    period: String(STEP_SECONDS),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
