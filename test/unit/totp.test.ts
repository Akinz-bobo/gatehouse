import { describe, expect, it } from 'vitest';
import {
  base32Decode,
  base32Encode,
  codeForStep,
  generateSecret,
  provisioningUri,
  stepAt,
  verifyCode,
} from '../../src/crypto/totp.js';

// The shared secret used by the RFC 6238 test vectors: ASCII "12345678901234567890".
const RFC_SECRET = base32Encode(Buffer.from('12345678901234567890'));

describe('TOTP (RFC 6238)', () => {
  it.each([
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
  ])('matches the RFC test vector at t=%d', (seconds, expected) => {
    expect(codeForStep(RFC_SECRET, stepAt(new Date(seconds * 1000)), 8)).toBe(expected);
  });

  it('accepts the current code and its neighbours, to allow for clock drift', () => {
    const secret = generateSecret();
    const now = new Date('2026-01-01T00:00:00Z');
    const step = stepAt(now);

    expect(verifyCode(secret, codeForStep(secret, step), now)).toBe(step);
    expect(verifyCode(secret, codeForStep(secret, step - 1n), now)).toBe(step - 1n);
    expect(verifyCode(secret, codeForStep(secret, step + 1n), now)).toBe(step + 1n);
  });

  it('rejects a code from two steps away', () => {
    const secret = generateSecret();
    const now = new Date('2026-01-01T00:00:00Z');
    expect(verifyCode(secret, codeForStep(secret, stepAt(now) - 2n), now)).toBeNull();
  });

  it.each(['12345', '1234567', 'abcdef', '', '12 456'])('rejects the malformed code %j', (code) => {
    expect(verifyCode(generateSecret(), code)).toBeNull();
  });

  it('round-trips base32', () => {
    const data = Buffer.from('hello, gatehouse');
    expect(base32Decode(base32Encode(data))).toEqual(data);
  });

  it('builds a provisioning URI an authenticator app can read', () => {
    const uri = new URL(provisioningUri('ABCDEFGH', 'ada@example.com', 'auth.example.com'));
    expect(uri.protocol).toBe('otpauth:');
    expect(uri.pathname).toBe('/auth.example.com:ada%40example.com');
    expect(uri.searchParams.get('secret')).toBe('ABCDEFGH');
    expect(uri.searchParams.get('issuer')).toBe('auth.example.com');
  });
});
