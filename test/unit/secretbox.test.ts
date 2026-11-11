import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { SecretBox } from '../../src/crypto/secretbox.js';
import { constantTimeEqual, hashToken, randomToken } from '../../src/crypto/tokens.js';

describe('SecretBox', () => {
  const box = new SecretBox(randomBytes(32));

  it('round-trips a value', () => {
    expect(box.decrypt(box.encrypt('a signing key'))).toBe('a signing key');
  });

  it('never produces the same ciphertext twice', () => {
    expect(box.encrypt('same')).not.toBe(box.encrypt('same'));
  });

  it('refuses a ciphertext that has been tampered with', () => {
    const [version, nonce, ciphertext, tag] = box.encrypt('a signing key').split('.');
    const flipped = Buffer.from(ciphertext ?? '', 'base64url');
    flipped[0] = (flipped[0] ?? 0) ^ 1;
    const forged = [version, nonce, flipped.toString('base64url'), tag].join('.');
    expect(() => box.decrypt(forged)).toThrow();
  });

  it('cannot be opened with a different key', () => {
    const other = new SecretBox(randomBytes(32));
    expect(() => other.decrypt(box.encrypt('a signing key'))).toThrow();
  });

  it('rejects a key of the wrong length', () => {
    expect(() => new SecretBox(randomBytes(16))).toThrow(/32 bytes/);
  });
});

describe('tokens', () => {
  it('generates distinct URL-safe tokens', () => {
    const token = randomToken();
    expect(token).toMatch(/^[\w-]{43}$/);
    expect(randomToken()).not.toBe(token);
  });

  it('hashes deterministically', () => {
    expect(hashToken('abc')).toBe(hashToken('abc'));
    expect(hashToken('abc')).not.toBe(hashToken('abd'));
  });

  it('compares strings of any length', () => {
    expect(constantTimeEqual('secret', 'secret')).toBe(true);
    expect(constantTimeEqual('secret', 'secrex')).toBe(false);
    expect(constantTimeEqual('secret', 'longer-secret')).toBe(false);
  });
});
