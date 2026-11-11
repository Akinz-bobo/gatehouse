import { describe, expect, it } from 'vitest';
import { AuthError } from '../../src/core/errors.js';
import { assertAcceptablePassword } from '../../src/core/password-policy.js';

const reasonFor = (password: string, email = 'ada@example.com') => {
  try {
    assertAcceptablePassword(password, email);
    return null;
  } catch (error) {
    if (error instanceof AuthError) return error.message;
    throw error;
  }
};

describe('password policy', () => {
  it('accepts a long passphrase with no symbols or digits', () => {
    expect(reasonFor('correct horse battery staple')).toBeNull();
  });

  it('rejects a short password', () => {
    expect(reasonFor('Sh0rt!pw')).toMatch(/at least 12/);
  });

  it('rejects an over-long password', () => {
    expect(reasonFor('x1'.repeat(100))).toMatch(/at most 128/);
  });

  it('rejects a common password, whatever its case', () => {
    expect(reasonFor('Password1234')).toMatch(/too common/);
  });

  it('rejects a repetitive password', () => {
    expect(reasonFor('aaaaaaaaaaaaaa')).toMatch(/repetitive/);
  });

  it('rejects a password built on the email address', () => {
    expect(reasonFor('lovelace-2026!', 'lovelace@example.com')).toMatch(/email/);
  });
});
