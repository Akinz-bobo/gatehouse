import { describe, expect, it } from 'vitest';
import { hasPermission, permissionCovers } from '../../src/modules/rbac/permissions.js';

describe('permissionCovers', () => {
  it.each([
    ['invoices:read', 'invoices:read', true],
    ['invoices:read', 'invoices:write', false],
    ['invoices:*', 'invoices:read', true],
    ['invoices:*', 'invoices:refunds:create', true],
    ['invoices:refunds:*', 'invoices:refunds:create', true],
    ['invoices:refunds:*', 'invoices:read', false],
    ['*', 'anything:at:all', true],
    // A wildcard covers what is under a name, not names that merely start with it.
    ['invoices:*', 'invoices', false],
    ['invoices:*', 'invoicesx:read', false],
    ['invoices', 'invoices:read', false],
  ])('%s covers %s: %s', (granted, required, expected) => {
    expect(permissionCovers(granted, required)).toBe(expected);
  });
});

describe('hasPermission', () => {
  it('passes when any granted permission covers the requirement', () => {
    expect(hasPermission(['users:read', 'invoices:*'], 'invoices:write')).toBe(true);
  });

  it('fails with no permissions', () => {
    expect(hasPermission([], 'invoices:read')).toBe(false);
  });
});
