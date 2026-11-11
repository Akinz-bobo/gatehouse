/**
 * Permissions are colon-separated strings, most general part first:
 * `invoices:read`, `invoices:refunds:create`. A granted permission may end in
 * a wildcard: `invoices:*` covers everything under `invoices`, and `*` covers
 * everything.
 */
export const PERMISSION_PATTERN = /^(\*|[a-z0-9_-]+(:[a-z0-9_-]+)*(:\*)?)$/;

/** True when `granted` covers `required`. */
export function permissionCovers(granted: string, required: string): boolean {
  if (granted === '*' || granted === required) return true;
  if (!granted.endsWith(':*')) return false;
  // `invoices:*` covers `invoices:read` but not `invoices` or `invoicesx:read`.
  return required.startsWith(granted.slice(0, -1));
}

export function hasPermission(granted: Iterable<string>, required: string): boolean {
  for (const permission of granted) {
    if (permissionCovers(permission, required)) return true;
  }
  return false;
}
