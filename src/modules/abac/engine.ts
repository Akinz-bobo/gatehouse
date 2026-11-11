/**
 * Attribute-based access control: decisions made from attributes of who is
 * asking (the subject), what they are asking for (the resource) and the
 * circumstances (the context), rather than from a fixed list of roles.
 *
 * This file is pure. It takes policies and a request and returns a decision,
 * with no database or network, so every rule can be tested in isolation.
 */

export type Condition =
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | { eq: [Operand, Operand] }
  | { ne: [Operand, Operand] }
  | { gt: [Operand, Operand] }
  | { gte: [Operand, Operand] }
  | { lt: [Operand, Operand] }
  | { lte: [Operand, Operand] }
  | { in: [Operand, Operand] }
  | { contains: [Operand, Operand] }
  | { exists: Operand };

/** A literal value, or a reference such as `{ "var": "resource.ownerId" }`. */
export type Operand = string | number | boolean | null | Operand[] | { var: string };

export interface Policy {
  id: string;
  name: string;
  effect: 'allow' | 'deny';
  actions: string[];
  resources: string[];
  condition: Condition | null;
}

export interface AccessRequest {
  action: string;
  subject: Record<string, unknown>;
  resource: { type: string } & Record<string, unknown>;
  context: Record<string, unknown>;
}

export interface Decision {
  allowed: boolean;
  /** Why: an explicit deny, a matching allow, or nothing matched. */
  reason: 'denied_by_policy' | 'allowed_by_policy' | 'no_matching_policy';
  /** The policies that decided the outcome. */
  policies: string[];
}

const MAX_DEPTH = 16;
const ROOTS = new Set(['subject', 'resource', 'context']);

function patternMatches(pattern: string, value: string): boolean {
  if (pattern === '*' || pattern === value) return true;
  return pattern.endsWith(':*') && value.startsWith(pattern.slice(0, -1));
}

function resolve(operand: Operand, request: AccessRequest): unknown {
  if (operand === null || typeof operand !== 'object') return operand;
  if (Array.isArray(operand)) return operand.map((item) => resolve(item, request));

  const [root, ...path] = operand.var.split('.');
  if (!root || !ROOTS.has(root)) return undefined;
  let value: unknown = request[root as 'subject' | 'resource' | 'context'];
  for (const key of path) {
    // Only walk plain data. Never follow the prototype chain.
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}

function compare(left: unknown, right: unknown): number | null {
  if (typeof left === 'number' && typeof right === 'number') return left - right;
  if (typeof left === 'string' && typeof right === 'string') {
    return left < right ? -1 : left > right ? 1 : 0;
  }
  // Values of different or unordered types cannot be ranked.
  return null;
}

/**
 * Evaluates a condition. Anything that cannot be evaluated (a missing
 * attribute, mismatched types, an unknown operator) is false, never an error
 * and never true: a broken policy must not grant access by accident.
 */
export function evaluateCondition(
  condition: Condition,
  request: AccessRequest,
  depth = 0,
): boolean {
  if (depth > MAX_DEPTH) return false;
  const next = (inner: Condition) => evaluateCondition(inner, request, depth + 1);
  const pair = (operands: [Operand, Operand]) =>
    [resolve(operands[0], request), resolve(operands[1], request)] as const;
  const ranked = (operands: [Operand, Operand], test: (difference: number) => boolean) => {
    const difference = compare(...pair(operands));
    return difference !== null && test(difference);
  };

  if ('all' in condition) return condition.all.every(next);
  if ('any' in condition) return condition.any.some(next);
  if ('not' in condition) return !next(condition.not);
  if ('exists' in condition) return resolve(condition.exists, request) !== undefined;
  if ('eq' in condition) {
    const [left, right] = pair(condition.eq);
    return left !== undefined && left === right;
  }
  if ('ne' in condition) {
    const [left, right] = pair(condition.ne);
    return left !== undefined && right !== undefined && left !== right;
  }
  if ('gt' in condition) return ranked(condition.gt, (difference) => difference > 0);
  if ('gte' in condition) return ranked(condition.gte, (difference) => difference >= 0);
  if ('lt' in condition) return ranked(condition.lt, (difference) => difference < 0);
  if ('lte' in condition) return ranked(condition.lte, (difference) => difference <= 0);
  if ('in' in condition) {
    const [needle, haystack] = pair(condition.in);
    return needle !== undefined && Array.isArray(haystack) && haystack.includes(needle);
  }
  if ('contains' in condition) {
    const [haystack, needle] = pair(condition.contains);
    return needle !== undefined && Array.isArray(haystack) && haystack.includes(needle);
  }
  return false;
}

/**
 * Decides a request against a set of policies.
 *
 *  1. If any matching policy denies, the answer is no. Deny always wins.
 *  2. Otherwise, if any matching policy allows, the answer is yes.
 *  3. Otherwise the answer is no. Nothing is allowed unless a policy says so.
 */
export function decide(policies: Policy[], request: AccessRequest): Decision {
  const matching = policies.filter(
    (policy) =>
      policy.actions.some((pattern) => patternMatches(pattern, request.action)) &&
      policy.resources.some((pattern) => patternMatches(pattern, request.resource.type)) &&
      (policy.condition === null || evaluateCondition(policy.condition, request)),
  );

  const denies = matching.filter((policy) => policy.effect === 'deny');
  if (denies.length > 0) {
    return {
      allowed: false,
      reason: 'denied_by_policy',
      policies: denies.map((policy) => policy.name),
    };
  }
  const allows = matching.filter((policy) => policy.effect === 'allow');
  if (allows.length > 0) {
    return {
      allowed: true,
      reason: 'allowed_by_policy',
      policies: allows.map((policy) => policy.name),
    };
  }
  return { allowed: false, reason: 'no_matching_policy', policies: [] };
}
