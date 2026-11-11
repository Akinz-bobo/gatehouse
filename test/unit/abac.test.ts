import { describe, expect, it } from 'vitest';
import {
  decide,
  evaluateCondition,
  type AccessRequest,
  type Condition,
  type Policy,
} from '../../src/modules/abac/engine.js';

const request: AccessRequest = {
  action: 'document:read',
  subject: { id: 'u1', roles: ['editor'], attributes: { department: 'finance', clearance: 3 } },
  resource: { type: 'document', ownerId: 'u1', department: 'finance', classification: 2 },
  context: { ip: '10.0.0.5', mfa: true },
};

const check = (condition: Condition) => evaluateCondition(condition, request);
const v = (path: string) => ({ var: path });

describe('conditions', () => {
  it('compares an attribute with a literal', () => {
    expect(check({ eq: [v('subject.attributes.department'), 'finance'] })).toBe(true);
    expect(check({ eq: [v('subject.attributes.department'), 'legal'] })).toBe(false);
  });

  it('compares two attributes, such as "the subject owns the resource"', () => {
    expect(check({ eq: [v('resource.ownerId'), v('subject.id')] })).toBe(true);
  });

  it('orders numbers', () => {
    expect(check({ gte: [v('subject.attributes.clearance'), v('resource.classification')] })).toBe(
      true,
    );
    expect(check({ lt: [v('subject.attributes.clearance'), 3] })).toBe(false);
  });

  it('checks membership both ways round', () => {
    expect(check({ in: [v('resource.department'), ['finance', 'legal']] })).toBe(true);
    expect(check({ contains: [v('subject.roles'), 'editor'] })).toBe(true);
    expect(check({ contains: [v('subject.roles'), 'admin'] })).toBe(false);
  });

  it('combines with all, any and not', () => {
    const owner: Condition = { eq: [v('resource.ownerId'), v('subject.id')] };
    const admin: Condition = { contains: [v('subject.roles'), 'admin'] };
    expect(check({ all: [owner, admin] })).toBe(false);
    expect(check({ any: [owner, admin] })).toBe(true);
    expect(check({ not: admin })).toBe(true);
  });

  it('treats a missing attribute as false, never as a match', () => {
    expect(check({ eq: [v('subject.attributes.missing'), v('resource.alsoMissing')] })).toBe(false);
    expect(check({ ne: [v('subject.attributes.missing'), 'x'] })).toBe(false);
    expect(check({ gt: [v('subject.attributes.missing'), 1] })).toBe(false);
    expect(check({ exists: v('subject.attributes.missing') })).toBe(false);
    expect(check({ exists: v('context.mfa') })).toBe(true);
  });

  it('refuses to compare values of different types', () => {
    expect(check({ gt: [v('subject.attributes.department'), 1] })).toBe(false);
  });

  it('cannot reach outside the request or up the prototype chain', () => {
    expect(check({ exists: v('process.env') })).toBe(false);
    expect(check({ exists: v('subject.constructor') })).toBe(false);
    expect(check({ exists: v('subject.__proto__') })).toBe(false);
  });

  it('fails closed on an operator it does not know', () => {
    expect(check({ regex: ['a', 'b'] } as unknown as Condition)).toBe(false);
  });

  it('fails closed on a condition nested too deeply', () => {
    let nested: Condition = { eq: [1, 1] };
    for (let depth = 0; depth < 40; depth++) nested = { all: [nested] };
    expect(check(nested)).toBe(false);
  });
});

describe('decisions', () => {
  const policy = (overrides: Partial<Policy>): Policy => ({
    id: overrides.name ?? 'p',
    name: 'p',
    effect: 'allow',
    actions: ['document:read'],
    resources: ['document'],
    condition: null,
    ...overrides,
  });

  it('denies when no policy matches', () => {
    expect(decide([], request)).toEqual({
      allowed: false,
      reason: 'no_matching_policy',
      policies: [],
    });
  });

  it('allows when a policy matches', () => {
    const decision = decide([policy({ name: 'readers' })], request);
    expect(decision).toEqual({ allowed: true, reason: 'allowed_by_policy', policies: ['readers'] });
  });

  it('lets a deny override any number of allows', () => {
    const decision = decide(
      [
        policy({ name: 'readers' }),
        policy({ name: 'owners', condition: { eq: [v('resource.ownerId'), v('subject.id')] } }),
        policy({
          name: 'no-finance',
          effect: 'deny',
          condition: { eq: [v('resource.department'), 'finance'] },
        }),
      ],
      request,
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'denied_by_policy',
      policies: ['no-finance'],
    });
  });

  it('ignores a policy whose condition is not met', () => {
    const decision = decide(
      [policy({ condition: { eq: [v('subject.attributes.department'), 'legal'] } })],
      request,
    );
    expect(decision.allowed).toBe(false);
  });

  it('matches actions and resource types by wildcard', () => {
    expect(decide([policy({ actions: ['document:*'], resources: ['*'] })], request).allowed).toBe(
      true,
    );
    expect(decide([policy({ actions: ['invoice:*'] })], request).allowed).toBe(false);
    expect(decide([policy({ resources: ['invoice'] })], request).allowed).toBe(false);
  });
});
