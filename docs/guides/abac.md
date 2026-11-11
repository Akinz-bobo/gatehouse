# Policies (`abac`)

Enable with `MODULES=abac`, usually alongside `rbac`.

Roles answer "what kind of user is this?". Attribute-based access control answers questions roles cannot: "is this _their_ document?", "is the invoice under their approval limit?", "is it office hours?". A decision looks at three things:

|              | What                                                   | Where it comes from                                    |
| ------------ | ------------------------------------------------------ | ------------------------------------------------------ |
| **subject**  | Who is asking: `id`, `email`, `roles`, `attributes`    | The verified token and the database. Never the request |
| **resource** | What they want to touch: `type` plus anything you send | Your service, in the request                           |
| **context**  | Circumstances: time, IP, amount                        | Your service, in the request                           |

## Policies

A policy says: for these actions, on these resource types, when this condition holds, allow or deny.

```bash
curl -s $BASE/v1/policies -H "authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' -d '{
    "name": "owners edit their documents",
    "effect": "allow",
    "actions": ["documents:update", "documents:delete"],
    "resources": ["document"],
    "condition": { "eq": [{ "var": "resource.ownerId" }, { "var": "subject.id" }] }
  }'
```

`actions` and `resources` accept exact values, a trailing wildcard (`documents:*`) or `*`. A policy with no `condition` always applies when action and resource match.

### How a decision is made

1. Collect every policy that matches the action and resource type and whose condition is true.
2. If any of them is a **deny**, the answer is no.
3. Otherwise, if any is an **allow**, the answer is yes.
4. Otherwise the answer is no.

So nothing is allowed until a policy allows it, and a deny can never be overridden.

### Conditions

A condition is a JSON object with exactly one operator.

| Operator                 | Meaning                                     | Example                                                                                    |
| ------------------------ | ------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `eq`, `ne`               | Equal, not equal                            | `{ "eq": [{ "var": "resource.status" }, "draft"] }`                                        |
| `gt`, `gte`, `lt`, `lte` | Compare two numbers or two strings          | `{ "lte": [{ "var": "resource.amount" }, { "var": "subject.attributes.approvalLimit" }] }` |
| `in`                     | The first value is in the second (an array) | `{ "in": [{ "var": "resource.region" }, ["eu", "uk"]] }`                                   |
| `contains`               | The first (an array) contains the second    | `{ "contains": [{ "var": "subject.roles" }, "auditor"] }`                                  |
| `exists`                 | The value is present                        | `{ "exists": { "var": "resource.ownerId" } }`                                              |
| `all`, `any`, `not`      | Combine conditions                          | `{ "all": [ ..., ... ] }`                                                                  |

An operand is a literal (string, number, boolean, null, array) or a reference `{ "var": "path" }` that starts at `subject`, `resource` or `context`.

Anything that cannot be evaluated is **false**: a missing attribute, a comparison between a number and a string, nesting that is too deep. A mistake in a policy can fail to grant access, but it cannot grant access by accident.

## Asking for a decision

```bash
curl -s $BASE/v1/authz/evaluate -H "authorization: Bearer $USER_TOKEN" \
  -H 'content-type: application/json' -d '{
    "action": "documents:update",
    "resource": { "type": "document", "ownerId": "7b0c...", "archived": false },
    "context": { "hour": 14 }
  }'
```

```json
{ "allowed": true, "reason": "allowed_by_policy", "policies": ["owners edit their documents"] }
```

`reason` is `allowed_by_policy`, `denied_by_policy` or `no_matching_policy`, and `policies` names the ones that decided it, which makes "why was I refused?" answerable.

Your service loads the resource, sends its relevant attributes, and enforces the answer:

```ts
const document = await documents.findById(id);
const decision = await gatehouse.evaluate(userToken, {
  action: 'documents:update',
  resource: { type: 'document', ownerId: document.ownerId, archived: document.archived },
});
if (!decision.allowed) return reply.status(403).send();
```

## Worked examples

**Freeze archived documents for everyone**, whatever else is allowed:

```json
{
  "name": "archived documents are frozen",
  "effect": "deny",
  "actions": ["documents:*"],
  "resources": ["document"],
  "condition": { "eq": [{ "var": "resource.archived" }, true] }
}
```

**Approval limits** from a user attribute:

```json
{
  "name": "approve invoices within limit",
  "effect": "allow",
  "actions": ["invoices:approve"],
  "resources": ["invoice"],
  "condition": {
    "all": [
      { "contains": [{ "var": "subject.roles" }, "approver"] },
      { "lte": [{ "var": "resource.amount" }, { "var": "subject.attributes.approvalLimit" }] },
      { "ne": [{ "var": "resource.createdBy" }, { "var": "subject.id" }] }
    ]
  }
}
```

The last clause is separation of duties: nobody approves their own invoice.

**Office hours only**, with the hour supplied by your service:

```json
{
  "name": "reports in office hours",
  "effect": "allow",
  "actions": ["reports:read"],
  "resources": ["report"],
  "condition": {
    "all": [{ "gte": [{ "var": "context.hour" }, 9] }, { "lt": [{ "var": "context.hour" }, 17] }]
  }
}
```

## User attributes

`subject.attributes` comes from the `attributes` JSON column on the user. Gatehouse does not expose an endpoint to edit it yet, because who may set which attribute is specific to each product. Set it from your own back office:

```sql
UPDATE users SET attributes = attributes || '{"department":"finance","approvalLimit":500000}' WHERE id = $1;
```

## Things to know

- Gatehouse trusts the `resource` and `context` your service sends. Send them from your backend, built from your own data, never passed through from a browser.
- `subject.roles` is empty unless `rbac` is enabled.
- Policies are read on every decision, so changes apply immediately.
- Managing policies needs a superuser or `auth:policies:manage`.
