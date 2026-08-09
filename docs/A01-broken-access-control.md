# A01:2025 — Broken Access Control

## Vulnerability Name + OWASP Category

**Insecure Direct Object Reference (IDOR) via Incorrect Authorization Scope**
OWASP Top 10 2025 — **A01: Broken Access Control**

## Location

- **File:** `src/routes/projects.ts`
- **Route:** `GET /projects/:id`
- **Vulnerable line:**
```typescript
  if (project.org_id !== user.orgId && user.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }
```

## Description

The `GET /projects/:id` endpoint is supposed to enforce **strict per-user ownership** — only the user who created a project (or an org admin) should be able to access it. Instead, the check compares the project's `org_id` against the requesting user's `orgId`, rather than comparing `owner_id` against the requesting user's `userId`.

Since the intended authorization boundary is *ownership*, not *org membership*, this check enforces the wrong scope. Any authenticated user who shares an organization with the resource owner passes the check, regardless of whether they actually own the resource.

## Proof of Concept

**Setup:** Two users, `alice` (owner of project `id: 1`) and `bob`, both members of the same org (`orgId: 3`). Neither is an admin.

**1. Alice creates a project:**
```bash
curl -X POST http://localhost:3000/projects \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <alice_token>" \
  -d '{"name":"Alice Secret Project"}'
```
Response:
```json
{"id":1,"name":"Alice Secret Project","owner_id":1}
```

**2. Before fix — bob (member, different owner, same org) requests alice's project:**
```bash
curl http://localhost:3000/projects/1 \
  -H "Authorization: Bearer <bob_token>"
```v
Response (secure baseline, `owner_id` check):
```json
{"error":"forbidden"}
```

**3. After introducing the bug — same request, `org_id` check in place:**
```bash
curl http://localhost:3000/projects/1 \
  -H "Authorization: Bearer <bob_token>"
```
Response:
```json
{"id":1,"org_id":3,"owner_id":1,"name":"Alice Secret Project"}
```

Bob, a plain `member` with no ownership relationship to the project, successfully retrieves alice's private data.

## Root Cause

The authorization check was implemented against the wrong relationship. The project object carries two distinct scoping fields — `owner_id` (who created/owns it) and `org_id` (which organization it belongs to). The check used `org_id`, which answers "does this user belong to the same organization as the resource," not "does this user own the resource." Because every member of an org shares the same `orgId`, this check is satisfied for *any* member of the org — the ownership boundary is effectively erased for everyone except users outside the org entirely.

This is a realistic mistake because both fields are plausible things to check, both are present on the JWT and the DB row, and the code still reads as if it performs a real authorization check — there's no missing `if`, no obviously absent logic. The bug is in *which* relationship was chosen, not whether a check exists.

## Impact

- **Confidentiality:** Any authenticated member of an org can read every other member's private projects (and, by inheritance, their tasks) within that org — a full horizontal privilege escalation across all users sharing an org.
- **Scope:** Affects `GET /projects/:id` directly; since task access inherits project ownership via the same authorization pattern, a parallel mistake in `tasks.ts` would expose task data too.
- **Severity:**  **High** — no special privileges required beyond being a valid, authenticated member of the same org; trivially exploitable by changing a single path parameter.

## Fix

Restore the ownership-based check, comparing `owner_id` against the requesting user's `userId` instead of `org_id`/`orgId`:

```typescript
if (project.owner_id !== user.userId && user.role !== "admin") {
  return res.status(403).json({ error: "forbidden" });
}
```

See `fixed/` for the corrected version of `projects.ts`. The `org_id` field should not be used as an authorization boundary for project-level resources under the current ownership model — it is retained on the `projects` table for organizational grouping/display only, not access control.