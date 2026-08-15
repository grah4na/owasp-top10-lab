
doc = """# Vulnerability: Malicious Post-Install Script in Dependency

## OWASP Category

A03:2025 — Software Supply Chain Failures

---

## Location

- `A03/malicious-package/package.json` — fake dependency with `postinstall` lifecycle script
- `A03/malicious-package/steal.js` — malicious script that exfiltrates developer secrets
- `A03/malicious-package/index.js` — benign exported function (camouflage)
- `A03/package.json` — root app that depends on the malicious package

---

## Description

The application depends on a third-party package (`a03-logger-utils`) that contains a malicious `postinstall` script. When `npm install` is executed, npm automatically runs the `postinstall` script, which executes arbitrary code with the same privileges as the developer's shell.

The malicious script (`steal.js`) performs the following actions:
1. Reads `~/.npmrc` — contains npm authentication tokens for publishing packages
2. Harvests `process.env` — leaks environment variables, paths, and potential secrets
3. Captures system fingerprinting data (hostname, username, timestamp)
4. Writes all harvested data to a local file (`.exfiltrated.json`) — simulating exfiltration to an attacker-controlled server

The package also exports a legitimate-looking logging function (`formatLog`) to appear benign during normal usage. The malicious behavior is completely invisible to the developer after installation.

Additionally, `npm audit` — the standard tool for dependency vulnerability scanning — returns **0 vulnerabilities** because it only checks for known CVEs in the National Vulnerability Database. It does not detect malicious code, suspicious lifecycle scripts, or behavioral anomalies in packages.

This maps directly to the OWASP A03 scenario of the 2025 `Shai-Hulud` npm worm, where malicious packages used post-install scripts to harvest npm tokens and self-propagate by publishing compromised versions of other packages.

---

## Proof of Concept

### PoC 1: Malicious Package Installation and Data Exfiltration

**Step 1 — Install the malicious package:**
```bash
cd ~/projects/owasp-top10-lab/exploits/A03
npm install
```

**Output:**
```
added 83 packages, and audited 85 packages in 9s
...
a03-logger-utils: installed successfully
```

The `postinstall` script runs silently during installation. The "installed successfully" message is the only visible indicator — the data theft is invisible.

**Step 2 — Verify exfiltrated data:**
```bash
cat malicious-package/.exfiltrated.json | head -c 800
```

**Output (truncated):**
```json
{
  "timestamp": "2026-08-12T15:30:00.000Z",
  "hostname": "grah4na-desktop",
  "username": "grah4na",
  "npmrc": "//registry.npmjs.org/:_authToken=npm_xxxxxxxxxxxxxxxx\n...",
  "env": {
    "KDE_FULL_SESSION": "true",
    "USER": "grah4na",
    "HOME": "/home/grah4na",
    "npm_config_user_agent": "npm/10.9.8 node/v22.22.3 linux x64",
    ...
  }
}
```

**Leaked:** npm auth token (from `~/.npmrc`), username, hostname, home directory, full environment variables.

**Step 3 — App uses the package normally (no visible signs of compromise):**
```bash
curl http://localhost:3000/
```

**Output:**
```json
{
  "message": "A03 Supply Chain Lab",
  "log": "[2026-08-12T15:30:00.000Z] INFO: App is running"
}
```

The app functions normally. The developer has no indication that secrets were stolen during installation.

---

### PoC 2: npm Audit Blind Spot

**Request:**
```bash
cd ~/projects/owasp-top10-lab/exploits/A03
npm audit
```

**Output:**
```
found 0 vulnerabilities
```

**Why this matters:** `npm audit` only checks for known CVEs in the National Vulnerability Database. A brand-new malicious package with no CVE history passes the audit with zero flags. A developer relying solely on `npm audit` would falsely believe their dependencies are safe.

---

## Root Cause

1. **npm runs lifecycle scripts by default:** `npm install` automatically executes `postinstall`, `preinstall`, and `prepare` scripts from any package without user confirmation. This is by design in npm, but it means any installed package can run arbitrary code.

2. **No script blocking configured:** The project lacks `.npmrc` with `ignore-scripts=true`, leaving the default behavior (scripts enabled) active.

3. **No behavioral dependency scanning:** The developer relies only on `npm audit`, which is CVE-based and cannot detect novel malicious code, typosquatting, or compromised legitimate packages.

4. **No package provenance verification:** The package is installed from a local path (`file:./malicious-package`) with no signature verification, attestation, or source code review. In a real attack, this would be a package from npm with a compromised or typosquatted name.

5. **Developer trust in package names:** The package name `a03-logger-utils` appears legitimate. Real-world attacks use typosquatting (`expres` vs `express`) or compromised accounts of legitimate maintainers.

---

## Impact

| Impact | Severity | Details |
|--------|----------|---------|
| **npm token theft** | Critical | Stolen `~/.npmrc` auth tokens allow attacker to publish malicious versions of packages the victim has access to |
| **Environment variable leakage** | High | `process.env` may contain API keys, database URLs, cloud credentials, JWT secrets |
| **System fingerprinting** | Medium | Hostname, username, paths reveal internal infrastructure details |
| **Self-propagating worm** | Critical | With npm tokens, attacker can publish compromised versions of the victim's packages, infecting all downstream users (Shai-Hulud pattern) |
| **Supply chain poisoning** | Critical | Attacker can inject backdoors into packages the victim maintains, affecting thousands of downstream projects |

**Chained impact:** A single compromised developer machine → stolen npm tokens → malicious package published to npm → all users of that package compromised. This is exactly how the 2025 `Shai-Hulud` worm spread to 500+ package versions.

---

## Fix

### Fix 1: Block Lifecycle Scripts (Immediate)

Create `.npmrc` in project root:
```
ignore-scripts=true
```

**Verification:**
```bash
rm -rf node_modules/a03-logger-utils
rm -f malicious-package/.exfiltrated.json
npm install --ignore-scripts
cat malicious-package/.exfiltrated.json 2>/dev/null || echo "No exfil file — script was blocked"
```

**Output:**
```
No exfil file — script was blocked
```

### Fix 2: Use npm Provenance and Attestation

When publishing or installing packages, verify provenance:
```bash
# Install with provenance check (npm v9.5.0+)
npm install --provenance

# Or configure globally
npm config set provenance true
```

Provenance attestation links the package to its CI/CD build, making it harder for attackers to publish unauthorized versions.

### Fix 3: Behavioral Dependency Scanning

Use tools that analyze package behavior, not just CVEs:
- **Socket.dev** — detects suspicious code patterns, network calls, file system access in dependencies
- **Snyk** — combines CVE scanning with behavior analysis
- **npm's `npm query`** — inspect package scripts before installation:
  ```bash
  npm query ':root > *[scripts.postinstall]' | jq .
  ```

### Fix 4: Lockfile Enforcement in CI/CD

Always use `npm ci` (not `npm install`) in production builds:
```bash
npm ci --ignore-scripts
```

`npm ci` enforces `package-lock.json` and fails if versions don't match, preventing silent package swaps.

### Fix 5: Code Review for New Dependencies

Before adding any dependency:
1. Check the package's source on GitHub/npm
2. Review `package.json` for suspicious scripts
3. Check download counts, maintainer reputation, last publish date
4. Use `npm pack <package>` to inspect contents before installing

---

## Verification (Post-Fix)

```bash
# 1. Scripts are blocked
cd ~/projects/owasp-top10-lab/exploits/A03/fixed
npm install
cat ../malicious-package/.exfiltrated.json 2>/dev/null || echo "PASS: No exfiltration"

# 2. App still works normally
curl http://localhost:3000/
# → {"message":"A03 Supply Chain Lab — FIXED","log":"[...] INFO: App is running securely"}

# 3. npm audit still passes (demonstrating its limitation)
npm audit
# → found 0 vulnerabilities (this is expected — audit doesn't catch malicious scripts)
```

---

## References

- [OWASP Top 10 2025 — A03 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [npm scripts documentation](https://docs.npmjs.com/cli/v10/using-npm/scripts)
- [npm ignore-scripts config](https://docs.npmjs.com/cli/v10/using-npm/config#ignore-scripts)
- [npm provenance and attestations](https://docs.npmjs.com/generating-provenance-statements)
- [Socket.dev — behavioral dependency scanning](https://socket.dev/)
- [Shai-Hulud npm worm (2025)](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) — referenced in OWASP A03 scenarios
"""

with open('/mnt/agents/output/A03-software-supply-chain-failures.md', 'w') as f:
    f.write(doc)

print("Done.")
