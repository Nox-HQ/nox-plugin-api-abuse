# nox-plugin-api-abuse

**Detect API authorization flaws, BOLA vulnerabilities, and abuse patterns in server code.**

<!-- badges -->
![Track: Dynamic Runtime](https://img.shields.io/badge/track-Dynamic%20Runtime-orange)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-api-abuse` identifies the most exploited categories of API vulnerabilities: missing authentication, Broken Object Level Authorization (BOLA), missing rate limiting on auth endpoints, mass assignment, and verbose error responses that leak internal details. These correspond to OWASP API Security Top 10 categories A1 (BOLA), A2 (Broken Authentication), A3 (Excessive Data Exposure), and A6 (Mass Assignment).

APIs are the primary attack surface of modern applications. BOLA -- where a user can access other users' resources by manipulating object IDs in request parameters -- has been the number one API vulnerability for years. Mass assignment -- where an entire request body is bound to a database model without field filtering -- enables privilege escalation and data manipulation. Verbose error responses that return stack traces or internal error messages give attackers a roadmap to exploit further vulnerabilities.

This plugin uses a two-pass scanning approach. The first pass reads the entire file to detect mitigation patterns (authentication middleware, rate limiting). The second pass checks each line against abuse rules and suppresses findings for rules that have mitigations present in the file. This design acknowledges that authentication and rate limiting are typically applied as middleware or decorators at the module level, not inline with each handler.

## Use Cases

### OWASP API Security Top 10 Compliance

Your security team needs to verify that all API endpoints have authentication checks, that object-level authorization is properly enforced, and that authentication endpoints have rate limiting. Run this plugin across your API services to get a finding-by-finding map against the OWASP API Security Top 10.

### BOLA/IDOR Detection

A developer writes `user = db.find(req.params.userId)` without verifying that the authenticated user has permission to access the requested user's data. This plugin detects the pattern of user IDs extracted from request parameters and used directly in database queries, flagging potential BOLA vulnerabilities.

### Mass Assignment Prevention

A Node.js developer writes `User.create(req.body)` or a Go developer writes `json.NewDecoder(r.Body).Decode(&user)`, binding the entire request payload to the model. An attacker could add `"role": "admin"` to the request body and escalate their privileges. This plugin catches these full-body binding patterns.

### Error Leakage Audit

Before a penetration test, your team wants to ensure that no API endpoint returns raw error messages, stack traces, or internal exception details to clients. This plugin scans for patterns like `http.Error(w, err.Error(), 500)` and `res.json({ error: err.stack })` that would expose internals.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-api-abuse
   ```

2. **Create a test file** (`demo/api.go`):

   ```go
   package main

   import (
       "encoding/json"
       "fmt"
       "net/http"
   )

   type User struct {
       ID    string `json:"id"`
       Name  string `json:"name"`
       Role  string `json:"role"`
       Email string `json:"email"`
   }

   func handleGetUser(w http.ResponseWriter, r *http.Request) {
       userID := r.URL.Query().Get("userId")
       user, err := db.FindById(userID)
       if err != nil {
           http.Error(w, err.Error(), http.StatusInternalServerError)
           return
       }
       json.NewEncoder(w).Encode(user)
   }

   func handleCreateUser(w http.ResponseWriter, r *http.Request) {
       var user User
       json.NewDecoder(r.Body).Decode(&user)
       db.Create(user)
   }

   func main() {
       http.HandleFunc("/api/users", handleGetUser)
       http.HandleFunc("/api/login", handleCreateUser)
   }
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/api-abuse demo/
   ```

4. **Review findings**

   ```
   nox-plugin-api-abuse: 5 findings

   API-ABUSE-001 [HIGH] Missing authentication check on handler:
     func handleGetUser(w http.ResponseWriter, r *http.Request) {
     demo/api.go:16:16
     CWE: CWE-306

   API-ABUSE-002 [HIGH] BOLA risk: user ID from request used directly in database
     query without ownership check: userID := r.URL.Query().Get("userId")
     demo/api.go:17:17
     CWE: CWE-639

   API-ABUSE-005 [MEDIUM] Verbose error response: internal details leaked to client:
     http.Error(w, err.Error(), http.StatusInternalServerError)
     demo/api.go:20:20
     CWE: CWE-209

   API-ABUSE-004 [HIGH] Mass assignment vulnerability: full request body bound to
     model without field filtering: json.NewDecoder(r.Body).Decode(&user)
     demo/api.go:28:28
     CWE: CWE-915

   API-ABUSE-003 [MEDIUM] Missing rate limiting on authentication endpoint:
     http.HandleFunc("/api/login", handleCreateUser)
     demo/api.go:33:33
     CWE: CWE-307
   ```

## Rules

| ID | Description | Severity | Confidence | CWE |
|----|-------------|----------|------------|-----|
| API-ABUSE-001 | Missing authentication check on handler | High | High | CWE-306 |
| API-ABUSE-002 | BOLA risk: user ID from request used directly in database query without ownership check | High | Medium | CWE-639 |
| API-ABUSE-003 | Missing rate limiting on authentication endpoint | Medium | Medium | CWE-307 |
| API-ABUSE-004 | Mass assignment vulnerability: full request body bound to model without field filtering | High | Medium | CWE-915 |
| API-ABUSE-005 | Verbose error response: internal details leaked to client | Medium | High | CWE-209 |

### Mitigation Suppression

| Rule | Suppressed When File Contains |
|------|-------------------------------|
| API-ABUSE-001 | `authMiddleware`, `requireAuth`, `isAuthenticated`, `jwt.verify`, `passport.authenticate`, `@login_required`, `@requires_auth`, `@permission_required` |
| API-ABUSE-003 | `rate_limit`, `ratelimit`, `throttle`, `limiter`, `RateLimiter`, `slowDown` |

## Supported Languages / File Types

| Language | Extensions | Detection Scope |
|----------|-----------|-----------------|
| Go | `.go` | HTTP handlers, `Query`/`Param`/`FormValue` usage, `json.NewDecoder` binding, `http.Error` with `err.Error()` |
| Python | `.py` | Flask/Django views, `request.args`/`request.json` usage, `**request.json` spreading, `traceback`/`str(e)` in responses |
| JavaScript | `.js` | Express routes, `req.params`/`req.body` usage, `create(req.body)` binding, `err.stack`/`err.message` in responses |
| TypeScript | `.ts` | Express routes, `req.params`/`req.body` usage, `create(req.body)` binding, `err.stack`/`err.message` in responses |

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

**Note:** This plugin uses `RiskActive` safety classification with `NeedsConfirmation`, meaning Nox may prompt for user confirmation before executing the scan in interactive mode.

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-api-abuse
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-api-abuse.git
cd nox-plugin-api-abuse
go build -o nox-plugin-api-abuse .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestBOLADetection

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-api-abuse .
docker run --rm nox-plugin-api-abuse
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk** -- Recursively traverses the workspace root, skipping `.git`, `vendor`, `node_modules`, `__pycache__`, and `.venv` directories.

2. **Two-pass file analysis:**
   - **Pass 1 (mitigation scan):** Reads all lines and checks the full file content against mitigation patterns. Builds a map of which rules have mitigations present (e.g., if `authMiddleware` is found anywhere in the file, API-ABUSE-001 findings are suppressed).
   - **Pass 2 (rule matching):** Iterates over each line and checks against all `abuseRule` patterns for the file's extension. Mitigated rules are skipped.

3. **Rule structure:** Each rule includes a CWE identifier and multiple regex patterns per file extension. Multiple patterns per extension are OR-matched. Findings include CWE metadata for integration with vulnerability management systems.

4. **Output** -- Findings include the matched line, file location, CWE identifier, and language metadata.

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Write tests for new detection rules
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
