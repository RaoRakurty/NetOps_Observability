# Authentication

The dashboard and the Go API now require sign-in. Tokens are JWT
HS256, hashed passwords are PBKDF2-SHA256 at 600,000 iterations. Both
sides are written in pure Go stdlib, no external crypto modules.

## How users get created

* The installer (`scripts/install.py`) generates an
  `ADMIN_INITIAL_PASSWORD` and writes it (with `ADMIN_USERNAME=admin`)
  into `deployment/docker/.env`.
* On first start of the api container, if the user store is empty, the
  admin is created. After that the env var is ignored — rotating it
  has no effect.
* Add more users via the API:
  ```
  curl -X POST http://localhost:8000/api/auth/login -d '{"username":"admin","password":"..."}'
  # take the returned token and:
  # (no /api/users CRUD yet — added in a follow-up; for now users.json
  # is the source of truth, edit it directly with the container stopped.)
  ```

## How sign-in works

1. The SPA shows the Login page if there's no token (or the saved one
   was rejected by `/api/auth/me`).
2. User submits credentials → POST `/api/auth/login`.
3. Server validates against the user store, issues a 24h JWT signed
   with `JWT_SECRET`, returns it plus the public user record.
4. SPA stores the token in `localStorage` and re-renders into the app.
5. Every subsequent API call attaches `Authorization: Bearer <token>`.
6. On 401 anywhere, the SPA clears the token and shows Login again.

The protected paths are everything under `/api/` and `/admin/` except:

| Path                    | Why public |
|-------------------------|------------|
| `/api/auth/login`       | needed to obtain a token |
| `/admin/health`         | docker healthchecks, monitoring |
| `/admin/version`        | trivial, no PII |
| `/metrics`              | metrics scrape (Prometheus exposition format, scraped by VictoriaMetrics) |

Everything else (devices, logs, flows, findings, copilot, GraphQL,
admin endpoints) requires a valid bearer token.

## Changing passwords

In the dashboard, **Settings → Change password**. The same flow is also
exposed at:

```
POST /api/auth/change-password
Authorization: Bearer ...
{"current_password": "...", "new_password": "..."}
```

The minimum length is 8 characters; tighten it in `src/backend/users.go`
if you have a stronger policy.

## Where the user store lives

`/data/users.json` inside the api container, which is the bind-mounted
host directory `./data/api/`. Mode 0600, atomic-rename writes. Back it
up with the rest of `data/`.

## Production hardening checklist

Before exposing this beyond a trusted network:

- [ ] Put HTTPS in front of nginx (Let's Encrypt via certbot, or a
      load balancer terminating TLS). See `docs/DEPLOY_LINUX.md`.
- [ ] Set a strong, stable `JWT_SECRET` and rotate it deliberately
      (rotating it invalidates every active session).
- [ ] Remove the `dev-only-do-not-use-in-production` fallback in
      `src/backend/auth.go:jwtSecret()` — fail closed instead.
- [ ] Add rate limiting on `/api/auth/login` (nginx `limit_req_zone`).
- [ ] Move the user store to PostgreSQL when you have more than a
      handful of operators. The `userStore` contract is small enough
      that the swap is one file.
- [ ] Add RBAC enforcement — the `Role` field is present and stored,
      but no handler checks it yet. Pattern:
      `if userFrom(r.Context()).Role != "admin" { 403 }`.

## What's intentionally NOT here

- **OAuth/SSO.** Single-tenant auth on purpose. Swap in Authelia or
  similar in front of nginx if you need IdP-backed sign-in.
- **MFA.** Add via the same `Authelia in front of nginx` pattern, or
  bolt TOTP onto the login handler when needed.
- **Session/cookie auth.** Tokens are stateless on the server. Better
  for horizontal scaling, slightly worse for "force-logout this user
  right now" — to do that today, rotate `JWT_SECRET`.
