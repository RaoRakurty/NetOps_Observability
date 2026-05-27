# Tests

Unit tests now ship alongside the code:

```
src/backend/
├── password_test.go    — PBKDF2 hash/verify, malformed encoding rejection
├── jwt_test.go         — HS256 roundtrip, signature tampering, expiry, alg=none attack
├── users_test.go       — user store CRUD, case-insensitivity, persistence, seed-only-once
└── alerts/parse_test.go — rules-file YAML parser

src/correlation/
└── test_anomaly.py     — z-score anomaly scorer
```

Run them from inside the appropriate workspace:

```
# Go backend
cd src/backend
go test ./...

# Python correlation
cd src/correlation
pip install -r requirements.txt   # only the first time
python -m unittest test_anomaly
```

The Go tests cover the security-critical helpers — JWT verification
must reject the alg-none confusion attack, password verification must
be constant-time, and the user store must remain case-insensitive
across restarts. Integration and end-to-end tests are not yet written;
those live under `tests/integration/` and `tests/e2e/` when added.
