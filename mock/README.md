# mock — a deliberately vulnerable app

A tiny Express-shaped app with planted defects, used as the end-to-end target for ai-sec's
own tests and for practising the modules. It is **never run**: ai-sec only reads it. There is
no server to start and no dependency to install.

Every defect is listed in `expected.json` with the finding it should produce, so
`tests/exam.test.mjs` (M4) can check that a scan names the right cause rather than merely
producing output.

Planted defects:

| File | Defect | CWE | Module |
|---|---|---|---|
| `app/db.js` | SQL injection via string-built query | CWE-89 | M1, M6, M8 |
| `app/db.js` | Missing tenant predicate — cross-tenant read | CWE-639 | M5, M8 |
| `app/routes.js` | Admin route registered before the auth middleware | CWE-862 | M5 |
| `app/routes.js` | Open redirect from a query parameter | CWE-601 | M1 |
| `app/auth.js` | Reset token from `Math.random` | CWE-330 | M4, M12 |
| `app/auth.js` | Password hashed with MD5 | CWE-916 | M12 |
| `app/upload.js` | Path traversal in the download handler | CWE-22 | M1 |
| `app/fetch.js` | SSRF — user-supplied URL fetched server-side | CWE-918 | M1 |
| `config/settings.js` | Hardcoded AWS key and DB password | CWE-798 | M3 |
| `package.json` | Pinned dependency with a known CVE | — | M2 |
| `Dockerfile` | Runs as root, `:latest` base image | — | M10 |

Do not copy any of this into real code.
