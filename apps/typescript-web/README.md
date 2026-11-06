# TypeScript web scan target

Small standalone Node.js HTTP service with browser page (`/`), JSON API (`/api/info`), and health endpoint (`/health`). Uses only Node.js built-ins at runtime. No external database, credentials, or deliberately unsafe code. This sample is a scan target, not production service.

## Local use

Requires Node.js 20.19+ and Corepack (or pnpm 9.15.9). From this directory:

```sh
corepack pnpm install --frozen-lockfile
corepack pnpm test
corepack pnpm start
curl http://127.0.0.1:3000/health
```

`pnpm test` builds TypeScript and runs Node's test runner. `PORT` defaults to `3000`; `HOST` defaults to `127.0.0.1` locally. Only GET and HEAD supported. Request logs record method, known route or `other`, and status; no query strings or headers. Capture stdout with access controls and retention if deploying beyond local testing.

## Container

```sh
docker build -t typescript-web:local .
docker run --rm -p 127.0.0.1:3000:3000 typescript-web:local
```

Container binds `0.0.0.0:3000` internally for port forwarding, runs as non-root `node`, and ships only compiled JavaScript. Host port binding above limits exposure to loopback. TLS termination and monitoring are deployment responsibilities; do not expose directly to public traffic. For scans, target this directory or built image. Dependency/OS findings may change as vulnerability databases evolve.

Rollback: remove only `apps/typescript-web/`; no shared resources or state migrations involved.
