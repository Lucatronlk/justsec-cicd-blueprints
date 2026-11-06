# Python health API

Dependency-free HTTP service. `GET /health` returns `200` with `{"status": "ok"}`; unknown paths return JSON `404`. Other HTTP methods use Python's default `501` response.

## Run locally

```sh
python3 app.py
curl http://127.0.0.1:8080/health
python3 -m unittest -v test_app
```

`HOST` defaults to `127.0.0.1`, `PORT` defaults to `8080`. Docker sets `HOST=0.0.0.0` for container networking:

```sh
docker build -t python-health-api apps/python-api
docker run --rm -p 127.0.0.1:8080:8080 python-health-api
```

Build commands assume repository root as working directory. Run tests from `apps/python-api`. Container runs as numeric nonroot UID/GID 65532. Image uses versioned Python base; production pipelines should pin approved digest. No TLS inside service: terminate TLS at trusted ingress, restrict access and forward access logs to central logging. Status-only access logs go to stderr (paths and query strings omitted). Health endpoint reports process availability only, not downstream dependencies.

Rollback: remove `apps/python-api/` (no persistent state or external resources).
