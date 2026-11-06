# Minimal .NET API

ASP.NET Core 10 minimal API with no third-party packages. `GET /health` returns HTTP 200 and `{"status":"ok"}`. Health response contains no internal state.

## Local

Install .NET SDK 10.0.100 (or newer 10.0.x patch), then from this directory:

```sh
dotnet restore DotnetApi.csproj
dotnet run --project DotnetApi.csproj --urls http://127.0.0.1:8080
curl --fail http://127.0.0.1:8080/health
bash tests/smoke.sh
```

## Container

```sh
docker build -t dotnet-api:local .
docker run --rm -p 127.0.0.1:8080:8080 dotnet-api:local
```

Container runs as built-in non-root `APP_UID` on HTTP port 8080. Terminate TLS at a trusted ingress or reverse proxy in deployments; do not publish container directly to internet. Image tags specify versions but remain mutable; resolve and pin approved image digests in production. Route application logs to central sink with controlled retention, and monitor health failures. No credentials or data storage are needed.

Scope: `apps/dotnet-api/` only. Rollback: remove this directory or revert its changes; no state or migration exists.
