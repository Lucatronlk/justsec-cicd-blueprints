# Container scan sample

Static HTML web page packaged in a non-root Nginx container for Dockerfile lint, image vulnerability scans and SBOM generation. Base image is pinned to a digest resolved during local build; verify provenance and refresh regularly before production use.

```sh
docker build -t container-web:scan .
docker run --rm -p 127.0.0.1:8080:8080 container-web:scan
# In another terminal: curl --fail http://127.0.0.1:8080/
```

Container binds only to localhost on host. Stop with Ctrl-C. Do not publish this test image as production artifact.
