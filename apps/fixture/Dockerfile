# The fixture image: the same shape as the calling repositories' images, so the
# release workflow's build, check and scan steps run against something real.
# The base is pinned by digest; Dependabot moves it.
FROM python:3.13-slim@sha256:bf44cdfcb76cd3b41e879bc058fc37ec5872002ccfde7fcb765e218cde0cd79c

LABEL org.opencontainers.image.title="fixture-app"
LABEL org.opencontainers.image.source="https://github.com/Lucatronlk/justsec-cicd-blueprints"

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
# No third-party dependencies: --no-deps proves that, and there is nothing to hash.
# pip is removed after the install: the image never installs anything again,
# and pip's vendored setuptools and msgpack are what Trivy otherwise reports
# against an image that ships neither.
RUN pip install --no-cache-dir --no-deps . \
    && pip uninstall -y pip \
    && useradd --create-home --uid 1000 app
USER app
ENTRYPOINT ["fixture-app"]
