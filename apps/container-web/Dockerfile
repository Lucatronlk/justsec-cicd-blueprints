FROM nginxinc/nginx-unprivileged:1.27.5@sha256:f9dfa9c20b2b0b7c5cc830374f22f23dee3f750b6c5291ca7e0330b5c88e6403

COPY --chown=101:101 index.html /usr/share/nginx/html/index.html

USER 101:101
EXPOSE 8080
# Runtime health probe should be configured by the orchestrator.
