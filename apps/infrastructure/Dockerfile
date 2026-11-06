# Reproducible CLI image for local validation of this example; no credentials are baked in.
# Supply a sandbox backend/provider configuration when running a plan; never auto-apply.
FROM ghcr.io/opentofu/opentofu:1.12.6
WORKDIR /workspace
COPY main.tf /workspace/main.tf
ENTRYPOINT ["tofu"]
CMD ["version"]
