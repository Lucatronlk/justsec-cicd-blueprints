# Reproducible CLI image for local validation of this example; no credentials are baked in.
# Supply a sandbox backend/provider configuration when running a plan; never auto-apply.
FROM ghcr.io/opentofu/opentofu:1.12.6-minimal@sha256:2fedbb3e956b083582543dabb76eba17e9f961dfd055311ea054a6191cfae9dd AS tofu
FROM alpine:3.21@sha256:87a4361f6c819618a6bafa2ed5228714cb0bb22195d2b49c95eb26799990128a
COPY --from=tofu /usr/local/bin/tofu /usr/local/bin/tofu
WORKDIR /workspace
COPY main.tf /workspace/main.tf
USER 65532:65532
ENTRYPOINT ["tofu"]
CMD ["version"]
