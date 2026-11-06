# Security Policy

## Supported versions

This repository ships reusable GitHub Actions workflows and the scripts they
rely on. Callers pin a commit SHA with the release tag in a comment; the
latest release is the supported one. Callers pinned to an older commit should
move to a current one to pick up fixes.

Do not commit real credentials, tokens, certificates, production data or
internal company material to this repository.

## Reporting a vulnerability

Report security issues **privately**, not in a public issue: open a
[GitHub Security Advisory](https://github.com/Lucatronlk/justsec-cicd-blueprints/security/advisories/new)
for this repository. It notifies the maintainer and keeps the report private
until a fix is available.

Please include:

- The affected workflow, action or script (file and, if applicable, job/step)
- A description of the issue and its potential impact
- Steps to reproduce, or a minimal example if practical

## What to expect

There is no formal SLA. Reports are triaged as soon as practical, and anything
that could affect a calling repository's secrets, supply chain or CI
environment is prioritised.

## Scope

In scope: the reusable workflows and composite actions under
`.github/workflows/` and `.github/actions/`, and the scripts under `scripts/`.
`apps/fixture/` and `apps/sample-app/` exist only to exercise the workflows and
are not supported artifacts.
