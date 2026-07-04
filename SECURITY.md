# Security Policy

Mantis-DNS handles DNS resolution and policy enforcement for its deployers'
networks — security issues here can affect availability and confidentiality
of every client behind it. We take reports seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email **support@bluenetworks.it** with:

- A description of the vulnerability and its impact.
- Steps to reproduce (PoC code/config welcome).
- Affected component (filter node, control plane, UI, Kea integration,
  packaging) and version/commit.

You should receive an acknowledgment within 3 business days. We'll work with
you on a fix timeline and coordinated disclosure; please give us a reasonable
window to patch before any public disclosure.

## Supported versions

Only the latest tagged release (`v*`, see [releases](../../releases)) receives
security fixes. There is no LTS branch at this stage of the project.

## Scope

In scope: `services/filter`, `services/control`, `apps/ui`, `services/kea`
integration, `packaging/`, `charts/`, `infra/cloud-init`, and the release
pipeline in `.github/workflows/`.

Out of scope: vulnerabilities in third-party dependencies upstream of this
project (report those to the respective maintainers) unless Mantis-DNS's use
of them introduces the issue.
