# Native TLS protocol dependency checks

This public repository builds and tests public PostgreSQL and Node dependencies
using synthetic loopback fixtures. It contains no application, production
configuration, credentials, messages, or real database connections. Its CI
uses GitHub's standard `ubuntu-24.04-arm` runner for public repositories and
only the minimum `contents: read` workflow permission.

The build fetches PostgreSQL 18.6 from the official release site and verifies
its pinned SHA-256, installs integrity-pinned public npm dependencies, compiles
the native addon for Node 24, and runs loopback SCRAM-SHA-256-PLUS and TLS
tests. Negative cases include absent channel binding, disallowed authentication
fallback, forged signatures, untrusted certificates, wrong hostnames, and TLS
refusal. No real endpoint or credential is contacted or used.

The workflow stages the native dependency closure, preserves the PostgreSQL and
operating-system package license metadata, checks AArch64 ELF and missing
libraries, reports glibc symbol requirements, and checks compressed size,
expanded size, and file count against the referenced Function archive limits.
After extracting the final archive it runs the synthetic Node tests again with
`LD_LIBRARY_PATH` removed. A parseable CA bundle on the runner and synthetic CA
tests do **not** prove the CA store or ABI of a different deployment runtime.
The one-day CI artifact contains dependencies only; it is not a deployed app or
proof that any hosted Function can run them. Final app packaging and target
runtime verification require separate work.

See [GitHub standard public runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Neon native dependency guidance](https://github.com/neondatabase/agent-skills/blob/main/skills/neon-functions/references/native-binaries.md),
and [PostgreSQL connection options](https://www.postgresql.org/docs/current/libpq-connect.html).
