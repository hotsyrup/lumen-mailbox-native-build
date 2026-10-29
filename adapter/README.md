# Synthetic strict-connection probe

This is a dependency-compatibility experiment, not an application database
adapter. It executes only `SELECT 1 AS value` and returns a boolean success or a
fixed error. Tests use an explicitly fake addon and synthetic values; they do
not verify libpq, SCRAM, TLS, CA trust, or runtime compatibility.

The parent process starts a one-shot child with an explicit minimal environment;
the child discards any added environment variables before loading `pg-native`.
The connection URL is passed by stdin rather than arguments or environment, and
the URI, native errors and stderr are never returned by the probe. The trusted
hostname must be provided by the caller as an exact value. These choices reduce
the previous environment race and accidental error disclosure; they do not
secure a compromised host, caller, dependency, loader, certificate store, or
operating system.

The child requires libpq support for `channel_binding=require`,
`sslmode=verify-full`, `sslrootcert=system`, `require_auth=scram-sha-256`,
`sslcertmode=disable`, and `gssencmode=disable`. Verify the exact libpq version,
native addon and linked libraries, system CA availability and correctness, and
positive/negative protocol behavior on the target runtime. This probe must not be
integrated with an application or used with real credentials until independent
review and those checks succeed. It is not an authorization to deploy.

Run synthetic plumbing tests with `node --test adapter/strict-probe.test.mjs`.
