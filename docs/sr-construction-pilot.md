# SR Construction Windows pilot

## Verified compatibility review

Reviewed SR Construction development commit
22e7cb9902bba0b2ad33f6e046dc880e6233d127.

- Backend: ASP.NET Core net10.0, SQL Server, JWT and Identity.
- Current CI: Ubuntu build/test, EF migration check and SQL Server container.
- Security package: Dharmu.Security.AspNetCore 0.2.0, net10.0-windows.
- Current health endpoint: GET /api/health.
- Static frontend is served by the API, and the initial admin CLI is separate.

A direct unconditional package reference would require a Windows-compatible target
and invalidate the assumption that the existing Linux application tests exercise
the licensed build. Do not remove existing Linux jobs or silently disable licensing
based on operating system, environment name, missing configuration or exceptions.

## Proposed integration (not implemented)

Keep existing cross-platform build/tests. Add an explicit Windows deployment target
and separate Windows CI coverage for the licensed target. Evaluate multi-targeting
against the current EF/SQL and browser test workflows before selecting the final
project configuration. The Windows publish must fail if it lacks the package or
the compiled trusted public key. Do not distribute the unlicensed target to
customers. Use an owner-approved issuer key, pinned into the Windows build.

Add the existing license middleware before business routes and any static content
that must be licensed; retain authentication, authorization and rate limiting.
The exact health exclusion should be /api/health, and only the intended GET/HEAD
activation and health routes should be exempt. Explicitly verify CORS preflight
behavior for any separate frontend; do not add a blanket business-route bypass.
Keep license and runtime-state paths outside wwwroot, under a dedicated data
directory retained across upgrades. Preserve the initial admin setup and database
migration behavior. Do not alter SQL Server schema for the license package.

## Physical / IIS acceptance

Use an isolated non-production site and separate test ledger/key slot.

1. On two separate Windows computers, provision the device tool with the same
   chosen policy (software CNG or TPM). Set RequireTpmDeviceIdentity consistently.
2. Deploy the same licensed Windows build to both machines. Verify each activation
   request has a different machine code. No private key or owner ledger may be
   copied to either client.
3. Issue a finite test license for machine A. A must allow protected requests;
   B must reject the copied A license. A valid license must not bypass JWT/roles.
4. On A, test renewal, revocation, restoring the prior file, restarting and
   deleting only runtime.state while retaining its initialized marker. Confirm
   fail-closed behavior. Perform destructive state tests only on the test site.
5. Protect a non-secret test value with DPAPI on A. B must fail to decrypt it.
6. Verify IIS application-pool identity can open its device key and read its
   license; grant only necessary state-directory access. Test app-pool recycling
   and concurrent worker processes sharing the same canonical local state path.
7. Test expired license behavior and confirm the owner-approved data export /
   backup recovery process remains available. Current middleware denies protected
   requests with 403 and does not implement read-only business access.
8. Measure actual billing and database performance with and without the package
   in controlled test builds. Record hardware, app-pool identity, package build
   commit, test outcomes and timings before production approval.

The GitHub runner is not either physical computer or the customer's IIS server.
These are required manual acceptance checks, not completed tests.

## Package source

Use the exact approved CI artifact or an authorized private GitHub Packages
restore for the pilot. The verified 0.2.0 artifact from Phase 8 is
https://github.com/dharmendra1031/Dharmu.Security/actions/runs/45776595291/artifacts/15096761042.
Never mix same-version development artifacts from different commits or commit feed
tokens. Publish a stable version only after the release gates are satisfied.
