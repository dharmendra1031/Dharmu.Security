# Dharmu.Security

Reusable offline licensing and Windows security components for ASP.NET Core applications.

## Current development foundation

- ECDSA P-256 signed offline license validation
- signed offline activation requests with device proof
- product binding
- non-exportable Windows CNG device identity
- optional TPM-backed device identity
- machine-code generation from the device public key
- pinned public signing keys compiled into the application
- `KeyId` based signing-key selection and rotation support
- license start and expiry validation
- DPAPI protected local secrets
- DPAPI protected connection-string configuration helper
- interactive DPAPI secret provisioning tool
- DPAPI protected trusted-clock runtime state
- clock rollback detection
- ASP.NET Core license middleware
- generic fail-closed license response with server-side logging
- offline activation request download endpoint
- client device provisioning tool
- private GitHub Packages workflow

## Projects

- `Dharmu.Security.Core`
- `Dharmu.Security.Windows`
- `Dharmu.Security.AspNetCore`
- `Dharmu.Security.DeviceTool`
- `Dharmu.Security.SecretTool`
- `Dharmu.Security.LicenseTool` (owner-only, non-packable)

## Security boundary

The standalone issuer's private signing key is never included in this repository,
NuGet packages, or customer deployments. The legacy License Manager is not
required by the new standalone system.

The public verification key is not secret, but it is pinned into the compiled
application instead of being loaded from an editable file next to the publish
output. This prevents simple replacement of both the license and trust key.

The client device private key is created as a non-exportable Windows CNG key.
When TPM provisioning is selected, the Windows Platform Crypto Provider is used.

Production database credentials must not be committed to source control.

## Documentation

- `docs/integration.md`
- `docs/offline-activation.md`
- `docs/private-license-tool.md`
- `docs/production-readiness.md`
- `docs/sr-construction-pilot.md`

## Package verification and private release

The 0.2.0 development build at commit 23ab5b64 passed 51 automated tests,
package inspection, isolated package restore, and real Windows Kestrel
activation/revocation testing with CNG and DPAPI. See the [CI run](https://github.com/dharmendra1031/Dharmu.Security/actions/runs/45776595291).
Every subsequent candidate must pass its own CI and deployment acceptance gates.
No private feed publication is established by this result.

The package publishing workflow is **release-tag gated**, not triggered by normal development commits. From a reviewed `development` commit, release candidate version `0.2.0` only after approval by pushing the matching tag:

```bash
git checkout development
git pull --ff-only origin development
git tag security-v0.2.0
git push origin security-v0.2.0
```

Only create the tag after confirming the commit and version. GitHub Actions validates that the tag matches every project version, calls the same build/test/package-consumption workflow used on development, and publishes only the verified runtime artifacts to GitHub Packages using a scoped `GITHUB_TOKEN`. Confirm private package visibility and authorized restore in GitHub Packages before deploying. The issuer is never a runtime package. Treat published package versions as immutable. Consuming projects need separately authorized package-read credentials; never commit tokens to source. A successful CI artifact upload alone **does not mean** the private feed has a published package.

## Still pending verification / hardening

- Published private GitHub Packages feed and authorized cross-repository restore
- IIS App Pool key-permission test
- Physical second-machine rejection (single Windows runner activation and revocation already passed)
- Signing-key rotation deployment test
- Offline expiry/grace and permitted read/export enforcement

Development happens on the `development` branch.
