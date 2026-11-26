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

The License Manager private signing key is never included in this repository,
NuGet packages, or customer deployments.

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

## Package verification and private release

The earlier 0.1.0 baseline passed restore/build, unit tests, packaging and a sample consumption build. Latest security and issuer changes require a fresh successful Windows CI run before release.

The package publishing workflow is **release-tag gated**, not triggered by normal development commits. From a reviewed `development` commit, release version `0.1.0` by pushing the matching tag:

```bash
git checkout development
git pull --ff-only origin development
git tag security-v0.1.0
git push origin security-v0.1.0
```

Only create the tag after confirming the commit and version. GitHub Actions will validate that the tag matches each project version, rerun build and tests, and publish to **private GitHub Packages** using `GITHUB_TOKEN`. Treat published package versions as immutable. Consuming projects need separately authorized package-read credentials; never commit tokens to source. A successful CI artifact upload alone **does not mean** the private feed has a published package.

## Still pending verification / hardening

- Published private GitHub Packages feed and authorized cross-repository restore
- IIS App Pool key-permission test
- End-to-end activation and copy-to-second-machine rejection
- Signing-key rotation deployment test
- Offline expiry/grace and permitted read/export enforcement

Development happens on the `development` branch.
