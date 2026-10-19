# Dharmu.Security

Reusable offline licensing and Windows security components for ASP.NET Core applications.

## Current development foundation

- ECDSA P-256 signed offline license validation
- signed offline activation requests with device proof
- product binding
- non-exportable Windows CNG device identity
- optional TPM-backed device identity
- machine-code generation from the device public key
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

## Security boundary

The License Manager private signing key is never included in this repository,
NuGet packages, or customer deployments.

Client applications receive only the public verification key.

The client device private key is created as a non-exportable Windows CNG key.
When TPM provisioning is selected, the Windows Platform Crypto Provider is used.

Production database credentials must not be committed to source control.

## Offline activation and secrets

See `docs/offline-activation.md`.

## Still pending verification / hardening

- real .NET build verification
- automated tests
- private NuGet package consumption test
- IIS App Pool key-permission test
- end-to-end copy-to-second-machine rejection test
- signing/public-key rotation support

Development happens on the `development` branch.
