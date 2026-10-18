# Dharmu.Security

Reusable security components for ASP.NET Core applications deployed on Windows/IIS.

## Current foundation

- ECDSA signed offline license validation
- Product and machine binding checks
- License start/expiry validation
- Windows machine identity provider
- Windows DPAPI secret protection
- ASP.NET Core license middleware

## Projects

- `Dharmu.Security.Core`
- `Dharmu.Security.Windows`
- `Dharmu.Security.AspNetCore`

## Security boundary

The private signing key must never be committed to this repository or shipped with client applications.
Client applications contain only the public verification key.

Production database credentials must not be committed to source control.

## Planned next

- TPM-backed device key support
- clock rollback protection
- activation request format
- package tests
- private NuGet publishing

Development happens on the `development` branch.
