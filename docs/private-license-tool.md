# Private License Tool (owner only)

A standalone Windows console application, not a NuGet package. Build/publish
only on a trusted owner workstation. Do not distribute the tool, signing key
or ledger to customer machines. Customer projects install the ASP.NET Core
runtime package only; it does not reference this tool.

Use a dedicated Windows account/workstation with restrictive ACLs and backups.
The signing key is a non-exportable CNG machine key named DharmuSecurityIssuer
(key ID issuer-v1), separate from the legacy License Manager signing key and
the customer device key. Use --tpm consistently on supported hardware. Loss
of this non-exportable key requires a planned trust-key rotation; exporting
its public PEM is not a private-key backup.

Build on Windows:
```powershell
dotnet publish src/Dharmu.Security.LicenseTool -c Release -r win-x64 --self-contained false
```

Run these commands from the tool directory on the owner machine:
```powershell
.\Dharmu.Security.LicenseTool.exe init C:\Owner\issuer-public.pem --tpm
.\Dharmu.Security.LicenseTool.exe issue C:\Owner\Ledger C:\Owner\activation.json SR_CONSTRUCTION 1 1 365 --tpm
.\Dharmu.Security.LicenseTool.exe renew C:\Owner\Ledger <license-id> 365 --tpm
.\Dharmu.Security.LicenseTool.exe revoke C:\Owner\Ledger <license-id> --tpm
```

List all current licenses, filter by customer ID, or inspect historical signed revisions:
```powershell
.\Dharmu.Security.LicenseTool.exe list C:\Owner\Ledger --tpm
.\Dharmu.Security.LicenseTool.exe list C:\Owner\Ledger 1 --tpm
.\Dharmu.Security.LicenseTool.exe history C:\Owner\Ledger <license-id> --tpm
```

The parent directory for the PEM must already exist. For a lifetime license
use lifetime instead of 365. IDs for customer and product are owner-maintained
positive numeric references; no customer master UI is implemented. Confirm the
product and customer before issuing. The tool validates the signed device
request, its age and the machine code, then signs a schema 2 license.

Use one authoritative ledger directory per issuer; protect it against deletion
and rollback. The ledger contains the latest signed license per random positive
ID; copy the resulting .lic file to the customer, never move the ledger record.
Issuing a second non-revoked license for the same product code and machine
is rejected, even when the original license is expired or a different customer
ID is entered. Renew it, or explicitly revoke it before authorized replacement.
The check authenticates existing ledger records under the exclusive lock; keep
one authoritative ledger. Revocation must still reach the customer to disable
an older offline license.

Renew/revoke increments its revision. Repeated revocation is idempotent, and a
revoked ID cannot be renewed. Updates use an exclusive ledger lock and atomic
file replacement. Before replacement, the previous authenticated signed file
is durably archived in history/<license-id>/<revision>.lic. The top-level
license remains authoritative; a failed replacement can leave an identical
archived copy, which history displays only once. Back up the entire ledger
including history. Archive files are owner-only and must never be supplied
as current licenses. Existing ledgers start recording history at their current
revision; earlier overwritten revisions cannot be reconstructed. This is
signed revision history, not an immutable operator audit log: local deletion
or rollback is possible and operator identities are not recorded.

Pin the exported public key under issuer-v1 in a compatible client build.
Do not mix legacy Manager and standalone issuer records or share signing keys.
The legacy Manager remains a separate existing system. No migration of its
records has been performed. Revocation requires delivery and observation on
the customer server; offline administrator state rollback remains a limitation.

## Signing key loss and recovery

Preserve the owner ledger, exported public key and issuer provider configuration.
Do not attempt to recreate a lost non-exportable private key under the old key
identity. If the original key cannot be recovered through supported hardware
recovery, use a separately identified replacement signing key, update the
client's compiled trust configuration, and reissue licenses after verifying
customer entitlements and device requests. The current CLI uses a fixed key ID;
a controlled rotation workflow needs implementation before that transition.
Never share the private key or weaken signature checks to restore access.
