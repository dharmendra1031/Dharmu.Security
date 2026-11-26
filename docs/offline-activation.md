# Offline activation

## Client server

1. Install the application build containing the pinned License Manager public key.
2. Provision the device identity once:

   `Dharmu.Security.DeviceTool.exe`

   Use `--tpm` when the target Windows machine has a usable TPM:

   `Dharmu.Security.DeviceTool.exe --tpm`

3. Start the ASP.NET Core application.
4. Download the activation request from:

   `/license/activation-request`

5. Move the JSON request to the License Manager using approved offline media.

The activation request is signed by the client's non-exportable device private key.
The request includes the device public key, but never the private key.

## License Manager

1. Select the customer license.
2. Import the activation request.
3. Verify the activation-request device signature.
4. Recalculate MachineCode from the supplied device public key.
5. Verify customer, product, machine and validity.
6. Export the signed `.lic` file.

Edited or forged activation requests fail device-signature verification.

## Client server

1. Copy the signed license file to the configured license path.
2. Restart the application.

The License Manager public verification key is not deployed as an editable file.
It is pinned into the application build and selected by the license `KeyId`.

The application verifies the license signature, product, device identity, expiry
and trusted clock state locally. No internet connection is required.

Keep the runtime state file outside web-accessible directories, with write access
restricted to the application identity. Missing state during a running process
causes rejection. A new process still cannot distinguish a first activation from
a deleted or restored state without an independent trusted anchor. DPAPI does not
provide rollback resistance against a local administrator. Do not advertise
fully offline clock protection as tamper-proof.

## Offline revocation

A fully offline installation cannot be remotely revoked instantly.

When a license is deactivated in License Manager:

1. Future normal license export and renewal are blocked.
2. License Manager can export a signed revocation `.lic` file.
3. The revocation file must be transferred to the customer server.
4. Replacing the active license with the signed revocation file and making a
   protected request records the authenticated revocation in local runtime state.
   That license ID is then terminal, including after normal application restart.

If the customer never receives or applies the revocation file, the previously
issued offline license remains usable until its signed expiry date. Use finite
license periods when ongoing commercial control is required.

## License revisions and upgrade

New License Manager exports use schema 2 and a positive signed revision.
The SDK accepts legacy schema 1 with revision zero until a newer revision has
been observed for that license ID. Renewals increase the revision; an older
revision is then rejected. Revocations are terminal for the same license ID.
Issue a new license ID for an authorized replacement. Upgrade the SDK before
issuing schema 2 files; earlier SDK builds cannot read them.

The revision history is stored in the existing DPAPI-protected runtime state.
It survives normal restarts but not administrator-controlled deletion or
restoration of all trusted local state. It requires a single application process
per state path and restrictive filesystem ACLs. An independent trusted anchor
or online lease is necessary for stronger anti-rollback guarantees.

## Protected database connection string

Run on the target Windows server:

`Dharmu.Security.SecretTool.exe`

Enter the production connection string interactively. The tool outputs a
DPAPI-protected Base64 value.

Store only that value:

```json
{
  "ProtectedConnectionStrings": {
    "DefaultConnection": "<protected-value>"
  }
}
```

Read it at startup:

```csharp
var connectionString =
    builder.Configuration.GetDharmuProtectedConnectionString("DefaultConnection");
```

The protected value is tied to the Windows machine through DPAPI and should not
be treated as a replacement for SQL Server authentication, least privilege, or
OS access controls.
