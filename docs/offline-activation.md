# Offline activation

## Client server

1. Install the application build containing the pinned standalone issuer public key.
2. Open `Dharmu.Security.DeviceTool.exe` as a local administrator. Enter the exact product code and select Prepare device keys or Generate signed activation request. The GUI uses the same existing keys and never exports private keys. For unattended provisioning use `Dharmu.Security.DeviceTool.exe --provision`.

   Use `--tpm` when the target Windows machine has a usable TPM:

   `Dharmu.Security.DeviceTool.exe --provision --tpm`

   Set `options.RequireTpmDeviceIdentity = true` in the application for this
   provisioning mode. The default is software CNG only. Existing TPM installations
   must set this option before upgrading. The runtime does not silently switch
   providers if the configured key cannot be opened.

3. Start the ASP.NET Core application.
4. Download the activation request from:

   `/license/activation-request`

5. Move the JSON request to the owner-only License Tool using approved offline media.

The activation request is signed by the client's non-exportable device private key.
The request includes the device public key, but never the private key.

## Private License Tool

Use the owner-only commands in [private-license-tool.md](private-license-tool.md).
The issuer authenticates the device request, checks product and machine identity,
and signs the license using the owner's private key. Copy the resulting signed
`.lic` file from the ledger without moving the authoritative record.

Edited or forged activation requests fail device-signature verification.

## Client server

1. In the Device Tool choose Import signed license, the independently verified owner public PEM matching the application's compiled pin, and the configured license directory. The tool checks the signed file before replacing license.lic. It does not modify runtime state. Alternatively copy the signed license file manually.
2. Restart the application.

The issuer public verification key is not deployed as an editable file.
It is pinned into the application build and selected by the license `KeyId`.

The application verifies the license signature, product, device identity, expiry
and trusted clock state locally. No internet connection is required.

Keep the runtime state file outside web-accessible directories, with write access
restricted to the application identity. Missing state during a running process
causes rejection. A local .initialized sidecar also detects isolated state-file
deletion across restarts. Preserve both files during deployment and backup.
An existing valid state is migrated by creating its marker. The marker is not an
independent trusted anchor: deletion or rollback of the whole directory remains
possible for a local administrator. DPAPI does not provide rollback resistance.
An authenticated expired license updates trusted time without granting access;
the first observed expiry is persisted immediately, including within the normal
write interval. Do not advertise fully offline protection as tamper-proof.

## Offline revocation

A fully offline installation cannot be remotely revoked instantly.

When a license is revoked with the private tool:

1. Renewal of the revoked ID is blocked.
2. The private tool saves a signed revocation `.lic` file.
3. The revocation file must be transferred to the customer server.
4. Replacing the active license with the signed revocation file and making a
   protected request records the authenticated revocation in local runtime state.
   That license ID is then terminal, including after normal application restart.

If the customer never receives or applies the revocation file, the previously
issued offline license remains usable until its signed expiry date. Use finite
license periods when ongoing commercial control is required.

## License revisions and upgrade

The standalone issuer uses schema 2 and a positive signed revision.
The SDK accepts legacy schema 1 with revision zero until a newer revision has
been observed for that license ID. Renewals increase the revision; an older
revision is then rejected. Revocations are terminal for the same license ID.
Issue a new license ID for an authorized replacement. Upgrade the SDK before
issuing schema 2 files; earlier SDK builds cannot read them.

The revision history is stored in the existing DPAPI-protected runtime state.
It survives normal restarts but not administrator-controlled deletion or
restoration of all trusted local state. Cooperating workers use an exclusive lock file and merge the latest persisted
state before validation. All workers must use the same canonical local state
path, filesystem and restrictive ACLs. Do not delete the lock file while workers
are running. A failed state write blocks the observing worker, but cannot
guarantee other workers observe an event that never reached durable storage. An independent trusted anchor
or online lease is necessary for stronger anti-rollback guarantees.

## Protected database connection string

Use Protect secret in the Device Tool GUI, or run on the target Windows server:

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
