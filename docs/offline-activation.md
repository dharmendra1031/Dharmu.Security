# Offline activation

## Client server

1. Install the application.
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
2. Copy the License Manager public signing key to the configured public-key path.
3. Restart the application.

The application verifies the license signature, product, device identity, expiry
and trusted clock state locally. No internet connection is required.

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
