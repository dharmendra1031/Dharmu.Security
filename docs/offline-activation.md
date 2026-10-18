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

## License Manager

1. Select the customer license.
2. Import the activation request.
3. Verify customer, product, machine and validity.
4. Export the signed `.lic` file.

## Client server

1. Copy the signed license file to the configured license path.
2. Copy the public signing key to the configured public-key path.
3. Restart the application.

The application verifies the signature, product, device identity and validity locally.
No internet connection is required.
