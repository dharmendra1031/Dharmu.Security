# Production release acceptance

## Security boundaries

- Customer builds contain public keys only. The issuer, private signing keys,
  owner ledger and provisioning tools are not runtime package dependencies.
- Keep license and state files outside public static-file paths. Use restrictive
  NTFS ACLs for the IIS identity; the issuer must not run under that identity.
- A raw DPAPI LocalMachine fixture unexpectedly decrypted on the second Windows
  runner in run 45777468023, despite distinct CNG signing identities. Root cause
  is not established. New protected data uses random DPAPI entropy encrypted
  with a separately provisioned non-exportable software CNG RSA key. This adds
  independent key possession to decryption; it is not TPM attestation or a
  per-user authorization boundary. Restrict access to both machine keys.
  A full machine clone including key material, or a local administrator with
  application/key access, is outside the protection guarantee.
- The new format rejects old DPAPI-only blobs. Do not delete or reset existing
  runtime state to upgrade. Before upgrading any existing deployment, obtain
  an approved original-machine migration preserving all revision/clock records;
  re-protect connection strings from their original securely held values.
  No production release has been published, and the automated migration tool
  remains a prerequisite if pre-release state is already in use.
- The local initialized marker is not an independent trusted clock. Offline
  revocation and signing-key retirement require delivery to the customer.
- Software CNG identity is not TPM hardware attestation. Test explicit provider
  selection and key permissions before deploying; do not change a live provider.
- All cooperating workers must use the same canonical local runtime state path.
  Keep the state and sidecar files during upgrades. A disk failure can prevent
  a revocation from reaching another worker.
- License middleware is not authentication or authorization. Only explicitly
  designated read-only health/activation paths may bypass enforcement. Avoid
  putting business endpoints or data under public static-file middleware.
- The legacy issuer-v1 ID requires the original pinned public key and provider.
  Named slots have fingerprint-derived IDs. Protect previous public PEMs against
  substitution and reconcile records before compromise recovery.

## Required release gates

1. Build, direct/transitive NuGet vulnerability audit, test, runtime-only package inspection and isolated NuGet restore.
   The packaged Kestrel smoke test also exercises real software CNG provisioning,
   the standalone issuer CLI, activation download, access denial before issue,
   successful licensed access, revocation, stale file rejection and host restart.
   A second independent Windows CI job consumes the exact built runtime NuGet
   packages and copies a disposable test license and DPAPI ciphertext from the
   first runner. It requires a different device identity, explicit MachineMismatch,
   HTTP 403, and a cryptographic failure from the device-bound DPAPI protector.
   Only synthetic data and the
   public verification key cross jobs; no private key or owner ledger is uploaded.
   Both jobs are virtual Windows environments, not IIS or physical TPM hardware.
2. Review Windows CI diagnostic timing with SECURITY_BENCH markers.
3. A real IIS CI job on a disposable Windows runner provisions an isolated site,
   installs the official .NET 10 Hosting Bundle, uses an ApplicationPoolIdentity
   with explicit client-key and state-directory ACLs, and verifies activation,
   worker recycling, revocation and stale-license rejection. The test uses
   the same runtime package artifacts as the build. Its result must pass before
   release. Customer-server testing, concurrent IIS workers, file loss, storage
   failure and physical TPM ACLs still require deployment acceptance.
4. Two independent Windows machines: provision keys, generate signed request,
   issue license, reject copied license and DPAPI ciphertext on the other
   machine, exercise renew/revoke and authorized replacement. Test TPM if used.
5. Confirm customer data backup/export and recovery policy before expiry
   enforcement; the current middleware returns 403 for protected endpoints.
6. Approve the exact tested commit and publish private packages. Verify package
   visibility and authorized restore; do not distribute owner-only artifacts.
7. Pilot one real application and measure end-to-end billing and database
   latency on target hardware before broad rollout.

These are acceptance criteria, not a claim that manual or physical tests
have already passed. No fully offline design can guarantee piracy prevention
against a privileged local administrator.
