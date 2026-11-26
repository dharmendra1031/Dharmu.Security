# Production release acceptance

## Security boundaries

- Customer builds contain public keys only. The issuer, private signing keys,
  owner ledger and provisioning tools are not runtime package dependencies.
- Keep license and state files outside public static-file paths. Use restrictive
  NTFS ACLs for the IIS identity; the issuer must not run under that identity.
- DPAPI LocalMachine is machine-scoped, not a per-user authorization boundary.
  A local account with blob access can potentially decrypt it on that machine.
  Local administrators can also replace application code or roll back state.
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

1. Build, test, runtime-only package inspection and isolated NuGet restore.
2. Review Windows CI diagnostic timing with SECURITY_BENCH markers.
3. Real IIS deployment with least-privilege ACLs, app-pool recycling and
   concurrent workers. Test fail-closed behavior on file loss, corrupt state,
   storage failure and invalid license; verify normal application errors.
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
