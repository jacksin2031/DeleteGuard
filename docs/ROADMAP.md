# DeleteGuard roadmap

## v0.1 MVP

- NTFS folder/data-volume protection with inherited deny-delete ACL.
- UAC-elevated broker for protect, unprotect and one-time approved deletion.
- Persistent policy store under `%ProgramData%\DeleteGuard`.
- JSONL audit log.
- CLI status/list/doctor/audit commands.
- CI build, tests and Windows package artifact.

## v0.2 minifilter

Move the enforcement decision below Win32 into a signed Windows File System Minifilter:

- Intercept delete disposition (`FileDispositionInformation` / `FileDispositionInformationEx`).
- Intercept destructive rename/move out of a protected scope.
- Broker-to-driver authorization tokens scoped to process, operation and path.
- Eliminate the temporary ACL-removal race in the MVP.
- Add service/driver health state and fail-closed policy.

## v0.3 volume protection

- Detect and gate destructive volume operations where feasible.
- Add explicit format/partition/raw-disk threat model and privileged management UI.
- Recovery-mode workflow and emergency policy export.
