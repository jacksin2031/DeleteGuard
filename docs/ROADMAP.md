# DeleteGuard roadmap

## v0.1 MVP — complete

- NTFS folder/data-volume protection with inherited deny-delete ACL.
- UAC-elevated broker for protect, unprotect and one-time approved deletion.
- Persistent policy store under `%ProgramData%\DeleteGuard`.
- JSONL audit log.
- CLI status/list/doctor/audit commands.
- CI build, tests and Windows package artifact.

## v0.2 minifilter kernel gate — prototype

Implemented in the v0.2 development branch:

- Intercept delete disposition (`FileDispositionInformation` / `FileDispositionInformationEx`).
- Intercept `FILE_DELETE_ON_CLOSE`.
- Broker-to-driver grants scoped to process ID, target path and short TTL.
- Preserve v0.1 ACL as a fallback layer.
- Close the normal approved-delete ACL-removal race by keeping unrelated processes blocked in the minifilter.
- Pinned WDK/SDK CI build and unsigned driver artifact.

Still required before v0.2 can be treated as production-ready:

- Microsoft-assigned production minifilter altitude.
- Production driver signing path.
- Loaded-driver VM integration tests, Driver Verifier and stress/race testing.
- Destructive rename/move-out interception.
- Driver/service health surfaced in `doctor`.

## v0.2.1 interactive approval UX

- User-mode request/tray service receives denied-delete notifications from the minifilter.
- Show the process, executable, target path and requested operation.
- Explicit user choice: deny or request administrator approval.
- UAC-elevated grant issuer creates a one-operation/scoped grant.
- Safely retry or coordinate the originating deletion without placing UI in kernel mode.
- Rate limiting, timeout and duplicate-request coalescing.

## v0.3 volume protection

- Detect and gate destructive volume operations where feasible.
- Add explicit format/partition/raw-disk threat model and privileged management UI.
- Recovery-mode workflow and emergency policy export.
