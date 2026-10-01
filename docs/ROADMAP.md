# DeleteGuard roadmap

## v0.1 MVP — complete

- NTFS folder/data-volume protection with inherited deny-delete ACL.
- UAC-elevated broker for protect, unprotect and one-time approved deletion.
- Persistent policy store under `%ProgramData%\DeleteGuard`.
- JSONL audit log.
- CLI status/list/doctor/audit commands.
- CI build, tests and Windows package artifact.

## v0.2 minifilter kernel gate — build-verified prototype

Implemented in the v0.2 development branch:

- Intercept delete disposition (`FileDispositionInformation` / `FileDispositionInformationEx`).
- Intercept `FILE_DELETE_ON_CLOSE`.
- Broker-to-driver grants scoped to process ID, target path and short TTL.
- Preserve v0.1 ACL as a fallback layer.
- Close the normal approved-delete ACL-removal race by keeping unrelated processes blocked in the minifilter.
- Pinned WDK/SDK CI build, Universal ApiValidator, Inf2Cat and unsigned driver artifact.

Still required before v0.2 can be treated as production-ready:

- Microsoft-assigned production minifilter altitude.
- Production driver signing path.
- Loaded-driver VM evidence under Driver Verifier and stress/race testing.
- Destructive rename/move-out interception or an explicitly accepted scope boundary.
- Driver/service health and recovery hardening.

## v0.2.1 interactive approval UX — build-verified prototype

Implemented:

- Minifilter emits best-effort denied-delete events without waiting on UI.
- Privileged Event Relay receives kernel events and persists a bounded protected history.
- Unelevated desktop Agent shows process/path approval requests.
- Explicit deny/approve choice; approval launches the existing UAC Broker.
- Protocol v3 separates command and event roles while leaving the Filter Manager port privileged.
- Broker/Relay synchronization mutex prevents policy reset from racing a live grant.
- Duplicate-event coalescing and 4 MiB history rotation.
- Windows Service / per-user Agent deployment scripts.

Still required:

- Loaded-driver desktop-session validation of Explorer/Agent/UAC behavior.
- Process identity hardening beyond PID/name for future hostile-local-process threat models.
- UX polish, localization and richer operation/process presentation.

## v0.2.2 runtime validation gate — harness implemented

Implemented in `scripts/testvm` and `docs/RUNTIME-VALIDATION.md`:

- disposable-VM safety marker and hard-coded `C:\DeleteGuard-VMTest` destructive-test boundary;
- guarded TESTSIGNING preparation without automatic Secure Boot/firmware changes;
- self-created local test certificate, driver image signing, catalog regeneration/signing and verification;
- test-stack install/load through Filter Manager;
- Driver Verifier targeted only at `DeleteGuardFilter.sys` with reset-on-boot-fail mode;
- automated PowerShell/CMD/.NET/Win32/delete-on-close/recursive-delete checks;
- Event Relay outage and repeated-denial stress checks;
- scoped-grant competing-process race check;
- optional driver unload/reload + ACL fallback validation;
- machine-readable runtime acceptance report;
- guarded cleanup.

Release gate remaining: execute the harness in an actual disposable Windows 11 VM, retain the report/dumps/verifier evidence, and resolve any runtime findings before making PR #3 ready for review.

## v0.3 volume protection

- Detect and gate destructive volume operations where feasible.
- Add explicit format/partition/raw-disk threat model and privileged management UI.
- Recovery-mode workflow and emergency policy export.
