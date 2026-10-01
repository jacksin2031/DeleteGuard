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
- Broker-to-driver grants scoped to process identity, target path and short TTL.
- Preserve v0.1 ACL as a fallback layer.
- Close the normal approved-delete ACL-removal race by keeping unrelated processes blocked in the minifilter.
- Pinned WDK/SDK CI build, Universal ApiValidator, Inf2Cat and unsigned driver artifact.

Still required before v0.2 can be treated as production-ready:

- Microsoft-assigned production minifilter altitude.
- Production driver signing path.
- Loaded-driver VM evidence under Driver Verifier and stress/race testing.
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

## v0.2.3 approval-flood hardening — build/unit-test verified

Implemented:

- Relay recent-event state is bounded even under unique-path floods;
- automatic modal prompts are limited to 3 per rolling 30 seconds;
- suppressed/stale events are not replayed later as fresh approval opportunities;
- throttle/unmappable warning notifications are rate-limited;
- enforcement remains kernel/ACL fail-closed when UI is throttled.

## v0.2.4 process-identity grants — build-verified

Implemented:

- kernel grants bind PID plus `PsGetProcessStartKey`, target path and expiry;
- request identity uses `FltGetRequestorProcessId` + `FltGetRequestorProcess`;
- a PID reused after Broker termination cannot inherit the remaining short-lived grant;
- no long-lived `EPROCESS` reference is retained.

## v0.2.5 rename boundary — implementation in validation

Implemented on the stacked development branch:

- intercept `FileRenameInformation` and `FileRenameInformationEx`;
- resolve destination paths with `FltGetDestinationFileNameInformation`;
- block a protected source from moving into a different or unprotected root;
- block replace-existing rename operations whenever the source or destination touches protected scope, including outside-to-protected overwrite attempts;
- allow ordinary non-replace renames that remain inside the same protected root;
- fail closed when a protected source has an invalid/unresolvable rename destination;
- emit distinct `RenameOut` and `RenameReplace` operation codes while keeping protocol-v3 structure sizes unchanged;
- never convert destructive rename denials into delete approval/UAC prompts;
- extend disposable-VM validation with move-out and replace-existing attacks during the Broker ACL-relaxation window.

Release gate remaining: execute the complete stacked harness in an actual disposable Windows 11 VM, retain runtime report/dumps/verifier evidence, complete the manual Explorer/Agent/UAC checklist, and resolve any loaded-driver findings before promoting the minifilter stack.

## v0.3 volume protection

- Detect and gate destructive volume operations where feasible.
- Add explicit format/partition/raw-disk threat model and privileged management UI.
- Recovery-mode workflow and emergency policy export.
