# DeleteGuard roadmap

## v0.1 MVP — complete

- NTFS folder/data-volume protection with inherited deny-delete ACL.
- UAC-elevated broker for protect, unprotect and one-time approved deletion.
- Persistent policy store under `%ProgramData%\DeleteGuard`.
- JSONL audit log.
- CLI status/list/doctor/audit commands.
- CI build, tests and Windows package artifact.

## v0.2 minifilter kernel gate — build-verified prototype

Implemented:

- delete disposition (`FileDispositionInformation` / `FileDispositionInformationEx`);
- `FILE_DELETE_ON_CLOSE`;
- short-lived Broker delete grants;
- v0.1 ACL fallback;
- pinned WDK/SDK CI build, Universal ApiValidator, Inf2Cat and unsigned driver artifact.

Still required before production:

- Microsoft-assigned production minifilter altitude;
- production driver signing path;
- loaded-driver VM evidence under Driver Verifier and stress/race testing;
- driver/service health and recovery hardening.

## v0.2.1 interactive approval UX — build-verified prototype

Implemented:

- best-effort kernel denial events without waiting on UI;
- LocalSystem Event Relay and unelevated desktop Agent;
- deny-first -> explicit approval -> UAC Broker delete;
- protocol v3 command/event roles;
- Broker/Relay synchronization mutex;
- bounded event history and duplicate coalescing.

Still required:

- loaded-driver desktop-session validation of Explorer/Agent/UAC behavior;
- UX polish, localization and richer process presentation.

## v0.2.2 runtime validation gate — harness implemented

Implemented in `scripts/testvm` and `docs/RUNTIME-VALIDATION.md`:

- disposable-VM marker and hard `C:\DeleteGuard-VMTest` destructive boundary;
- guarded TESTSIGNING preparation and local non-exportable test certificate;
- driver/catalog test signing and verification;
- Filter Manager install/load checks;
- Driver Verifier targeted only at `DeleteGuardFilter.sys`;
- PowerShell/CMD/.NET/Win32/delete-on-close/recursive-delete checks;
- Event Relay outage and denial stress checks;
- scoped-grant competing-process race check;
- guarded cleanup and machine-readable evidence.

Release gate remaining: execute the harness in an actual disposable Windows 11 VM, retain report/dumps/verifier evidence, and resolve all runtime findings.

## v0.2.3 approval-flood hardening — build-verified

- Relay duplicate state is bounded to 512 entries.
- Automatic Agent approval prompts are limited to 3 per rolling 30 seconds.
- Suppressed/stale events cannot replay later as fresh approval requests.

## v0.2.4 process-identity grants — build-verified

- Kernel grants bind to PID + `PsGetProcessStartKey` + path + TTL.
- Enforcement uses Filter Manager requestor identity rather than current-thread process identity.
- No long-lived `EPROCESS` reference is retained.

## v0.2.5 namespace-escape gate — in validation

- Gate rename/move namespace mutations in `IRP_MJ_SET_INFORMATION`.
- Deny a protected source moving outside its protecting root.
- Deny rename-with-replace when the destination is protected.
- Delete grants deliberately do not authorize namespace mutations.
- Namespace denials are visible but never auto-approvable by the Agent.
- Disposable-VM harness includes move-out and replace-destination race tests during an approved Broker delete window.

Release gate: WDK/.NET CI plus loaded-driver namespace race validation under Driver Verifier.

## v0.3 volume protection

- Detect and gate destructive volume operations where feasible.
- Add explicit format/partition/raw-disk threat model and privileged management UI.
- Recovery-mode workflow and emergency policy export.
