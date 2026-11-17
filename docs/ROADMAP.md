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

- Intercept delete disposition (`FileDispositionInformation` / `FileDispositionInformationEx`).
- Intercept `FILE_DELETE_ON_CLOSE`.
- Broker-to-driver grants scoped to process identity, target path and short TTL.
- Preserve v0.1 ACL as a fallback layer.
- Close the normal approved-delete ACL-removal race by keeping unrelated processes blocked in the minifilter.
- Pinned WDK/SDK CI build, Universal ApiValidator, Inf2Cat and unsigned driver artifact.

Still required before production readiness:

- Microsoft-assigned production minifilter altitude.
- Production driver signing path.
- Loaded-driver VM evidence under Driver Verifier and stress/race testing.
- Driver/service health and recovery hardening.

## v0.2.1 interactive approval UX — build-verified prototype

Implemented:

- Minifilter emits best-effort denied-operation events without waiting on UI.
- Privileged Event Relay receives kernel events and persists a bounded protected history.
- Unelevated desktop Agent shows process/path delete-approval requests.
- Explicit deny/approve choice; delete approval launches the UAC Broker.
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

Release gate remaining: execute the harness in an actual disposable Windows 11 VM, retain the report/dumps/verifier evidence, and resolve runtime findings before promoting the kernel stack.

## v0.2.3 approval-flood hardening — build-verified

- Bounded Relay recent-event state.
- Duplicate suppression with hard cap under unique-path floods.
- Automatic approval prompts limited to a rolling budget.
- Throttled warning notifications.
- Suppressed/stale events never replay later as fresh approvals.

## v0.2.4 process-identity grants — build-verified

- Kernel grant identity is PID + `PsGetProcessStartKey`, not PID alone.
- Request matching uses the actual Filter Manager I/O requestor process.
- No long-lived `EPROCESS` reference retained.
- User-mode ABI remains protocol v3.

## v0.2.5 destructive rename protection — implementation under validation

- Intercept `FileRenameInformation` / `FileRenameInformationEx`.
- Deny protected-source move-out beyond all protected roots.
- Deny rename-with-replace targeting a protected destination.
- Deny renaming an ancestor directory that contains a configured protected root, preventing the policy path from becoming stale while protected data moves with its parent.
- Allow ordinary rename/move operations that remain within protected roots and do not rename a protected-root ancestor.
- Keep delete grants delete-only; rename events are non-approvable.
- Preserve normalized rename name-information through synchronized post-op and call `FltGetTunneledName` before release.
- Main runtime harness validates move-out and protected-destination replacement beneath the fixed safe VM root.
- `run-protected-ancestor-rename-validation.ps1` independently validates the protected-ancestor bypass and operation `RenameProtectedAncestor = 5`.

Remaining review items after v0.2.5:

- execute all loaded-driver rename suites under Driver Verifier;
- retain allowed-rename/name-tunneling runtime evidence;
- alternate-namespace threat model beyond hard links (reparse points, streams, short names);
- recovery/uninstall and service/driver tamper-hardening.

## v0.2.6 hard-link alias containment — implementation in validation

- Gate `FileLinkInformation`, `FileLinkInformationEx` and their kernel-only `BypassAccessCheck` variants.
- A protected file may gain hard-link aliases only inside the same protecting root (`HardLinkOut = 6`).
- Link-with-replace cannot replace a protected destination (`ReplaceProtectedLinkDestination = 7`).
- If a protected-source or replace-existing destination cannot be resolved, the request fails closed.
- Hard-link denials use `HardLinkDenied` events and remain non-approvable by the Agent.
- The rename gate also covers the kernel-only `FileRenameInformationBypassAccessCheck` / `...ExBypassAccessCheck` classes.
- Managed tests lock protocol versions, structure sizes and every enum value, and parse `DeleteGuardFilter.h` so native and managed definitions cannot drift apart.
- CI compiles `scripts/testvm/HardLinkProbe.cs` under Windows PowerShell 5.1 in addition to parsing every test-VM script.
- New disposable-VM harnesses: `run-hardlink-validation.ps1` (external alias denial, same-root allow, native replace denial, ACL-relaxation race) and `run-rename-boundary-validation.ps1` (bidirectional rename race).

Release gate remaining: execute all loaded-driver suites under Driver Verifier in a disposable Windows 11 VM and retain the evidence.

## v0.2.7 consolidation

The v0.2.5/v0.2.6 work was developed on three parallel lines that each re-implemented the same rename hooks with incompatible protocol values. They were consolidated onto the `hardlink-namespace` line (protocol operations 3–7) and the unique parts of the others were ported:

- the hard-link kernel gate, previously staged behind a self-committing CI workflow whose final anchor could never match, is now ordinary reviewed source;
- the hard-link and rename-boundary VM harnesses, the probe-compile CI step and the ABI parity tests;
- the unresolved-replace fail-closed behaviour of the rename-resolution line was already present on this line and needed no port.

The previous line tips are preserved as `archive/*` branches and the original remote branches are untouched.

## v0.2.9 bulk-delete guard — build-verified, runtime gate pending

- Per-folder protection type: full protection (unchanged) or bulk-delete guard.
- Driver (protocol v4): `AddBulkGuardRoot`, per-root rate limiter (`DeleteGuardBulk.h`), `BulkDelete` event naming the folder; bulk-guard roots are exempt from the rename/link gates.
- The rate limiter is a dependency-free header compiled into the driver and unit-tested in user mode, including mutation checks (`tests/native`, run by CI).
- Broker: `--bulk-guard [--threshold=N] [--window=S]`; refuses unless the driver answers (exit code 13); keeps the delete grant alive during long deletions.
- Relay/Agent: bulk events are non-approvable; dedicated notice.
- Management window: protection-type dialog and column; CLI `--bulk-guard`; ten languages.

Release gate remaining: run `scripts/testvm/run-bulkguard-validation.ps1` (and the existing suites, now against protocol v4) in a disposable VM under Driver Verifier.

## v0.3 volume protection

- Detect and gate destructive volume operations where feasible.
- Add explicit format/partition/raw-disk threat model and privileged management UI.
- Recovery-mode workflow and emergency policy export.
