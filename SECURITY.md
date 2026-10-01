# Security model

DeleteGuard is a defense-in-depth deletion and protected-namespace guard for selected NTFS paths. The current kernel work remains a development prototype and is not production-ready.

## Enforcement layers

### NTFS ACL fallback

Protected roots receive inherited deny rules for delete operations. This remains the fallback when the development minifilter is unavailable.

### Minifilter kernel gate

`DeleteGuardFilter.sys` attaches to NTFS and currently gates:

- `FileDispositionInformation` / `FileDispositionInformationEx` deletion;
- `FILE_DELETE_ON_CLOSE`;
- rename/move namespace mutations through `FileRenameInformation*`;
- NTFS hard-link namespace mutations through `FileLinkInformation*`.

For deletion, a configured protected path is denied unless the actual I/O requestor has a valid short-lived path-scoped grant. Since v0.2.4, a grant binds PID + process start key + target path + expiry, so PID reuse cannot inherit a still-live Broker grant.

Delete grants do not authorize namespace changes. A protected source cannot be renamed, moved, or hard-linked outside its protecting root. Replace-existing rename/link operations cannot replace a protected destination. If a protected-source destination cannot be safely resolved, the namespace mutation fails closed.

### Safe set-information buffer capture

`IRP_MJ_SET_INFORMATION` can expose buffers originating from user mode. DeleteGuard does not directly trust or retain those buffers:

- fixed-size disposition data is probed when required and copied into kernel-local structures before inspection;
- variable-length rename/link metadata is length-checked;
- the destination filename is copied into nonpaged kernel memory before Filter Manager destination resolution;
- accesses are wrapped in structured exception handling.

Rename and hard-link operations deliberately share this capture path so alias containment does not introduce a second, weaker parser.

### Elevated Broker

`DeleteGuard.Broker.exe` requires administrator elevation. For an approved deletion it synchronizes policies, obtains a grant scoped to the Broker process identity and target path, temporarily relaxes the ACL, performs the deletion, revokes the grant, then restores/synchronizes protection.

If the driver is present but refuses synchronization or grant creation, the Broker fails closed before relaxing the ACL.

## Interactive approval boundary

Protocol v3 has two roles on the same administrator/SYSTEM-only Filter Manager communication port:

- command clients synchronize roots and manage delete grants;
- one event client receives best-effort protected-operation denial notifications.

`DeleteGuard.EventRelay.exe` runs as LocalSystem and writes denial events into the protected `%ProgramData%\DeleteGuard` directory. Ordinary users can read the denial stream but do not receive kernel command access.

`DeleteGuard.Agent.exe` runs unelevated in the interactive session. Fresh delete denials may become an explicit approval prompt. Choosing Yes starts the existing Broker with Windows UAC elevation.

Namespace-mutation denials are deliberately **not approvable**. Rename, move, replacement, and hard-link alias denials are visibility/warning events only and can never be transformed into an unintended Broker deletion.

The denial stream is not an authorization source. The Broker independently checks that a delete target is still covered by a current protection policy.

## Deny-then-approved-delete behavior

The original application delete request is denied immediately. The kernel does not wait for desktop UI or UAC. If the user later approves the prompt, the elevated Broker performs a separate approved deletion.

Notification failure, Agent failure, UAC cancellation, or no response never permits the original operation.

## ACL-relaxation race protections

During an approved recursive deletion the v0.1 ACL must temporarily be relaxed on the protected root. The minifilter therefore continues to enforce boundaries during this window:

- unrelated delete requests remain blocked;
- delete grants are bound to Broker process identity and approved path;
- protected files cannot be moved or renamed out of their protecting root;
- rename-with-replace cannot overwrite a protected destination;
- protected files cannot acquire a hard-link alias outside their protecting root;
- link-with-replace cannot replace a protected destination.

The disposable-VM harness contains competing-process race cases for delete, rename/move, replacement, and hard-link escape.

## Event-channel protections

- Kernel notification delivery is best effort and never changes the deny decision.
- Relay synchronization uses the same global mutation mutex as the Broker so policy reset cannot clear a live deletion grant mid-operation.
- The driver accepts multiple command clients and one event client.
- Repeated identical denial events are suppressed for a short interval by the Relay.
- Automatic Agent approval prompts are rate-limited.
- Denial history is bounded and rotated.

## Current namespace boundary

The development gate now covers destructive rename/move and NTFS hard-link alias creation. Reparse-point protection roots remain unsupported/rejected.

This is not yet a claim of complete production-grade alias containment. Loaded-driver testing must still exercise normalized-name behavior, existing hard-link edge cases, reparse interactions, cross-volume failures, and hostile/malformed set-information requests under Driver Verifier.

## Development status

The CI driver artifact is unsigned and intended only for disposable test VMs. The INF still uses a development altitude. CI verifies compilation, Universal ApiValidator, Inf2Cat signability, managed protocol/build/tests/package, Windows PowerShell 5.1 parsing, native test-probe compilation, and destructive-path safety guards.

Loaded-driver runtime testing, Driver Verifier evidence, namespace/hard-link race testing, production altitude allocation, release signing, and recovery/tamper review are still required before production use.

DeleteGuard is not a backup. Independent versioned backups remain necessary for important data.
