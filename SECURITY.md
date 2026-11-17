# Security model

DeleteGuard is a defense-in-depth deletion and destructive-namespace guard for selected NTFS paths. The current development stack combines the v0.1 ACL fallback with the v0.2+ minifilter, interactive approval pipeline and guarded test-VM validation tooling.

## Enforcement layers

### NTFS ACL fallback

Protected roots receive inherited deny rules for delete operations. This remains the fallback when the development minifilter is unavailable.

The ACL layer is intentionally conservative: Windows `DELETE` permission participates in rename/move and replace semantics, so strict protection can interfere with applications that use atomic rename/replace saves.

### Minifilter kernel gate

`DeleteGuardFilter.sys` attaches to NTFS and checks:

- delete disposition requests;
- delete-on-close;
- rename/move requests that would take a protected source outside all protected roots;
- rename-with-replace requests whose destination is protected;
- rename requests for an ancestor directory that currently contains a configured protected root.

Protected deletion is denied unless the actual I/O requestor matches a valid short-lived path-scoped delete grant. The grant is bound to the Broker PID **and** Windows process start key, plus target path and expiry, reducing PID-reuse risk.

Rename enforcement intentionally does not use delete grants. A user approval to delete a target is not permission to move protected data out of protection, replace a protected destination, or relocate a configured protected root by renaming one of its parents.

### Elevated Broker

`DeleteGuard.Broker.exe` requires administrator elevation. For an approved deletion it synchronizes policies, obtains a grant scoped to Broker process identity and target path, temporarily relaxes the ACL, performs the deletion, revokes the grant, then restores/synchronizes protection.

If the driver is present but refuses synchronization or grant creation, the Broker fails closed before relaxing the ACL.

## Destructive rename boundary

v0.2.5 denies three namespace mutations in kernel mode:

- **MoveOut**: a protected source resolves to a destination outside every protected root.
- **ReplaceProtectedDestination**: a rename with replace-if-exists semantics resolves to a protected destination.
- **RenameProtectedAncestor**: the rename source is an ancestor directory containing a configured protected root. Renaming it would move the protected subtree while leaving the stored policy path pointing at the old location.

Internal renames that remain within protected roots are allowed by the minifilter, provided the renamed object is not itself an ancestor that contains a configured root. Rename denials are notification-only: the Event Relay marks them non-approvable and the desktop Agent never maps them into the delete Broker.

If Filter Manager cannot safely resolve a destination for a protected-source rename, DeleteGuard fails closed. A replace-if-exists operation is also handled conservatively when protection state cannot be established safely.

For allowed renames where normalized name information was queried in pre-operation, DeleteGuard uses a synchronized post-operation callback and `FltGetTunneledName` before releasing the cached name-information references. This follows the Filter Manager lifecycle required for rename operations that may be affected by NTFS name tunneling.

This strict policy can block application atomic-save workflows that rename a temporary file over a protected target. Protected roots should therefore be chosen for data where explicit integrity/deletion protection is more important than transparent replacement semantics.

## Interactive approval boundary

Protocol v3 has two roles on the same administrator/SYSTEM-only Filter Manager communication port:

- command clients synchronize roots and manage delete grants;
- one event client receives best-effort denied-operation notifications.

`DeleteGuard.EventRelay.exe` runs as LocalSystem and writes denial events into the protected `%ProgramData%\DeleteGuard` directory. Ordinary users can read the denial stream but do not receive kernel command access.

`DeleteGuard.Agent.exe` runs unelevated in the interactive session. It can show an approval prompt only for a fresh, approvable delete-denial event. Choosing Yes starts the existing Broker with Windows UAC elevation. Rename denial events show a warning only.

The denial stream is not an authorization source. The Broker independently checks that the delete target is still covered by a current protection policy.

## Deny-then-approved-delete behavior

The original application delete request is denied immediately. The kernel does not wait for desktop UI or UAC. If the user later approves the prompt, the elevated Broker performs a separate approved deletion.

This means Explorer, PowerShell, or another caller can show Access Denied before the approved Broker deletion finishes. Notification failure, Agent failure, UAC cancellation, or no response never permits the original deletion.

## Event-channel protections

- Kernel notification delivery is best effort and never changes the deny decision.
- Relay synchronization uses the same global mutation mutex as the Broker so policy reset cannot clear a live deletion grant mid-operation.
- The driver accepts multiple command clients and one event client.
- Repeated identical denial events are suppressed for a short interval with a hard in-memory cap.
- Automatic modal delete-approval prompts are rate-limited; throttling never changes enforcement.
- Denial history rotates at 4 MiB and retains one previous file.

## Current scope and non-goals

DeleteGuard is not yet a complete storage-integrity boundary. Current development releases do not claim protection against:

- disk/volume formatting, partition deletion or raw-disk writes;
- offline access from another OS or physical media access;
- filesystem corruption or hardware failure;
- a determined local administrator that deliberately disables/uninstalls/tampers with the development protection stack;
- every alternate NTFS namespace mechanism. Hard-link aliases are gated since v0.2.6, but reparse points, alternate data streams, short (8.3) names and cross-volume behaviour remain explicit threat-model/runtime-review items.

The filter currently attaches to NTFS only.

## Namespace mutation gate

Delete grants never authorize namespace changes. The filter denies, without any approval path:

- renaming/moving a protected source outside every protected root;
- rename-with-replace onto a protected destination;
- renaming an ancestor directory that contains a protected root;
- creating a hard link to a protected file outside its protecting root (`FileLinkInformation*`);
- link-with-replace onto a protected destination.

If a protected source or replace-existing destination cannot be resolved safely, the request fails closed. The kernel-only `...BypassAccessCheck` information classes are gated like their user-mode counterparts.

## Development status

The CI driver artifact is unsigned and intended only for disposable test VMs. The INF still uses a development altitude. CI verifies compilation, API validation, package signability, managed tests and guarded test-harness syntax/safety boundaries, but loaded-driver runtime testing under Driver Verifier is still required before production use.

The repository's runtime tooling refuses destructive testing outside `C:\DeleteGuard-VMTest` and requires an explicit machine-bound disposable-VM marker. v0.2.5 adds a dedicated protected-ancestor rename test beneath that fixed test root so this policy-path relocation bypass can be exercised without touching any normal host data.

DeleteGuard is not a backup. Independent versioned backups remain necessary for important data.
