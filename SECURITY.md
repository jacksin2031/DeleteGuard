# Security model

DeleteGuard v0.2.1 is a defense-in-depth deletion guard for selected NTFS paths.

## Enforcement layers

### NTFS ACL fallback

Protected roots receive inherited deny rules for delete operations. This remains the fallback when the development minifilter is unavailable.

### Minifilter kernel gate

`DeleteGuardFilter.sys` attaches to NTFS and currently checks delete disposition requests and delete-on-close. A configured protected path is denied unless the requesting process has a valid short-lived path-scoped grant.

### Elevated Broker

`DeleteGuard.Broker.exe` requires administrator elevation. For an approved deletion it synchronizes policies, obtains a grant scoped to the Broker PID and target path, temporarily relaxes the ACL, performs the deletion, revokes the grant, then restores/synchronizes protection.

If the driver is present but refuses synchronization or grant creation, the Broker fails closed before relaxing the ACL.

## Interactive approval boundary

Protocol v3 adds two roles on the same administrator/SYSTEM-only Filter Manager communication port:

- command clients synchronize roots and manage grants;
- one event client receives best-effort delete-denied notifications.

`DeleteGuard.EventRelay.exe` runs as LocalSystem and writes denial events into the protected `%ProgramData%\DeleteGuard` directory. Ordinary users can read the denial stream but do not receive kernel command access.

`DeleteGuard.Agent.exe` runs unelevated in the interactive session. It can show an approval prompt for a fresh denial event. Choosing Yes starts the existing Broker with Windows UAC elevation.

The denial stream is not an authorization source. The Broker independently checks that the target is still covered by a current protection policy.

## Deny-then-approved-delete behavior

The original application delete request is denied immediately. The kernel does not wait for desktop UI or UAC. If the user later approves the prompt, the elevated Broker performs a separate approved deletion.

This means Explorer, PowerShell, or another caller can show Access Denied before the approved Broker deletion finishes. Notification failure, Agent failure, UAC cancellation, or no response never permits the original deletion.

## Event-channel protections

- Kernel notification delivery is best effort and never changes the deny decision.
- Relay synchronization uses the same global mutation mutex as the Broker so policy reset cannot clear a live deletion grant mid-operation.
- The driver accepts multiple command clients and one event client.
- Repeated identical denial events are suppressed for a short interval by the Relay.
- Denial history rotates at 4 MiB and retains one previous file.

## Development status

The CI driver artifact is unsigned and intended only for disposable test VMs. The INF still uses a development altitude. CI verifies compilation, API validation and package signability, but loaded-driver runtime testing, Driver Verifier, stress testing and release signing are still required before production use.

DeleteGuard is not a backup. Independent versioned backups remain necessary for important data.
