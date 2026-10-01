# Security model

DeleteGuard v0.2 is a **defense-in-depth deletion guard** for selected NTFS paths. It combines the v0.1 ACL fallback with a filesystem minifilter prototype that can deny destructive delete requests below Win32.

## Protection layers

### 1. NTFS ACL fallback

A protected root receives an explicit inherited deny rule for `DELETE` and `DELETE_CHILD`. This remains active even if the minifilter is not installed or not running.

### 2. Minifilter kernel gate

`DeleteGuardFilter.sys` attaches to NTFS and currently evaluates:

- `IRP_MJ_SET_INFORMATION` with `FileDispositionInformation`;
- `IRP_MJ_SET_INFORMATION` with `FileDispositionInformationEx` and `FILE_DISPOSITION_DELETE`;
- `IRP_MJ_CREATE` with `FILE_DELETE_ON_CLOSE`.

For a configured protected NT path, the driver returns `STATUS_ACCESS_DENIED` unless the deleting process has an unexpired scoped grant.

### 3. Elevated broker grants

`DeleteGuard.Broker.exe` requires UAC elevation. When `deleteguard delete <path>` is approved, the broker:

1. synchronizes enabled protected roots to the driver;
2. obtains a grant bound to the broker PID and target path with a 15-second TTL;
3. temporarily removes the v0.1 delete ACL;
4. performs the deletion;
5. explicitly revokes the grant;
6. restores/synchronizes protection as needed.

If the driver is present but refuses synchronization or grant creation, the broker fails closed before relaxing the ACL. If the driver is unavailable, v0.1 ACL behavior remains available.

## Important v0.2 boundaries

- The driver artifact produced by CI is **unsigned** and intended only for disposable driver-test VMs.
- The INF contains a development-only altitude. A Microsoft-assigned production minifilter altitude is required before release.
- Kernel code is build-verified in CI, but that is not equivalent to a loaded-driver runtime, stress, verifier, or HLK validation.
- Arbitrary Explorer/cmd/PowerShell/application delete attempts are denied; they do not yet automatically launch a UAC prompt. The explicit approval path remains `deleteguard delete`.
- The driver communication protocol currently uses an in-memory fixed-size root/grant table. Driver state is reconstructed from the protected policy store when the broker connects.
- If the driver cannot resolve a file name for an intercepted request, it lets the request continue to the filesystem and relies on the ACL fallback. This avoids an unsafe kernel-wide fail-closed policy on unresolved names while the prototype is being validated.
- v0.2 supports NTFS and drive-letter-backed protected policies. Reparse-point protection roots remain rejected.
- The kernel gate currently covers deletion disposition and delete-on-close. Destructive rename/move-out enforcement is still planned.

## Administrator threat model

DeleteGuard is primarily intended to prevent accidental deletion, automation mistakes, and unauthorized destructive operations by ordinary user processes. A determined local administrator can potentially disable/unload a development driver, take ownership, edit ACLs, alter policy files, boot another OS, or access storage offline.

Production hardening will require signed driver deployment, service/driver tamper considerations, a production altitude, installation ACL review, and loaded-driver security testing.

## Out of scope

DeleteGuard does not currently protect against:

- disk formatting or partition deletion;
- raw-disk writes;
- offline access or alternate-OS boot;
- filesystem corruption;
- hardware/media failure;
- malicious firmware or kernel compromise.

DeleteGuard is not a backup. Keep independent, versioned backups of important data.
