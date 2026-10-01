# DeleteGuard minifilter design

DeleteGuard v0.2 adds a Windows file-system minifilter to close the temporary ACL-release race in v0.1. v0.2.1 adds the denied-event/interactive approval pipeline. v0.2.2 adds a guarded loaded-driver validation harness for disposable Windows test VMs. v0.2.4 hardens delete grants against Windows PID reuse. v0.2.5 adds destructive rename/move-out protection.

## Enforcement path

```text
Explorer / cmd / PowerShell / Python / Win32 API
                         |
                         v
                  I/O request
                         |
                         v
              DeleteGuardFilter.sys
               /               \
     protected + no grant     not protected
             |                    |
      STATUS_ACCESS_DENIED        v
             |             normal NTFS processing
             v
       best-effort event
             |
   LocalSystem Event Relay
             |
      desktop Agent prompt
             |
       Yes -> Windows UAC
             |
      DeleteGuard.Broker
```

Approved Broker delete path:

```text
sync protected NT paths
-> grant {broker PID + process-start identity, target path, <=30s TTL}
-> temporarily remove v0.1 DELETE ACL
-> perform deletion
-> revoke grant
-> re-sync policies / restore ACL when appropriate
```

The ACL layer remains present as a fallback. If the driver is unavailable, v0.1 behavior remains active. If the driver is present but rejects a sync or grant command, the broker fails closed and does not relax the ACL.

## Operations intercepted

The kernel gate currently handles:

- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformation`;
- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformationEx`;
- `IRP_MJ_CREATE` with `FILE_DELETE_ON_CLOSE`;
- `IRP_MJ_SET_INFORMATION` + `FileRenameInformation`;
- `IRP_MJ_SET_INFORMATION` + `FileRenameInformationEx`.

The filter attaches to NTFS only, matching the v0.1 support boundary.

### Destructive rename policy

v0.2.5 treats two rename classes as destructive protected mutations:

1. **Move out**: the source is under a protected root and the resolved destination is outside every protected root.
2. **Replace protected destination**: a rename request carries replace-if-exists semantics and its resolved destination is under a protected root.

Both are denied in the minifilter before the rename completes. Ordinary rename/move operations that remain within protected roots are allowed by the minifilter.

Rename enforcement intentionally does **not** consume the delete-grant table. Approving a deletion therefore cannot silently widen into permission to move protected data elsewhere or replace a protected destination. If a user deliberately needs such a namespace mutation, they must explicitly change/unprotect the relevant policy first.

The replace-protected-destination rule is intentionally conservative. Software that performs atomic save/replace by renaming a temporary file over a protected target can receive Access Denied. For critical/archive-style protected roots, that is the expected policy boundary rather than an implicit bypass.

The rename destination buffer is copied before resolution and is converted to a normalized destination name with Filter Manager. `IRP_MJ_SET_INFORMATION` is a buffered operation, so the filesystem receives the I/O-manager-owned information buffer rather than a mutable raw user pointer. If a protected-source destination cannot be resolved safely, DeleteGuard fails closed.

For allowed rename operations where DeleteGuard queried normalized source and/or destination information, the pre-operation callback returns `FLT_PREOP_SYNCHRONIZE`, retains those name-information references in a small nonpaged completion context, and the post-operation callback calls `FltGetTunneledName` before releasing them. This follows Filter Manager's required lifecycle for normalized rename names that can be affected by NTFS file-name tunneling. The tunneled final component is not persisted as a new authorization decision; destructive containment is still decided before the namespace mutation occurs.

The disposable-VM runtime suite validates both move-out denial and protected-destination replacement denial using only sibling directories under `C:\DeleteGuard-VMTest`. Allowed-rename/tunneling behavior remains part of Driver Verifier/runtime evidence rather than being inferred from build success alone.

## Protected roots

The broker converts Win32 paths such as:

```text
D:\Projects\Important
```

to the device-path form observed by Filter Manager:

```text
\Device\HarddiskVolumeX\Projects\Important
```

The prototype stores up to 64 active roots. A path matches a root only when it is the same path or a true descendant boundary, not merely a string prefix.

## Scoped delete grants

A delete grant contains:

- broker process ID;
- the broker process start key resolved by the driver with `PsLookupProcessByProcessId` + `PsGetProcessStartKey`;
- normalized NT target path;
- expiry timestamp;
- maximum TTL of 30 seconds.

For every protected delete request, the filter obtains the actual I/O requestor with `FltGetRequestorProcessId` and `FltGetRequestorProcess`, then requires both PID and process start key to match the grant. This prevents a different process from inheriting a still-live grant if Windows reuses the Broker's PID after an abnormal Broker termination.

The driver does not retain a long-lived `EPROCESS` reference for the grant. It references the process only while resolving the grant identity, reads the start key, and immediately dereferences the object.

A grant covers the target and descendants so one elevated recursive delete can remove a tree. The broker normally requests 15 seconds and explicitly revokes the grant in `finally` after the operation.

While the v0.1 ACL is temporarily absent, unrelated processes remain blocked by the minifilter. The runtime validation harness includes a competing-process race test specifically for this boundary.

## Communication security and protocol v3

The driver exposes `\DeleteGuardPort` through `FltCreateCommunicationPort` with the Filter Manager default security descriptor for `FLT_PORT_ALL_ACCESS`. The port therefore remains restricted to privileged callers rather than being opened directly to a normal desktop Agent.

Protocol v3 distinguishes two connection roles:

- **Command**: privileged Broker/Relay policy synchronization (`ping`, reset/add/remove roots, grant, revoke).
- **Event**: LocalSystem Event Relay receives denied-operation notifications.

The fixed ABI layout remains unchanged in v0.2.5. Event semantics add a rename-denied type and operation values for move-out and protected-destination replacement.

The process start key is internal kernel grant state, so the user-mode command ABI does not change and protocol v3 remains valid.

The Agent never receives kernel command access. The Relay persists a bounded read-only denial history under `%ProgramData%\DeleteGuard` for the Agent. Delete events can be approval candidates; rename denial events are always recorded as non-approvable so they cannot accidentally invoke the delete broker.

Kernel event delivery is zero-wait/best-effort. A missing or slow user-mode listener must never stall filesystem I/O or convert a deny into an allow.

The C# side contains ABI-size/layout tests and enum-value tests for the native/managed protocol contract.

## Build

The x64 driver build is pinned to the VS2022-compatible WDK/SDK `10.0.26100.6584` NuGet packages.

```powershell
.\scripts\build-driver.ps1 -Configuration Release
```

Output:

```text
artifacts\driver-x64\DeleteGuardFilter.sys
artifacts\driver-x64\DeleteGuardFilter.inf
artifacts\driver-x64\DeleteGuardFilter.cat
```

CI deliberately publishes an **unsigned** driver artifact.

## Runtime testing and signing

Do not load the CI driver on a production machine. Build verification, Universal ApiValidator and Inf2Cat signability are not substitutes for a loaded-driver test.

Use the guarded disposable-VM runbook:

- [RUNTIME-VALIDATION.md](RUNTIME-VALIDATION.md)

The test harness covers local test signing, Filter Manager load/unload, targeted Driver Verifier, multiple deletion paths, Relay outage behavior, repeated denial stress, scoped-grant race testing, destructive rename/move-out checks and optional driver reload/ACL fallback.

The interactive Agent/UAC acceptance remains manual by design because it validates a real desktop session and Windows secure-desktop elevation flow.

## Production release blockers

Before any public/production driver release, DeleteGuard still needs:

1. a Microsoft-assigned production minifilter altitude;
2. a production driver signing / attestation or HLK path as applicable;
3. recorded loaded-driver VM runs under Driver Verifier with no violations;
4. stress/race and destructive-rename runtime results retained as release evidence;
5. hard-link/alternate-namespace and name-resolution/tunneling runtime threat-model review;
6. service/driver tamper-hardening review and recovery/uninstall validation.

The altitude in `DeleteGuardFilter.inf` is development-only and must not be shipped as a production altitude.
