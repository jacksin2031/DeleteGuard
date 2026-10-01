# DeleteGuard minifilter design

DeleteGuard v0.2 adds a Windows file-system minifilter to close the temporary ACL-release race in v0.1. v0.2.1 adds denied-event/interactive approval, v0.2.2 adds guarded disposable-VM validation, v0.2.4 binds delete grants to process start identity, and v0.2.5 gates destructive namespace escape.

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
     protected + denied       allowed
             |                    |
      STATUS_ACCESS_DENIED        v
             |             normal NTFS processing
             v
       best-effort event
             |
   LocalSystem Event Relay
             |
        desktop Agent
```

Approved delete path:

```text
Agent/CLI -> Windows UAC -> DeleteGuard.Broker
                           |
                           +-> sync protected NT paths
                           +-> grant {Broker PID + process-start key, target path, <=30s TTL}
                           +-> temporarily relax v0.1 DELETE ACL
                           +-> perform approved deletion
                           +-> revoke grant
                           +-> re-sync policy / restore ACL
```

The ACL layer remains a fallback. If the driver is unavailable, v0.1 behavior remains active. If the driver is present but rejects sync or grant creation, the Broker fails closed before relaxing the ACL.

## Operations intercepted

### Destructive deletion

- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformation`
- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformationEx`
- `IRP_MJ_CREATE` with `FILE_DELETE_ON_CLOSE`

### Namespace mutation

- `FileRenameInformation`
- `FileRenameInformationBypassAccessCheck`
- `FileRenameInformationEx`
- `FileRenameInformationExBypassAccessCheck`

For rename/move operations:

- a protected source may remain inside its existing protecting root;
- a protected source moving outside that root is denied;
- rename-with-replace is denied when its destination is protected;
- if a protected-source destination cannot be safely resolved, the operation fails closed;
- delete grants do not authorize namespace mutation.

This specifically protects unrelated files during the Broker's temporary ACL-relaxation window.

The filter attaches to NTFS only, matching the ACL support boundary.

## Safe capture of set-information buffers

`SetFileInformation.InfoBuffer` is treated as untrusted when the request originates in user mode.

For disposition operations, the minifilter probes when required and copies the fixed-size input into a kernel-local structure before checking the delete flag.

Rename operations use a two-stage capture:

1. safely inspect/copy the fixed header fields (`RootDirectory`, flags, filename length);
2. validate the variable filename length, allocate nonpaged kernel memory, then probe/copy the filename into that stable buffer.

Destination resolution uses only the captured kernel copy. Structured exception handling protects the probe/copy boundary. This prevents direct bad-pointer dereferences and prevents user mode from changing rename metadata between validation and use.

## Protected roots

The Broker converts Win32 paths such as:

```text
D:\Projects\Important
```

to normalized device-path form observed by Filter Manager:

```text
\Device\HarddiskVolumeX\Projects\Important
```

The prototype stores up to 64 active roots. A path matches a root only when it is the same path or a true descendant boundary, not a raw string prefix.

## Scoped delete grants

A grant contains:

- Broker process ID;
- Broker process start key resolved by the driver with `PsLookupProcessByProcessId` + `PsGetProcessStartKey`;
- normalized NT target path;
- expiry timestamp;
- maximum TTL of 30 seconds.

For every protected delete request, the filter obtains the actual I/O requestor through Filter Manager and requires both PID and process start key to match. Windows PID reuse therefore cannot inherit a surviving grant after an abnormal Broker exit.

The driver does not retain a long-lived `EPROCESS` reference. It references the process only while resolving identity, reads the start key, then dereferences it.

A delete grant covers the approved target and descendants so one elevated recursive delete can remove a tree. The Broker normally requests 15 seconds and explicitly revokes the grant in `finally`.

## Namespace-denial UX

Protocol v3 preserves the same fixed managed/native ABI. `DriverDeleteOperation.NamespaceMutation` / `DgDeleteOperationNamespaceMutation` identifies rename/move denial events without changing structure sizes.

The Relay persists these events but marks them non-approvable. The Agent shows a warning only; it never turns a denied rename/move into Yes -> UAC -> Broker delete.

## Communication security

The driver exposes `\DeleteGuardPort` with Filter Manager's privileged security descriptor. Protocol v3 distinguishes:

- **Command** clients for policy synchronization and delete grant management;
- **Event** client for the LocalSystem Relay.

The normal desktop Agent never receives kernel command access.

Kernel event delivery is zero-wait/best-effort. A missing or slow user-mode listener cannot stall filesystem I/O and cannot convert a deny into an allow.

## Build verification

The x64 build is pinned to the VS2022-compatible WDK/SDK `10.0.26100.6584` NuGet toolchain.

```powershell
.\scripts\build-driver.ps1 -Configuration Release
```

CI verifies:

- WDK x64 compilation;
- warnings-as-errors;
- Universal ApiValidator;
- INF/package generation and Inf2Cat signability;
- managed protocol/build/tests/package;
- Windows PowerShell 5.1 parsing of test-VM scripts;
- destructive-test path boundary smoke checks.

The CI driver artifact remains **unsigned**.

## Runtime validation

Do not load the CI driver on a normal or production machine. Build verification is not a loaded-driver test.

Use the guarded disposable-VM runbook in [RUNTIME-VALIDATION.md](RUNTIME-VALIDATION.md). The harness covers test signing, Filter Manager load/unload, targeted Driver Verifier, multiple delete paths, relay outage, stress, grant races, and namespace move/replace races.

The interactive Agent/UAC acceptance remains manual because it validates a real desktop session and Windows secure-desktop elevation flow.

## Remaining namespace boundary

NTFS hard-link creation uses `FileLinkInformation` / `FileLinkInformationEx` and can introduce another pathname for an existing file. It is a separate v0.2.6 hardening item. Until it is gated and runtime-validated, DeleteGuard should not claim complete alias containment for all NTFS namespace mechanisms.

Reparse-point protection roots remain rejected.

## Production release blockers

Before any public/production driver release, DeleteGuard still needs:

1. Microsoft-assigned production minifilter altitude;
2. production driver signing / attestation or HLK path as applicable;
3. recorded loaded-driver VM runs under Driver Verifier with no violations;
4. retained stress/race evidence for delete and namespace gates;
5. hard-link/alias policy completion or an explicitly documented accepted boundary;
6. service/driver tamper-hardening review;
7. recovery and uninstall validation.

The altitude in `DeleteGuardFilter.inf` is development-only and must not ship as a production altitude.
