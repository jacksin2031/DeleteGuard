# DeleteGuard minifilter design

DeleteGuard v0.2 adds a Windows file-system minifilter to close the temporary ACL-release race in v0.1. v0.2.1 adds denied-event/interactive approval, v0.2.2 adds guarded disposable-VM validation, v0.2.4 binds delete grants to process start identity, v0.2.5 gates destructive rename/move namespace escape, and v0.2.6 extends namespace containment to NTFS hard links.

## Enforcement path

```text
Explorer / cmd / PowerShell / Python / Win32 / Native API
                           |
                           v
                    I/O request
                           |
                           v
                DeleteGuardFilter.sys
                 /                 \
       protected + denied         allowed
               |                      |
        STATUS_ACCESS_DENIED          v
               |               normal NTFS processing
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

### Rename / move namespace mutation

- `FileRenameInformation`
- `FileRenameInformationBypassAccessCheck`
- `FileRenameInformationEx`
- `FileRenameInformationExBypassAccessCheck`

### Hard-link namespace mutation

- `FileLinkInformation`
- `FileLinkInformationBypassAccessCheck`
- `FileLinkInformationEx`
- `FileLinkInformationExBypassAccessCheck`

For namespace operations:

- a protected source may remain inside its existing protecting root;
- a protected source moving, renaming, or hard-linking outside that root is denied;
- replace-existing rename/link operations are denied when the destination is protected;
- if a protected-source destination cannot be safely resolved, the operation fails closed;
- delete grants do not authorize namespace mutation.

This specifically protects unrelated files and aliases during the Broker's temporary ACL-relaxation window. Hard-link containment also matters outside that window because hard-link creation is not fundamentally a delete operation and therefore cannot be delegated to the v0.1 DELETE ACL alone.

The filter attaches to NTFS only.

## Safe capture of set-information buffers

`SetFileInformation.InfoBuffer` is treated as untrusted when the request originates in user mode.

For disposition operations, the minifilter probes when required and copies the fixed-size input into a kernel-local structure before checking delete flags.

Rename and hard-link operations share a two-stage namespace capture:

1. safely inspect/copy fixed header fields (`RootDirectory`, replace semantics, filename length);
2. validate the variable filename length, allocate nonpaged kernel memory, then probe/copy the filename into that stable buffer.

Destination resolution uses only the captured kernel copy. Structured exception handling protects the probe/copy boundary. This avoids direct bad-pointer dereference and prevents user mode from changing namespace metadata between validation and use.

## Destination-name resolution

For rename and hard-link operations, the filter uses `FltGetDestinationFileNameInformation` with the captured root handle/name. Enforcement compares the normalized destination path against the configured protected-root table.

A protected source moving to an unresolved destination is denied rather than allowed. For an unprotected source, a non-replacing operation can proceed without a protected-source containment decision; replace-existing requests are resolved so a protected destination cannot be overwritten.

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

Namespace operations never consult delete grants as an authorization to escape or replace protected namespace entries.

## Namespace-denial UX

Protocol v3 preserves the same fixed managed/native ABI. `DriverDeleteOperation.NamespaceMutation` / `DgDeleteOperationNamespaceMutation` identifies rename, move, replacement, and hard-link alias denials without changing structure sizes.

The Relay persists these events but marks them non-approvable. The Agent shows a warning only; it never turns a denied namespace operation into Yes -> UAC -> Broker delete.

Managed tests lock the protocol version, client-role values, command values, event value, operation values, and structure sizes to catch managed/native ABI drift.

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
- Windows PowerShell 5.1 compilation of native test probes such as `HardLinkProbe.cs`;
- destructive-test path boundary smoke checks.

The CI driver artifact remains **unsigned**.

## Runtime validation

Do not load the CI driver on a normal or production machine. Build verification is not a loaded-driver test.

Use the guarded disposable-VM runbook in [RUNTIME-VALIDATION.md](RUNTIME-VALIDATION.md). The harness covers test signing, Filter Manager load/unload, targeted Driver Verifier, multiple delete paths, relay outage, stress, grant races, rename/move replacement races, and hard-link alias races.

`run-hardlink-validation.ps1` uses a dedicated sentinel-guarded `C:\DeleteGuard-VMTest\HardLinkCase`. It verifies:

- external alias creation from a protected source returns access denied;
- a same-root hard link remains allowed;
- native `FileLinkInformationEx + FILE_LINK_REPLACE_IF_EXISTS` cannot replace a protected destination;
- an unrelated process cannot create an external alias during the Broker ACL-relaxation window.

The interactive Agent/UAC acceptance remains manual because it validates a real desktop session and Windows secure-desktop elevation flow.

## Remaining validation boundary

The kernel code now gates deletion, destructive rename/move, and NTFS hard-link alias escape. That is still not equivalent to production-ready namespace containment.

Before release, loaded-driver testing must exercise hostile/malformed buffers, existing hard-link edge cases, normalized-name behavior, reparse interactions, cross-volume failures, and concurrency under Driver Verifier. Reparse-point protection roots remain rejected.

## Production release blockers

Before any public/production driver release, DeleteGuard still needs:

1. Microsoft-assigned production minifilter altitude;
2. production driver signing / attestation or HLK path as applicable;
3. recorded loaded-driver VM runs under Driver Verifier with no violations;
4. retained stress/race evidence for delete, rename/move, and hard-link namespace gates;
5. service/driver tamper-hardening review;
6. recovery and uninstall validation.

The altitude in `DeleteGuardFilter.inf` is development-only and must not ship as a production altitude.
