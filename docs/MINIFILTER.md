# DeleteGuard minifilter design

DeleteGuard v0.2 adds a Windows file-system minifilter to close the temporary ACL-release race in v0.1. v0.2.1 adds the denied-event/interactive approval pipeline. v0.2.2 adds a guarded loaded-driver validation harness for disposable Windows test VMs.

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

Approved Broker path:

```text
sync protected NT paths
-> grant {broker PID, target path, <=30s TTL}
-> temporarily remove v0.1 DELETE ACL
-> perform deletion
-> revoke grant
-> re-sync policies / restore ACL when appropriate
```

The ACL layer remains present as a fallback. If the driver is unavailable, v0.1 behavior remains active. If the driver is present but rejects a sync or grant command, the broker fails closed and does not relax the ACL.

## Operations intercepted

The kernel gate currently handles:

- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformation`
- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformationEx`
- `IRP_MJ_CREATE` with `FILE_DELETE_ON_CLOSE`

The filter attaches to NTFS only, matching the v0.1 support boundary. Destructive rename/move-out enforcement remains future work.

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

## Scoped grants

A grant contains:

- broker process ID
- normalized NT target path
- expiry timestamp
- maximum TTL of 30 seconds

A grant covers the target and descendants so one elevated recursive delete can remove a tree. The broker normally requests 15 seconds and explicitly revokes the grant in `finally` after the operation.

While the v0.1 ACL is temporarily absent, unrelated processes remain blocked by the minifilter. The runtime validation harness includes a competing-process race test specifically for this boundary.

## Communication security and protocol v3

The driver exposes `\DeleteGuardPort` through `FltCreateCommunicationPort` with the Filter Manager default security descriptor for `FLT_PORT_ALL_ACCESS`. The port therefore remains restricted to privileged callers rather than being opened directly to a normal desktop Agent.

Protocol v3 distinguishes two connection roles:

- **Command**: privileged Broker/Relay policy synchronization (`ping`, reset/add/remove roots, grant, revoke).
- **Event**: LocalSystem Event Relay receives delete-denied notifications.

The Agent never receives kernel command access. The Relay persists a bounded read-only denial history under `%ProgramData%\DeleteGuard` for the Agent.

Kernel event delivery is zero-wait/best-effort. A missing or slow user-mode listener must never stall filesystem I/O or convert a deny into an allow.

The C# side contains ABI-size/layout tests for the fixed native/managed protocol structures.

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

The test harness covers local test signing, Filter Manager load/unload, targeted Driver Verifier, multiple deletion paths, Relay outage behavior, repeated denial stress, scoped-grant race testing and optional driver reload/ACL fallback.

The interactive Agent/UAC acceptance remains manual by design because it validates a real desktop session and Windows secure-desktop elevation flow.

## Production release blockers

Before any public/production driver release, DeleteGuard still needs:

1. a Microsoft-assigned production minifilter altitude;
2. a production driver signing / attestation or HLK path as applicable;
3. recorded loaded-driver VM runs under Driver Verifier with no violations;
4. stress/race testing results retained as release evidence;
5. destructive rename/move-out enforcement or an explicitly accepted scope boundary;
6. service/driver tamper-hardening review and recovery/uninstall validation.

The altitude in `DeleteGuardFilter.inf` is development-only and must not be shipped as a production altitude.
