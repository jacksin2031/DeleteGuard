# DeleteGuard v0.2 minifilter design

DeleteGuard v0.2 adds a Windows file-system minifilter to close the temporary ACL-release race in v0.1.

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
                          normal NTFS processing

Approved path:

deleteguard delete <path>
        |
        v
UAC -> DeleteGuard.Broker.exe
        |
        +--> sync protected NT paths to minifilter
        +--> grant {broker PID, target path, <=30s TTL}
        +--> temporarily remove v0.1 DELETE ACL
        +--> perform deletion
        +--> revoke grant
        +--> re-sync policies / restore ACL when appropriate
```

The ACL layer remains present as a fallback. If the driver is unavailable, v0.1 behavior remains active. If the driver is present but rejects a sync or grant command, the broker fails closed and does not relax the ACL.

## Operations intercepted

The v0.2 kernel gate currently handles:

- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformation`
- `IRP_MJ_SET_INFORMATION` + `FileDispositionInformationEx`
- `IRP_MJ_CREATE` with `FILE_DELETE_ON_CLOSE`

The filter attaches to NTFS only, matching the v0.1 support boundary.

## Protected roots

The broker converts Win32 paths such as:

```text
D:\Projects\Important
```

to the device-path form observed by Filter Manager:

```text
\Device\HarddiskVolumeX\Projects\Important
```

The kernel stores up to 64 active roots in the v0.2 prototype. A path matches a root only when it is the same path or a true descendant boundary, not merely a string prefix.

## Scoped grants

A grant contains:

- broker process ID
- normalized NT target path
- expiry timestamp
- maximum TTL of 30 seconds

A grant covers the target and descendants so one elevated recursive delete can remove a tree. The broker normally requests 15 seconds and explicitly revokes the grant in `finally` after the operation.

This means that while the v0.1 ACL is temporarily absent, unrelated processes remain blocked by the minifilter.

## Communication security

The driver exposes `\DeleteGuardPort` with `FltCreateCommunicationPort` and the Filter Manager default security descriptor for `FLT_PORT_ALL_ACCESS`. The current protocol is fixed-layout version 2 and supports:

- ping
- reset roots
- add root
- remove root
- grant
- revoke

The C# side contains ABI-size tests to catch native/managed structure drift.

## Build

The driver build is pinned to the VS2022-compatible WDK/SDK `10.0.26100.6584` NuGet packages.

```powershell
.\scripts\build-driver.ps1 -Configuration Release
```

Output:

```text
artifacts\driver-x64\DeleteGuardFilter.sys
artifacts\driver-x64\DeleteGuardFilter.inf
```

CI deliberately publishes an **unsigned** driver artifact.

## Testing and signing

Do not load the CI driver on a production machine. Driver installation/testing belongs in a disposable Windows driver-test VM with a deliberate test-signing workflow.

Before any public/production release, DeleteGuard still needs:

1. a Microsoft-assigned minifilter altitude;
2. production driver signing / attestation or HLK path as applicable;
3. VM integration tests with the actual loaded driver;
4. stress/race tests for recursive deletion, delete-on-close and concurrent processes;
5. event-driven user notification / approval UX for arbitrary Explorer or shell delete attempts.

The altitude in `DeleteGuardFilter.inf` is development-only and must not be shipped as a production altitude.

## Current UX boundary

v0.2 provides kernel enforcement, but arbitrary Explorer/PowerShell delete attempts are still **denied**, not automatically converted into a UAC dialog. `deleteguard delete <path>` is the approved UAC path.

The next user-experience layer is an interactive request broker/tray: the minifilter reports a denied deletion request, the user explicitly chooses to approve it, UAC elevates the grant issuer, and the originating operation is retried under a scoped grant. The kernel filter must never display UI itself.
