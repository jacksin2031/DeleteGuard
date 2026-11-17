# DeleteGuard

DeleteGuard is a Windows protection tool that makes deletion of selected NTFS folders or data volumes an **administrator-approved action**.

## v0.2.x architecture

DeleteGuard now has three cooperating protection/UI layers:

1. **NTFS ACL fallback** — inherited deny rules for `DELETE` and `DELETE_CHILD` block ordinary deletion even when the minifilter is unavailable.
2. **DeleteGuardFilter.sys** — a filesystem minifilter blocks destructive delete requests unless the deleting PID has a short-lived, path-scoped grant.
3. **Interactive approval pipeline** — blocked kernel events can be relayed by a LocalSystem service to an unelevated desktop Agent. If the user chooses Yes, the Agent starts the existing elevated Broker via UAC and the Broker performs the approved deletion.

The desktop Agent never has direct kernel command access. The Filter Manager communication port remains restricted to administrators/SYSTEM.

## Behaviour

After protecting a path:

```powershell
# UAC prompt
deleteguard protect D:\Projects\Important

# Denied by ACL, and by the minifilter when it is installed/running
Remove-Item D:\Projects\Important -Recurse -Force
cmd /c rmdir /s /q D:\Projects\Important
# Explorer deletion is also denied.

# Explicit UAC-approved deletion
deleteguard delete D:\Projects\Important\old-build
```

When the v0.2.1 Event Relay and Agent are also running, an arbitrary blocked delete can additionally produce a desktop approval prompt. The original delete request is still denied immediately. If approved, DeleteGuard performs a separate elevated deletion through the Broker.

This **deny-then-approved-delete** model intentionally avoids holding filesystem I/O open while waiting for desktop UI or UAC.

## Approved deletion sequence

When the minifilter is active, the Broker performs:

```text
sync protected roots
-> grant {DeleteGuard.Broker PID + target + 15s TTL}
-> relax ACL
-> delete
-> revoke grant
-> restore/sync protection
```

If the driver is absent, the ACL path remains functional. If the driver is present but rejects policy synchronization or a grant, DeleteGuard fails closed and does not relax the ACL.

## Commands

```text
deleteguard protect <path> [--allow-volume-root]
deleteguard unprotect <path>
deleteguard delete <path>
deleteguard status <path>
deleteguard list
deleteguard audit [count]
deleteguard doctor
```

Protecting the Windows system-volume root is refused. Protecting a non-system NTFS volume root requires the explicit `--allow-volume-root` option.

## Kernel operations covered

The minifilter currently gates:

- `FileDispositionInformation`
- `FileDispositionInformationEx`
- `FILE_DELETE_ON_CLOSE`
- `FileRenameInformation` / `FileRenameInformationEx` (and the kernel-only `BypassAccessCheck` classes): move-out of a protected root, rename-with-replace onto a protected destination, and renaming an ancestor directory that contains a protected root are denied
- `FileLinkInformation` / `FileLinkInformationEx` (and the `BypassAccessCheck` classes): hard links to a protected file outside its root, and link-with-replace onto a protected destination, are denied

This covers the normal destructive delete paths used by Explorer, shell commands, PowerShell and Win32 applications once the driver is installed and active. Rename and hard-link denials are never approvable: a delete grant does not authorize namespace changes. See [SECURITY.md](SECURITY.md) for the exact scope and remaining gaps.

## Build user-mode package

Requirements:

- Windows 11 or Windows 10 2004+
- .NET 8 SDK
- PowerShell 7 or Windows PowerShell 5.1
- NTFS for protected paths

```powershell
git clone https://github.com/jacksin2031/DeleteGuard.git
cd DeleteGuard
.\scripts\build.ps1
```

Output:

```text
artifacts\win-x64
```

The package contains the CLI, elevated Broker, Event Relay service, and desktop Agent.

## Build minifilter

The x64 driver build is pinned to the VS2022-compatible WDK/SDK `10.0.26100.6584` NuGet toolchain.

```powershell
.\scripts\build-driver.ps1 -Configuration Release
```

Output:

```text
artifacts\driver-x64
```

The CI driver artifact is intentionally **unsigned**. Do not load it on a production machine. See [docs/MINIFILTER.md](docs/MINIFILTER.md).

## Install user-mode package

From an elevated PowerShell:

```powershell
.\scripts\install.ps1
```

Open a new terminal and verify:

```powershell
deleteguard doctor
```

To install the v0.2.1 Event Relay service:

```powershell
.\scripts\install-approval.ps1
```

Then run this once as the desktop user who should receive approval prompts:

```powershell
.\scripts\enable-agent.ps1
```

Driver installation is intentionally not automated in the normal installer while the minifilter remains a development driver requiring test/production signing and a production altitude.

## Loaded-driver validation

Kernel runtime testing has a separate guarded workflow. **Use only a disposable Windows 11 VM.** Do not test-sign/load the development driver on a normal workstation or on important data.

See [docs/RUNTIME-VALIDATION.md](docs/RUNTIME-VALIDATION.md).

The `scripts/testvm` workflow requires an explicit disposable-VM acknowledgment and machine-bound marker, test-signs the driver locally, enables targeted Driver Verifier, and restricts destructive tests to exactly `C:\DeleteGuard-VMTest` and its descendants.

GitHub CI checks the test-VM scripts for Windows PowerShell 5.1 syntax, but CI does not claim that the driver has been runtime-validated until the suite is executed in an actual disposable VM and its report/verifier evidence is retained.

## Safe ACL-only first test

Without loading the development driver, use a disposable folder, not important data:

```powershell
mkdir C:\DeleteGuard-Test
Set-Content C:\DeleteGuard-Test\hello.txt 'test'

deleteguard protect C:\DeleteGuard-Test
Remove-Item C:\DeleteGuard-Test\hello.txt   # expected: Access Denied
deleteguard status C:\DeleteGuard-Test

deleteguard delete C:\DeleteGuard-Test\hello.txt  # UAC approval
deleteguard unprotect C:\DeleteGuard-Test
```

## Runtime state

```text
%ProgramData%\DeleteGuard\policies.json
%ProgramData%\DeleteGuard\audit.jsonl
%ProgramData%\DeleteGuard\denied-events.jsonl
%ProgramData%\DeleteGuard\denied-events.1.jsonl
```

The denied-event stream rotates at 4 MiB and retains one previous file.

## Security scope

DeleteGuard is designed to prevent accidental or unauthorized destructive file operations on configured paths. It is not a backup and does not protect against raw disk writes, partition deletion, formatting, offline attacks, filesystem corruption or physical device failure.

See [SECURITY.md](SECURITY.md), [docs/MINIFILTER.md](docs/MINIFILTER.md), [docs/INTERACTIVE_APPROVAL.md](docs/INTERACTIVE_APPROVAL.md), [docs/RUNTIME-VALIDATION.md](docs/RUNTIME-VALIDATION.md), and [docs/ROADMAP.md](docs/ROADMAP.md).
