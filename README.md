# DeleteGuard

DeleteGuard is a Windows protection tool that makes deletion of selected NTFS folders or data volumes an **administrator-approved action**.

## v0.2 architecture

DeleteGuard uses two enforcement layers:

1. **NTFS ACL fallback** — inherited deny rules for `DELETE` and `DELETE_CHILD` block ordinary deletion even when the minifilter is not available.
2. **DeleteGuardFilter.sys** — a filesystem minifilter blocks destructive delete requests at the I/O layer unless the deleting PID has a short-lived, path-scoped grant issued by the elevated broker.

This closes the main v0.1 race: during an approved deletion the broker must temporarily relax the ACL, but the minifilter continues blocking every other process while allowing only the broker PID on the approved target path.

## Behaviour

After protecting a path:

```powershell
# UAC prompt
deleteguard protect D:\Projects\Important

# Denied by ACL, and by the minifilter when it is installed/running
Remove-Item D:\Projects\Important -Recurse -Force
cmd /c rmdir /s /q D:\Projects\Important
# Explorer deletion is also denied.

# UAC-approved deletion
deleteguard delete D:\Projects\Important\old-build
```

When the minifilter is active, `deleteguard delete` performs this sequence:

```text
sync protected roots
-> grant {DeleteGuard.Broker PID + target + 15s TTL}
-> relax ACL
-> delete
-> revoke grant
-> restore/sync protection
```

If the driver is absent, the v0.1 ACL path remains functional. If the driver is present but rejects policy synchronization or a grant, DeleteGuard fails closed and does not relax the ACL.

### Current UX boundary

An arbitrary failing `Remove-Item` or Explorer delete is currently **denied**; it does not yet automatically open a UAC prompt. `deleteguard delete <path>` is the approval path.

The next UI layer will turn denied kernel events into an interactive approval request. The kernel driver itself will never display UI.

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

## Kernel operations covered in v0.2

The minifilter currently gates:

- `FileDispositionInformation`
- `FileDispositionInformationEx`
- `FILE_DELETE_ON_CLOSE`

This covers the normal destructive delete paths used by Explorer, shell commands, PowerShell and Win32 applications once the driver is installed and active.

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

Driver installation is intentionally not automated in the normal installer while v0.2 remains a development minifilter requiring test/production signing and a production altitude.

## Safe first test

Use a disposable folder, not important data:

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
```

## Security scope

DeleteGuard is designed to prevent accidental or unauthorized destructive file operations on configured paths. It is not a backup and does not protect against raw disk writes, partition deletion, formatting, offline attacks, filesystem corruption or physical device failure.

See [SECURITY.md](SECURITY.md), [docs/MINIFILTER.md](docs/MINIFILTER.md), and [docs/ROADMAP.md](docs/ROADMAP.md).
