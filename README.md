# DeleteGuard

DeleteGuard is a Windows protection tool that makes deletion of selected NTFS folders or data volumes an **administrator-approved action**.

The v0.1 MVP deliberately uses NTFS ACL enforcement so it can be built and tested without shipping an unsigned kernel driver. A future minifilter version is planned for stronger enforcement.

## MVP behaviour

After protecting a path:

```powershell
# UAC prompt
deleteguard protect D:\Projects\Important

# These should fail with Access Denied
Remove-Item D:\Projects\Important -Recurse -Force
cmd /c rmdir /s /q D:\Projects\Important
# Explorer deletion is also denied.

# This launches the UAC broker and performs one approved deletion
deleteguard delete D:\Projects\Important\old-build
```

`deleteguard delete` is intentionally the approval path in v0.1. An arbitrary failing `Remove-Item` or Explorer delete does **not** automatically open a UAC prompt; it is denied. Automatic interception-and-prompting requires the planned filesystem minifilter.

Because Windows uses the `DELETE` access right for rename/move semantics too, v0.1 strict protection can also block renames, moves and some applications' atomic-save/replace workflows inside the protected tree. Use the MVP first on archive/critical-data folders. The minifilter phase will distinguish destructive deletion from safe in-scope renames.

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

## Architecture

```text
Explorer / cmd / PowerShell / apps
              |
              v
       NTFS access check
       DENY delete/delete-child
              |
          Access Denied

User -> deleteguard.exe
              |
              v
        UAC / runas
              |
              v
   DeleteGuard.Broker.exe
      |        |        |
      |        |        +--> audit.jsonl
      |        +----------> policies.json
      +-------------------> controlled ACL release -> delete -> re-apply
```

The CLI runs unelevated. Only the broker has a `requireAdministrator` manifest. Administrative operations are serialized with a global mutex.

## Build

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

The package is written to `artifacts\win-x64`.

## Install

From an elevated PowerShell:

```powershell
.\scripts\install.ps1
```

Open a new terminal and verify:

```powershell
deleteguard doctor
```

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

## Data files

Runtime state lives under:

```text
%ProgramData%\DeleteGuard\policies.json
%ProgramData%\DeleteGuard\audit.jsonl
```

## Security scope

v0.1 is designed to prevent **accidental deletion and deletion by ordinary non-elevated processes**. It is not yet a kernel-enforced boundary against a malicious local administrator, raw disk access, formatting, offline access or physical failure. See [SECURITY.md](SECURITY.md).

The roadmap for the filesystem minifilter and stronger volume protection is in [docs/ROADMAP.md](docs/ROADMAP.md).
