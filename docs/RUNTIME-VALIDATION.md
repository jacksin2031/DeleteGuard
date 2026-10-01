# DeleteGuard loaded-driver runtime validation

DeleteGuard kernel testing must be performed only in a **disposable Windows 11 test VM**. The repository intentionally refuses to automate these steps unless `prepare-test-vm.ps1` has created a machine-bound safety marker.

Do **not** use important files, your normal workstation, or a production VM for this procedure.

## Why this is separate from CI

GitHub Actions verifies that the minifilter builds with the pinned WDK, passes Universal ApiValidator/Inf2Cat signability, and that the managed components build/test/package. That does not prove a kernel driver is safe when actually loaded.

Runtime validation therefore adds:

- a local test certificate and test-signed driver image/catalog;
- actual minifilter load/unload through Filter Manager;
- Driver Verifier targeted only at `DeleteGuardFilter.sys`;
- NTFS deletion attempts from several user-mode paths;
- Event Relay outage testing;
- broker grant/concurrent-delete race testing;
- destructive rename boundary/race testing;
- optional driver unload/reload + ACL fallback testing;
- a JSON acceptance report.

## Prerequisites

Inside the disposable VM:

- Windows 11 x64;
- Visual Studio 2022 Build Tools/Visual Studio with C++ tooling required by `scripts/build-driver.ps1`;
- .NET 8 SDK;
- PowerShell 5.1 or newer;
- Internet access for the pinned WDK/SDK NuGet restore;
- repository checkout on an NTFS volume.

Test signing requires a reboot after enabling `TESTSIGNING`. Secure Boot can prevent BCDEdit from enabling it, and DeleteGuard deliberately does not alter firmware settings. If Memory Integrity/HVCI is enabled, the binary still needs a digital signature; the DeleteGuard test workflow therefore signs both the driver image and catalog with a self-created test certificate rather than relying on a purely unsigned image.

Microsoft references:

- https://learn.microsoft.com/windows-hardware/drivers/install/the-testsigning-boot-configuration-option
- https://learn.microsoft.com/windows-hardware/drivers/devtest/driver-verifier
- https://learn.microsoft.com/windows-hardware/drivers/devtest/file-system-filter-verification
- https://learn.microsoft.com/windows-hardware/drivers/ifs/loading-and-unloading

## 1. Mark the disposable VM and enable test signing

Run an elevated PowerShell:

```powershell
.\scripts\testvm\prepare-test-vm.ps1 `
  -IUnderstandThisIsADisposableVm `
  -EnableTestSigning
```

If Secure Boot blocks the change, disable Secure Boot manually **only in the disposable VM**, then run the command again.

Reboot the VM before continuing.

The marker is machine-bound and stored at:

```text
%ProgramData%\DeleteGuard-TestVM.marker.json
```

All subsequent test-VM scripts refuse to run without it.

## 2. Run the prerequisite gate after reboot

From an elevated PowerShell:

```powershell
.\scripts\testvm\check-prerequisites.ps1
```

This records the OS/architecture, .NET/Visual Studio tooling, TESTSIGNING configuration visibility, Secure Boot state and Memory Integrity/HVCI state. It fails before driver installation when a required prerequisite is missing.

BCDEdit output is localized, so the script does not treat an English `Yes` string as the final proof that test mode is active. The definitive gate is whether Windows accepts and loads the locally test-signed `DeleteGuardFilter` in the next stages.

## 3. Build and test-sign the driver

```powershell
.\scripts\testvm\sign-test-driver.ps1
```

This performs the normal WDK build, creates a short-lived local code-signing certificate, signs `DeleteGuardFilter.sys`, regenerates the catalog so its hashes match the signed image, signs the catalog, and verifies kernel-policy/catalog signatures.

The private key is not exported from the test VM.

## 4. Install and load the test stack

```powershell
.\scripts\testvm\install-test-stack.ps1
```

This installs the minifilter INF, loads `DeleteGuardFilter` through Filter Manager, builds/installs the user-mode package, and installs `DeleteGuardEventRelay` as LocalSystem.

To also enable the tray Agent for the currently logged-in test user:

```powershell
.\scripts\testvm\install-test-stack.ps1 -SkipUserModeBuild -EnableAgentForCurrentUser
```

The installation step fails if Windows refuses to load the signed driver, so a bad TESTSIGNING/signature state cannot silently continue into the runtime suite.

## 5. Enable Driver Verifier

```powershell
.\scripts\testvm\enable-verifier.ps1
```

The script uses:

```text
verifier /standard /driver DeleteGuardFilter.sys
verifier /bootmode resetonbootfail
```

Only the DeleteGuard driver is selected. Reboot the VM after enabling Verifier.

## 6. Verify loaded state after the Verifier reboot

```powershell
.\scripts\testvm\verify-loaded-state.ps1
```

This checks that:

- `DeleteGuardFilter` is present in `fltmc filters`;
- `DeleteGuardEventRelay` is Running;
- Driver Verifier settings reference `DeleteGuardFilter.sys` when configured;
- `deleteguard doctor` can report the installed user-mode/kernel state.

You can also inspect the underlying tools directly:

```powershell
verifier /querysettings
fltmc filters
Get-Service DeleteGuardEventRelay
& "$env:ProgramFiles\DeleteGuard\deleteguard.exe" doctor
```

Do not run stress validation if the filter or Relay checks fail.

## 7. Run the automated runtime suite

From an elevated PowerShell:

```powershell
.\scripts\testvm\run-runtime-validation.ps1
```

The suite creates and destroys data only beneath:

```text
C:\DeleteGuard-VMTest
```

It refuses any destructive target outside that root.

Current automated checks include:

1. PowerShell `Remove-Item` is denied.
2. `cmd.exe del` is denied.
3. `.NET File.Delete` is denied.
4. Win32 `SetFileInformationByHandle(FileDispositionInfo)` is denied.
5. Win32 `FILE_FLAG_DELETE_ON_CLOSE` is denied.
6. Recursive directory deletion is denied.
7. Enforcement remains active while Event Relay is stopped.
8. Repeated denied-delete stress leaves the file intact.
9. An approved 500-file Broker delete succeeds.
10. A competing process cannot delete a sentinel during the Broker's scoped grant/ACL-relaxation window.
11. An explicit approved file delete succeeds.
12. Kernel denial events reach Event Relay.

For an additional driver unload/reload + ACL fallback check:

```powershell
.\scripts\testvm\run-runtime-validation.ps1 -IncludeDriverReload
```

A machine-readable report is written to:

```text
%ProgramData%\DeleteGuard\runtime-validation-YYYYMMDD-HHMMSS.json
```

### 7a. Run the destructive rename boundary race suite

After the base suite passes, run:

```powershell
.\scripts\testvm\run-rename-boundary-validation.ps1
```

This separate suite stays under the same hard-coded `C:\DeleteGuard-VMTest` boundary and attacks the Broker's temporary ACL-relaxation window from a competing process. It verifies:

1. a protected source cannot be renamed/moved into an unprotected sibling directory;
2. the unprotected destination is never created;
3. an outside source cannot replace an existing protected target via `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)`;
4. the protected target keeps its original contents;
5. the outside replacement source remains intact;
6. Event Relay receives operation `3` (`RenameOut`) and operation `4` (`RenameReplace`);
7. both destructive rename events are persisted with `canApprove=false` and therefore cannot enter the automatic UAC delete-approval path.

## 8. Manual Agent/UAC acceptance

This part is intentionally not automated because it validates real desktop-session UX and Windows UAC.

1. Enable the Agent for the logged-in test user if it is not already enabled:

   ```powershell
   .\scripts\enable-agent.ps1
   ```

2. Create a fresh disposable root under `C:\DeleteGuard-VMTest`, protect it, and place one file inside.
3. From Explorer, try to delete that file.
4. Expected first result: Explorer receives Access Denied; DeleteGuard Agent displays the blocked process/path request.
5. Choose **No**. The file must remain.
6. Retry the Explorer delete.
7. Choose **Yes** in DeleteGuard Agent.
8. Windows UAC must appear for `DeleteGuard.Broker.exe`.
9. Cancel UAC. The file must remain.
10. Retry and approve both Agent and UAC. The separate Broker delete should remove only the requested target.

Repeat the same UX path from a non-elevated PowerShell `Remove-Item` attempt.

For v0.2.5, also verify that a blocked protected move-out and a blocked replace-existing rename produce warning-only Agent notifications and **never** offer the delete/UAC approval action.

## Crash / verifier acceptance

During runtime tests, any of the following is a release blocker:

- BSOD / bugcheck attributable to `DeleteGuardFilter.sys`;
- Driver Verifier violation;
- filter unload deadlock or hang;
- unexpected deletion, move-out, or overwrite of protected test data;
- unrelated process gaining delete/rename access during a scoped grant;
- policy not being restored after Event Relay/driver restart;
- destructive rename event becoming automatically approvable;
- Agent approval deleting a path different from the displayed target.

If the VM bugchecks, preserve the dump and verifier settings before reverting the snapshot.

## 9. Cleanup

When finished:

```powershell
.\scripts\testvm\cleanup-test-vm.ps1 -DisableTestSigning
```

Reboot the VM, then discard/revert the VM snapshot.

The cleanup script resets Driver Verifier, unloads the filter when possible, removes the test service registration/certificate, removes only the sentinel-protected test root, disables the approval Agent/service, and removes the disposable-VM marker.

Because the VM is disposable, the test procedure does not attempt aggressive driver-store cleanup that could accidentally target an unrelated package.
