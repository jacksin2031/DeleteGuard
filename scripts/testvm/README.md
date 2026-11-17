# DeleteGuard disposable-VM test scripts

These scripts are **not** normal installation scripts. They exist only for loaded-kernel-driver validation in an expendable Windows 11 VM.

Read `docs/RUNTIME-VALIDATION.md` and `docs/TEST-VM-ACCEPTANCE-CHECKLIST.md` before using them.

Safety invariants:

- `prepare-test-vm.ps1` requires `-IUnderstandThisIsADisposableVm` before it creates a machine-bound marker.
- Every later script requires that marker.
- Destructive runtime test paths are restricted to `C:\DeleteGuard-VMTest` and descendants.
- Existing test paths are rejected when a required sentinel is missing.
- Reparse/junction components are rejected by the shared safety gate.
- The scripts never disable Secure Boot or alter firmware settings automatically.
- Driver Verifier targets only `DeleteGuardFilter.sys` and uses reset-on-boot-fail mode.
- The test-signing private key is generated inside the disposable VM and is never exported.
- `cleanup-test-vm.ps1` refuses to delete the test root unless its sentinel file is present.

Typical sequence:

```powershell
# elevated
.\scripts\testvm\prepare-test-vm.ps1 -IUnderstandThisIsADisposableVm -EnableTestSigning
# reboot
.\scripts\testvm\check-prerequisites.ps1
.\scripts\testvm\sign-test-driver.ps1
.\scripts\testvm\install-test-stack.ps1 -EnableAgentForCurrentUser
.\scripts\testvm\enable-verifier.ps1
# reboot
.\scripts\testvm\verify-loaded-state.ps1
.\scripts\testvm\run-runtime-validation.ps1 -IncludeDriverReload
.\scripts\testvm\run-protected-ancestor-rename-validation.ps1
.\scripts\testvm\run-rename-boundary-validation.ps1
.\scripts\testvm\run-hardlink-validation.ps1
.\scripts\testvm\run-bulkguard-validation.ps1
# perform the manual Explorer/Agent/UAC checks in docs/RUNTIME-VALIDATION.md
.\scripts\testvm\cleanup-test-vm.ps1 -DisableTestSigning
# reboot, then discard/revert the VM
```

`run-protected-ancestor-rename-validation.ps1` specifically protects a child directory and attempts to rename its unprotected parent. Passing requires the parent and protected child to remain at their configured paths, operation `RenameProtectedAncestor = 5` to reach Event Relay, and the event to remain non-approvable.

`run-rename-boundary-validation.ps1` races a competing process against the Broker's ACL-relaxation window and requires protected move-out and replace-existing renames to stay denied (operations `MoveOut = 3`, `ReplaceProtectedDestination = 4`).

`run-bulkguard-validation.ps1` protects a folder with `--bulk-guard` and requires: normal edit/rename/move/single delete to work; a recursive delete of hundreds of files to stop near the threshold; persistent retries to delete nothing during the lock; an operation-8 event naming the folder that is not approvable; the lock to clear after a quiet period; and a Broker-approved bulk deletion to succeed.

`run-hardlink-validation.ps1` requires an external hard link to a protected file to fail with `ERROR_ACCESS_DENIED`, a same-root link to succeed, and a native replace-existing link onto a protected destination to return `STATUS_ACCESS_DENIED`, including during the ACL-relaxation window. It uses `HardLinkProbe.cs`, which CI compiles under Windows PowerShell 5.1.
