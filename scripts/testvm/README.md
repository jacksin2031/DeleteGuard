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
# perform the manual Explorer/Agent/UAC checks in docs/RUNTIME-VALIDATION.md
.\scripts\testvm\cleanup-test-vm.ps1 -DisableTestSigning
# reboot, then discard/revert the VM
```

`run-protected-ancestor-rename-validation.ps1` specifically protects a child directory and attempts to rename its unprotected parent. Passing requires the parent and protected child to remain at their configured paths, operation `RenameProtectedAncestor = 5` to reach Event Relay, and the event to remain non-approvable.
