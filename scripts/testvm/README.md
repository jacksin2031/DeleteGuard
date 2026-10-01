# DeleteGuard disposable-VM test scripts

These scripts are **not** normal installation scripts. They exist only for loaded-kernel-driver validation in an expendable Windows 11 VM.

Read `docs/RUNTIME-VALIDATION.md` before using them.

Safety invariants:

- `prepare-test-vm.ps1` requires `-IUnderstandThisIsADisposableVm` before it creates a machine-bound marker.
- Every later script requires that marker.
- Destructive runtime test paths are restricted to `C:\DeleteGuard-VMTest` and descendants.
- The scripts never disable Secure Boot or alter firmware settings automatically.
- Driver Verifier targets only `DeleteGuardFilter.sys` and uses reset-on-boot-fail mode.
- The test-signing private key is generated inside the disposable VM and is never exported.
- `cleanup-test-vm.ps1` refuses to delete the test root unless its sentinel file is present.

Typical sequence:

```powershell
# elevated
.\scripts\testvm\prepare-test-vm.ps1 -IUnderstandThisIsADisposableVm -EnableTestSigning
# reboot
.\scripts\testvm\sign-test-driver.ps1
.\scripts\testvm\install-test-stack.ps1 -EnableAgentForCurrentUser
.\scripts\testvm\enable-verifier.ps1
# reboot
.\scripts\testvm\run-runtime-validation.ps1 -IncludeDriverReload
# perform the manual Explorer/Agent/UAC checks in docs/RUNTIME-VALIDATION.md
.\scripts\testvm\cleanup-test-vm.ps1 -DisableTestSigning
# reboot, then discard/revert the VM
```
