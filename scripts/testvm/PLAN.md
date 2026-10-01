# Runtime validation plan

This file is intentionally short so a tester can see the phase order without reading the full runbook.

1. `prepare-test-vm.ps1 -IUnderstandThisIsADisposableVm -EnableTestSigning`
2. Reboot the disposable VM.
3. `check-prerequisites.ps1`
4. `sign-test-driver.ps1`
5. `install-test-stack.ps1 -EnableAgentForCurrentUser`
6. `enable-verifier.ps1`
7. Reboot the disposable VM.
8. `run-runtime-validation.ps1 -IncludeDriverReload`
9. Complete the manual Explorer/Agent/UAC checks in `docs/RUNTIME-VALIDATION.md`.
10. Save evidence listed in `docs/TEST-VM-ACCEPTANCE-CHECKLIST.md`.
11. `cleanup-test-vm.ps1 -DisableTestSigning`
12. Reboot and discard/revert the VM.

Any bugcheck, Driver Verifier/Filter Verifier violation, unexpected deletion, grant-scope failure, or incorrect Agent/UAC target is a release blocker.
