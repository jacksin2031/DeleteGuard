# DeleteGuard disposable VM acceptance checklist

Use this checklist together with `docs/RUNTIME-VALIDATION.md`.

## Environment

- [ ] Disposable Windows 11 x64 VM / revertible snapshot
- [ ] No important data in the VM
- [ ] Secure Boot state understood; no firmware changes performed by DeleteGuard scripts
- [ ] TESTSIGNING enabled only in the VM
- [ ] DeleteGuard local test certificate created inside the VM
- [ ] `DeleteGuardFilter.sys` and catalog signature verification passed
- [ ] `fltmc filters` shows `DeleteGuardFilter`
- [ ] `DeleteGuardEventRelay` is Running
- [ ] Driver Verifier targets `DeleteGuardFilter.sys` only

## Automated runtime suite

- [ ] Windows PowerShell `Remove-Item` denied
- [ ] `cmd.exe del` denied
- [ ] `.NET File.Delete` denied
- [ ] Win32 `FileDispositionInfo` denied
- [ ] Win32 delete-on-close denied
- [ ] recursive directory deletion denied
- [ ] enforcement survives Event Relay outage
- [ ] repeated denied-delete stress leaves sentinel intact
- [ ] approved recursive Broker deletion succeeds
- [ ] competing process remains blocked during scoped grant
- [ ] explicit approved file deletion succeeds
- [ ] denial events reach Event Relay
- [ ] protected source cannot move/rename outside its protected root during Broker ACL relaxation
- [ ] move-out destination is never created
- [ ] outside source cannot replace an existing protected target via `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)`
- [ ] protected replacement target retains its original content
- [ ] `RenameOut` event reaches Relay with `canApprove=false`
- [ ] `RenameReplace` event reaches Relay with `canApprove=false`
- [ ] optional filter unload leaves ACL fallback effective
- [ ] optional filter reload restores kernel event/enforcement path
- [ ] runtime JSON report has `passed: true`

## Manual interactive approval

- [ ] Explorer delete fails first and Agent shows the correct target
- [ ] Agent **No** leaves target intact
- [ ] Agent **Yes** invokes Windows UAC
- [ ] UAC cancellation leaves target intact
- [ ] Agent **Yes** + UAC approval deletes only the displayed target
- [ ] non-elevated PowerShell attempt follows the same prompt/UAC flow
- [ ] protected move-out produces a warning-only Agent notification
- [ ] protected replace-existing rename produces a warning-only Agent notification
- [ ] neither destructive rename path offers delete/UAC approval
- [ ] duplicate rapid attempts do not create an unusable prompt storm
- [ ] rapid **unique-path** denied deletes produce no more than 3 automatic modal approval prompts within 30 seconds
- [ ] additional flood events remain denied and are not replayed later as fresh prompts
- [ ] throttle warning balloon appears at most once per 15 seconds while the flood continues
- [ ] explicit `deleteguard delete <path>` remains available while automatic prompts are throttled

## Driver Verifier / stability

- [ ] no verifier bugcheck
- [ ] no Filter Verifier violation
- [ ] no filter unload hang
- [ ] no Event Relay reconnect hang
- [ ] no leaked/stuck protected policy after test cleanup
- [ ] no unexpected file deletion, move-out, or overwrite during race/stress cases

## Evidence to retain

- [ ] runtime-validation JSON report
- [ ] rename-boundary validation console/result evidence
- [ ] `verifier /querysettings` output
- [ ] `fltmc filters` output
- [ ] `deleteguard doctor` output
- [ ] relevant `%ProgramData%\DeleteGuard` audit/denial logs
- [ ] crash dumps / Event Viewer / SetupAPI logs if any failure occurs

A checked list is not itself sufficient for production release. Production still requires a Microsoft-assigned minifilter altitude and an appropriate production driver signing path.
