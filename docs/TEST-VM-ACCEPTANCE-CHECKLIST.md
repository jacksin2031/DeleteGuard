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
- [ ] protected source cannot move from the protected subtree to an unprotected sibling
- [ ] denied move-out leaves source intact and does not create destination
- [ ] overwrite/replace rename from an unprotected sibling cannot replace a protected destination
- [ ] denied protected-destination replacement leaves both source and destination intact
- [ ] Event Relay records `MoveOut` and `ReplaceProtectedDestination` operation values
- [ ] both direct rename denial events are `canApprove: false`
- [ ] `run-protected-ancestor-rename-validation.ps1` passes under Driver Verifier
- [ ] `run-rename-boundary-validation.ps1` passes under Driver Verifier
- [ ] `run-hardlink-validation.ps1` passes under Driver Verifier
- [ ] an external hard link to a protected file is denied and the same-root link is allowed
- [ ] hard-link denial events are `canApprove: false`
- [ ] an ancestor directory containing a protected root cannot be renamed
- [ ] the configured protected root remains at its original path after the denied ancestor rename
- [ ] Event Relay records `RenameProtectedAncestor = 5`
- [ ] protected-ancestor rename event is `canApprove: false`
- [ ] enforcement survives Event Relay outage
- [ ] repeated denied-delete stress leaves sentinel intact
- [ ] approved recursive Broker deletion succeeds
- [ ] competing process remains blocked during scoped grant
- [ ] explicit approved file deletion succeeds
- [ ] denial events reach Event Relay
- [ ] optional filter unload leaves ACL fallback effective
- [ ] optional filter reload restores kernel event/enforcement path
- [ ] runtime JSON reports have `passed: true`

## Manual interactive approval

- [ ] Explorer delete fails first and Agent shows the correct target
- [ ] Agent **No** leaves target intact
- [ ] Agent **Yes** invokes Windows UAC
- [ ] UAC cancellation leaves target intact
- [ ] Agent **Yes** + UAC approval deletes only the displayed target
- [ ] non-elevated PowerShell attempt follows the same prompt/UAC flow
- [ ] Explorer move-out of a protected file is denied
- [ ] blocked move-out shows a rename warning, not a delete-approval modal
- [ ] renaming a parent directory that contains a protected root is denied and produces a non-approvable rename warning
- [ ] rename denial never launches `DeleteGuard.Broker.exe`
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
- [ ] no unexpected file deletion during race/stress cases
- [ ] no protected source escapes through rename/move-out
- [ ] no protected destination is changed through replace rename
- [ ] no configured protected root can be displaced by renaming one of its ancestors
- [ ] allowed internal rename path shows no completion-context leak or tunneling-related verifier failure

## Evidence to retain

- [ ] runtime-validation JSON report
- [ ] ancestor-rename-validation JSON report
- [ ] `verifier /querysettings` output
- [ ] `fltmc filters` output
- [ ] `deleteguard doctor` output
- [ ] relevant `%ProgramData%\DeleteGuard` audit/denial logs
- [ ] crash dumps / Event Viewer / SetupAPI logs if any failure occurs

A checked list is not itself sufficient for production release. Production still requires a Microsoft-assigned minifilter altitude and an appropriate production driver signing path.
