# DeleteGuard v0.2.1 VM acceptance

This kit prepares loaded-driver validation; producing the kit does not validate the driver.
Keep PR #3 as Draft until automated checks and the manual release gates below have evidence.

## Prerequisites and recovery

- Disposable Windows 11 x64 VM on NTFS, with a snapshot taken before installation.
- VM administrator account plus a separate ordinary desktop user for Agent/UAC checks.
- PowerShell 7 and the .NET 8 Desktop Runtime. Python 3 is optional; absent Python is `NOT_RUN`.
- No production data, host shared folders, redirected data drives, or other DeleteGuard policies in this VM.
- A test-signed driver installed and loaded by the VM operator, and the v0.2.1 user-mode package.
- Record VM name, snapshot identifier, Windows build, signing certificate thumbprint, and artifact hashes.

The bundle contains an **unsigned** CI driver. Enabling TESTSIGNING alone does not sign a driver.
Use the [Microsoft test-signing workflow](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/test-signing-driver-packages)
and [test computer configuration](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option).
Test signing, certificate trust, Secure Boot changes, driver installation, reboot and Driver Verifier configuration
are deliberately outside the automated script. Perform them only in the disposable VM.
Preserve hashes of both the original CI driver and the final test-signed image.

The INF service is `DeleteGuardFilter`, instance `DeleteGuardFilter Instance`, development altitude `370149.9`.
Installation and signing must preserve the INF settings. The development altitude is not a production allocation.
Verify `fltmc filters`, `fltmc instances -f DeleteGuardFilter`, and elevated `deleteguard doctor`;
service existence or a successful doctor process exit alone is insufficient evidence of kernel enforcement.
Run also requires `-ExpectedLoadedDriverSha256`, taken from the test-signed image you deployed.
The script compares it with the service image on disk and records driver service state and Filter Manager output.
Do not replace the service image after loading it: a disk hash does not independently prove the bytes already resident in kernel memory.

Before mutation tests, close the desktop Agent so a delayed approval cannot delete a fixture while it is being checked.
The elevated automated suite tests enforcement and Broker behavior; it does not prove ordinary-user port restrictions or UAC.
Use `scripts/install.ps1`, `scripts/install-approval.ps1`, and `scripts/enable-agent.ps1` only in the VM when preparing the manual approval phase.

## Run the kit

Extract the acceptance bundle to a local VM directory, such as `C:\DeleteGuard-Acceptance`.
The package is at `artifacts\win-x64`; the driver is at `artifacts\driver-x64`.
The source repository uses the same relative layout.

The safe helper regression suite can run after packaging without elevation or a loaded driver:
`pwsh -NoProfile -File .\scripts\vm-tests\Test-HarnessHelpers.ps1`.
It uses generated unprotected scratch files under `artifacts\harness-helper-fixtures` and tests ownership inventory,
content snapshots, native API controls and refusal to clean up a pre-existing unowned GUID subtree.
These are tool tests, not protected-delete runtime acceptance.

Read-only preflight (an output directory explicitly requests an evidence file):

```powershell
pwsh -NoProfile -File .\scripts\Test-VmAcceptance.ps1 `
  -PackageDirectory .\artifacts\win-x64 `
  -OutputDirectory C:\DeleteGuard-Evidence\preflight
```

Automated fixture tests, **inside the prepared VM**, from elevated PowerShell:

```powershell
$signedDriverHash = (Get-FileHash -LiteralPath C:\DeleteGuard-TestSigned\DeleteGuardFilter.sys -Algorithm SHA256).Hash
pwsh -NoProfile -File .\scripts\Test-VmAcceptance.ps1 `
  -Mode Run -DisposableVm `
  -ExpectedLoadedDriverSha256 $signedDriverHash `
  -PackageDirectory .\artifacts\win-x64 `
  -OutputDirectory C:\DeleteGuard-Evidence\run-001
```

Run requires the explicit disposable-VM assertion, recognized virtual hardware, elevation, an active communication port
and NTFS before it creates fixtures or registers a policy. A hypervisor-present flag alone does not identify a VM.
Fixtures use a fresh GUID below `%TEMP%\DeleteGuard.VmAcceptance`; do not supply real data as fixtures.
Cleanup failures are failures and retain the exact path for recovery. Restore the snapshot after collecting evidence.
Do not force deletion of an unexpected path to make cleanup appear successful.
Cleanup verifies an inventory of the files/directories created by this run; an unexpected item retains the fixture for investigation.

The suite covers denial via PowerShell, CMD, .NET, optional Python and native Win32 APIs;
unprotected prefix siblings; approved file/tree deletion; restored ACL; and kernel-only denial while the exact fixture guard ACL
is temporarily removed. The kernel-only check holds the same mutation mutex as Broker/Relay and restores the ACL in `finally`.
Access Denied with the ACL present establishes combined protection, not an isolated kernel result.
Broker grant/revoke output is recorded as the Broker's claim; cross-process/expiry behavior has its own release gate.

## Evidence and release gates

The script emits structured case results, preflight observations, timestamps and package hashes.
`PASS` means that case's asserted behavior was observed. `FAIL` means the behavior disagreed with its expectation.
`BLOCKED` means a required environment/input was unavailable. `NOT_RUN` means no execution evidence exists.
An optional Python `NOT_RUN` leaves the aggregate `PARTIAL` when the required automated cases passed.
An automated-suite pass does not turn the following manual cases into passes.
Exit 0 from Run means the required automated cases passed; `overallStatus` remains `PARTIAL` while manual gates are `NOT_RUN`.
Exit 1 indicates failed assertions, exit 2 blocked prerequisites/evidence output, and exit 3 an incomplete required suite.
CMD denial evidence records the actual exit code and localized message; it does not report an inferred Win32 error as a measured code.

Copy `manual-results.template.json` to the evidence folder and record each actual run without replacing prior runs.
Every manual pass needs an artifact path or log excerpt, timestamp, actor/session, target path, expected behavior and observed result.
Do not copy a previous release's PASS onto a new driver hash.

| Gate | Required result and evidence |
| --- | --- |
| Explorer delete / recycle bin | Original deletion denied; fixture survives; matching Relay event records target/PID/operation; correct Agent prompt appears. Test permanent delete separately. |
| Agent No / closed dialog / no response | Fixture remains; no Broker-approved deletion or grant; filesystem caller returns without waiting for the UI. |
| Agent Yes + UAC approve | Prompt target matches event; UAC elevates Broker; exact fixture disappears; unrelated sibling survives; correlated audit records the grant path. |
| Agent Yes + UAC cancel | Fixture remains; no approved-delete audit entry or residual grant. |
| Ordinary-user boundary | Unelevated command/event-port access denied; event file readable but modifications denied; Agent stays unelevated. |
| Recursive caller deletion | CMD `rmdir`, PowerShell `Remove-Item -Recurse`, Python `shutil.rmtree` denied on fresh protected trees with all expected files accounted for. Broker-approved recursive deletion succeeds. |
| PID / path / expiry / revoke | Without ACL masking: grant permits only its PID and target descendants; other PID/sibling stays denied; expiry and explicit revoke deny subsequent deletion. Record driver replies and actual I/O results. |
| Event burst / rotation | Exercise real Relay events beyond 4 MiB, verify one retained previous file, parseable records, duplicate suppression and no enforcement bypass. Offline serialization tests are separate evidence. |
| Relay restart / driver restart | Denials remain enforced; policy synchronization and notifications recover; no Broker grant cleared during a concurrent approved operation. Record start/stop timing and finite recovery bound. |
| Concurrent deletes / Broker race | Independent processes delete different fixtures during approved deletion and Relay reconnection; unauthorized files remain intact; operations finish within the recorded deadline. |
| Multiple users / RDP | Verify the observed prompt recipient(s), approval identity, cancellation, disconnected sessions and lack of I/O stalls. Record whether duplicate prompts occur. |
| Reboot / shutdown | Relay blocked in receive does not hang shutdown; post-boot loaded-driver/policy/notification state observed. |
| FileDispositionInformationEx | A direct native probe exercises the extended disposition operation with and without a grant; ordinary DeleteFile alone does not establish this case. |
| Driver Verifier / sustained stress | Exact driver enabled under Verifier; actual stress count/duration/process count recorded; no bugcheck, deadlock or unauthorized deletion. Preserve any dump instead of converting a crash to a pass. |

Use [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)
and [File System Filter Verification](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/file-system-filter-verification)
in the VM only. A starting configuration is `verifier /standard /driver DeleteGuardFilter.sys`, followed by reboot
and `verifier /querysettings`. Select filter verification according to the VM's Windows build and Microsoft documentation.
Keep a snapshot and VM console recovery route; `verifier /reset` plus reboot is the documented reset path when the VM can boot.
The kit does not enable Verifier or restart the machine.

Release remains blocked until required gates pass on the exact tested build. Production signing and an assigned altitude remain
separate requirements even after VM acceptance succeeds.
