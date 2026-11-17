# Interactive approval prototype (v0.2.1+)

DeleteGuard v0.2.1 adds a user-visible approval path for deletion attempts denied by the v0.2 minifilter. v0.2.3 hardens that path against denial-event and approval-prompt flooding.

## Security architecture

```text
Explorer / PowerShell / cmd / application
        |
        | delete protected target
        v
DeleteGuardFilter.sys
        |
        | 1. deny with STATUS_ACCESS_DENIED
        | 2. best-effort delete-denied event
        v
admin-only FltMgr communication port
        |
        v
DeleteGuard.EventRelay.exe (LocalSystem service)
        |
        | bounded de-dup + bounded JSONL history
        v
%ProgramData%\DeleteGuard\denied-events.jsonl
        |
        | read-only for ordinary users
        v
DeleteGuard.Agent.exe (interactive user session)
        |
        | bounded unsolicited prompt rate
        | user clicks Yes
        v
UAC / runas
        |
        v
DeleteGuard.Broker.exe
        |
        | scoped kernel grant + controlled ACL release
        v
approved deletion
```

The desktop Agent never receives access to the kernel command channel. The Filter Manager communication port keeps its administrator/SYSTEM-only security descriptor. The Event Relay is the privileged boundary that receives kernel events and writes a read-only-for-users event stream.

## Deny-then-approved-delete semantics

DeleteGuard intentionally does **not** hold the original filesystem request open while waiting for UI or UAC.

The original delete request is denied immediately. If the user approves the prompt, the elevated broker performs a separate, explicitly approved deletion. Explorer, PowerShell, or another caller can therefore display an Access Denied error before the approved broker deletion completes.

This keeps filesystem I/O independent of desktop availability, UAC latency, hung sessions, disconnected RDP sessions, user interaction, and prompt-rate limiting. A missing/suppressed notification never changes enforcement.

## Kernel event channel

Protocol v3 distinguishes two roles on the same administrator-only FltMgr server port:

- `Command`: policy synchronization and short-lived delete grants.
- `Event`: kernel-to-user denial notifications.

The driver allows multiple command clients plus one event client so Event Relay synchronization does not monopolize the broker command path.

A delete-denied event contains:

- protocol version;
- event type;
- requestor PID;
- delete operation (`Disposition` or `DeleteOnClose`);
- monotonically increasing driver sequence;
- normalized NT device path.

Event delivery is best effort and uses a zero-wait kernel send. Failure to notify never changes enforcement: the delete remains denied.

## Event Relay

`DeleteGuard.EventRelay.exe` is intended to run as `LocalSystem` using the Windows Service Control Manager.

On connection/reconnection it:

1. acquires the same global mutation mutex used by the elevated broker before synchronizing policy state;
2. synchronizes protected policies to the driver;
3. opens the event-role connection;
4. receives denial events;
5. converts NT device paths back to drive-letter paths where possible;
6. records the process name when still available;
7. suppresses identical PID/operation/path events within two seconds;
8. keeps the in-memory de-duplication state hard-capped at 512 entries, evicting stale/oldest entries under a unique-path flood;
9. appends accepted events to the protected JSONL stream.

Using the same mutation mutex is important because `ResetRoots` also clears active grants. Relay synchronization must not run concurrently with an approved broker deletion.

The event history is also bounded on disk. `denied-events.jsonl` rotates at 4 MiB and at most one previous file (`denied-events.1.jsonl`) is retained.

## Desktop Agent and prompt-flood behavior

`DeleteGuard.Agent.exe` runs unelevated in the interactive user's session.

It reads recent denial events and prompts only for newly observed events. A Yes response starts the existing broker with `Verb=runas`, which produces the Windows UAC administrator prompt. A No response, closed dialog, UAC cancellation, missing Agent, missing Relay, notification loss, or rate-limited prompt never permits the original deletion.

To avoid approval/UAC fatigue from a malicious or buggy process, automatic modal approval prompts are limited to **3 prompts per rolling 30 seconds**. Further newly observed events are marked consumed and remain denied; they are not replayed later as fresh approval opportunities. While throttled, the Agent emits at most one warning balloon every 15 seconds.

Prompt throttling affects only unsolicited UI. A deliberate administrator can still use:

```powershell
deleteguard delete <path>
```

for an explicit approval path.

The Agent does not trust the JSONL file as authorization. The elevated broker re-validates that the target is still covered by a DeleteGuard policy before any delete is attempted.

## Installation in a test VM

First build/install the user-mode package:

```powershell
.\scripts\build.ps1 -Configuration Release -Runtime win-x64
.\scripts\install.ps1 -Runtime win-x64
```

Then, from elevated PowerShell, install the relay service:

```powershell
.\scripts\install-approval.ps1
```

Run this once as each interactive Windows user who should receive prompts:

```powershell
.\scripts\enable-agent.ps1
```

The development minifilter remains unsigned. Installing the Relay and Agent does not install, test-sign, or load `DeleteGuardFilter.sys`.

## Removal

Elevated PowerShell:

```powershell
.\scripts\uninstall-approval.ps1
```

Then in each user account where the Agent was enabled:

```powershell
.\scripts\disable-agent.ps1
```

## Validation still required

Before this layer can be considered production-ready it still needs loaded-driver VM validation covering at least:

- Explorer delete and recycle-bin paths;
- `Remove-Item`, `del`, `rmdir`, Python, .NET and direct Win32 delete APIs;
- recursive directory deletion;
- multiple rapid unique-path denial events: Relay state remains bounded and no more than 3 automatic modal prompts occur in 30 seconds;
- event-log rotation;
- service restart and driver restart behavior;
- UAC approve/cancel/no-response flows;
- broker/relay synchronization races;
- multiple signed-in users / RDP sessions;
- Driver Verifier and sustained delete stress;
- system shutdown/reboot while the Relay is blocked in `FilterGetMessage`.
