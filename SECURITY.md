# Security model

DeleteGuard v0.1 is an **accidental-deletion and non-elevated-process protection MVP**, not a security boundary against a determined local administrator.

## What v0.1 protects

On an NTFS protected root, DeleteGuard adds an explicit inherited deny rule for `DELETE` and `DELETE_CHILD`. This blocks ordinary deletion through Explorer, `cmd`, PowerShell and user-mode applications while the ACL remains intact.

Administrative mutations are performed by `DeleteGuard.Broker.exe`, whose manifest requires UAC elevation. Policy and audit state are stored in `%ProgramData%\DeleteGuard` with an administrator/SYSTEM-owned ACL and read access for standard users.

## Known limitations

- A local administrator can deliberately change ACLs, take ownership or otherwise bypass the MVP.
- A knowledgeable owner may be able to alter descendant ACL inheritance. The minifilter phase is intended to remove ACL tampering as a bypass path.
- `deleteguard delete` temporarily removes the guard ACL while its elevated deletion executes, creating a short race window.
- NTFS uses the `DELETE` right for rename/move operations; strict MVP protection can therefore block renames, moves, and atomic replace-save patterns in protected trees.
- The MVP does not protect against disk formatting, partition deletion, raw-disk writes, offline access, booting another OS, filesystem corruption or physical device failure.
- Reparse-point roots are rejected. Reparse points nested below a protected root are outside the MVP's strong guarantees.
- Only NTFS is supported.

Do not treat DeleteGuard as a backup. Keep independent, versioned backups of important data.
