#pragma once

/*
 * Bulk-delete guard: a small rate-limiter state machine.
 *
 * Deliberately free of kernel dependencies (only ULONG/ULONGLONG/BOOLEAN) so the exact same
 * code is compiled into the minifilter and unit-tested in user mode (tests/native).
 *
 * Time is in 100 ns units (KeQueryInterruptTime). Semantics, per protected root:
 *   - up to Threshold deletions are allowed within one WindowMs window;
 *   - the next deletion trips a lock: it and every further attempt are denied;
 *   - while locked, each attempt pushes the lock expiry out again, so a runaway command that
 *     keeps retrying can never simply wait the lock out. The lock lasts LockoutMs of quiet;
 *   - after the lock expires the counters start fresh.
 */

#define DG_BULK_MIN_THRESHOLD 1UL
#define DG_BULK_MAX_THRESHOLD 1000000UL
#define DG_BULK_MIN_WINDOW_MS 1000UL
#define DG_BULK_MAX_WINDOW_MS 3600000UL
#define DG_BULK_MIN_LOCKOUT_MS 15000UL
#define DG_BULK_NOTIFY_INTERVAL_MS 5000UL
#define DG_100NS_PER_MS 10000ULL

typedef struct _DG_BULK_STATE {
    ULONG Threshold;
    ULONG WindowMs;
    ULONG LockoutMs;
    ULONGLONG WindowStart;
    ULONG Count;
    ULONGLONG LockedUntil;
    ULONGLONG LastNotify;
} DG_BULK_STATE;

/* Returns FALSE (and leaves the state untouched) when a parameter is out of range. */
static __inline BOOLEAN DgBulkConfigure(DG_BULK_STATE *State, ULONG Threshold, ULONG WindowMs)
{
    ULONGLONG lockoutMs;

    if (Threshold < DG_BULK_MIN_THRESHOLD || Threshold > DG_BULK_MAX_THRESHOLD ||
        WindowMs < DG_BULK_MIN_WINDOW_MS || WindowMs > DG_BULK_MAX_WINDOW_MS) {
        return FALSE;
    }

    lockoutMs = (ULONGLONG)WindowMs * 3ULL;
    if (lockoutMs < DG_BULK_MIN_LOCKOUT_MS) {
        lockoutMs = DG_BULK_MIN_LOCKOUT_MS;
    }

    State->Threshold = Threshold;
    State->WindowMs = WindowMs;
    State->LockoutMs = (ULONG)lockoutMs;
    State->WindowStart = 0;
    State->Count = 0;
    State->LockedUntil = 0;
    State->LastNotify = 0;
    return TRUE;
}

/*
 * Decide one deletion at time Now (> 0). Returns TRUE to allow, FALSE to deny.
 * *Notify is set when a denial should be reported to user mode; reports are rate-limited
 * so a wipe attempting millions of deletes cannot flood the event channel.
 */
static __inline BOOLEAN DgBulkAllow(DG_BULK_STATE *State, ULONGLONG Now, BOOLEAN *Notify)
{
    ULONGLONG lockout = (ULONGLONG)State->LockoutMs * DG_100NS_PER_MS;
    ULONGLONG window = (ULONGLONG)State->WindowMs * DG_100NS_PER_MS;
    BOOLEAN deny = FALSE;

    *Notify = FALSE;

    if (State->LockedUntil != 0) {
        if (Now < State->LockedUntil) {
            State->LockedUntil = Now + lockout;
            deny = TRUE;
        }
        else {
            State->LockedUntil = 0;
            State->WindowStart = 0;
            State->Count = 0;
        }
    }

    if (!deny) {
        if (State->WindowStart == 0 || Now - State->WindowStart >= window) {
            State->WindowStart = Now;
            State->Count = 0;
        }

        if (State->Count >= State->Threshold) {
            State->LockedUntil = Now + lockout;
            deny = TRUE;
        }
        else {
            State->Count++;
        }
    }

    if (deny &&
        (State->LastNotify == 0 ||
         Now - State->LastNotify >= (ULONGLONG)DG_BULK_NOTIFY_INTERVAL_MS * DG_100NS_PER_MS)) {
        State->LastNotify = Now;
        *Notify = TRUE;
    }

    return deny ? FALSE : TRUE;
}
