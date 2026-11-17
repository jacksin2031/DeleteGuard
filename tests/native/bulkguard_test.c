/*
 * User-mode unit tests for drivers/DeleteGuard.Filter/DeleteGuardBulk.h, the exact state machine
 * compiled into the minifilter. Build and run with tests/native/run-native-tests.ps1.
 */
#include <windows.h>
#include <stdio.h>

#include "../../drivers/DeleteGuard.Filter/DeleteGuardBulk.h"

static int gFailures = 0;

#define CHECK(condition, message)                                                   \
    do {                                                                            \
        if (!(condition)) {                                                         \
            printf("FAIL line %d: %s\n", __LINE__, message);                        \
            ++gFailures;                                                            \
        }                                                                           \
    } while (0)

#define SECONDS(n) ((ULONGLONG)(n) * 1000ULL * DG_100NS_PER_MS)
#define T0 SECONDS(1000) /* any non-zero start; the real clock is KeQueryInterruptTime */

static void InitState(DG_BULK_STATE *state, ULONG threshold, ULONG windowMs)
{
    ZeroMemory(state, sizeof(*state));
    CHECK(DgBulkConfigure(state, threshold, windowMs), "valid configuration accepted");
}

static void TestConfigureRejectsOutOfRange(void)
{
    DG_BULK_STATE s;
    ZeroMemory(&s, sizeof(s));
    CHECK(!DgBulkConfigure(&s, 0, 10000), "threshold 0 rejected");
    CHECK(!DgBulkConfigure(&s, DG_BULK_MAX_THRESHOLD + 1, 10000), "huge threshold rejected");
    CHECK(!DgBulkConfigure(&s, 10, DG_BULK_MIN_WINDOW_MS - 1), "tiny window rejected");
    CHECK(!DgBulkConfigure(&s, 10, DG_BULK_MAX_WINDOW_MS + 1), "huge window rejected");
    CHECK(s.Threshold == 0, "rejected configuration leaves state untouched");
    CHECK(DgBulkConfigure(&s, 1, DG_BULK_MIN_WINDOW_MS), "lower bounds accepted");
    CHECK(DgBulkConfigure(&s, DG_BULK_MAX_THRESHOLD, DG_BULK_MAX_WINDOW_MS), "upper bounds accepted");
}

static void TestLockoutLength(void)
{
    DG_BULK_STATE s;
    InitState(&s, 10, 1000);
    CHECK(s.LockoutMs == DG_BULK_MIN_LOCKOUT_MS, "short window uses the 15 s minimum lockout");
    InitState(&s, 10, 10000);
    CHECK(s.LockoutMs == 30000, "lockout is three windows when that is longer");
}

static void TestAllowsExactlyThresholdThenDenies(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    ULONG i;
    InitState(&s, 25, 10000);

    for (i = 0; i < 25; ++i) {
        CHECK(DgBulkAllow(&s, T0 + i, &notify), "deletions up to the threshold are allowed");
        CHECK(!notify, "allowed deletions never notify");
    }

    CHECK(!DgBulkAllow(&s, T0 + 25, &notify), "the deletion after the threshold is denied");
    CHECK(notify, "the first denial notifies");
    CHECK(!DgBulkAllow(&s, T0 + 26, &notify), "further deletions stay denied");
}

static void TestSlowDeletionsNeverTrip(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    ULONG i;
    InitState(&s, 5, 10000);

    /* One deletion every 3 s is 3 per 10 s window: always under the threshold of 5. */
    for (i = 0; i < 200; ++i) {
        CHECK(DgBulkAllow(&s, T0 + SECONDS(3) * i, &notify), "steady slow deletion is never blocked");
    }
}

static void TestWindowResetsCount(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    ULONG i;
    InitState(&s, 5, 10000);

    for (i = 0; i < 5; ++i) {
        CHECK(DgBulkAllow(&s, T0, &notify), "first window allows the threshold");
    }

    /* Exactly one window later the counter starts over, without ever having tripped. */
    for (i = 0; i < 5; ++i) {
        CHECK(DgBulkAllow(&s, T0 + SECONDS(10), &notify), "a new window allows the threshold again");
    }
    CHECK(!DgBulkAllow(&s, T0 + SECONDS(10), &notify), "but the sixth in that window is denied");
}

static void TestRetryingExtendsTheLock(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    ULONGLONG t;
    ULONG i;
    InitState(&s, 3, 10000); /* lockout 30 s */

    for (i = 0; i < 3; ++i) {
        DgBulkAllow(&s, T0, &notify);
    }
    CHECK(!DgBulkAllow(&s, T0, &notify), "trips");

    /* A runaway command retries every 20 s for ten minutes: the lock must never expire. */
    for (t = T0 + SECONDS(20); t < T0 + SECONDS(600); t += SECONDS(20)) {
        CHECK(!DgBulkAllow(&s, t, &notify), "persistent retries cannot wait the lock out");
    }
}

static void TestLockExpiresAfterQuietPeriod(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    ULONG i;
    InitState(&s, 3, 10000); /* lockout 30 s */

    for (i = 0; i < 3; ++i) {
        DgBulkAllow(&s, T0, &notify);
    }
    CHECK(!DgBulkAllow(&s, T0, &notify), "trips");

    CHECK(!DgBulkAllow(&s, T0 + SECONDS(29), &notify), "still locked just before expiry (and extended to +59 s)");
    CHECK(!DgBulkAllow(&s, T0 + SECONDS(58), &notify), "the previous denial pushed expiry out");
    CHECK(DgBulkAllow(&s, T0 + SECONDS(89), &notify), "allowed again after a full quiet lockout");

    /* Counters started fresh: the full threshold is available again. */
    CHECK(DgBulkAllow(&s, T0 + SECONDS(89), &notify), "second allowed after reset");
    CHECK(DgBulkAllow(&s, T0 + SECONDS(89), &notify), "third allowed after reset");
    CHECK(!DgBulkAllow(&s, T0 + SECONDS(89), &notify), "fourth denied: threshold applies afresh");
}

static void TestNotificationsAreRateLimited(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    ULONG notified = 0;
    ULONGLONG t;
    InitState(&s, 1, 10000);

    DgBulkAllow(&s, T0, &notify);

    /* 100000 denied attempts within one second must produce a single notification. */
    for (t = 1; t <= 100000; ++t) {
        DgBulkAllow(&s, T0 + t * 100, &notify); /* 10 microseconds apart */
        if (notify) {
            ++notified;
        }
    }
    CHECK(notified == 1, "a denial storm produces one notification");

    /* After the notify interval another one is allowed. */
    DgBulkAllow(&s, T0 + SECONDS(6), &notify);
    CHECK(notify, "a later denial notifies again");
}

static void TestSurvivesLargeClockValues(void)
{
    DG_BULK_STATE s;
    BOOLEAN notify;
    const ULONGLONG big = 0x7000000000000000ULL; /* far larger than any real uptime */
    InitState(&s, 2, 10000);

    CHECK(DgBulkAllow(&s, big, &notify), "first allowed at a huge timestamp");
    CHECK(DgBulkAllow(&s, big + 1, &notify), "second allowed");
    CHECK(!DgBulkAllow(&s, big + 2, &notify), "third denied");
}

int main(void)
{
    TestConfigureRejectsOutOfRange();
    TestLockoutLength();
    TestAllowsExactlyThresholdThenDenies();
    TestSlowDeletionsNeverTrip();
    TestWindowResetsCount();
    TestRetryingExtendsTheLock();
    TestLockExpiresAfterQuietPeriod();
    TestNotificationsAreRateLimited();
    TestSurvivesLargeClockValues();

    if (gFailures != 0) {
        printf("%d check(s) FAILED\n", gFailures);
        return 1;
    }

    printf("bulk-guard native tests passed\n");
    return 0;
}
