#pragma once

#include <fltKernel.h>

#define DG_PROTOCOL_VERSION 3u
#define DG_PORT_NAME L"\\DeleteGuardPort"
#define DG_MAX_PATH_CHARS 520
#define DG_MAX_ROOTS 64
#define DG_MAX_GRANTS 32

typedef enum _DG_CLIENT_ROLE {
    DgClientRoleCommand = 1,
    DgClientRoleEvent = 2
} DG_CLIENT_ROLE;

typedef enum _DG_COMMAND_TYPE {
    DgCommandPing = 0,
    DgCommandResetRoots = 1,
    DgCommandAddRoot = 2,
    DgCommandRemoveRoot = 3,
    DgCommandGrant = 4,
    DgCommandRevoke = 5
} DG_COMMAND_TYPE;

typedef enum _DG_EVENT_TYPE {
    DgEventDeleteDenied = 1
} DG_EVENT_TYPE;

typedef enum _DG_DELETE_OPERATION {
    DgDeleteOperationDisposition = 1,
    DgDeleteOperationDeleteOnClose = 2
} DG_DELETE_OPERATION;

typedef struct _DG_CONNECT_CONTEXT {
    ULONG Version;
    ULONG Role;
} DG_CONNECT_CONTEXT, *PDG_CONNECT_CONTEXT;

typedef struct _DG_COMMAND {
    ULONG Version;
    ULONG Type;
    ULONG ProcessId;
    ULONG TtlMilliseconds;
    WCHAR Path[DG_MAX_PATH_CHARS];
} DG_COMMAND, *PDG_COMMAND;

typedef struct _DG_REPLY {
    NTSTATUS Status;
    ULONG RootCount;
} DG_REPLY, *PDG_REPLY;

typedef struct _DG_EVENT {
    ULONG Version;
    ULONG Type;
    ULONG ProcessId;
    ULONG Operation;
    ULONGLONG Sequence;
    WCHAR Path[DG_MAX_PATH_CHARS];
} DG_EVENT, *PDG_EVENT;

typedef struct _DG_ROOT_ENTRY {
    USHORT Length;
    WCHAR Path[DG_MAX_PATH_CHARS];
} DG_ROOT_ENTRY, *PDG_ROOT_ENTRY;

typedef struct _DG_GRANT_ENTRY {
    ULONG ProcessId;
    ULONGLONG ProcessStartKey;
    ULONGLONG ExpiresAt100ns;
    USHORT Length;
    WCHAR Path[DG_MAX_PATH_CHARS];
} DG_GRANT_ENTRY, *PDG_GRANT_ENTRY;
