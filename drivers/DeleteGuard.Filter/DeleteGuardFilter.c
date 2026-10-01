#include <fltKernel.h>
#include "DeleteGuardFilter.h"

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;
EX_PUSH_LOCK gStateLock;
DG_ROOT_ENTRY gRoots[DG_MAX_ROOTS];
DG_GRANT_ENTRY gGrants[DG_MAX_GRANTS];

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS DgUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS DgInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static FLT_PREOP_CALLBACK_STATUS DgPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_PREOP_CALLBACK_STATUS DgPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static NTSTATUS DgPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie);
static VOID DgPortDisconnect(_In_opt_ PVOID ConnectionCookie);
static NTSTATUS DgPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

static BOOLEAN DgSetInfoRequestsDelete(_In_ PFLT_CALLBACK_DATA Data);
static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(_Inout_ PFLT_CALLBACK_DATA Data);
static BOOLEAN DgPathIsSameOrDescendant(_In_ PCUNICODE_STRING Candidate, _In_reads_(RootChars) const WCHAR *Root, _In_ USHORT RootChars);
static BOOLEAN DgIsProtectedAndGranted(_In_ PCUNICODE_STRING Name, _In_ ULONG ProcessId, _Out_ PBOOLEAN Granted);
static NTSTATUS DgReadCommandPath(_In_ const DG_COMMAND *Command, _Out_ PUSHORT LengthChars);
static NTSTATUS DgAddRoot(_In_ const DG_COMMAND *Command);
static NTSTATUS DgRemoveRoot(_In_ const DG_COMMAND *Command);
static NTSTATUS DgGrant(_In_ const DG_COMMAND *Command);
static NTSTATUS DgRevoke(_In_ const DG_COMMAND *Command);
static ULONG DgRootCountLocked(VOID);

CONST FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, DgPreCreate, NULL },
    { IRP_MJ_SET_INFORMATION, 0, DgPreSetInformation, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION gRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    gCallbacks,
    DgUnload,
    DgInstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DgUnload)
#pragma alloc_text(PAGE, DgInstanceSetup)
#endif

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializePushLock(&gStateLock);
    RtlZeroMemory(gRoots, sizeof(gRoots));
    RtlZeroMemory(gGrants, sizeof(gGrants));

    status = FltRegisterFilter(DriverObject, &gRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = FltBuildDefaultSecurityDescriptor(&securityDescriptor, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    RtlInitUnicodeString(&portName, DG_PORT_NAME);
    InitializeObjectAttributes(
        &objectAttributes,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor);

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &objectAttributes,
        NULL,
        DgPortConnect,
        DgPortDisconnect,
        DgPortMessage,
        1);

    FltFreeSecurityDescriptor(securityDescriptor);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
        return status;
    }

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return status;
}

static NTSTATUS DgUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    if (gClientPort != NULL && gFilterHandle != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
    }

    if (gFilterHandle != NULL) {
        FltUnregisterFilter(gFilterHandle);
        gFilterHandle = NULL;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS DgInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    PAGED_CODE();

    // v0.2 intentionally matches the v0.1 NTFS-only ACL safety boundary.
    if (VolumeFilesystemType != FLT_FSTYPE_NTFS) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

static FLT_PREOP_CALLBACK_STATUS DgPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return DgEnforceDelete(Data);
}

static FLT_PREOP_CALLBACK_STATUS DgPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);

    if (!DgSetInfoRequestsDelete(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return DgEnforceDelete(Data);
}

static BOOLEAN DgSetInfoRequestsDelete(_In_ PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;

    if (buffer == NULL) {
        return FALSE;
    }

    if (infoClass == FileDispositionInformation && length >= sizeof(FILE_DISPOSITION_INFORMATION)) {
        return ((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile ? TRUE : FALSE;
    }

    if (infoClass == FileDispositionInformationEx && length >= sizeof(FILE_DISPOSITION_INFORMATION_EX)) {
        return FlagOn(((PFILE_DISPOSITION_INFORMATION_EX)buffer)->Flags, FILE_DISPOSITION_DELETE) ? TRUE : FALSE;
    }

    return FALSE;
}

static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(_Inout_ PFLT_CALLBACK_DATA Data)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN granted = FALSE;
    BOOLEAN isProtected;
    ULONG processId = HandleToULong(PsGetCurrentProcessId());

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);

    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &nameInfo);
    }

    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        // The ACL layer remains the v0.2 fallback if a name cannot be resolved.
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    isProtected = DgIsProtectedAndGranted(&nameInfo->Name, processId, &granted);
    FltReleaseFileNameInformation(nameInfo);

    if (!isProtected || granted) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static BOOLEAN DgPathIsSameOrDescendant(
    _In_ PCUNICODE_STRING Candidate,
    _In_reads_(RootChars) const WCHAR *Root,
    _In_ USHORT RootChars)
{
    UNICODE_STRING rootString;
    USHORT candidateChars;

    if (Candidate == NULL || Candidate->Buffer == NULL || Root == NULL || RootChars == 0) {
        return FALSE;
    }

    rootString.Buffer = (PWCH)Root;
    rootString.Length = (USHORT)(RootChars * sizeof(WCHAR));
    rootString.MaximumLength = rootString.Length;

    if (!RtlPrefixUnicodeString(&rootString, Candidate, TRUE)) {
        return FALSE;
    }

    candidateChars = (USHORT)(Candidate->Length / sizeof(WCHAR));
    if (candidateChars == RootChars) {
        return TRUE;
    }

    return candidateChars > RootChars && Candidate->Buffer[RootChars] == L'\\';
}

static BOOLEAN DgIsProtectedAndGranted(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _Out_ PBOOLEAN Granted)
{
    ULONG index;
    ULONGLONG now = KeQueryInterruptTime();
    BOOLEAN isProtected = FALSE;

    *Granted = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0 &&
            DgPathIsSameOrDescendant(Name, gRoots[index].Path, gRoots[index].Length)) {
            isProtected = TRUE;
            break;
        }
    }

    if (isProtected) {
        for (index = 0; index < DG_MAX_GRANTS; ++index) {
            if (gGrants[index].Length == 0 ||
                gGrants[index].ProcessId != ProcessId ||
                gGrants[index].ExpiresAt100ns <= now) {
                continue;
            }

            if (DgPathIsSameOrDescendant(Name, gGrants[index].Path, gGrants[index].Length)) {
                *Granted = TRUE;
                break;
            }
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return isProtected;
}

static NTSTATUS DgPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    if (ConnectionCookie != NULL) {
        *ConnectionCookie = NULL;
    }

    if (InterlockedCompareExchangePointer((PVOID volatile *)&gClientPort, ClientPort, NULL) != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    return STATUS_SUCCESS;
}

static VOID DgPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gFilterHandle != NULL && gClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gClientPort);
    }
}

static NTSTATUS DgPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength)
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    DG_REPLY reply = { 0 };
    PDG_COMMAND command;

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(DG_COMMAND)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    command = (PDG_COMMAND)InputBuffer;
    if (command->Version != DG_PROTOCOL_VERSION) {
        status = STATUS_REVISION_MISMATCH;
        goto Complete;
    }

    switch ((DG_COMMAND_TYPE)command->Type) {
    case DgCommandPing:
        status = STATUS_SUCCESS;
        break;

    case DgCommandResetRoots:
        KeEnterCriticalRegion();
        ExAcquirePushLockExclusive(&gStateLock);
        RtlZeroMemory(gRoots, sizeof(gRoots));
        RtlZeroMemory(gGrants, sizeof(gGrants));
        ExReleasePushLockExclusive(&gStateLock);
        KeLeaveCriticalRegion();
        status = STATUS_SUCCESS;
        break;

    case DgCommandAddRoot:
        status = DgAddRoot(command);
        break;

    case DgCommandRemoveRoot:
        status = DgRemoveRoot(command);
        break;

    case DgCommandGrant:
        status = DgGrant(command);
        break;

    case DgCommandRevoke:
        status = DgRevoke(command);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

Complete:
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);
    reply.Status = status;
    reply.RootCount = DgRootCountLocked();
    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();

    if (OutputBuffer != NULL && OutputBufferLength >= sizeof(reply)) {
        RtlCopyMemory(OutputBuffer, &reply, sizeof(reply));
        *ReturnOutputBufferLength = sizeof(reply);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS DgReadCommandPath(_In_ const DG_COMMAND *Command, _Out_ PUSHORT LengthChars)
{
    USHORT index;

    if (Command == NULL || LengthChars == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < DG_MAX_PATH_CHARS; ++index) {
        if (Command->Path[index] == L'\0') {
            if (index == 0) {
                return STATUS_OBJECT_PATH_INVALID;
            }
            *LengthChars = index;
            return STATUS_SUCCESS;
        }
    }

    return STATUS_NAME_TOO_LONG;
}

static NTSTATUS DgAddRoot(_In_ const DG_COMMAND *Command)
{
    NTSTATUS status;
    USHORT lengthChars;
    ULONG index;
    LONG freeIndex = -1;
    UNICODE_STRING commandPath;

    status = DgReadCommandPath(Command, &lengthChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    commandPath.Buffer = (PWCH)Command->Path;
    commandPath.Length = (USHORT)(lengthChars * sizeof(WCHAR));
    commandPath.MaximumLength = commandPath.Length;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        UNICODE_STRING existing;
        if (gRoots[index].Length == 0) {
            if (freeIndex < 0) {
                freeIndex = (LONG)index;
            }
            continue;
        }

        existing.Buffer = gRoots[index].Path;
        existing.Length = (USHORT)(gRoots[index].Length * sizeof(WCHAR));
        existing.MaximumLength = existing.Length;
        if (RtlEqualUnicodeString(&existing, &commandPath, TRUE)) {
            status = STATUS_SUCCESS;
            goto Exit;
        }
    }

    if (freeIndex < 0) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    gRoots[freeIndex].Length = lengthChars;
    RtlCopyMemory(gRoots[freeIndex].Path, Command->Path, lengthChars * sizeof(WCHAR));
    gRoots[freeIndex].Path[lengthChars] = L'\0';
    status = STATUS_SUCCESS;

Exit:
    ExReleasePushLockExclusive(&gStateLock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS DgRemoveRoot(_In_ const DG_COMMAND *Command)
{
    NTSTATUS status;
    USHORT lengthChars;
    ULONG index;
    UNICODE_STRING commandPath;

    status = DgReadCommandPath(Command, &lengthChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    commandPath.Buffer = (PWCH)Command->Path;
    commandPath.Length = (USHORT)(lengthChars * sizeof(WCHAR));
    commandPath.MaximumLength = commandPath.Length;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gStateLock);

    status = STATUS_NOT_FOUND;
    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        UNICODE_STRING existing;
        if (gRoots[index].Length == 0) {
            continue;
        }

        existing.Buffer = gRoots[index].Path;
        existing.Length = (USHORT)(gRoots[index].Length * sizeof(WCHAR));
        existing.MaximumLength = existing.Length;
        if (RtlEqualUnicodeString(&existing, &commandPath, TRUE)) {
            RtlZeroMemory(&gRoots[index], sizeof(gRoots[index]));
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&gStateLock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS DgGrant(_In_ const DG_COMMAND *Command)
{
    NTSTATUS status;
    USHORT lengthChars;
    ULONG index;
    LONG slot = -1;
    ULONGLONG now;

    status = DgReadCommandPath(Command, &lengthChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (Command->ProcessId == 0 || Command->TtlMilliseconds == 0 || Command->TtlMilliseconds > 30000) {
        return STATUS_INVALID_PARAMETER;
    }

    now = KeQueryInterruptTime();

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gStateLock);

    for (index = 0; index < DG_MAX_GRANTS; ++index) {
        if (gGrants[index].Length == 0 || gGrants[index].ExpiresAt100ns <= now) {
            slot = (LONG)index;
            break;
        }
    }

    if (slot < 0) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    RtlZeroMemory(&gGrants[slot], sizeof(gGrants[slot]));
    gGrants[slot].ProcessId = Command->ProcessId;
    gGrants[slot].ExpiresAt100ns = now + ((ULONGLONG)Command->TtlMilliseconds * 10000ULL);
    gGrants[slot].Length = lengthChars;
    RtlCopyMemory(gGrants[slot].Path, Command->Path, lengthChars * sizeof(WCHAR));
    gGrants[slot].Path[lengthChars] = L'\0';
    status = STATUS_SUCCESS;

Exit:
    ExReleasePushLockExclusive(&gStateLock);
    KeLeaveCriticalRegion();
    return status;
}

static NTSTATUS DgRevoke(_In_ const DG_COMMAND *Command)
{
    NTSTATUS status;
    USHORT lengthChars;
    ULONG index;
    UNICODE_STRING commandPath;

    status = DgReadCommandPath(Command, &lengthChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    commandPath.Buffer = (PWCH)Command->Path;
    commandPath.Length = (USHORT)(lengthChars * sizeof(WCHAR));
    commandPath.MaximumLength = commandPath.Length;

    KeEnterCriticalRegion();
    ExAcquirePushLockExclusive(&gStateLock);

    status = STATUS_NOT_FOUND;
    for (index = 0; index < DG_MAX_GRANTS; ++index) {
        UNICODE_STRING existing;
        if (gGrants[index].Length == 0 || gGrants[index].ProcessId != Command->ProcessId) {
            continue;
        }

        existing.Buffer = gGrants[index].Path;
        existing.Length = (USHORT)(gGrants[index].Length * sizeof(WCHAR));
        existing.MaximumLength = existing.Length;
        if (RtlEqualUnicodeString(&existing, &commandPath, TRUE)) {
            RtlZeroMemory(&gGrants[index], sizeof(gGrants[index]));
            status = STATUS_SUCCESS;
            break;
        }
    }

    ExReleasePushLockExclusive(&gStateLock);
    KeLeaveCriticalRegion();
    return status;
}

static ULONG DgRootCountLocked(VOID)
{
    ULONG index;
    ULONG count = 0;

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0) {
            ++count;
        }
    }

    return count;
}
