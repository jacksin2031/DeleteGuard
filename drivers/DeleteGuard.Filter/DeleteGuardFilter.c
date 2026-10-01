#include <fltKernel.h>
#include "DeleteGuardFilter.h"

#define DG_MAX_COMMAND_CLIENTS 4
#define DG_CONNECTION_COOKIE_COMMAND_BASE 1u
#define DG_CONNECTION_COOKIE_EVENT 0x100u
#define DG_RENAME_POOL_TAG 'rGDD'

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gCommandClientPorts[DG_MAX_COMMAND_CLIENTS];
PFLT_PORT gEventClientPort = NULL;
EX_PUSH_LOCK gStateLock;
DG_ROOT_ENTRY gRoots[DG_MAX_ROOTS];
DG_GRANT_ENTRY gGrants[DG_MAX_GRANTS];
volatile LONG64 gEventSequence = 0;

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
static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ DG_DELETE_OPERATION Operation);
static FLT_PREOP_CALLBACK_STATUS DgEnforceRenameBoundary(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID DgPublishDeniedEvent(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ DG_DELETE_OPERATION Operation);
static BOOLEAN DgPathIsSameOrDescendant(_In_ PCUNICODE_STRING Candidate, _In_reads_(RootChars) const WCHAR *Root, _In_ USHORT RootChars);
static BOOLEAN DgIsProtectedPath(_In_ PCUNICODE_STRING Name);
static BOOLEAN DgHasProtectedRoots(VOID);
static DG_DELETE_OPERATION DgClassifyRename(
    _In_ PCUNICODE_STRING Source,
    _In_ PCUNICODE_STRING Destination,
    _In_ BOOLEAN ReplaceRequested);
static BOOLEAN DgIsProtectedAndGranted(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessStartKey,
    _Out_ PBOOLEAN Granted);
static NTSTATUS DgReadCommandPath(_In_ const DG_COMMAND *Command, _Out_ PUSHORT LengthChars);
static NTSTATUS DgAddRoot(_In_ const DG_COMMAND *Command);
static NTSTATUS DgRemoveRoot(_In_ const DG_COMMAND *Command);
static NTSTATUS DgGrant(_In_ const DG_COMMAND *Command);
static NTSTATUS DgRevoke(_In_ const DG_COMMAND *Command);
static ULONG DgRootCountLocked(VOID);
static BOOLEAN DgIsCommandCookie(_In_ ULONG_PTR Cookie);

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
    RtlZeroMemory(gCommandClientPorts, sizeof(gCommandClientPorts));

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
        DG_MAX_COMMAND_CLIENTS + 1);

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
    ULONG index;

    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    if (gServerPort != NULL) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    if (gFilterHandle != NULL) {
        for (index = 0; index < DG_MAX_COMMAND_CLIENTS; ++index) {
            if (gCommandClientPorts[index] != NULL) {
                FltCloseClientPort(gFilterHandle, &gCommandClientPorts[index]);
            }
        }

        if (gEventClientPort != NULL) {
            FltCloseClientPort(gFilterHandle, &gEventClientPort);
        }

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

    return DgEnforceDelete(Data, DgDeleteOperationDeleteOnClose);
}

static FLT_PREOP_CALLBACK_STATUS DgPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;

    UNREFERENCED_PARAMETER(CompletionContext);

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoClass == FileRenameInformation || infoClass == FileRenameInformationEx) {
        return DgEnforceRenameBoundary(Data, FltObjects);
    }

    if (!DgSetInfoRequestsDelete(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return DgEnforceDelete(Data, DgDeleteOperationDisposition);
}

static BOOLEAN DgSetInfoRequestsDelete(_In_ PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
    BOOLEAN requestsDelete = FALSE;

    if (buffer == NULL) {
        return FALSE;
    }

    __try {
        if (infoClass == FileDispositionInformation && length >= sizeof(FILE_DISPOSITION_INFORMATION)) {
            requestsDelete = ((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile ? TRUE : FALSE;
        }
        else if (infoClass == FileDispositionInformationEx && length >= sizeof(FILE_DISPOSITION_INFORMATION_EX)) {
            requestsDelete = FlagOn(((PFILE_DISPOSITION_INFORMATION_EX)buffer)->Flags, FILE_DISPOSITION_DELETE) ? TRUE : FALSE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return requestsDelete;
}

static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ DG_DELETE_OPERATION Operation)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PEPROCESS requestorProcess;
    BOOLEAN granted = FALSE;
    BOOLEAN isProtected;
    ULONG processId;
    ULONGLONG processStartKey = 0;

    processId = FltGetRequestorProcessId(Data);
    requestorProcess = FltGetRequestorProcess(Data);
    if (requestorProcess != NULL) {
        processStartKey = PsGetProcessStartKey(requestorProcess);
    }

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
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    isProtected = DgIsProtectedAndGranted(
        &nameInfo->Name,
        processId,
        processStartKey,
        &granted);
    if (!isProtected || granted) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    DgPublishDeniedEvent(&nameInfo->Name, processId, Operation);
    FltReleaseFileNameInformation(nameInfo);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS DgEnforceRenameBoundary(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION sourceNameInfo = NULL;
    PFLT_FILE_NAME_INFORMATION destinationNameInfo = NULL;
    PFILE_RENAME_INFORMATION renameInfo;
    PVOID infoBuffer;
    ULONG infoLength;
    ULONG minimumLength = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
    ULONG fileNameLength = 0;
    HANDLE rootDirectory = NULL;
    PWSTR fileNameCopy = NULL;
    FILE_INFORMATION_CLASS infoClass;
    BOOLEAN sourceProtected;
    BOOLEAN hasProtectedRoots;
    BOOLEAN replaceRequested = FALSE;
    DG_DELETE_OPERATION renameOperation = (DG_DELETE_OPERATION)0;
    PCUNICODE_STRING eventName;
    ULONG processId;

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &sourceNameInfo);

    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &sourceNameInfo);
    }

    if (!NT_SUCCESS(status) || sourceNameInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    sourceProtected = DgIsProtectedPath(&sourceNameInfo->Name);
    hasProtectedRoots = DgHasProtectedRoots();
    if (!sourceProtected && !hasProtectedRoots) {
        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    infoLength = Data->Iopb->Parameters.SetFileInformation.Length;
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    if (infoBuffer == NULL || infoLength < minimumLength) {
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
            goto Deny;
        }
        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    renameInfo = (PFILE_RENAME_INFORMATION)infoBuffer;
    __try {
        rootDirectory = renameInfo->RootDirectory;
        fileNameLength = renameInfo->FileNameLength;
        if (infoClass == FileRenameInformationEx) {
            replaceRequested = FlagOn(renameInfo->Flags, FILE_RENAME_REPLACE_IF_EXISTS) ? TRUE : FALSE;
        }
        else {
            replaceRequested = renameInfo->ReplaceIfExists ? TRUE : FALSE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
            goto Deny;
        }
        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FltObjects == NULL || FltObjects->Instance == NULL || Data->Iopb->TargetFileObject == NULL) {
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
        }
        else if (replaceRequested && hasProtectedRoots) {
            renameOperation = DgDeleteOperationRenameReplace;
        }

        if (renameOperation != 0) {
            goto Deny;
        }

        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (fileNameLength == 0 ||
        (fileNameLength % sizeof(WCHAR)) != 0 ||
        fileNameLength > (infoLength - minimumLength)) {
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
        }
        else if (replaceRequested && hasProtectedRoots) {
            renameOperation = DgDeleteOperationRenameReplace;
        }

        if (renameOperation != 0) {
            goto Deny;
        }

        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    fileNameCopy = (PWSTR)ExAllocatePool2(
        POOL_FLAG_PAGED,
        (SIZE_T)fileNameLength + sizeof(WCHAR),
        DG_RENAME_POOL_TAG);
    if (fileNameCopy == NULL) {
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
        }
        else if (replaceRequested && hasProtectedRoots) {
            renameOperation = DgDeleteOperationRenameReplace;
        }

        if (renameOperation != 0) {
            goto Deny;
        }

        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        RtlCopyMemory(fileNameCopy, renameInfo->FileName, fileNameLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(fileNameCopy, DG_RENAME_POOL_TAG);
        fileNameCopy = NULL;
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
        }
        else if (replaceRequested && hasProtectedRoots) {
            renameOperation = DgDeleteOperationRenameReplace;
        }

        if (renameOperation != 0) {
            goto Deny;
        }

        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    fileNameCopy[fileNameLength / sizeof(WCHAR)] = L'\0';

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        rootDirectory,
        fileNameCopy,
        fileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationNameInfo);

    if (!NT_SUCCESS(status)) {
        status = FltGetDestinationFileNameInformation(
            FltObjects->Instance,
            Data->Iopb->TargetFileObject,
            rootDirectory,
            fileNameCopy,
            fileNameLength,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &destinationNameInfo);
    }

    ExFreePoolWithTag(fileNameCopy, DG_RENAME_POOL_TAG);
    fileNameCopy = NULL;

    if (!NT_SUCCESS(status) || destinationNameInfo == NULL) {
        if (sourceProtected) {
            renameOperation = DgDeleteOperationRenameOut;
        }
        else if (replaceRequested && hasProtectedRoots) {
            renameOperation = DgDeleteOperationRenameReplace;
        }

        if (renameOperation != 0) {
            goto Deny;
        }

        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    renameOperation = DgClassifyRename(
        &sourceNameInfo->Name,
        &destinationNameInfo->Name,
        replaceRequested);
    if (renameOperation == 0) {
        FltReleaseFileNameInformation(destinationNameInfo);
        FltReleaseFileNameInformation(sourceNameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

Deny:
    if (fileNameCopy != NULL) {
        ExFreePoolWithTag(fileNameCopy, DG_RENAME_POOL_TAG);
    }

    eventName = &sourceNameInfo->Name;
    if (renameOperation == DgDeleteOperationRenameReplace && destinationNameInfo != NULL) {
        eventName = &destinationNameInfo->Name;
    }

    processId = FltGetRequestorProcessId(Data);
    DgPublishDeniedEvent(eventName, processId, renameOperation);

    if (destinationNameInfo != NULL) {
        FltReleaseFileNameInformation(destinationNameInfo);
    }
    FltReleaseFileNameInformation(sourceNameInfo);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static VOID DgPublishDeniedEvent(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ DG_DELETE_OPERATION Operation)
{
    DG_EVENT event = { 0 };
    LARGE_INTEGER timeout;
    USHORT chars;

    if (gFilterHandle == NULL || gEventClientPort == NULL || Name == NULL || Name->Buffer == NULL) {
        return;
    }

    if (KeGetCurrentIrql() > APC_LEVEL) {
        return;
    }

    chars = (USHORT)(Name->Length / sizeof(WCHAR));
    if (chars >= DG_MAX_PATH_CHARS) {
        chars = DG_MAX_PATH_CHARS - 1;
    }

    event.Version = DG_PROTOCOL_VERSION;
    event.Type = DgEventDeleteDenied;
    event.ProcessId = ProcessId;
    event.Operation = Operation;
    event.Sequence = (ULONGLONG)InterlockedIncrement64(&gEventSequence);
    RtlCopyMemory(event.Path, Name->Buffer, chars * sizeof(WCHAR));
    event.Path[chars] = L'\0';

    timeout.QuadPart = 0;
    (VOID)FltSendMessage(
        gFilterHandle,
        &gEventClientPort,
        &event,
        sizeof(event),
        NULL,
        NULL,
        &timeout);
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

static BOOLEAN DgIsProtectedPath(_In_ PCUNICODE_STRING Name)
{
    ULONG index;
    BOOLEAN isProtected = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0 &&
            DgPathIsSameOrDescendant(Name, gRoots[index].Path, gRoots[index].Length)) {
            isProtected = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return isProtected;
}

static BOOLEAN DgHasProtectedRoots(VOID)
{
    ULONG index;
    BOOLEAN hasRoots = FALSE;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0) {
            hasRoots = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return hasRoots;
}

static DG_DELETE_OPERATION DgClassifyRename(
    _In_ PCUNICODE_STRING Source,
    _In_ PCUNICODE_STRING Destination,
    _In_ BOOLEAN ReplaceRequested)
{
    ULONG index;
    LONG sourceRoot = -1;
    LONG destinationRoot = -1;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length == 0) {
            continue;
        }

        if (sourceRoot < 0 &&
            DgPathIsSameOrDescendant(Source, gRoots[index].Path, gRoots[index].Length)) {
            sourceRoot = (LONG)index;
        }

        if (destinationRoot < 0 &&
            DgPathIsSameOrDescendant(Destination, gRoots[index].Path, gRoots[index].Length)) {
            destinationRoot = (LONG)index;
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();

    if (sourceRoot >= 0 && sourceRoot != destinationRoot) {
        return DgDeleteOperationRenameOut;
    }

    if (ReplaceRequested && (sourceRoot >= 0 || destinationRoot >= 0)) {
        return DgDeleteOperationRenameReplace;
    }

    return (DG_DELETE_OPERATION)0;
}

static BOOLEAN DgIsProtectedAndGranted(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessStartKey,
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
                gGrants[index].ProcessStartKey != ProcessStartKey ||
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
    DG_CONNECT_CONTEXT context;
    ULONG index;

    UNREFERENCED_PARAMETER(ServerPortCookie);

    if (ConnectionCookie == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ConnectionCookie = NULL;

    if (ConnectionContext == NULL || SizeOfContext < sizeof(context)) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        RtlCopyMemory(&context, ConnectionContext, sizeof(context));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (context.Version != DG_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }

    if (context.Role == DgClientRoleCommand) {
        for (index = 0; index < DG_MAX_COMMAND_CLIENTS; ++index) {
            if (InterlockedCompareExchangePointer(
                    (PVOID volatile *)&gCommandClientPorts[index],
                    ClientPort,
                    NULL) == NULL) {
                *ConnectionCookie = (PVOID)(ULONG_PTR)(DG_CONNECTION_COOKIE_COMMAND_BASE + index);
                return STATUS_SUCCESS;
            }
        }

        return STATUS_DEVICE_BUSY;
    }

    if (context.Role == DgClientRoleEvent) {
        if (InterlockedCompareExchangePointer(
                (PVOID volatile *)&gEventClientPort,
                ClientPort,
                NULL) != NULL) {
            return STATUS_DEVICE_BUSY;
        }

        *ConnectionCookie = (PVOID)(ULONG_PTR)DG_CONNECTION_COOKIE_EVENT;
        return STATUS_SUCCESS;
    }

    return STATUS_INVALID_PARAMETER;
}

static VOID DgPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    ULONG_PTR cookie = (ULONG_PTR)ConnectionCookie;

    if (gFilterHandle == NULL) {
        return;
    }

    if (DgIsCommandCookie(cookie)) {
        ULONG index = (ULONG)(cookie - DG_CONNECTION_COOKIE_COMMAND_BASE);
        if (gCommandClientPorts[index] != NULL) {
            FltCloseClientPort(gFilterHandle, &gCommandClientPorts[index]);
        }
    }
    else if (cookie == DG_CONNECTION_COOKIE_EVENT && gEventClientPort != NULL) {
        FltCloseClientPort(gFilterHandle, &gEventClientPort);
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
    DG_COMMAND commandCopy;
    DG_REPLY reply = { 0 };
    const DG_COMMAND *command = &commandCopy;

    if (!DgIsCommandCookie((ULONG_PTR)PortCookie)) {
        return STATUS_ACCESS_DENIED;
    }

    if (ReturnOutputBufferLength == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(DG_COMMAND)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (((ULONG_PTR)InputBuffer % TYPE_ALIGNMENT(DG_COMMAND)) != 0) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    if (OutputBuffer == NULL || OutputBufferLength < sizeof(DG_REPLY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (((ULONG_PTR)OutputBuffer % TYPE_ALIGNMENT(DG_REPLY)) != 0) {
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    __try {
        RtlCopyMemory(&commandCopy, InputBuffer, sizeof(commandCopy));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

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

    __try {
        RtlCopyMemory(OutputBuffer, &reply, sizeof(reply));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    *ReturnOutputBufferLength = sizeof(reply);
    return STATUS_SUCCESS;
}

static BOOLEAN DgIsCommandCookie(_In_ ULONG_PTR Cookie)
{
    return Cookie >= DG_CONNECTION_COOKIE_COMMAND_BASE &&
        Cookie < (DG_CONNECTION_COOKIE_COMMAND_BASE + DG_MAX_COMMAND_CLIENTS);
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
    PEPROCESS process = NULL;
    USHORT lengthChars;
    ULONG index;
    LONG slot = -1;
    ULONGLONG now;
    ULONGLONG processStartKey;

    status = DgReadCommandPath(Command, &lengthChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (Command->ProcessId == 0 || Command->TtlMilliseconds == 0 || Command->TtlMilliseconds > 30000) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(Command->ProcessId), &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    processStartKey = PsGetProcessStartKey(process);
    ObDereferenceObject(process);
    process = NULL;

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
    gGrants[slot].ProcessStartKey = processStartKey;
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
