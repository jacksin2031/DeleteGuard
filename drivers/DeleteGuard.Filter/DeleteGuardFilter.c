#include <fltKernel.h>
#include "DeleteGuardFilter.h"

#define DG_MAX_COMMAND_CLIENTS 4
#define DG_CONNECTION_COOKIE_COMMAND_BASE 1u
#define DG_CONNECTION_COOKIE_EVENT 0x100u
#define DG_RENAME_BUFFER_TAG 'nRgD'
#define DG_RENAME_CONTEXT_TAG 'cRgD'

typedef struct _DG_RENAME_COMPLETION_CONTEXT {
    PFLT_FILE_NAME_INFORMATION SourceNameInfo;
    PFLT_FILE_NAME_INFORMATION DestinationNameInfo;
} DG_RENAME_COMPLETION_CONTEXT, *PDG_RENAME_COMPLETION_CONTEXT;

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
static FLT_POSTOP_CALLBACK_STATUS DgPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);
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
static BOOLEAN DgSetInfoRequestsRename(_In_ PFLT_CALLBACK_DATA Data);
static BOOLEAN DgSetInfoRequestsLink(_In_ PFLT_CALLBACK_DATA Data);
static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ DG_DELETE_OPERATION Operation);
static FLT_PREOP_CALLBACK_STATUS DgEnforceRename(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_PREOP_CALLBACK_STATUS DgEnforceLink(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);
static FLT_PREOP_CALLBACK_STATUS DgAllowRenameWithNameLifecycle(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
    _In_opt_ PFLT_FILE_NAME_INFORMATION SourceInfo,
    _In_ BOOLEAN SourceNormalized,
    _In_opt_ PFLT_FILE_NAME_INFORMATION DestinationInfo,
    _In_ BOOLEAN DestinationNormalized);
static VOID DgPublishDeniedEvent(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ DG_EVENT_TYPE EventType,
    _In_ DG_DELETE_OPERATION Operation);
static BOOLEAN DgPathIsSameOrDescendant(
    _In_ PCUNICODE_STRING Candidate,
    _In_reads_(RootChars) const WCHAR *Root,
    _In_ USHORT RootChars);
static BOOLEAN DgIsProtectedPath(_In_ PCUNICODE_STRING Name);
static BOOLEAN DgPathContainsProtectedRoot(_In_ PCUNICODE_STRING Name);
static BOOLEAN DgHasProtectedRoots(VOID);

typedef enum _DG_DELETE_DECISION {
    DgDecisionNotProtected = 0,
    DgDecisionAllow,
    DgDecisionDenyFull,
    DgDecisionDenyBulk
} DG_DELETE_DECISION;

static DG_DELETE_DECISION DgDecideDelete(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessStartKey,
    _Out_writes_(DG_MAX_PATH_CHARS + 1) PWCHAR RootPathCopy,
    _Out_ PUSHORT RootPathChars,
    _Out_ PBOOLEAN Notify);
static NTSTATUS DgReadCommandPath(_In_ const DG_COMMAND *Command, _Out_ PUSHORT LengthChars);
static NTSTATUS DgAddRoot(_In_ const DG_COMMAND *Command, _In_ ULONG Mode);
static ULONG DgFullRootCountLocked(VOID);
static NTSTATUS DgRemoveRoot(_In_ const DG_COMMAND *Command);
static NTSTATUS DgGrant(_In_ const DG_COMMAND *Command);
static NTSTATUS DgRevoke(_In_ const DG_COMMAND *Command);
static ULONG DgRootCountLocked(VOID);
static BOOLEAN DgIsCommandCookie(_In_ ULONG_PTR Cookie);

CONST FLT_OPERATION_REGISTRATION gCallbacks[] = {
    { IRP_MJ_CREATE, 0, DgPreCreate, NULL },
    { IRP_MJ_SET_INFORMATION, 0, DgPreSetInformation, DgPostSetInformation },
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
    if (DgSetInfoRequestsDelete(Data)) {
        return DgEnforceDelete(Data, DgDeleteOperationDisposition);
    }

    if (DgSetInfoRequestsRename(Data)) {
        return DgEnforceRename(Data, FltObjects, CompletionContext);
    }

    if (DgSetInfoRequestsLink(Data)) {
        return DgEnforceLink(Data, FltObjects, CompletionContext);
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_POSTOP_CALLBACK_STATUS DgPostSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    PDG_RENAME_COMPLETION_CONTEXT context = (PDG_RENAME_COMPLETION_CONTEXT)CompletionContext;
    PFLT_FILE_NAME_INFORMATION tunneled = NULL;

    UNREFERENCED_PARAMETER(FltObjects);

    if (context == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (!FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) && NT_SUCCESS(Data->IoStatus.Status)) {
        if (context->SourceNameInfo != NULL) {
            tunneled = NULL;
            (VOID)FltGetTunneledName(Data, context->SourceNameInfo, &tunneled);
            if (tunneled != NULL) {
                FltReleaseFileNameInformation(tunneled);
            }
        }

        if (context->DestinationNameInfo != NULL) {
            tunneled = NULL;
            (VOID)FltGetTunneledName(Data, context->DestinationNameInfo, &tunneled);
            if (tunneled != NULL) {
                FltReleaseFileNameInformation(tunneled);
            }
        }
    }

    if (context->DestinationNameInfo != NULL) {
        FltReleaseFileNameInformation(context->DestinationNameInfo);
    }
    if (context->SourceNameInfo != NULL) {
        FltReleaseFileNameInformation(context->SourceNameInfo);
    }
    ExFreePool(context);

    return FLT_POSTOP_FINISHED_PROCESSING;
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

static BOOLEAN DgSetInfoRequestsRename(_In_ PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    return infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx ||
        infoClass == FileRenameInformationBypassAccessCheck ||
        infoClass == FileRenameInformationExBypassAccessCheck;
}

static BOOLEAN DgSetInfoRequestsLink(_In_ PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    return infoClass == FileLinkInformation ||
        infoClass == FileLinkInformationEx ||
        infoClass == FileLinkInformationBypassAccessCheck ||
        infoClass == FileLinkInformationExBypassAccessCheck;
}

static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ DG_DELETE_OPERATION Operation)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PEPROCESS requestorProcess;
    DG_DELETE_DECISION decision;
    WCHAR rootPathCopy[DG_MAX_PATH_CHARS + 1];
    USHORT rootPathChars = 0;
    BOOLEAN notify = FALSE;
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

    decision = DgDecideDelete(
        &nameInfo->Name,
        processId,
        processStartKey,
        rootPathCopy,
        &rootPathChars,
        &notify);
    if (decision == DgDecisionNotProtected || decision == DgDecisionAllow) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (decision == DgDecisionDenyBulk) {
        /* Report the protected folder (not each file) and only when the limiter says so, so a wipe
           attempting millions of deletes cannot flood the event channel. */
        if (notify) {
            UNICODE_STRING rootName;
            rootName.Buffer = rootPathCopy;
            rootName.Length = (USHORT)(rootPathChars * sizeof(WCHAR));
            rootName.MaximumLength = rootName.Length;
            DgPublishDeniedEvent(&rootName, processId, DgEventDeleteDenied, DgDeleteOperationBulkDelete);
        }
    }
    else {
        DgPublishDeniedEvent(&nameInfo->Name, processId, DgEventDeleteDenied, Operation);
    }

    FltReleaseFileNameInformation(nameInfo);

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

static FLT_PREOP_CALLBACK_STATUS DgAllowRenameWithNameLifecycle(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext,
    _In_opt_ PFLT_FILE_NAME_INFORMATION SourceInfo,
    _In_ BOOLEAN SourceNormalized,
    _In_opt_ PFLT_FILE_NAME_INFORMATION DestinationInfo,
    _In_ BOOLEAN DestinationNormalized)
{
    PDG_RENAME_COMPLETION_CONTEXT context;

    if (!SourceNormalized && !DestinationNormalized) {
        if (DestinationInfo != NULL) {
            FltReleaseFileNameInformation(DestinationInfo);
        }
        if (SourceInfo != NULL) {
            FltReleaseFileNameInformation(SourceInfo);
        }
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    context = (PDG_RENAME_COMPLETION_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DG_RENAME_COMPLETION_CONTEXT),
        DG_RENAME_CONTEXT_TAG);
    if (context == NULL) {
        if (DestinationInfo != NULL) {
            FltReleaseFileNameInformation(DestinationInfo);
        }
        if (SourceInfo != NULL) {
            FltReleaseFileNameInformation(SourceInfo);
        }
        Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    RtlZeroMemory(context, sizeof(*context));
    if (SourceNormalized) {
        context->SourceNameInfo = SourceInfo;
    }
    else if (SourceInfo != NULL) {
        FltReleaseFileNameInformation(SourceInfo);
    }

    if (DestinationNormalized) {
        context->DestinationNameInfo = DestinationInfo;
    }
    else if (DestinationInfo != NULL) {
        FltReleaseFileNameInformation(DestinationInfo);
    }

    *CompletionContext = context;
    return FLT_PREOP_SYNCHRONIZE;
}

static FLT_PREOP_CALLBACK_STATUS DgEnforceRename(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PFILE_RENAME_INFORMATION renameInfo;
    PFLT_FILE_NAME_INFORMATION sourceInfo = NULL;
    PFLT_FILE_NAME_INFORMATION destinationInfo = NULL;
    PWSTR destinationName = NULL;
    HANDLE rootDirectory = NULL;
    ULONG destinationNameLength = 0;
    ULONG inputLength;
    ULONG minimumLength;
    ULONG processId;
    BOOLEAN sourceProtected;
    BOOLEAN sourceContainsProtectedRoot;
    BOOLEAN destinationProtected;
    BOOLEAN replaceIfExists = FALSE;
    BOOLEAN sourceNormalized = FALSE;
    BOOLEAN destinationNormalized = FALSE;
    NTSTATUS status;

    if (CompletionContext == NULL || FltObjects == NULL || FltObjects->Instance == NULL || Data->Iopb->TargetFileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    *CompletionContext = NULL;

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    inputLength = Data->Iopb->Parameters.SetFileInformation.Length;
    minimumLength = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);

    if (renameInfo == NULL || inputLength < minimumLength) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        rootDirectory = renameInfo->RootDirectory;
        destinationNameLength = renameInfo->FileNameLength;
        replaceIfExists = (infoClass == FileRenameInformation || infoClass == FileRenameInformationBypassAccessCheck)
            ? (renameInfo->ReplaceIfExists ? TRUE : FALSE)
            : (FlagOn(renameInfo->Flags, FILE_RENAME_REPLACE_IF_EXISTS) ? TRUE : FALSE);

        if (destinationNameLength == 0 ||
            (destinationNameLength % sizeof(WCHAR)) != 0 ||
            destinationNameLength > inputLength - minimumLength) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        destinationName = (PWSTR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            destinationNameLength,
            DG_RENAME_BUFFER_TAG);
        if (destinationName == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        RtlCopyMemory(destinationName, renameInfo->FileName, destinationNameLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (destinationName != NULL) {
            ExFreePool(destinationName);
        }
        Data->IoStatus.Status = GetExceptionCode();
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    processId = FltGetRequestorProcessId(Data);

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &sourceInfo);
    if (NT_SUCCESS(status) && sourceInfo != NULL) {
        sourceNormalized = TRUE;
    }
    else {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &sourceInfo);
    }

    if (!NT_SUCCESS(status) || sourceInfo == NULL) {
        ExFreePool(destinationName);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    sourceProtected = DgIsProtectedPath(&sourceInfo->Name);
    sourceContainsProtectedRoot = DgPathContainsProtectedRoot(&sourceInfo->Name);

    if (sourceContainsProtectedRoot) {
        DgPublishDeniedEvent(
            &sourceInfo->Name,
            processId,
            DgEventRenameDenied,
            DgDeleteOperationRenameProtectedAncestor);
        FltReleaseFileNameInformation(sourceInfo);
        ExFreePool(destinationName);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (!sourceProtected && !replaceIfExists) {
        ExFreePool(destinationName);
        return DgAllowRenameWithNameLifecycle(
            Data,
            CompletionContext,
            sourceInfo,
            sourceNormalized,
            NULL,
            FALSE);
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        rootDirectory,
        destinationName,
        destinationNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationInfo);

    ExFreePool(destinationName);
    destinationName = NULL;

    if (NT_SUCCESS(status) && destinationInfo != NULL) {
        destinationNormalized = TRUE;
    }
    else {
        if (sourceProtected || (replaceIfExists && DgHasProtectedRoots())) {
            DgPublishDeniedEvent(
                &sourceInfo->Name,
                processId,
                DgEventRenameDenied,
                sourceProtected ? DgDeleteOperationMoveOut : DgDeleteOperationReplaceProtectedDestination);
            FltReleaseFileNameInformation(sourceInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        return DgAllowRenameWithNameLifecycle(
            Data,
            CompletionContext,
            sourceInfo,
            sourceNormalized,
            NULL,
            FALSE);
    }

    destinationProtected = DgIsProtectedPath(&destinationInfo->Name);

    if (replaceIfExists && destinationProtected) {
        DgPublishDeniedEvent(
            &destinationInfo->Name,
            processId,
            DgEventRenameDenied,
            DgDeleteOperationReplaceProtectedDestination);
        FltReleaseFileNameInformation(destinationInfo);
        FltReleaseFileNameInformation(sourceInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (sourceProtected && !destinationProtected) {
        DgPublishDeniedEvent(
            &sourceInfo->Name,
            processId,
            DgEventRenameDenied,
            DgDeleteOperationMoveOut);
        FltReleaseFileNameInformation(destinationInfo);
        FltReleaseFileNameInformation(sourceInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return DgAllowRenameWithNameLifecycle(
        Data,
        CompletionContext,
        sourceInfo,
        sourceNormalized,
        destinationInfo,
        destinationNormalized);
}

static FLT_PREOP_CALLBACK_STATUS DgEnforceLink(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PFILE_LINK_INFORMATION linkInfo;
    PFLT_FILE_NAME_INFORMATION sourceInfo = NULL;
    PFLT_FILE_NAME_INFORMATION destinationInfo = NULL;
    PWSTR destinationName = NULL;
    HANDLE rootDirectory = NULL;
    ULONG destinationNameLength = 0;
    ULONG inputLength;
    ULONG minimumLength;
    ULONG processId;
    BOOLEAN sourceProtected;
    BOOLEAN destinationProtected;
    BOOLEAN replaceIfExists = FALSE;
    BOOLEAN sourceNormalized = FALSE;
    BOOLEAN destinationNormalized = FALSE;
    NTSTATUS status;

    if (CompletionContext == NULL || FltObjects == NULL || FltObjects->Instance == NULL || Data->Iopb->TargetFileObject == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    *CompletionContext = NULL;

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    linkInfo = (PFILE_LINK_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    inputLength = Data->Iopb->Parameters.SetFileInformation.Length;
    minimumLength = FIELD_OFFSET(FILE_LINK_INFORMATION, FileName);

    if (linkInfo == NULL || inputLength < minimumLength) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    __try {
        rootDirectory = linkInfo->RootDirectory;
        destinationNameLength = linkInfo->FileNameLength;
        replaceIfExists = (infoClass == FileLinkInformation || infoClass == FileLinkInformationBypassAccessCheck)
            ? (linkInfo->ReplaceIfExists ? TRUE : FALSE)
            : (FlagOn(linkInfo->Flags, FILE_LINK_REPLACE_IF_EXISTS) ? TRUE : FALSE);

        if (destinationNameLength == 0 ||
            (destinationNameLength % sizeof(WCHAR)) != 0 ||
            destinationNameLength > inputLength - minimumLength) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        destinationName = (PWSTR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            destinationNameLength,
            DG_RENAME_BUFFER_TAG);
        if (destinationName == NULL) {
            Data->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        RtlCopyMemory(destinationName, linkInfo->FileName, destinationNameLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (destinationName != NULL) {
            ExFreePool(destinationName);
        }
        Data->IoStatus.Status = GetExceptionCode();
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    processId = FltGetRequestorProcessId(Data);

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &sourceInfo);
    if (NT_SUCCESS(status) && sourceInfo != NULL) {
        sourceNormalized = TRUE;
    }
    else {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &sourceInfo);
    }

    if (!NT_SUCCESS(status) || sourceInfo == NULL) {
        ExFreePool(destinationName);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    sourceProtected = DgIsProtectedPath(&sourceInfo->Name);
    if (!sourceProtected && !replaceIfExists) {
        ExFreePool(destinationName);
        return DgAllowRenameWithNameLifecycle(
            Data,
            CompletionContext,
            sourceInfo,
            sourceNormalized,
            NULL,
            FALSE);
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        Data->Iopb->TargetFileObject,
        rootDirectory,
        destinationName,
        destinationNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationInfo);

    ExFreePool(destinationName);
    destinationName = NULL;

    if (NT_SUCCESS(status) && destinationInfo != NULL) {
        destinationNormalized = TRUE;
    }
    else {
        if (sourceProtected || (replaceIfExists && DgHasProtectedRoots())) {
            DgPublishDeniedEvent(
                &sourceInfo->Name,
                processId,
                DgEventHardLinkDenied,
                sourceProtected ? DgDeleteOperationHardLinkOut : DgDeleteOperationReplaceProtectedLinkDestination);
            FltReleaseFileNameInformation(sourceInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        return DgAllowRenameWithNameLifecycle(
            Data,
            CompletionContext,
            sourceInfo,
            sourceNormalized,
            NULL,
            FALSE);
    }

    destinationProtected = DgIsProtectedPath(&destinationInfo->Name);

    if (replaceIfExists && destinationProtected) {
        DgPublishDeniedEvent(
            &destinationInfo->Name,
            processId,
            DgEventHardLinkDenied,
            DgDeleteOperationReplaceProtectedLinkDestination);
        FltReleaseFileNameInformation(destinationInfo);
        FltReleaseFileNameInformation(sourceInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (sourceProtected && !destinationProtected) {
        DgPublishDeniedEvent(
            &sourceInfo->Name,
            processId,
            DgEventHardLinkDenied,
            DgDeleteOperationHardLinkOut);
        FltReleaseFileNameInformation(destinationInfo);
        FltReleaseFileNameInformation(sourceInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    return DgAllowRenameWithNameLifecycle(
        Data,
        CompletionContext,
        sourceInfo,
        sourceNormalized,
        destinationInfo,
        destinationNormalized);
}
static VOID DgPublishDeniedEvent(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ DG_EVENT_TYPE EventType,
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
    event.Type = EventType;
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

    /* Bulk-guard roots deliberately do not take part in the rename/link gates: normal renames and
       moves in such a folder must keep working. */
    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0 &&
            gRoots[index].Mode == DG_ROOT_MODE_FULL &&
            DgPathIsSameOrDescendant(Name, gRoots[index].Path, gRoots[index].Length)) {
            isProtected = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return isProtected;
}

static BOOLEAN DgPathContainsProtectedRoot(_In_ PCUNICODE_STRING Name)
{
    ULONG index;
    USHORT nameChars;
    BOOLEAN containsRoot = FALSE;

    if (Name == NULL || Name->Buffer == NULL || Name->Length == 0) {
        return FALSE;
    }

    nameChars = (USHORT)(Name->Length / sizeof(WCHAR));

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        UNICODE_STRING protectedRoot;

        if (gRoots[index].Length == 0) {
            continue;
        }

        protectedRoot.Buffer = gRoots[index].Path;
        protectedRoot.Length = (USHORT)(gRoots[index].Length * sizeof(WCHAR));
        protectedRoot.MaximumLength = protectedRoot.Length;

        if (DgPathIsSameOrDescendant(&protectedRoot, Name->Buffer, nameChars)) {
            containsRoot = TRUE;
            break;
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return containsRoot;
}

static BOOLEAN DgHasProtectedRoots(VOID)
{
    BOOLEAN hasRoots;

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);
    hasRoots = DgFullRootCountLocked() != 0;
    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return hasRoots;
}

static DG_DELETE_DECISION DgDecideDelete(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ProcessStartKey,
    _Out_writes_(DG_MAX_PATH_CHARS + 1) PWCHAR RootPathCopy,
    _Out_ PUSHORT RootPathChars,
    _Out_ PBOOLEAN Notify)
{
    ULONG index;
    LONG rootIndex = -1;
    ULONGLONG now = KeQueryInterruptTime();
    BOOLEAN granted = FALSE;
    DG_DELETE_DECISION decision = DgDecisionNotProtected;

    *RootPathChars = 0;
    *Notify = FALSE;
    RootPathCopy[0] = L'\0';

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0 &&
            DgPathIsSameOrDescendant(Name, gRoots[index].Path, gRoots[index].Length)) {
            rootIndex = (LONG)index;
            break;
        }
    }

    if (rootIndex >= 0) {
        for (index = 0; index < DG_MAX_GRANTS; ++index) {
            if (gGrants[index].Length == 0 ||
                gGrants[index].ProcessId != ProcessId ||
                gGrants[index].ProcessStartKey != ProcessStartKey ||
                gGrants[index].ExpiresAt100ns <= now) {
                continue;
            }

            if (DgPathIsSameOrDescendant(Name, gGrants[index].Path, gGrants[index].Length)) {
                granted = TRUE;
                break;
            }
        }

        if (granted) {
            /* An approved Broker deletion is never counted against the bulk limit. */
            decision = DgDecisionAllow;
        }
        else if (gRoots[rootIndex].Mode == DG_ROOT_MODE_BULK) {
            KIRQL oldIrql;
            BOOLEAN allowed;

            KeAcquireSpinLock(&gRoots[rootIndex].BulkLock, &oldIrql);
            allowed = DgBulkAllow(&gRoots[rootIndex].Bulk, now, Notify);
            KeReleaseSpinLock(&gRoots[rootIndex].BulkLock, oldIrql);

            if (allowed) {
                decision = DgDecisionAllow;
            }
            else {
                decision = DgDecisionDenyBulk;
                *RootPathChars = gRoots[rootIndex].Length;
                RtlCopyMemory(RootPathCopy, gRoots[rootIndex].Path, gRoots[rootIndex].Length * sizeof(WCHAR));
                RootPathCopy[gRoots[rootIndex].Length] = L'\0';
            }
        }
        else {
            decision = DgDecisionDenyFull;
        }
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return decision;
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
        status = DgAddRoot(command, DG_ROOT_MODE_FULL);
        break;

    case DgCommandAddBulkGuardRoot:
        status = DgAddRoot(command, DG_ROOT_MODE_BULK);
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

static NTSTATUS DgAddRoot(_In_ const DG_COMMAND *Command, _In_ ULONG Mode)
{
    NTSTATUS status;
    USHORT lengthChars;
    ULONG index;
    LONG freeIndex = -1;
    UNICODE_STRING commandPath;
    DG_BULK_STATE bulk;

    status = DgReadCommandPath(Command, &lengthChars);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlZeroMemory(&bulk, sizeof(bulk));
    if (Mode == DG_ROOT_MODE_BULK &&
        !DgBulkConfigure(&bulk, Command->ProcessId, Command->TtlMilliseconds)) {
        return STATUS_INVALID_PARAMETER;
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

    RtlZeroMemory(&gRoots[freeIndex], sizeof(gRoots[freeIndex]));
    KeInitializeSpinLock(&gRoots[freeIndex].BulkLock);
    gRoots[freeIndex].Mode = Mode;
    gRoots[freeIndex].Bulk = bulk;
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

static ULONG DgFullRootCountLocked(VOID)
{
    ULONG index;
    ULONG count = 0;

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length != 0 && gRoots[index].Mode == DG_ROOT_MODE_FULL) {
            ++count;
        }
    }

    return count;
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
