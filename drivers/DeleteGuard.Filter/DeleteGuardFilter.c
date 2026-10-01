#include <fltKernel.h>
#include "DeleteGuardFilter.h"

#define DG_MAX_COMMAND_CLIENTS 4
#define DG_CONNECTION_COOKIE_COMMAND_BASE 1u
#define DG_CONNECTION_COOKIE_EVENT 0x100u
#define DG_NAMESPACE_POOL_TAG 'sNgD'

PFLT_FILTER gFilterHandle = NULL;
PFLT_PORT gServerPort = NULL;
PFLT_PORT gCommandClientPorts[DG_MAX_COMMAND_CLIENTS];
PFLT_PORT gEventClientPort = NULL;
EX_PUSH_LOCK gStateLock;
DG_ROOT_ENTRY gRoots[DG_MAX_ROOTS];
DG_GRANT_ENTRY gGrants[DG_MAX_GRANTS];
volatile LONG64 gEventSequence = 0;

typedef struct _DG_NAMESPACE_CAPTURE {
    HANDLE RootDirectory;
    BOOLEAN ReplaceIfExists;
    ULONG FileNameLength;
    PWCHAR FileName;
} DG_NAMESPACE_CAPTURE, *PDG_NAMESPACE_CAPTURE;

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

static BOOLEAN DgCopySetInformationBuffer(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_bytes_(DestinationLength) PVOID Destination,
    _In_ ULONG DestinationLength);
static BOOLEAN DgSetInfoRequestsDelete(_In_ PFLT_CALLBACK_DATA Data);
static BOOLEAN DgSetInfoRequestsNamespaceMutation(_In_ PFLT_CALLBACK_DATA Data);
static NTSTATUS DgCaptureNamespaceRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PDG_NAMESPACE_CAPTURE Capture);
static VOID DgReleaseNamespaceCapture(_Inout_ PDG_NAMESPACE_CAPTURE Capture);
static FLT_PREOP_CALLBACK_STATUS DgEnforceDelete(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ DG_DELETE_OPERATION Operation);
static FLT_PREOP_CALLBACK_STATUS DgEnforceNamespaceMutation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID DgPublishDeniedEvent(
    _In_ PCUNICODE_STRING Name,
    _In_ ULONG ProcessId,
    _In_ DG_DELETE_OPERATION Operation);
static BOOLEAN DgPathIsSameOrDescendant(
    _In_ PCUNICODE_STRING Candidate,
    _In_reads_(RootChars) const WCHAR *Root,
    _In_ USHORT RootChars);
static BOOLEAN DgGetProtectingRoot(
    _In_ PCUNICODE_STRING Name,
    _Out_opt_ PDG_ROOT_ENTRY Root);
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
    UNREFERENCED_PARAMETER(CompletionContext);

    if (DgSetInfoRequestsNamespaceMutation(Data)) {
        return DgEnforceNamespaceMutation(Data, FltObjects);
    }

    if (!DgSetInfoRequestsDelete(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return DgEnforceDelete(Data, DgDeleteOperationDisposition);
}

static BOOLEAN DgCopySetInformationBuffer(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_writes_bytes_(DestinationLength) PVOID Destination,
    _In_ ULONG DestinationLength)
{
    PVOID source;
    ULONG sourceLength;

    if (Data == NULL || Data->Iopb == NULL || Destination == NULL || DestinationLength == 0) {
        return FALSE;
    }

    source = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    sourceLength = Data->Iopb->Parameters.SetFileInformation.Length;
    if (source == NULL || sourceLength < DestinationLength) {
        return FALSE;
    }

    __try {
        if (Data->RequestorMode == UserMode && !FLT_IS_SYSTEM_BUFFER(Data)) {
            ProbeForRead(source, DestinationLength, sizeof(UCHAR));
        }
        RtlCopyMemory(Destination, source, DestinationLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN DgSetInfoRequestsDelete(_In_ PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    if (infoClass == FileDispositionInformation) {
        FILE_DISPOSITION_INFORMATION disposition = { 0 };
        if (!DgCopySetInformationBuffer(Data, &disposition, sizeof(disposition))) {
            return FALSE;
        }
        return disposition.DeleteFile ? TRUE : FALSE;
    }

    if (infoClass == FileDispositionInformationEx) {
        FILE_DISPOSITION_INFORMATION_EX dispositionEx = { 0 };
        if (!DgCopySetInformationBuffer(Data, &dispositionEx, sizeof(dispositionEx))) {
            return FALSE;
        }
        return FlagOn(dispositionEx.Flags, FILE_DISPOSITION_DELETE) ? TRUE : FALSE;
    }

    return FALSE;
}

static BOOLEAN DgSetInfoRequestsNamespaceMutation(_In_ PFLT_CALLBACK_DATA Data)
{
    FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    return infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationBypassAccessCheck ||
        infoClass == FileRenameInformationEx ||
        infoClass == FileRenameInformationExBypassAccessCheck ||
        infoClass == FileLinkInformation ||
        infoClass == FileLinkInformationBypassAccessCheck ||
        infoClass == FileLinkInformationEx ||
        infoClass == FileLinkInformationExBypassAccessCheck;
}

static NTSTATUS DgCaptureNamespaceRequest(
    _In_ PFLT_CALLBACK_DATA Data,
    _Out_ PDG_NAMESPACE_CAPTURE Capture)
{
    FILE_INFORMATION_CLASS infoClass;
    PVOID infoBuffer;
    ULONG bufferLength;
    ULONG headerLength;
    ULONG fileNameLength;
    HANDLE rootDirectory;
    BOOLEAN replaceIfExists;
    PWCHAR sourceFileName;
    PWCHAR fileNameCopy;

    if (Data == NULL || Data->Iopb == NULL || Capture == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(Capture, sizeof(*Capture));
    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    bufferLength = Data->Iopb->Parameters.SetFileInformation.Length;

    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationBypassAccessCheck ||
        infoClass == FileRenameInformationEx ||
        infoClass == FileRenameInformationExBypassAccessCheck) {
        PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)infoBuffer;
        headerLength = FIELD_OFFSET(FILE_RENAME_INFORMATION, FileName);
        if (renameInfo == NULL || bufferLength < headerLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        __try {
            if (Data->RequestorMode == UserMode && !FLT_IS_SYSTEM_BUFFER(Data)) {
                ProbeForRead(renameInfo, headerLength, sizeof(UCHAR));
            }

            rootDirectory = renameInfo->RootDirectory;
            fileNameLength = renameInfo->FileNameLength;
            sourceFileName = renameInfo->FileName;
            if (infoClass == FileRenameInformation || infoClass == FileRenameInformationBypassAccessCheck) {
                replaceIfExists = renameInfo->ReplaceIfExists ? TRUE : FALSE;
            }
            else {
                replaceIfExists = FlagOn(renameInfo->Flags, FILE_RENAME_REPLACE_IF_EXISTS) ? TRUE : FALSE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    else if (infoClass == FileLinkInformation ||
        infoClass == FileLinkInformationBypassAccessCheck ||
        infoClass == FileLinkInformationEx ||
        infoClass == FileLinkInformationExBypassAccessCheck) {
        PFILE_LINK_INFORMATION linkInfo = (PFILE_LINK_INFORMATION)infoBuffer;
        headerLength = FIELD_OFFSET(FILE_LINK_INFORMATION, FileName);
        if (linkInfo == NULL || bufferLength < headerLength) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        __try {
            if (Data->RequestorMode == UserMode && !FLT_IS_SYSTEM_BUFFER(Data)) {
                ProbeForRead(linkInfo, headerLength, sizeof(UCHAR));
            }

            rootDirectory = linkInfo->RootDirectory;
            fileNameLength = linkInfo->FileNameLength;
            sourceFileName = linkInfo->FileName;
            if (infoClass == FileLinkInformation || infoClass == FileLinkInformationBypassAccessCheck) {
                replaceIfExists = linkInfo->ReplaceIfExists ? TRUE : FALSE;
            }
            else {
                replaceIfExists = FlagOn(linkInfo->Flags, FILE_LINK_REPLACE_IF_EXISTS) ? TRUE : FALSE;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    else {
        return STATUS_INVALID_INFO_CLASS;
    }

    if (fileNameLength == 0 ||
        (fileNameLength % sizeof(WCHAR)) != 0 ||
        fileNameLength > (bufferLength - headerLength)) {
        return STATUS_INVALID_PARAMETER;
    }

    fileNameCopy = (PWCHAR)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        fileNameLength,
        DG_NAMESPACE_POOL_TAG);
    if (fileNameCopy == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    __try {
        if (Data->RequestorMode == UserMode && !FLT_IS_SYSTEM_BUFFER(Data)) {
            ProbeForRead(sourceFileName, fileNameLength, sizeof(WCHAR));
        }
        RtlCopyMemory(fileNameCopy, sourceFileName, fileNameLength);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ExFreePoolWithTag(fileNameCopy, DG_NAMESPACE_POOL_TAG);
        return GetExceptionCode();
    }

    Capture->RootDirectory = rootDirectory;
    Capture->ReplaceIfExists = replaceIfExists;
    Capture->FileNameLength = fileNameLength;
    Capture->FileName = fileNameCopy;
    return STATUS_SUCCESS;
}

static VOID DgReleaseNamespaceCapture(_Inout_ PDG_NAMESPACE_CAPTURE Capture)
{
    if (Capture != NULL && Capture->FileName != NULL) {
        ExFreePoolWithTag(Capture->FileName, DG_NAMESPACE_POOL_TAG);
        Capture->FileName = NULL;
        Capture->FileNameLength = 0;
    }
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

static FLT_PREOP_CALLBACK_STATUS DgEnforceNamespaceMutation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION sourceInfo = NULL;
    PFLT_FILE_NAME_INFORMATION destinationInfo = NULL;
    DG_NAMESPACE_CAPTURE namespaceCapture = { 0 };
    DG_ROOT_ENTRY sourceRoot = { 0 };
    BOOLEAN sourceProtected;
    BOOLEAN destinationProtected;
    ULONG processId;

    processId = FltGetRequestorProcessId(Data);

    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &sourceInfo);

    if (!NT_SUCCESS(status)) {
        status = FltGetFileNameInformation(
            Data,
            FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT,
            &sourceInfo);
    }

    if (!NT_SUCCESS(status) || sourceInfo == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    sourceProtected = DgGetProtectingRoot(&sourceInfo->Name, &sourceRoot);

    status = DgCaptureNamespaceRequest(Data, &namespaceCapture);
    if (!NT_SUCCESS(status)) {
        if (sourceProtected) {
            DgPublishDeniedEvent(
                &sourceInfo->Name,
                processId,
                DgDeleteOperationNamespaceMutation);
            FltReleaseFileNameInformation(sourceInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        FltReleaseFileNameInformation(sourceInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!sourceProtected && !namespaceCapture.ReplaceIfExists) {
        DgReleaseNamespaceCapture(&namespaceCapture);
        FltReleaseFileNameInformation(sourceInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (FltObjects == NULL || FltObjects->Instance == NULL || FltObjects->FileObject == NULL) {
        if (sourceProtected) {
            DgPublishDeniedEvent(
                &sourceInfo->Name,
                processId,
                DgDeleteOperationNamespaceMutation);
            DgReleaseNamespaceCapture(&namespaceCapture);
            FltReleaseFileNameInformation(sourceInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        DgReleaseNamespaceCapture(&namespaceCapture);
        FltReleaseFileNameInformation(sourceInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetDestinationFileNameInformation(
        FltObjects->Instance,
        FltObjects->FileObject,
        namespaceCapture.RootDirectory,
        namespaceCapture.FileName,
        namespaceCapture.FileNameLength,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &destinationInfo);

    DgReleaseNamespaceCapture(&namespaceCapture);

    if (!NT_SUCCESS(status) || destinationInfo == NULL) {
        if (sourceProtected) {
            DgPublishDeniedEvent(
                &sourceInfo->Name,
                processId,
                DgDeleteOperationNamespaceMutation);
            FltReleaseFileNameInformation(sourceInfo);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return FLT_PREOP_COMPLETE;
        }

        FltReleaseFileNameInformation(sourceInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    destinationProtected = DgGetProtectingRoot(&destinationInfo->Name, NULL);

    if (sourceProtected &&
        !DgPathIsSameOrDescendant(
            &destinationInfo->Name,
            sourceRoot.Path,
            sourceRoot.Length)) {
        DgPublishDeniedEvent(
            &sourceInfo->Name,
            processId,
            DgDeleteOperationNamespaceMutation);
        FltReleaseFileNameInformation(destinationInfo);
        FltReleaseFileNameInformation(sourceInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    if (namespaceCapture.ReplaceIfExists && destinationProtected) {
        DgPublishDeniedEvent(
            &destinationInfo->Name,
            processId,
            DgDeleteOperationNamespaceMutation);
        FltReleaseFileNameInformation(destinationInfo);
        FltReleaseFileNameInformation(sourceInfo);
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }

    FltReleaseFileNameInformation(destinationInfo);
    FltReleaseFileNameInformation(sourceInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
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

static BOOLEAN DgGetProtectingRoot(
    _In_ PCUNICODE_STRING Name,
    _Out_opt_ PDG_ROOT_ENTRY Root)
{
    ULONG index;
    BOOLEAN found = FALSE;

    if (Root != NULL) {
        RtlZeroMemory(Root, sizeof(*Root));
    }

    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&gStateLock);

    for (index = 0; index < DG_MAX_ROOTS; ++index) {
        if (gRoots[index].Length == 0 ||
            !DgPathIsSameOrDescendant(Name, gRoots[index].Path, gRoots[index].Length)) {
            continue;
        }

        if (Root != NULL) {
            RtlCopyMemory(Root, &gRoots[index], sizeof(*Root));
        }
        found = TRUE;
        break;
    }

    ExReleasePushLockShared(&gStateLock);
    KeLeaveCriticalRegion();
    return found;
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
