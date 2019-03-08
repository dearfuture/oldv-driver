#include <ntddk.h>
#include <tdikrnl.h>
#include <ntverp.h>
#include "ktdi.h"

NTSTATUS tdi_open_transport_address(PUNICODE_STRING devName, ULONG addr, USHORT port, BOOLEAN shared, PHANDLE addressHandle, PFILE_OBJECT *addressFileObject)
{
    OBJECT_ATTRIBUTES           attr;
    PFILE_FULL_EA_INFORMATION   eaBuffer;
    ULONG                       eaSize;
    PTA_IP_ADDRESS              localAddr;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

#if (VER_PRODUCTBUILD >= 2195)
    InitializeObjectAttributes(&attr, devName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
#else
    InitializeObjectAttributes(&attr, devName, OBJ_CASE_INSENSITIVE, NULL, NULL);
#endif

    eaSize = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName[0]) +
             TDI_TRANSPORT_ADDRESS_LENGTH                      +
             1                                                 +
             sizeof(TA_IP_ADDRESS);

    eaBuffer = (PFILE_FULL_EA_INFORMATION) ExAllocatePool(PagedPool, eaSize);

    if (eaBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    eaBuffer->NextEntryOffset = 0;
    eaBuffer->Flags = 0;
    eaBuffer->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH;
    eaBuffer->EaValueLength = sizeof(TA_IP_ADDRESS);

    RtlCopyMemory(eaBuffer->EaName, TdiTransportAddress, eaBuffer->EaNameLength + 1);

    localAddr = (PTA_IP_ADDRESS)(eaBuffer->EaName + eaBuffer->EaNameLength + 1);

    localAddr->TAAddressCount = 1;
    localAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    localAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    localAddr->Address[0].Address[0].sin_port = port;
    localAddr->Address[0].Address[0].in_addr = addr;

    RtlZeroMemory(localAddr->Address[0].Address[0].sin_zero, sizeof(localAddr->Address[0].Address[0].sin_zero));

    status = ZwCreateFile(
        addressHandle,
        GENERIC_READ | GENERIC_WRITE,
        &attr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        shared ? FILE_SHARE_READ | FILE_SHARE_WRITE : 0,
        FILE_OPEN,
        0,
        eaBuffer,
        eaSize
        );

    ExFreePool(eaBuffer);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByHandle(*addressHandle, FILE_ALL_ACCESS, NULL, KernelMode, addressFileObject, NULL);

    if (!NT_SUCCESS(status))
    {
        ZwClose(*addressHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS tdi_open_connection_endpoint(PUNICODE_STRING devName, PVOID connectionContext, BOOLEAN shared, PHANDLE connectionHandle, PFILE_OBJECT *connectionFileObject)
{
    OBJECT_ATTRIBUTES           attr;
    PFILE_FULL_EA_INFORMATION   eaBuffer;
    ULONG                       eaSize;
    PVOID                       *context;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

#if (VER_PRODUCTBUILD >= 2195)
    InitializeObjectAttributes(&attr, devName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
#else
    InitializeObjectAttributes(&attr, devName, OBJ_CASE_INSENSITIVE, NULL, NULL);
#endif

    eaSize = FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName[0]) +
             TDI_CONNECTION_CONTEXT_LENGTH                     +
             1                                                 +
             sizeof(PVOID);

    eaBuffer = (PFILE_FULL_EA_INFORMATION) ExAllocatePool(PagedPool, eaSize);

    if (eaBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    eaBuffer->NextEntryOffset = 0;
    eaBuffer->Flags = 0;
    eaBuffer->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH;
    eaBuffer->EaValueLength = sizeof(PVOID);

    RtlCopyMemory(eaBuffer->EaName, TdiConnectionContext, eaBuffer->EaNameLength + 1);

    context = (PVOID*) &(eaBuffer->EaName[eaBuffer->EaNameLength + 1]);

    *context = connectionContext;

    status = ZwCreateFile(
        connectionHandle,
        GENERIC_READ | GENERIC_WRITE,
        &attr,
        &iosb,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        shared ? FILE_SHARE_READ | FILE_SHARE_WRITE : 0,
        FILE_OPEN,
        0,
        eaBuffer,
        eaSize
        );

    ExFreePool(eaBuffer);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByHandle(*connectionHandle, FILE_ALL_ACCESS, NULL, KernelMode, connectionFileObject, NULL);

    if (!NT_SUCCESS(status))
    {
        ZwClose(*connectionHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS tdi_set_event_handler(PFILE_OBJECT addressFileObject, LONG eventType, PVOID eventHandler, PVOID eventContext)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(addressFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER, devObj, addressFileObject, &event, &iosb);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }


	TdiBuildSetEventHandler(irp, devObj, addressFileObject, NULL, NULL, eventType, eventHandler, eventContext);
	
    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

NTSTATUS tdi_unset_event_handler(PFILE_OBJECT addressFileObject, LONG eventType)
{
    return tdi_set_event_handler(addressFileObject, eventType, NULL, NULL);
}

NTSTATUS tdi_associate_address(PFILE_OBJECT connectionFileObject, HANDLE addressHandle)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = TdiBuildInternalDeviceControlIrp(TDI_ASSOCIATE_ADDRESS, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildAssociateAddress(irp, devObj, connectionFileObject, NULL, NULL, addressHandle);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

NTSTATUS tdi_disassociate_address(PFILE_OBJECT connectionFileObject)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = TdiBuildInternalDeviceControlIrp(TDI_DISASSOCIATE_ADDRESS, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildDisassociateAddress(irp, devObj, connectionFileObject, NULL, NULL);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

NTSTATUS tdi_connect(PFILE_OBJECT connectionFileObject, ULONG addr, USHORT port)
{
    PDEVICE_OBJECT              devObj;
    KEVENT                      event;
    PTDI_CONNECTION_INFORMATION remoteInfo;
    PTA_IP_ADDRESS              remoteAddr;
    PTDI_CONNECTION_INFORMATION returnInfo;
    PTA_IP_ADDRESS              returnAddr;
    PIRP                        irp;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, 2 * sizeof(TDI_CONNECTION_INFORMATION) + 2 * sizeof(TA_IP_ADDRESS));

    if (remoteInfo == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(remoteInfo, 2 * sizeof(TDI_CONNECTION_INFORMATION) + 2 * sizeof(TA_IP_ADDRESS));

    remoteInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    remoteInfo->RemoteAddress = (PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION);

    remoteAddr = (PTA_IP_ADDRESS) remoteInfo->RemoteAddress;

    remoteAddr->TAAddressCount = 1;
    remoteAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    remoteAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    remoteAddr->Address[0].Address[0].sin_port = port;
    remoteAddr->Address[0].Address[0].in_addr = addr;

    returnInfo = (PTDI_CONNECTION_INFORMATION)((PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    returnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    returnInfo->RemoteAddress = (PUCHAR)returnInfo + sizeof(TDI_CONNECTION_INFORMATION);

    returnAddr = (PTA_IP_ADDRESS) returnInfo->RemoteAddress;

    returnAddr->TAAddressCount = 1;
    returnAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    returnAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

    irp = TdiBuildInternalDeviceControlIrp(TDI_CONNECT, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        ExFreePool(remoteInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildConnect(irp, devObj, connectionFileObject, NULL, NULL, NULL, remoteInfo, returnInfo);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    ExFreePool(remoteInfo);

    return status;
}

NTSTATUS tdi_disconnect(PFILE_OBJECT connectionFileObject, ULONG flags)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = TdiBuildInternalDeviceControlIrp(TDI_DISCONNECT, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildDisconnect(irp, devObj, connectionFileObject, NULL, NULL, NULL, flags, NULL, NULL);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return status;
}

NTSTATUS tdi_listen(PFILE_OBJECT connectionFileObject, PULONG addr, PUSHORT port)
{
    PDEVICE_OBJECT              devObj;
    KEVENT                      event;
    PTDI_CONNECTION_INFORMATION remoteInfo;
    ULONG                       options;
    PTDI_CONNECTION_INFORMATION returnInfo;
    PTA_IP_ADDRESS              returnAddr;
    PIRP                        irp;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, 2 * sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    if (remoteInfo == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(remoteInfo, 2 * sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    options = 0;

    remoteInfo->Options = &options;
    remoteInfo->OptionsLength = sizeof(ULONG);
    remoteInfo->RemoteAddressLength = 0;
    remoteInfo->RemoteAddress = NULL;

    returnInfo = (PTDI_CONNECTION_INFORMATION)((PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION));

    returnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    returnInfo->RemoteAddress = (PUCHAR)returnInfo + sizeof(TDI_CONNECTION_INFORMATION);

    returnAddr = (PTA_IP_ADDRESS) returnInfo->RemoteAddress;

    returnAddr->TAAddressCount = 1;
    returnAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    returnAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

    irp = TdiBuildInternalDeviceControlIrp(TDI_LISTEN, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        ExFreePool(remoteInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    TdiBuildListen(irp, devObj, connectionFileObject, NULL, NULL, 0, remoteInfo, returnInfo);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    if (addr)
    {
        *addr = returnAddr->Address[0].Address[0].in_addr;
    }

    if (port)
    {
        *port = returnAddr->Address[0].Address[0].sin_port;
    }

    ExFreePool(remoteInfo);

    return status;
}

NTSTATUS tdi_send_dgram(PFILE_OBJECT addressFileObject, ULONG addr, USHORT port, const char *buf, int len)
{
    PDEVICE_OBJECT              devObj;
    KEVENT                      event;
    PTDI_CONNECTION_INFORMATION remoteInfo;
    PTA_IP_ADDRESS              remoteAddr;
    PIRP                        irp;
    PMDL                        mdl=NULL;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

    devObj = IoGetRelatedDeviceObject(addressFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    if (remoteInfo == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(remoteInfo, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    remoteInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    remoteInfo->RemoteAddress = (PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION);

    remoteAddr = (PTA_IP_ADDRESS) remoteInfo->RemoteAddress;

    remoteAddr->TAAddressCount = 1;
    remoteAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    remoteAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    remoteAddr->Address[0].Address[0].sin_port = port;
    remoteAddr->Address[0].Address[0].in_addr = addr;

    irp = TdiBuildInternalDeviceControlIrp(TDI_SEND_DATAGRAM, devObj, addressFileObject, &event, &iosb);

    if (irp == NULL)
    {
        ExFreePool(remoteInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (len)
    {
        mdl = IoAllocateMdl((void*) buf, len, FALSE, FALSE, NULL);

        if (mdl == NULL)
        {
            IoFreeIrp(irp);
            ExFreePool(remoteInfo);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            IoFreeIrp(irp);
            ExFreePool(remoteInfo);
            status = STATUS_INVALID_USER_BUFFER;
        }

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    TdiBuildSendDatagram(irp, devObj, addressFileObject, NULL, NULL, len ? mdl : 0, len, remoteInfo);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    ExFreePool(remoteInfo);

    return NT_SUCCESS(status) ? (ULONG) iosb.Information : status;
}

NTSTATUS tdi_recv_dgram(PFILE_OBJECT addressFileObject, PULONG addr, PUSHORT port, char *buf, int len, ULONG flags)
{
    PDEVICE_OBJECT              devObj;
    KEVENT                      event;
    PTDI_CONNECTION_INFORMATION remoteInfo;
    PTDI_CONNECTION_INFORMATION returnInfo;
    PTA_IP_ADDRESS              returnAddr;
    PIRP                        irp;
	PMDL                        mdl = NULL;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

    devObj = IoGetRelatedDeviceObject(addressFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, 2 * sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    if (remoteInfo == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(remoteInfo, 2 * sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    remoteInfo->RemoteAddressLength = 0;
    remoteInfo->RemoteAddress = NULL;

    returnInfo = (PTDI_CONNECTION_INFORMATION)((PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION));

    returnInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    returnInfo->RemoteAddress = (PUCHAR)returnInfo + sizeof(TDI_CONNECTION_INFORMATION);

    returnAddr = (PTA_IP_ADDRESS) returnInfo->RemoteAddress;

    returnAddr->TAAddressCount = 1;
    returnAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    returnAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;

    irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE_DATAGRAM, devObj, addressFileObject, &event, &iosb);

    if (irp == NULL)
    {
        ExFreePool(remoteInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (len)
    {
        mdl = IoAllocateMdl((void*) buf, len, FALSE, FALSE, NULL);

        if (mdl == NULL)
        {
            IoFreeIrp(irp);
            ExFreePool(remoteInfo);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            IoFreeIrp(irp);
            ExFreePool(remoteInfo);
            status = STATUS_INVALID_USER_BUFFER;
        }

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    TdiBuildReceiveDatagram(irp, devObj, addressFileObject, NULL, NULL, len ? mdl : 0, len, remoteInfo, returnInfo, flags);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    if (addr)
    {
        *addr = returnAddr->Address[0].Address[0].in_addr;
    }

    if (port)
    {
        *port = returnAddr->Address[0].Address[0].sin_port;
    }

    ExFreePool(remoteInfo);

    return NT_SUCCESS(status) ? (ULONG) iosb.Information : status;
}

NTSTATUS tdi_send_stream(PFILE_OBJECT connectionFileObject, const char *buf, int len, ULONG flags)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    PMDL            mdl=NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = TdiBuildInternalDeviceControlIrp(TDI_SEND, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (len)
    {
        mdl = IoAllocateMdl((void*) buf, len, FALSE, FALSE, NULL);

        if (mdl == NULL)
        {
            IoFreeIrp(irp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            IoFreeIrp(irp);
            status = STATUS_INVALID_USER_BUFFER;
        }

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    TdiBuildSend(irp, devObj, connectionFileObject, NULL, NULL, len ? mdl : 0, flags, len);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return NT_SUCCESS(status) ? (ULONG) iosb.Information : status;
}

NTSTATUS tdi_recv_stream(PFILE_OBJECT connectionFileObject, char *buf, int len, ULONG flags)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    PMDL            mdl=NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = TdiBuildInternalDeviceControlIrp(TDI_RECEIVE, devObj, connectionFileObject, &event, &iosb);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (len)
    {
        mdl = IoAllocateMdl((void*) buf, len, FALSE, FALSE, NULL);

        if (mdl == NULL)
        {
            IoFreeIrp(irp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            IoFreeIrp(irp);
            status = STATUS_INVALID_USER_BUFFER;
        }

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    TdiBuildReceive(irp, devObj, connectionFileObject, NULL, NULL, len ? mdl : 0, flags, len);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

	return NT_SUCCESS(status) ? (ULONG) iosb.Information : status;
}

static NTSTATUS tdi_send_mdl_completion(PDEVICE_OBJECT deviceObject, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(deviceObject);
	UNREFERENCED_PARAMETER(context);

    *irp->UserIosb = irp->IoStatus;

    if (irp->PendingReturned)
    {
        KeSetEvent(irp->UserEvent, IO_NO_INCREMENT, FALSE);
    }

    IoFreeIrp(irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS tdi_send_dgram_mdl(PFILE_OBJECT addressFileObject, ULONG addr, USHORT port, PMDL mdl)
{
    PDEVICE_OBJECT              devObj;
    KEVENT                      event;
    PTDI_CONNECTION_INFORMATION remoteInfo;
    PTA_IP_ADDRESS              remoteAddr;
    PIRP                        irp;
    PMDL                        nextMdl;
    ULONG                       len;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

    devObj = IoGetRelatedDeviceObject(addressFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    remoteInfo = (PTDI_CONNECTION_INFORMATION) ExAllocatePool(NonPagedPool, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    if (remoteInfo == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(remoteInfo, sizeof(TDI_CONNECTION_INFORMATION) + sizeof(TA_IP_ADDRESS));

    remoteInfo->RemoteAddressLength = sizeof(TA_IP_ADDRESS);
    remoteInfo->RemoteAddress = (PUCHAR)remoteInfo + sizeof(TDI_CONNECTION_INFORMATION);

    remoteAddr = (PTA_IP_ADDRESS) remoteInfo->RemoteAddress;

    remoteAddr->TAAddressCount = 1;
    remoteAddr->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP;
    remoteAddr->Address[0].AddressType = TDI_ADDRESS_TYPE_IP;
    remoteAddr->Address[0].Address[0].sin_port = port;
    remoteAddr->Address[0].Address[0].in_addr = addr;

    irp = IoAllocateIrp(devObj->StackSize, FALSE);

    if (irp == NULL)
    {
        ExFreePool(remoteInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    irp->UserIosb = &iosb;
    irp->UserEvent = &event;

    for (len = 0, nextMdl = mdl; nextMdl != NULL; nextMdl = nextMdl->Next)
    {
        len += MmGetMdlByteCount(nextMdl);
    }

    TdiBuildSendDatagram(irp, devObj, addressFileObject, tdi_send_mdl_completion, NULL, len ? mdl : 0, len, remoteInfo);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    ExFreePool(remoteInfo);

    return NT_SUCCESS(status) ? (ULONG) iosb.Information : status;
}

NTSTATUS tdi_send_stream_mdl(PFILE_OBJECT connectionFileObject, PMDL mdl, ULONG flags)
{
    PDEVICE_OBJECT  devObj;
    KEVENT          event;
    PIRP            irp;
    PMDL            nextMdl;
    ULONG           len;
    IO_STATUS_BLOCK iosb;
    NTSTATUS        status;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoAllocateIrp(devObj->StackSize, FALSE);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    irp->UserIosb = &iosb;
    irp->UserEvent = &event;

    for (len = 0, nextMdl = mdl; nextMdl != NULL; nextMdl = nextMdl->Next)
    {
        len += MmGetMdlByteCount(nextMdl);
    }

    TdiBuildSend(irp, devObj, connectionFileObject, tdi_send_mdl_completion, NULL, len ? mdl : 0, flags, len);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    return NT_SUCCESS(status) ? (ULONG) iosb.Information : status;
}

typedef struct _TDI_COMPLETION_CONTEXT {
    void (*completion_routine)(int status, void *context);
    void *context;
} TDI_COMPLETION_CONTEXT, *PTDI_COMPLETION_CONTEXT;

static NTSTATUS tdi_send_mdl_async_completion(PDEVICE_OBJECT deviceObject, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(deviceObject);

    PTDI_COMPLETION_CONTEXT ctx = (PTDI_COMPLETION_CONTEXT) context;

    if (ctx->completion_routine)
    {
        ctx->completion_routine(NT_SUCCESS(irp->IoStatus.Status) ? (ULONG) irp->IoStatus.Information : irp->IoStatus.Status, ctx->context);
    }

    ExFreePool(ctx);
    IoFreeIrp(irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS tdi_send_stream_mdl_async(PFILE_OBJECT connectionFileObject, PMDL mdl, ULONG flags, void (*completionRoutine)(int status, void *context), void *context)
{
    PDEVICE_OBJECT          devObj;
    PIRP                    irp;
    PTDI_COMPLETION_CONTEXT ctx;
    PMDL                    nextMdl;
    ULONG                   len;

    devObj = IoGetRelatedDeviceObject(connectionFileObject);

    irp = IoAllocateIrp(devObj->StackSize, FALSE);

    if (irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ctx = ExAllocatePool(NonPagedPool, sizeof(TDI_COMPLETION_CONTEXT));

    if (ctx == NULL)
    {
        IoFreeIrp(irp);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ctx->completion_routine = completionRoutine;
    ctx->context = context;

    for (len = 0, nextMdl = mdl; nextMdl != NULL; nextMdl = nextMdl->Next)
    {
        len += MmGetMdlByteCount(nextMdl);
    }

    TdiBuildSend(irp, devObj, connectionFileObject, tdi_send_mdl_async_completion, ctx, len ? mdl : 0, flags, len);

    return IoCallDriver(devObj, irp);
}

NTSTATUS tdi_query_address(PFILE_OBJECT addressFileObject, PULONG addr, PUSHORT port)
{
    PDEVICE_OBJECT              devObj;
    KEVENT                      event;
    PTRANSPORT_ADDRESS          localInfo;
    PTA_IP_ADDRESS              localAddr;
    PIRP                        irp;
    PMDL                        mdl;
    IO_STATUS_BLOCK             iosb;
    NTSTATUS                    status;

    devObj = IoGetRelatedDeviceObject(addressFileObject);

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    localInfo = (PTRANSPORT_ADDRESS) ExAllocatePool(NonPagedPool, sizeof(TDI_ADDRESS_INFO)*10);

    if (localInfo == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(localInfo, sizeof(TDI_ADDRESS_INFO)*10);

    irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, devObj, addressFileObject, &event, &iosb);

    if (irp == NULL)
    {
        ExFreePool(localInfo);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    {
        mdl = IoAllocateMdl((void*) localInfo, sizeof(TDI_ADDRESS_INFO)*10, FALSE, FALSE, NULL);

        if (mdl == NULL)
        {
            IoFreeIrp(irp);
            ExFreePool(localInfo);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            IoFreeMdl(mdl);
            IoFreeIrp(irp);
            ExFreePool(localInfo);
            status = STATUS_INVALID_USER_BUFFER;
        }

        if (!NT_SUCCESS(status))
        {
            return status;
        }
    }

    TdiBuildQueryInformation(irp, devObj, addressFileObject, NULL, NULL, TDI_QUERY_ADDRESS_INFO, mdl);

    status = IoCallDriver(devObj, irp);

    if (status == STATUS_PENDING)
    {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    localAddr = (PTA_IP_ADDRESS)&localInfo->Address[0];

    if (addr)
    {
        *addr = localAddr->Address[0].Address[0].in_addr;
    }

    if (port)
    {
        *port = localAddr->Address[0].Address[0].sin_port;
    }

    ExFreePool(localInfo);

    return status;
}
