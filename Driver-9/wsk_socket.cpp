#include "Base.h"
#include "wsk_socket.h"

NTSTATUS ddk::wsk_socket_mgr::DoConnectRaw(USHORT SocketType, ULONG Protocol,
	PSOCKADDR LocalAddress, PSOCKADDR RemoteAddress,
	wsk_socket **ppSocket)
{
	PIRP Irp = NULL;
	NTSTATUS Status;
	KEVENT CompEvent;

	KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);

	Irp = IoAllocateIrp(1, FALSE);
	if (Irp == NULL) {
		DBG_PRINT("insufficient resources\r\n");

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	IoSetCompletionRoutine(Irp,
		ddk::wsk_socket_mgr::WSK_CompletionRoutine,
		&CompEvent, TRUE, TRUE, TRUE);

	Status = this->ProviderNpi.Dispatch->WskSocketConnect(this->ProviderNpi.Client,
		SocketType,
		Protocol,
		LocalAddress,
		RemoteAddress,
		0,
		NULL, //SocketContext, 
		NULL, //Dispatch,
		NULL,
		NULL,
		NULL,
		Irp);
	DBG_PRINT("WskSocketConnect status %x\r\n", Status);

	KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);

	Status = Irp->IoStatus.Status;
	if (!NT_SUCCESS(Status)) {
		DBG_PRINT("WskSocketConnect status %x\r\n", Status);
		goto cleanup;
	}

	PWSK_SOCKET WskSocket = (PWSK_SOCKET)Irp->IoStatus.Information;
	wsk_socket *pSocket = new wsk_socket(WskSocket);
	*ppSocket = pSocket;
	Status = STATUS_SUCCESS;

cleanup:
	IoFreeIrp(Irp);
	return Status;
}