#pragma once
#include "Base.h"
#include "lock.h"
#include <vector>
#include <wsk.h>
namespace ddk
{
	static const WSK_CLIENT_DISPATCH MWskClientDispatch = {
		MAKE_WSK_VERSION(1, 0), // This sample uses WSK version 1.0
		0, // Reserved
		NULL // WskClientEvent callback is not required in WSK version 1.0
	};
//#define ntohs(x) RtlUshortByteSwap(x)
//#define htons(x) RtlUshortByteSwap(x)
//
//#define ntohl(x) RtlUlongByteSwap(x)
//#define htonl(x) RtlUlongByteSwap(x)
//
//#define ntohll(x) RtlUlonglongByteSwap(x)
//#define htonll(x) RtlUlonglongByteSwap(x)

	//class base_wsk_socket
	//{
	//public:
	//	virtual void shutdown() = 0;
	//};
	class wsk_socket;
	class wsk_socket_mgr:public Singleton<wsk_socket_mgr>
	{
	public:
		friend class wsk_socket;
		wsk_socket_mgr() {
			init_socket = false;
			WSK_CLIENT_NPI wskClientNpi;
			wskClientNpi.ClientContext = NULL;
			wskClientNpi.Dispatch = &MWskClientDispatch;
			auto Status = WskRegister(&wskClientNpi, &this->Registration);
			if (!NT_SUCCESS(Status)) {
				DBG_PRINT("WskRegister failed %x\r\n", Status);
				return;
			}

			Status = WskCaptureProviderNPI(&this->Registration, WSK_INFINITE_WAIT, &this->ProviderNpi);
			if (!NT_SUCCESS(Status)) {
				DBG_PRINT("WskCaptureProviderNPI failed %x\r\n", Status);
				WskDeregister(&this->Registration);
				return;
			}
			init_socket = true;
		}
		~wsk_socket_mgr()
		{
			release_lock.wait_for_release();
			socket_lock.lock();
			while (!m_socket_list.empty())
			{
				auto p = m_socket_list.back();
				if (p!=nullptr)
				{
#pragma warning(push)
#pragma warning(disable : 4150)
					delete p;
#pragma warning(pop)
				}
				m_socket_list.pop_back();
			}
			socket_lock.unlock();
			if (init_socket)
			{
				WskReleaseProviderNPI(&this->Registration);
				WskDeregister(&this->Registration);
			}
		}
		static 	NTSTATUS Connect(const WCHAR *host, const WCHAR *port, wsk_socket **ppSocket)
		{
			return getInstance().DoConnect(host, port, ppSocket);
		}
		NTSTATUS DoConnect(const WCHAR *host, const WCHAR *port, wsk_socket **ppSocket)
		{
			NTSTATUS Status;
			SOCKADDR_IN LocalAddress;
			SOCKADDR_IN RemoteAddress;
			UNICODE_STRING NodeName = { 0, 0, NULL };
			UNICODE_STRING ServiceName = { 0, 0, NULL };
			UNICODE_STRING RemoteName = { 0, 0, NULL };
			wsk_socket *pSocket = NULL;

			release_lock.only_acquire();
			auto exit_ = std::experimental::make_scope_exit([&]() {release_lock.release(); });

			IN4ADDR_SETANY(&LocalAddress);

			RtlInitUnicodeString(&NodeName, host);
			RtlInitUnicodeString(&ServiceName, port);

			Status = this->ResolveName(&NodeName, &ServiceName, NULL, &RemoteAddress);
			if (!NT_SUCCESS(Status)) {
				DBG_PRINT("ResolveName error %x for name %wZ %wZ\r\n", Status, &NodeName, &ServiceName);
				return Status;
			}

			Status = this->DoConnectRaw(SOCK_STREAM, IPPROTO_TCP, (PSOCKADDR)&LocalAddress, (PSOCKADDR)&RemoteAddress, &pSocket);
			if (!NT_SUCCESS(Status)) {
				DBG_PRINT("Connect error %x for name %wZ %wZ\r\n", Status, &NodeName, &ServiceName);
				return Status;
			}

			*ppSocket = pSocket;
			socket_lock.lock();
			m_socket_list.push_back(pSocket);
			socket_lock.unlock();
			return STATUS_SUCCESS;
		}
	private:
		bool init_socket;
		std::vector<wsk_socket*> m_socket_list;
		nt_lock release_lock;
		nt_mutex socket_lock;
		WSK_CLIENT_DISPATCH ClientDispatch;
		WSK_REGISTRATION    Registration;
		WSK_PROVIDER_NPI    ProviderNpi;
	public:
		static
			NTSTATUS
			WSK_CompletionRoutine(
				__in PDEVICE_OBJECT Reserved,
				__in PIRP Irp,
				__in PVOID Context
				)
		{
			PKEVENT CompEvent = (PKEVENT)Context;
			UNREFERENCED_PARAMETER(Reserved);
			UNREFERENCED_PARAMETER(Irp);
			KeSetEvent(CompEvent, 2, FALSE);
			return STATUS_MORE_PROCESSING_REQUIRED;
		}
	private:
		void remove(const wsk_socket *_socket)
		{
			socket_lock.lock();
			auto p = std::find(m_socket_list.begin(), m_socket_list.end(), _socket);
			if(p!=m_socket_list.end())
				m_socket_list.erase(p);
			socket_lock.unlock();
		}
		NTSTATUS ResolveName(PUNICODE_STRING NodeName,
			PUNICODE_STRING ServiceName, PADDRINFOEXW Hints,
			PSOCKADDR_IN ResolvedAddress)
		{
			NTSTATUS Status;
			PIRP Irp;
			KEVENT CompletionEvent;
			PADDRINFOEXW Results = NULL, AddrInfo = NULL;

			KeInitializeEvent(&CompletionEvent, SynchronizationEvent, FALSE);

			Irp = IoAllocateIrp(1, FALSE);
			if (Irp == NULL) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			IoSetCompletionRoutine(Irp, ddk::wsk_socket_mgr::WSK_CompletionRoutine, &CompletionEvent, TRUE, TRUE, TRUE);

			this->ProviderNpi.Dispatch->WskGetAddressInfo(
				this->ProviderNpi.Client,
				NodeName,
				ServiceName,
				NS_ALL,
				NULL, // Provider
				Hints,
				&Results,
				NULL, // OwningProcess
				NULL, // OwningThread
				Irp);

			KeWaitForSingleObject(&CompletionEvent, Executive,
				KernelMode, FALSE, NULL);

			Status = Irp->IoStatus.Status;

			IoFreeIrp(Irp);

			if (!NT_SUCCESS(Status)) {
				DBG_PRINT("resolve status %x\r\n", Status);
				return Status;
			}

			AddrInfo = Results; // your code here
			if (AddrInfo != NULL) {
				*ResolvedAddress = *((PSOCKADDR_IN)(AddrInfo->ai_addr));
			}
			else {
				Status = STATUS_UNSUCCESSFUL;
				DBG_PRINT("no addresses found\r\n");
			}

			this->ProviderNpi.Dispatch->WskFreeAddressInfo(
				this->ProviderNpi.Client,
				Results);

			return Status;
		}
	public:
		NTSTATUS Disconnect(PWSK_SOCKET WskSocket, ULONG Flags)
		{
			KEVENT CompEvent;
			NTSTATUS Status;
			PIRP Irp;

			KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);

			Irp = IoAllocateIrp(1, FALSE);
			if (Irp == NULL) {
				DBG_PRINT("insufficient resources\r\n");
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			IoSetCompletionRoutine(Irp,
				ddk::wsk_socket_mgr::WSK_CompletionRoutine,
				&CompEvent, TRUE, TRUE, TRUE);

			Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->WskDisconnect(WskSocket, NULL, Flags, Irp);
			DBG_PRINT("WskDisconnect status %x\r\n", Status);

			KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);

			Status = Irp->IoStatus.Status;

			if (!NT_SUCCESS(Status))
				DBG_PRINT("disconnect status %x\r\n", Status);

			IoFreeIrp(Irp);

			return Status;
		}
		NTSTATUS Close(PWSK_SOCKET WskSocket)
		{
			KEVENT CompEvent;
			NTSTATUS Status;
			PIRP Irp;

			KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);

			Irp = IoAllocateIrp(1, FALSE);
			if (Irp == NULL) {
				DBG_PRINT("insufficient resources\r\n");
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			IoSetCompletionRoutine(Irp,
				ddk::wsk_socket_mgr::WSK_CompletionRoutine,
				&CompEvent, TRUE, TRUE, TRUE);

			Status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)WskSocket->Dispatch)->Basic.WskCloseSocket(WskSocket, Irp);
			DBG_PRINT("WskCloseSocket status %x\r\n", Status);

			KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
			Status = Irp->IoStatus.Status;

			if (!NT_SUCCESS(Status))
				DBG_PRINT("close status %x\r\n", Status);

			IoFreeIrp(Irp);

			return Status;
		}
	private:
		NTSTATUS DoConnectRaw(USHORT SocketType, ULONG Protocol,
			PSOCKADDR LocalAddress, PSOCKADDR RemoteAddress,
			wsk_socket **ppSocket);

	};
	class wsk_socket
	{
	public:
		friend class wsk_socket_mgr;
		void shutdown() {
			Disconnect(0);
			Close();
		}
		wsk_socket(PWSK_SOCKET WskSocket)
		{
			Closing = Disconnecting = 0;
			this->WskSocket = WskSocket;
			this->Dispatch = reinterpret_cast<PWSK_PROVIDER_CONNECTION_DISPATCH>(const_cast<void*>(WskSocket->Dispatch));
		}
		~wsk_socket()
		{
			shutdown();
			//调用管理器remove
			ddk::wsk_socket_mgr::getInstance().remove(this);
		}
		NTSTATUS Disconnect(ULONG Flags)
		{
			if (0 != InterlockedCompareExchange(&this->Disconnecting, 1, 0)) {
				DBG_PRINT("socket %p already disconnecting\r\n", this);
				return STATUS_PENDING;
			}

			return ddk::wsk_socket_mgr::getInstance().Disconnect(this->WskSocket, Flags);
		}
		NTSTATUS Close()
		{
			if (0 != InterlockedCompareExchange(&this->Closing, 1, 0)) {
				DBG_PRINT("socket %p already closing\r\n", this);
				return STATUS_PENDING;
			}

			return ddk::wsk_socket_mgr::getInstance().Close(this->WskSocket);
		}
		NTSTATUS Receive(PVOID Buf, ULONG Size, PULONG pReceived, PBOOLEAN pbDisconnected)
		{
			ULONG BytesRcv;
			ULONG Offset;
			NTSTATUS Status = STATUS_UNSUCCESSFUL;

			Offset = 0;
			while (Offset < Size) {
				Status = this->Receive(0, (PVOID)((ULONG_PTR)Buf + Offset), Size - Offset, &BytesRcv);
				if (!NT_SUCCESS(Status)) {
					DBG_PRINT("received err %x\r\n", Status);
					break;
				}

				if (BytesRcv == 0) {
					DBG_PRINT("received 0 bytes\r\n");
					*pbDisconnected = TRUE;
					Status = STATUS_SUCCESS;
					break;
				}
				Offset += BytesRcv;
			}

			*pReceived = Offset;

			return Status;
		}
		NTSTATUS Send(PVOID Buf, ULONG Size, PULONG pSent)
		{
			ULONG BytesSent;
			ULONG Offset;
			NTSTATUS Status = STATUS_UNSUCCESSFUL;

			Offset = 0;
			while (Offset < Size) {
				Status = this->Send(WSK_FLAG_NODELAY, (PVOID)((ULONG_PTR)Buf + Offset), Size - Offset, &BytesSent);
				if (!NT_SUCCESS(Status)) {
					DBG_PRINT("send failed with err=%x\r\n", Status);
					break;
				}
				Offset += BytesSent;
			}

			*pSent = Offset;

			return Status;
		}
	private:
		NTSTATUS Send(ULONG Flags, PVOID Buf, ULONG Size, PULONG pSent)
		{
			WSK_BUF WskBuf;
			KEVENT CompEvent;
			PIRP Irp = NULL;
			PMDL Mdl = NULL;
			NTSTATUS Status;
			LARGE_INTEGER Timeout;

			*pSent = 0;
			KeInitializeEvent(&CompEvent, NotificationEvent, FALSE);

			Irp = IoAllocateIrp(1, FALSE);
			if (Irp == NULL) {
				
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			IoSetCompletionRoutine(Irp,
				ddk::wsk_socket_mgr::WSK_CompletionRoutine,
				&CompEvent, TRUE, TRUE, TRUE);

			Mdl = IoAllocateMdl(Buf, Size, FALSE, FALSE, NULL);
			if (Mdl == NULL) {
				Status = STATUS_INSUFFICIENT_RESOURCES;
				goto cleanup;
			}
			MmBuildMdlForNonPagedPool(Mdl);

			WskBuf.Offset = 0;
			WskBuf.Length = Size;
			WskBuf.Mdl = Mdl;

			Status = this->Dispatch->WskSend(this->WskSocket, &WskBuf, Flags, Irp);

			Timeout.QuadPart = -10 * 1000 * 1000 * 10;//wait 10sec 

			Status = KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, &Timeout);
			if (Status == STATUS_TIMEOUT) {	
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
			}

			Status = Irp->IoStatus.Status;

			if (!NT_SUCCESS(Status))
				DBG_PRINT("send status %x\r\n", Status);

			if (NT_SUCCESS(Status)) {
				*pSent = (ULONG)Irp->IoStatus.Information;
			}

		cleanup:
			if (Irp != NULL)
				IoFreeIrp(Irp);
			if (Mdl != NULL)
				IoFreeMdl(Mdl);

			return Status;
		}
	private:
		LONG	Closing;
		LONG	Disconnecting;
		PWSK_PROVIDER_CONNECTION_DISPATCH Dispatch;
		PWSK_SOCKET		WskSocket;
	private:
		NTSTATUS Receive(ULONG Flags, PVOID Buf, ULONG Size, ULONG *pReceived)
		{
			WSK_BUF WskBuf;
			KEVENT CompEvent;
			PIRP Irp = NULL;
			PMDL Mdl = NULL;
			NTSTATUS Status;
			LARGE_INTEGER Timeout;

			*pReceived = 0;
			KeInitializeEvent(&CompEvent, SynchronizationEvent, FALSE);

			Irp = IoAllocateIrp(1, FALSE);
			if (Irp == NULL) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			IoSetCompletionRoutine(Irp,
				ddk::wsk_socket_mgr::WSK_CompletionRoutine,
				&CompEvent, TRUE, TRUE, TRUE);

			Mdl = IoAllocateMdl(Buf, Size, FALSE, FALSE, NULL);
			if (Mdl == NULL) {
				Status = STATUS_INSUFFICIENT_RESOURCES;
				goto cleanup;
			}
			MmBuildMdlForNonPagedPool(Mdl);

			WskBuf.Offset = 0;
			WskBuf.Length = Size;
			WskBuf.Mdl = Mdl;

			Status = this->Dispatch->WskReceive(this->WskSocket, &WskBuf, Flags, Irp);

			Timeout.QuadPart = -10 * 1000 * 1000 * 10;//wait 10sec
			Status = KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, &Timeout);
			if (Status == STATUS_TIMEOUT) {
				IoCancelIrp(Irp);
				KeWaitForSingleObject(&CompEvent, Executive, KernelMode, FALSE, NULL);
			}

			Status = Irp->IoStatus.Status;

			if (!NT_SUCCESS(Status))
				DBG_PRINT("receive status %x\r\n", Status);

			if (NT_SUCCESS(Status)) {
				*pReceived = (ULONG)Irp->IoStatus.Information;
			}

		cleanup:
			if (Irp != NULL)
				IoFreeIrp(Irp);
			if (Mdl != NULL)
				IoFreeMdl(Mdl);

			return Status;
		}
	};
};