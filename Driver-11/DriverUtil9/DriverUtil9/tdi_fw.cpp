#include "Base.h"
#include "tdi_fw.h"
#include <map>
#include <vector>
extern "C"
{
#include<tdikrnl.h>
};
namespace ddk
{
	namespace tdi_fw_example
	{
		static const auto DEL_EVENT_WRAP = 1;
		static const auto GET_EVENT_WRAP = 2;
		static const auto TDI_FILTER_TIMER_ELAPSE_TIME = -10000000; //1 second
		static const auto WAIT_CONFIGURED_PROC_TIME = -100000;//10 milli second
		static const auto CONTEXT_MAGIC = 0x708090;
		static const auto TDI_EVENT_CONTEXT_MARK = 0xFEC02B01;
		//////////////////////////////////////////////////////////////////////////
		static PDEVICE_OBJECT TcpObject = nullptr;
		static LARGE_INTEGER g_SendingDelayTime = { 0 };
		static LARGE_INTEGER g_TimerElapse = { 0 };
		static LARGE_INTEGER g_ThreadWaitConfigProcTime = { 0 };
		static LARGE_INTEGER g_WaitNewIistItemTime = { 0 };
		static LARGE_INTEGER g_AllSendedDataSize = { 0 };
		static LARGE_INTEGER g_AllRecvedDataSize = { 0 };
		static BOOLEAN g_bThreadIrpProcessStop = FALSE;
		static KEVENT g_EventIrpListAdded;
		static KEVENT g_EventCompletion;
		static NPAGED_LOOKASIDE_LIST g_CompletionWrapList;
		static LONG g_CompletionIrpCount = 0;
		static BOOL g_bFiltering = TRUE;
		static ERESOURCE g_SyncResource;
		//////////////////////////////////////////////////////////////////////////
		static ddk::CThread ThreadProcessIrp;
		static ddk::CThread ThreadProcessWait;
		//////////////////////////////////////////////////////////////////////////
		static ddk::nt_attach_filter tcpfilter;

		static KSPIN_LOCK g_SpLockTdiEventHandlerInfo;
		static LIST_ENTRY g_TdiEventHandlerInfoList;

		//static ddk::nt_attach_filter udpfilter;
		//static ddk::nt_attach_filter_ex afdfilter;
		static NTSTATUS PspGetIrpProcess(PIRP pIrp, PEPROCESS &Process)
		{
			Process = nullptr;
			auto pThread = pIrp->Tail.Overlay.Thread;
			if (!pThread)
			{
				Process = IoGetCurrentProcess();
			}
			else
			{
				Process = IoThreadToProcess(pThread);
			}
			if (Process)
			{
				return STATUS_SUCCESS;
			}
			return STATUS_UNSUCCESSFUL;
		}
		static PDEVICE_OBJECT GetDeviceObject(std::wstring devName)
		{
			UNICODE_STRING nsDevName;
			PFILE_OBJECT fileobject = nullptr;
			PDEVICE_OBJECT devObject = nullptr;
			RtlInitUnicodeString(&nsDevName, devName.c_str());
			auto ns = IoGetDeviceObjectPointer(&nsDevName, FILE_ALL_ACCESS,
				&fileobject,
				&devObject);
			if (NT_SUCCESS(ns))
			{
				if (fileobject)
				{
					ObDereferenceObject(fileobject);
				}
				return devObject;
			}
			return nullptr;
		}
	};
};
using namespace ddk::tdi_fw_example;
//////////////////////////////////////////////////////////////////////////
NTSTATUS on_tdi_send_recv(PDEVICE_OBJECT lowerDev, PDEVICE_OBJECT object, PIRP Irp);
NTSTATUS on_tdi_seteventhandler(PDEVICE_OBJECT lowerDev, PDEVICE_OBJECT object, PIRP Irp);
NTSTATUS tdi_create_complete(PDEVICE_OBJECT dev, PIRP irp, PVOID context);
NTSTATUS tdi_query_com(PDEVICE_OBJECT dev, PIRP irp, PVOID context);
VOID TdiFilterCancel(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	);
PIRP DequeueIrp(PLIST_ENTRY pListHead, PKSPIN_LOCK SpLock);
VOID TimerDpcProcess(PKDPC pDpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2);
void tdi_fw_ProcessNotifyRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo);

//////////////////////////////////////////////////////////////////////////
VOID ThreadSendingSpeedControl();
VOID ThreadWaitCompletion();
//////////////////////////////////////////////////////////////////////////
using TDI_FW_CONTEXT = struct {
	int magic;
	PEPROCESS Process;
	PIRP queryIrp;
	PDEVICE_OBJECT queryDevice;
	PMDL mdl;
	PVOID old_handler;
	PVOID old_context;
};
using TDI_LMT_RULE = struct
{
	WCHAR szImageFileName[MAX_PATH];
	LONGLONG MaxSendSpeed;
	LONGLONG MaxRecvSpeed;
};
using TDI_LMT = struct {
	LARGE_INTEGER AllSuccSendedDataSize;
	LARGE_INTEGER AllSuccRecvedDataSize;
	LARGE_INTEGER AllSuccSendedDataSizePrev;
	LARGE_INTEGER AllSuccRecvedDataSizePrev;
	LARGE_INTEGER SuccSendedDataSizeOnce;
	LARGE_INTEGER SuccRecvedDataSizeOnce;
	LARGE_INTEGER SendedSizeOneSec;
	LARGE_INTEGER RecvedSizeOneSec;
	BOOL bStopSend;
	BOOL bStopRecv;
	LARGE_INTEGER SendingSpeed;
	PKTIMER pTimer;
	PKDPC pDpc;
	KSPIN_LOCK IrpListLock;
	LIST_ENTRY IrpList;
	LIST_ENTRY ListEntry;
	LONG dwRefCount;
	BOOL bCancel;
	bool TimerOk;
	PEPROCESS Process;
	TDI_LMT_RULE Rule;
};

using TDI_COMPLETION_WRAP = struct
{
	LIST_ENTRY ListEntry;
	CHAR bSendOpera;
	CHAR bWrap;
	CHAR bAssocIrp;
	CHAR bSync;
	PIO_COMPLETION_ROUTINE pCompletionRoutine;
	LPVOID pContext;
	CHAR Control;
	PEPROCESS pEProcess;
	TDI_LMT* pProcessNetWorkTrafficInfo;
};
using PTDI_COMPLETION_WRAP = TDI_COMPLETION_WRAP*;
using TDI_EVENT_HANDLER_WRAP = struct
{
	DWORD dwEventContextMark;
	DWORD dwEventType;
	PVOID pOrgEventHandler;
	PVOID pOrgEventContext;
	PEPROCESS pEProcess;
	TDI_LMT* pProcessNetWorkTrafficInfo;
	PFILE_OBJECT pAssocAddr;
	PDEVICE_OBJECT pDeviceObject;
};
using PTDI_EVENT_HANDLER_WRAP = TDI_EVENT_HANDLER_WRAP*;

using TDI_EVENT_HANDLER_LIST = struct
{
	LIST_ENTRY List;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrap;
};
using PTDI_EVENT_HANDLER_LIST = TDI_EVENT_HANDLER_LIST*;

using ClientEventConnect = NTSTATUS(NTAPI *)(
	_In_  PVOID              TdiEventContext,
	_In_  LONG               RemoteAddressLength,
	_In_  PVOID              RemoteAddress,
	_In_  LONG               UserDataLength,
	_In_  PVOID              UserData,
	_In_  LONG               OptionsLength,
	_In_  PVOID              Options,
	_Out_ CONNECTION_CONTEXT *ConnectionContext,
	_Out_ PIRP               *AcceptIrp
	);
using ClientEventReceive = NTSTATUS(NTAPI*)(
	PVOID  TdiEventContext,
	CONNECTION_CONTEXT  ConnectionContext,
	ULONG  ReceiveFlags,
	ULONG  BytesIndicated,
	ULONG  BytesAvailable,
	ULONG  *BytesTaken,
	PVOID  Tsdu,
	PIRP  *IoRequestPacket
	);
using ClientEventChainedReceive = NTSTATUS(NTAPI*)(
	IN PVOID  TdiEventContext,
	IN CONNECTION_CONTEXT  ConnectionContext,
	IN ULONG  ReceiveFlags,
	IN ULONG  ReceiveLength,
	IN ULONG  StartingOffset,
	IN PMDL  Tsdu,
	IN PVOID  TsduDescriptor
	);

using ClientEventReceiveDatagram = NTSTATUS(NTAPI*)(
	IN PVOID  TdiEventContext,
	IN LONG  SourceAddressLength,
	IN PVOID  SourceAddress,
	IN LONG  OptionsLength,
	IN PVOID  Options,
	IN ULONG  ReceiveDatagramFlags,
	IN ULONG  BytesIndicated,
	IN ULONG  BytesAvailable,
	OUT ULONG  *BytesTaken,
	IN PVOID  Tsdu,
	OUT PIRP  *IoRequestPacket
	);

NTSTATUS NTAPI on_tdi_ClientEventConnect(
	_In_  PVOID              TdiEventContext,
	_In_  LONG               RemoteAddressLength,
	_In_  PVOID              RemoteAddress,
	_In_  LONG               UserDataLength,
	_In_  PVOID              UserData,
	_In_  LONG               OptionsLength,
	_In_  PVOID              Options,
	_Out_ CONNECTION_CONTEXT *ConnectionContext,
	_Out_ PIRP               *AcceptIrp
	);
std::map<PEPROCESS, TDI_LMT*> m_lmt_control;
std::map<PIRP, TDI_LMT*>m_Cancle_table;
std::vector<TDI_LMT_RULE> m_lmt_rule;
ddk::nt_spinlock lmt_control_lock;
//////////////////////////////////////////////////////////////////////////
TDI_LMT *get_lmt(PEPROCESS Process);
void release_lmt(PEPROCESS Process);
NTSTATUS TdiFilterSyncSendProcess(TDI_LMT* pLmt, PDEVICE_OBJECT lwobj, PDEVICE_OBJECT object, PIRP Irp);
NTSTATUS TdiFilterCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, LPVOID pContext);
//////////////////////////////////////////////////////////////////////////
VOID DeleteEventWrap(PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList);
VOID UpdateEventHandlerWrap(TDI_LMT* pProcessNetWorkTrafficInfo,
	PEPROCESS pEProcess,
	PDEVICE_OBJECT pDeviceObject,
	PFILE_OBJECT pFileObject,
	DWORD dwEventType,
	PVOID pEventHandler,
	PVOID pEventContext,
	PTDI_EVENT_HANDLER_LIST *ppEventHandlerWrap,
	DWORD dwFlags);
NTSTATUS RestoreEventHandler(PTDI_EVENT_HANDLER_WRAP pEventHandlerWrap);
NTSTATUS TdiFilterRecvEventHandler(IN PVOID  TdiEventContext,
	IN CONNECTION_CONTEXT  ConnectionContext,
	IN ULONG  ReceiveFlags,
	IN ULONG  BytesIndicated,
	IN ULONG  BytesAvailable,
	OUT ULONG  *BytesTaken,
	IN PVOID  Tsdu,
	OUT PIRP  *IoRequestPacket
	);
NTSTATUS  TdiFilterChainedRecvHandler(
	IN PVOID  TdiEventContext,
	IN CONNECTION_CONTEXT  ConnectionContext,
	IN ULONG  ReceiveFlags,
	IN ULONG  ReceiveLength,
	IN ULONG  StartingOffset,
	IN PMDL  Tsdu,
	IN PVOID  TsduDescriptor
	);
NTSTATUS  TdiFilterRecvDatagramEventHandler(
	IN PVOID  TdiEventContext,
	IN LONG  SourceAddressLength,
	IN PVOID  SourceAddress,
	IN LONG  OptionsLength,
	IN PVOID  Options,
	IN ULONG  ReceiveDatagramFlags,
	IN ULONG  BytesIndicated,
	IN ULONG  BytesAvailable,
	OUT ULONG  *BytesTaken,
	IN PVOID  Tsdu,
	OUT PIRP  *IoRequestPacket
	);
//////////////////////////////////////////////////////////////////////////
NTSTATUS on_tdi_create(PDEVICE_OBJECT LowerDev, PDEVICE_OBJECT Object, PIRP Irp)
{
	PEPROCESS Process = nullptr;
	//IoGetCurrentProcess();
	auto ns = PspGetIrpProcess(Irp, Process);
	if (!NT_SUCCESS(ns))
	{
		goto PASS;
	}
	//这里就可以处理一个网络请求
	//不运行使用网络的话
	//auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	/*Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
	IoCompleteRequest(Irp, 0);
	return STATUS_NOT_IMPLEMENTED;*/
	//////////////////////////////////////////////////////////////////////////
	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	auto ea = (FILE_FULL_EA_INFORMATION *)Irp->AssociatedIrp.SystemBuffer;
	if (ea != NULL)
	{
		if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH)
		{
			LOG_DEBUG("this is tdi conn\r\n");
			auto cc = *(CONNECTION_CONTEXT*)(ea->EaName + ea->EaNameLength + 1);
			UNREFERENCED_PARAMETER(cc);
		}
		if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH)
		{
			LOG_DEBUG("this is tdi address\r\n");
			IoCopyCurrentIrpStackLocationToNext(Irp);
			auto context = (TDI_FW_CONTEXT *)malloc(sizeof(TDI_FW_CONTEXT));
			auto query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, TcpObject, IrpStack->FileObject, NULL, NULL);
			context->queryDevice = TcpObject;
			context->queryIrp = query_irp;
			IoSetCompletionRoutine(Irp, tdi_create_complete, context, TRUE, TRUE, TRUE);
			return IoCallDriver(LowerDev, Irp);
		}
	}
PASS:
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(LowerDev, Irp);
}

NTSTATUS on_tdi_internal_device_control(PDEVICE_OBJECT LowerDev, PDEVICE_OBJECT Object, PIRP Irp)
{
	PEPROCESS Process = nullptr;
	auto ns = PspGetIrpProcess(Irp, Process);
	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	//处理开始
	switch (IrpStack->MinorFunction)
	{
	case TDI_CONNECT:
		//链接远程,hips必备功能
	{
		LOG_DEBUG("tdi connect\r\n");
		LOG_DEBUG("Process %s\r\n", PsGetProcessImageFileName(Process));
		TA_ADDRESS *ta;
		TDI_REQUEST_KERNEL_CONNECT *trk = (TDI_REQUEST_KERNEL_CONNECT *)(&IrpStack->Parameters);
		ta = ((TRANSPORT_ADDRESS*)(trk->RequestConnectionInformation->RemoteAddress))->Address;
		PTDI_ADDRESS_IP ip = (PTDI_ADDRESS_IP)&(ta->Address);
		unsigned long Address = ip->in_addr;
		LOG_DEBUG("ip address:%d.%d.%d.%d\r\n",
			((char *)& Address)[0],
			((char *)& Address)[1],
			((char *)& Address)[2],
			((char *)& Address)[3]);
		LOG_DEBUG("port = %d\r\n", ddk::KSOCKET::ntohs(ip->sin_port));
	}
	break;
	case TDI_SEND:
	case TDI_RECEIVE:
	case TDI_SEND_DATAGRAM:
	case TDI_RECEIVE_DATAGRAM:
		return on_tdi_send_recv(LowerDev, Object, Irp);
		break;
	case TDI_SET_EVENT_HANDLER:
		return on_tdi_seteventhandler(LowerDev, Object, Irp);
		break;
	default:
		break;
	}
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(LowerDev, Irp);
}
NTSTATUS on_tdi_device_control(PDEVICE_OBJECT lwobj, PDEVICE_OBJECT object, PIRP Irp)
{
	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	if (!NT_SUCCESS(TdiMapUserRequest(object, Irp, IrpStack)))
	{
		IoSkipCurrentIrpStackLocation(Irp);
		return IoCallDriver(lwobj, Irp);
	}
	//return on_tdi_internal_device_control_xxx
	return on_tdi_internal_device_control(lwobj, object, Irp);
}
void init_tdi_filter()
{
	KeInitializeSpinLock(&g_SpLockTdiEventHandlerInfo);
	InitializeListHead(&g_TdiEventHandlerInfoList);

	g_TimerElapse.LowPart = TDI_FILTER_TIMER_ELAPSE_TIME;
	g_TimerElapse.HighPart = 0xFFFFFFFF;

	g_SendingDelayTime.LowPart = -10000;
	g_SendingDelayTime.HighPart = 0xFFFFFFFF;

	g_WaitNewIistItemTime.LowPart = TDI_FILTER_TIMER_ELAPSE_TIME;
	g_WaitNewIistItemTime.HighPart = 0xFFFFFFFF;

	g_ThreadWaitConfigProcTime.LowPart = WAIT_CONFIGURED_PROC_TIME;
	g_ThreadWaitConfigProcTime.HighPart = 0xFFFFFFFF;

	KeInitializeEvent(&g_EventIrpListAdded, SynchronizationEvent, 0);
	KeInitializeEvent(&g_EventCompletion, SynchronizationEvent, 0);
	ExInitializeResourceLite(&g_SyncResource);

	ExInitializeNPagedLookasideList(
		&g_CompletionWrapList,
		NULL,
		NULL,
		0,
		sizeof(TDI_COMPLETION_WRAP),
		'tdwf',
		0
		);
	ThreadProcessWait = ddk::CThread(ThreadWaitCompletion);
	//设置一个进程回调方便限速结构的创建和销毁
	ddk::nt_process_callback::getInstance().reg_callback_ex(tdi_fw_ProcessNotifyRoutine);
	//初始化tdi_fw for TCP
	TcpObject = GetDeviceObject(L"\\Device\\Tcp");
	tcpfilter.set_callback(IRP_MJ_CREATE, on_tdi_create);
	tcpfilter.set_callback(IRP_MJ_DEVICE_CONTROL, on_tdi_device_control);
	tcpfilter.set_callback(IRP_MJ_INTERNAL_DEVICE_CONTROL, on_tdi_internal_device_control);
	tcpfilter.attach_device(L"\\Device\\Tcp");

	//创建限速处理线程
	ThreadProcessIrp = ddk::CThread(ThreadSendingSpeedControl);

}


NTSTATUS tdi_create_complete(PDEVICE_OBJECT dev, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(dev);
	UNREFERENCED_PARAMETER(irp);
	UNREFERENCED_PARAMETER(context);
	LOG_DEBUG("enter createcomplete\n");
	auto irp_stack = IoGetCurrentIrpStackLocation(irp);
	auto *info = (TDI_FW_CONTEXT*)context;
	auto tai = (TDI_ADDRESS_INFO*)malloc(sizeof(TDI_ADDRESS_INFO));
	auto mdl = IoAllocateMdl(tai, sizeof(TDI_ADDRESS_INFO), FALSE, FALSE, info->queryIrp);
	MmBuildMdlForNonPagedPool(mdl);
	info->mdl = mdl;
	IoCopyCurrentIrpStackLocationToNext(irp);
	TdiBuildQueryInformation(info->queryIrp, info->queryDevice, irp_stack->FileObject, tdi_query_com, info, TDI_QUERY_ADDRESS_INFO, mdl);
	if (irp->PendingReturned)
	{
		IoMarkIrpPending(irp);
		LOG_DEBUG("pending\n");
	}
	IoCallDriver(info->queryDevice, info->queryIrp);
	IoFreeMdl(info->mdl);
	free(context);
	return STATUS_SUCCESS;
}

NTSTATUS tdi_query_com(PDEVICE_OBJECT dev, PIRP irp, PVOID context)
{
	UNREFERENCED_PARAMETER(dev);
	UNREFERENCED_PARAMETER(irp);
	UNREFERENCED_PARAMETER(context);
	if (irp->MdlAddress)
	{
		auto info = (TDI_FW_CONTEXT *)context;
		auto tai = (TDI_ADDRESS_INFO*)MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
		auto addr = tai->Address.Address;
		auto ip = (PTDI_ADDRESS_IP)&(addr->Address);
		unsigned long Address = ip->in_addr;
		unsigned short port;
		port = ip->sin_port;
		unsigned char ports[2];
		ports[0] = ((char *)& port)[0];
		ports[1] = ((char *)& port)[1];
		LOG_DEBUG("Process %s Bind Address %d.%d.%d.%d:%d\n",
			PsGetProcessImageFileName(info->Process),
			((char *)& Address)[0],
			((char *)& Address)[1],
			((char *)& Address)[2],
			((char *)& Address)[3],
			ports);
	}
	return STATUS_MORE_PROCESSING_REQUIRED;
}

void tdi_fw_ProcessNotifyRoutine(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	if (CreateInfo)
	{
		//创建进程
		WCHAR szImageName[MAX_PATH] = {};
		if (sizeof(szImageName) >= CreateInfo->ImageFileName->MaximumLength)
		{
			RtlCopyBytes(szImageName, CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->MaximumLength);
		}
		DBG_PRINT("Create Process = %ws\r\n", szImageName);
		auto _lens = wcslen(szImageName);
		for (auto item : m_lmt_rule)
		{
			auto _des_len = wcslen(item.szImageFileName);
			if (_des_len == _lens
				&& _wcsicmp(item.szImageFileName, szImageName) == 0)
			{
				//发现新大陆
				auto new_lmt = new TDI_LMT;
				if (new_lmt)
				{
					RtlZeroBytes(new_lmt, sizeof(TDI_LMT));

					new_lmt->dwRefCount = 1;
					new_lmt->pDpc = new KDPC;
					new_lmt->pTimer = new KTIMER;
					new_lmt->TimerOk = false;
					new_lmt->Rule = item;
					new_lmt->Process = Process;

					KLOCK_QUEUE_HANDLE _lock;
					lmt_control_lock.lock(&_lock);
					m_lmt_control[Process] = new_lmt;
					lmt_control_lock.unlock(&_lock);
				}
				break;
			}
		}
	}
	else
	{
		//结束时
		release_lmt(Process);
	}
	return;
}


NTSTATUS on_tdi_send_recv(PDEVICE_OBJECT lowerDev, PDEVICE_OBJECT object, PIRP Irp)
{
	//这里开始Send与Recv的世界了
	PTDI_COMPLETION_WRAP pCompletionWrap;
	NTSTATUS ns = STATUS_NOT_IMPLEMENTED;
	PEPROCESS Process;
	BOOLEAN bIsSend;
	PspGetIrpProcess(Irp, Process);
	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	auto MinorFunction = IrpStack->MinorFunction;
	auto pLmt = get_lmt(Process);
	auto exit_plmt = std::experimental::make_scope_exit([&]() {
		if (pLmt)
		{
			release_lmt(Process);
		}
	});
	if (TDI_RECEIVE == MinorFunction &&
		TDI_RECEIVE_PEEK == PtrToUlong(IrpStack->Parameters.Others.Argument2))
	{
		LOG_DEBUG("MinorFunction == TDI_RECEIVE recv flags == TDI_RECEIVE_PEEK \n");
		goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
	}
	if (!pLmt)
	{
		goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
	}
	if (FALSE != pLmt->bStopSend &&
		(TDI_SEND == MinorFunction ||
			TDI_SEND_DATAGRAM == MinorFunction))
	{
		goto WHEN_ACCESS_DENIED;
	}
	if (FALSE != pLmt->bStopRecv &&
		(TDI_RECEIVE_DATAGRAM == MinorFunction ||
			TDI_RECEIVE == MinorFunction))
	{
		goto WHEN_ACCESS_DENIED;
	}
	if (NULL == Irp->AssociatedIrp.SystemBuffer &&
		(TDI_SEND == MinorFunction ||
			TDI_SEND_DATAGRAM == MinorFunction))
	{
		//KdBreakPoint();

		if (TRUE == IoIsOperationSynchronous(Irp))
		{
			LOG_DEBUG("IoIsOperationSynchronous return TRUE \n");
			auto ntStatus = TdiFilterSyncSendProcess(pLmt, lowerDev, object, Irp);
			return ntStatus;
		}
		else
		{
			KIRQL IrpSpIrql;
			PDRIVER_CANCEL  OldCancelRoutine;

			LOG_DEBUG("add irp to process irp list \n");
			//ExInterlockedInsertTailList( &pProcessNetWorkTrafficInfo->IrpList, 
			//	&pIrp->Tail.Overlay.ListEntry, 
			//	&pProcessNetWorkTrafficInfo->IrpListLock );

			IoMarkIrpPending(Irp);
			KeAcquireSpinLock(&pLmt->IrpListLock, &IrpSpIrql);
			m_Cancle_table[Irp] = pLmt;
			OldCancelRoutine = IoSetCancelRoutine(Irp, TdiFilterCancel);
			ASSERT(NULL == OldCancelRoutine);

			InsertTailList(&pLmt->IrpList, &Irp->Tail.Overlay.ListEntry);

			if (Irp->Cancel)
			{
				OldCancelRoutine = IoSetCancelRoutine(Irp, NULL);
				if (OldCancelRoutine)
				{
					RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
					KeReleaseSpinLock(&pLmt->IrpListLock, IrpSpIrql);
					Irp->IoStatus.Status = STATUS_CANCELLED;
					Irp->IoStatus.Information = 0;
					IoCompleteRequest(Irp, IO_NO_INCREMENT);
					return STATUS_PENDING;
				}
			}
			KeReleaseSpinLock(&pLmt->IrpListLock, IrpSpIrql);
			KeSetEvent(&g_EventIrpListAdded, 0, FALSE);
			return STATUS_PENDING;
		}
	}
	pCompletionWrap = (PTDI_COMPLETION_WRAP)ExAllocateFromNPagedLookasideList(&g_CompletionWrapList);
	if (NULL == pCompletionWrap)
	{
		goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
	}

	if (TDI_SEND == MinorFunction ||
		TDI_SEND_DATAGRAM == MinorFunction)
	{
		bIsSend = TRUE;
	}
	else
	{
		bIsSend = FALSE;
	}


	pCompletionWrap->bSendOpera = bIsSend;
	pCompletionWrap->bWrap = FALSE;
	pCompletionWrap->bAssocIrp = FALSE;
	pCompletionWrap->bSync = TRUE;
	pCompletionWrap->pEProcess = Process;
	pCompletionWrap->pProcessNetWorkTrafficInfo = pLmt;

	if (Irp->CurrentLocation <= 1)
	{
		ASSERT(FALSE);
		ExFreeToNPagedLookasideList(&g_CompletionWrapList, pCompletionWrap);
		goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
	}

	IoCopyCurrentIrpStackLocationToNext(Irp);

	IoSetCompletionRoutine(Irp,
		TdiFilterCompletion,
		pCompletionWrap,
		TRUE,
		TRUE,
		TRUE
		);

	g_CompletionIrpCount++;
	goto CALL_PDO_DRIVER; //CALL_PDO_DRIVER_WAIT_COMPLETE;

SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER:
	IoSkipCurrentIrpStackLocation(Irp);
CALL_PDO_DRIVER:
	return IoCallDriver(lowerDev, Irp);
COMPLETE_IRP:
	Irp->IoStatus.Status = ns;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, 0);
	return ns;
WHEN_ACCESS_DENIED:
	ns = STATUS_ACCESS_DENIED;
	goto COMPLETE_IRP;
}
NTSTATUS on_tdi_seteventhandler(PDEVICE_OBJECT lowerDev, PDEVICE_OBJECT object, PIRP Irp)
{
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList;
	PEPROCESS Process;
	PspGetIrpProcess(Irp, Process);
	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
	auto pFileObject = IrpStack->FileObject;
	auto MinorFunction = IrpStack->MinorFunction;
	auto _event = (PTDI_REQUEST_KERNEL_SET_EVENT)&(IrpStack->Parameters);
	auto event_type = _event->EventType;
	if (event_type == TDI_EVENT_CONNECT && _event->EventHandler)
	{
		auto new_context = new TDI_FW_CONTEXT;
		if (new_context)
		{
			RtlZeroBytes(new_context, sizeof(TDI_FW_CONTEXT));
			new_context->old_context = _event->EventContext;
			new_context->old_handler = _event->EventHandler;
			new_context->Process = Process;
			new_context->magic = CONTEXT_MAGIC;
			_event->EventHandler = (PVOID)on_tdi_ClientEventConnect;
		}
	}
	if (TDI_EVENT_RECEIVE == event_type ||
		TDI_EVENT_RECEIVE_EXPEDITED == event_type ||
		TDI_EVENT_CHAINED_RECEIVE == event_type ||
		TDI_EVENT_CHAINED_RECEIVE_EXPEDITED == event_type ||
		TDI_EVENT_RECEIVE_DATAGRAM == event_type)
	{
		//接受数据处理
		pTdiEventHandlerList = NULL;
		//KdBreakPoint();

		//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;

		if (NULL == _event->EventHandler)
		{
			IoSkipCurrentIrpStackLocation(Irp);
			auto ntStatus = IoCallDriver(lowerDev, Irp);

			if (!NT_SUCCESS(ntStatus))
			{
				return ntStatus;
			}

			UpdateEventHandlerWrap(NULL,
				NULL,
				NULL,
				pFileObject,
				event_type,
				NULL,
				NULL,
				&pTdiEventHandlerList,
				DEL_EVENT_WRAP);

			return ntStatus;
		}

		auto pProcessNetWorkTrafficInfo = get_lmt(Process);
		if (NULL == pProcessNetWorkTrafficInfo)
		{
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		UpdateEventHandlerWrap(pProcessNetWorkTrafficInfo,
			Process,
			lowerDev,
			pFileObject,
			_event->EventType,
			_event->EventHandler,
			_event->EventContext,
			&pTdiEventHandlerList,
			GET_EVENT_WRAP);

		release_lmt(pProcessNetWorkTrafficInfo->Process);

		if (NULL == pTdiEventHandlerList)
		{
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		if (TDI_EVENT_RECEIVE == event_type ||
			TDI_EVENT_RECEIVE_EXPEDITED == event_type)
		{
			_event->EventHandler = TdiFilterRecvEventHandler;
		}
		else if (TDI_EVENT_CHAINED_RECEIVE == event_type ||
			TDI_EVENT_CHAINED_RECEIVE_EXPEDITED == event_type)
		{
			_event->EventHandler = TdiFilterChainedRecvHandler;
		}
		else
		{
			_event->EventHandler = TdiFilterRecvDatagramEventHandler;
		}

		ASSERT(NULL != pTdiEventHandlerList->pTdiEventHandlerWrap);
		_event->EventContext = pTdiEventHandlerList->pTdiEventHandlerWrap;


		IoSkipCurrentIrpStackLocation(Irp);
		auto ntStatus = IoCallDriver(lowerDev, Irp);

		if (!NT_SUCCESS(ntStatus))
		{
			DeleteEventWrap(pTdiEventHandlerList);
		}
		return ntStatus;

	}
SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER:
	IoSkipCurrentIrpStackLocation(Irp);
	return IoCallDriver(lowerDev, Irp);
}

NTSTATUS NTAPI on_tdi_ClientEventConnect(
	_In_  PVOID              TdiEventContext,
	_In_  LONG               RemoteAddressLength,
	_In_  PVOID              RemoteAddress,
	_In_  LONG               UserDataLength,
	_In_  PVOID              UserData,
	_In_  LONG               OptionsLength,
	_In_  PVOID              Options,
	_Out_ CONNECTION_CONTEXT *ConnectionContext,
	_Out_ PIRP               *AcceptIrp
	)
{
	NTSTATUS ns;
	auto context = (TDI_FW_CONTEXT*)TdiEventContext;
	auto func = (ClientEventConnect)context->old_handler;
	auto old_context = context->old_context;
	//重要的事情！
	if (context->magic == CONTEXT_MAGIC)
	{
		auto remote_addr = ((TRANSPORT_ADDRESS *)RemoteAddress)->Address;
		auto ip = (TDI_ADDRESS_IP *)(remote_addr->Address);
		auto Address = ip->in_addr;
		auto port = ip->sin_port;
		LOG_DEBUG("be Conntected\r\n");
		LOG_DEBUG("Process %s\r\n", PsGetProcessImageFileName(context->Process));
		LOG_DEBUG("ip address:%d.%d.%d.%d\r\n",
			((char *)& Address)[0],
			((char *)& Address)[1],
			((char *)& Address)[2],
			((char *)& Address)[3]);
		LOG_DEBUG("port = %d\r\n", ddk::KSOCKET::ntohs(ip->sin_port));
		ns = func(old_context, RemoteAddressLength, RemoteAddress, UserDataLength, UserData, OptionsLength,
			Options, ConnectionContext, AcceptIrp);
		delete context;
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}
	//在这里截取acceptirp
	if (AcceptIrp != NULL)
	{
		if (*AcceptIrp != NULL)
		{
			PIO_STACK_LOCATION sa = IoGetCurrentIrpStackLocation(*AcceptIrp);
			//这里可以干很多事情！！
			//tdi_disconnect(sa->FileObject, 0);
			//return STATUS_ACCESS_DENIED;
		}
	}
	return ns;
}
void release_lmt(PEPROCESS Process)
{
	KLOCK_QUEUE_HANDLE _lock;
	lmt_control_lock.lock(&_lock);
	if (m_lmt_control.find(Process) != m_lmt_control.end())
	{
		auto pLmt = m_lmt_control[Process];
		auto dwCurRefCount = InterlockedExchangeAdd(&pLmt->dwRefCount, -1);
		if (1 == dwCurRefCount)
		{
			if (pLmt->TimerOk)
				KeCancelTimer(pLmt->pTimer);

			m_lmt_control.erase(Process);
			delete pLmt->pDpc;
			delete pLmt->pTimer;
			delete pLmt;
		}
		else
		{
			//特么逗我！
		}
	}
	lmt_control_lock.unlock(&_lock);
}

TDI_LMT *get_lmt(PEPROCESS Process)
{
	TDI_LMT *result = nullptr;
	KLOCK_QUEUE_HANDLE _lock;
	lmt_control_lock.lock(&_lock);
	if (m_lmt_control.find(Process) != m_lmt_control.end())
	{
		auto pLmt = m_lmt_control[Process];
		if (pLmt)
		{
			InterlockedExchangeAdd(&pLmt->dwRefCount, 1);
			if (!pLmt->TimerOk)
			{
				KeInitializeSpinLock(&pLmt->IrpListLock);

				InitializeListHead(&pLmt->IrpList);

				KeInitializeTimer(pLmt->pTimer);
				KeInitializeDpc(pLmt->pDpc, TimerDpcProcess, (PVOID)Process);
				KeSetTimer(pLmt->pTimer, g_TimerElapse, pLmt->pDpc);
				pLmt->SendingSpeed.QuadPart = pLmt->Rule.MaxSendSpeed;
				pLmt->RecvedSizeOneSec.QuadPart = pLmt->Rule.MaxRecvSpeed;
				pLmt->TimerOk = true;
			}
		}
		result = pLmt;
	}
	lmt_control_lock.unlock(&_lock);
	return result;
}
VOID ThreadSendingSpeedControl()
{
	ddk::nt_attach_filter::filter_dev_ext *pDeviceExtension;
	NTSTATUS ntStatus;
	BYTE OldIrql;
	BOOL bWaitEvent;
	DWORD dwConfiguredProcessIoInfoCount;
	LIST_ENTRY AllProcessIoList;
	LIST_ENTRY *pListEntry;
	TDI_LMT* pProcessNetWorkTrafficInfo;
	PIRP pIrp;
	PIRP pIrpListed;
	PLIST_ENTRY pIrpListEntry;
	DWORD dwIrpCount;
	PIO_STACK_LOCATION pIrpSp;
	PIO_STACK_LOCATION pIrpSpNext;
	PTDI_REQUEST_KERNEL_SEND pTdiSendParam = nullptr;
	PTDI_REQUEST_KERNEL_SENDDG pTdiSendDGParam = nullptr;
	DWORD dwTransferLength;
	DWORD dwThreadWaitTime;
	LARGE_INTEGER TransferredSize;
	BOOL bIrpContextNotAlloced;
	DWORD dwTransferred;
	PMDL pMdl;
	PMDL pAllocMdl;
	PMDL pMdlNext;
	PBYTE pIrpMdlVA;
	BOOL bAssocIrpMakeDone;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	DWORD dwIrpQueryLength;
	PIRP pAssocIrp;
	PIO_STACK_LOCATION pAssocIrpSp;
	PIO_STACK_LOCATION pAssocIrpSpNext;
	DWORD dwSendingSpeedHigh;
	KLOCK_QUEUE_HANDLE _lock;
	bWaitEvent = TRUE;
	dwConfiguredProcessIoInfoCount = 0;

	//_try
	//{
	for (; ; )
	{
		//KdBreakPoint();

		if (TRUE == g_bThreadIrpProcessStop)
		{
			InitializeListHead(&AllProcessIoList);
			lmt_control_lock.lock(&_lock);
			for (auto item : m_lmt_control)
			{
				pProcessNetWorkTrafficInfo = (TDI_LMT*)item.second;

				InterlockedExchangeAdd(
					&pProcessNetWorkTrafficInfo->dwRefCount,
					1);

				InsertTailList(&AllProcessIoList, &pProcessNetWorkTrafficInfo->ListEntry);

			}

			lmt_control_lock.unlock(&_lock);

			if (IsListEmpty(&AllProcessIoList))
			{
				break;
			}

			for (; ; )
			{
				pListEntry = AllProcessIoList.Flink;

				if (pListEntry == &AllProcessIoList)
				{
					break;
				}

				RemoveEntryList(pListEntry);

				pProcessNetWorkTrafficInfo = (TDI_LMT*)CONTAINING_RECORD(pListEntry, TDI_LMT, ListEntry);

				pIrp = DequeueIrp(&pProcessNetWorkTrafficInfo->IrpList, &pProcessNetWorkTrafficInfo->IrpListLock);

				if (NULL == pIrp) //If value is null, then reach the tail of the irp list.
				{
					continue;
				}

				//pIrp = ( PIRP )CONTAINING_RECORD( pIrpListEntry, IRP, Tail.Overlay.ListEntry );

				pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
				pDeviceExtension = (ddk::nt_attach_filter::filter_dev_ext *)pIrpSp->DeviceObject->DeviceExtension;
				if (NULL == pIrp->AssociatedIrp.MasterIrp)
				{
					IoSetCancelRoutine(pIrp, NULL);
					m_Cancle_table.erase(pIrp);
				}
				IoSkipCurrentIrpStackLocation(pIrp);
				IoCallDriver(pDeviceExtension->LowerDevice, pIrp);
				release_lmt(pProcessNetWorkTrafficInfo->Process);
			}

			break;
		}

		if (TRUE == bWaitEvent)
		{
			ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
			KeWaitForSingleObject(&g_EventIrpListAdded, Executive, KernelMode, FALSE, &g_WaitNewIistItemTime);
		}

		if (0 == dwConfiguredProcessIoInfoCount)
		{
			KeDelayExecutionThread(KernelMode, FALSE, &g_ThreadWaitConfigProcTime);
		}

		bWaitEvent = TRUE;
		dwConfiguredProcessIoInfoCount = 0;

		InitializeListHead(&AllProcessIoList);


		lmt_control_lock.lock(&_lock);
		for (auto item : m_lmt_control)
		{
			pProcessNetWorkTrafficInfo = (TDI_LMT*)item.second;
			if (pProcessNetWorkTrafficInfo->SendingSpeed.LowPart != 0xFFFFFFFF ||
				pProcessNetWorkTrafficInfo->SendingSpeed.HighPart != 0x7FFFFFFF)
			{
				dwConfiguredProcessIoInfoCount++; //Record the count of the send speed configured process.
			}

			InterlockedExchangeAdd(
				&pProcessNetWorkTrafficInfo->dwRefCount,
				1);

			InsertTailList(&AllProcessIoList, &pProcessNetWorkTrafficInfo->ListEntry);

		}

		lmt_control_lock.unlock(&_lock);

		if (IsListEmpty(&AllProcessIoList))
		{
			continue;
		}

		//KdBreakPoint();

		for (; ; )
		{
			PDEVICE_OBJECT pPdoDevice;
			pListEntry = AllProcessIoList.Flink;

			ASSERT(TRUE == MmIsAddressValid(pListEntry));
			if (pListEntry == &AllProcessIoList)
			{
				break;
			}

			RemoveEntryList(pListEntry);

			pProcessNetWorkTrafficInfo = (TDI_LMT*)CONTAINING_RECORD(pListEntry, TDI_LMT, ListEntry);

			pIrp = DequeueIrp(&pProcessNetWorkTrafficInfo->IrpList, &pProcessNetWorkTrafficInfo->IrpListLock);

			if (NULL == pIrp) //If value is null, then reach the tail of the irp list.
			{
				goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
			}

			//pIrp = ( PIRP )CONTAINING_RECORD( pIrpListEntry, IRP, Tail.Overlay.ListEntry );

			//#define METHOD_BUFFERED                 0
			//#define METHOD_IN_DIRECT                1
			//#define METHOD_OUT_DIRECT               2
			//#define METHOD_NEITHER                  3

			//#define TDI_SEND                 (0x07) METHOD_NEITHER
			//#define TDI_RECEIVE              (0x08) METHOD_BUFFERED
			//#define TDI_SEND_DATAGRAM        (0x09) METHOD_IN_DIRECT
			//#define TDI_RECEIVE_DATAGRAM     (0x0A) METHOD_OUT_DIRECT
			//#define TDI_SET_EVENT_HANDLER    (0x0B) METHOD_NEITHER

			bWaitEvent = FALSE;
			dwIrpCount = pIrp->AssociatedIrp.IrpCount;

			KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
			KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
			KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
			KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
			KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
			//pIrpSp = IoGetCurrentIrpStackLocation( pIrp );
			//pDeviceExtension = ( PTDI_FILTER_DEVICE_EXTENSION )pIrpSp->DeviceObject->DeviceExtension;

			//goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;

			if (0 == dwIrpCount)
			{
				pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
				pDeviceExtension = (ddk::nt_attach_filter::filter_dev_ext*)pIrpSp->DeviceObject->DeviceExtension;
				pPdoDevice = pDeviceExtension->LowerDevice;
			}
			else
			{
				pIrpSp = IoGetNextIrpStackLocation(pIrp);
				pPdoDevice = pIrpSp->DeviceObject;
				pDeviceExtension = NULL;
			}

			ASSERT(TDI_SEND == pIrpSp->MinorFunction ||
				TDI_SEND_DATAGRAM == pIrpSp->MinorFunction);

			if (TDI_SEND == pIrpSp->MinorFunction)
			{
				pTdiSendParam = (PTDI_REQUEST_KERNEL_SEND)&pIrpSp->Parameters;
				dwTransferLength = pTdiSendParam->SendLength;
			}
			else
			{
				pTdiSendDGParam = (PTDI_REQUEST_KERNEL_SENDDG)&pIrpSp->Parameters;
				dwTransferLength = pTdiSendDGParam->SendLength;
			}

			//Control speeding speed by depart sending length and make these to associated irps, so this original irp become the master irp.
			if (dwTransferLength > pProcessNetWorkTrafficInfo->Rule.MaxSendSpeed)
			{
				if (0 == dwIrpCount)
				{
					pMdl = pIrp->MdlAddress;
					if (NULL == pMdl)
					{
						ASSERT(FALSE);
						goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
					}

					if (dwTransferLength != MmGetMdlByteCount(pMdl))
					{
						ASSERT(FALSE);
						goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
					}

					pIrpMdlVA = (PBYTE)MmGetMdlVirtualAddress(pMdl);

					if (NULL == pIrpMdlVA)
					{
						ASSERT(FALSE);
						goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
					}

					dwTransferred = 0;

					for (; ; )
					{
						if (dwTransferred >= dwTransferLength)
						{
							goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
						}

						bAssocIrpMakeDone = FALSE;
						dwIrpQueryLength = dwTransferLength - dwTransferred;

						if (pProcessNetWorkTrafficInfo->Rule.MaxSendSpeed < dwIrpQueryLength)
						{
							//If sending speed is negative, then it limits the max data size of you departed fragment of the packet.
							dwIrpQueryLength = pProcessNetWorkTrafficInfo->SendingSpeed.LowPart;
							dwSendingSpeedHigh = pProcessNetWorkTrafficInfo->SendingSpeed.HighPart;
						}
						else
						{
							dwSendingSpeedHigh = 0;
						}

						ASSERT(NULL != pDeviceExtension);

						pAssocIrp = IoMakeAssociatedIrp(
							pIrp,
							pDeviceExtension->LowerDevice->StackSize
							);

						if (NULL == pAssocIrp)
						{
							goto RELEASE_ASSOCIATED_IRP;
						}

						ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);


						pAllocMdl = IoAllocateMdl(
							pIrpMdlVA,
							dwTransferLength,
							FALSE,
							0,
							pAssocIrp
							);

						if (NULL == pAllocMdl)
						{
							IoFreeIrp(pAssocIrp);
							goto RELEASE_ASSOCIATED_IRP;
						}

						ASSERT(dwIrpQueryLength + dwTransferred <= dwTransferLength);

						IoBuildPartialMdl(
							pIrp->MdlAddress,
							pAllocMdl,
							pIrpMdlVA - dwIrpQueryLength - dwTransferred + dwTransferLength,
							dwIrpQueryLength
							);


						dwTransferred += dwIrpQueryLength;

						ASSERT(pAssocIrp->AssociatedIrp.MasterIrp == pIrp);

						pAssocIrpSpNext = IoGetNextIrpStackLocation(pAssocIrp);

						//This new associated irp do the same function of the original irp.
						pAssocIrpSpNext->MajorFunction = pIrpSp->MajorFunction;
						pAssocIrpSpNext->MinorFunction = pIrpSp->MinorFunction;
						pAssocIrpSpNext->DeviceObject = pDeviceExtension->LowerDevice;
						pAssocIrpSpNext->FileObject = pIrpSp->FileObject;


						if (TDI_SEND == pAssocIrpSpNext->MinorFunction)
						{
							PTDI_REQUEST_KERNEL_SEND pRequestSend;
							pRequestSend = (PTDI_REQUEST_KERNEL_SEND)&pAssocIrpSpNext->Parameters;

							pRequestSend->SendFlags = pTdiSendParam->SendFlags;
							pRequestSend->SendLength = dwIrpQueryLength;

						}
						else
						{
							PTDI_REQUEST_KERNEL_SENDDG pRequestSendDG;
							pRequestSendDG = (PTDI_REQUEST_KERNEL_SENDDG)&pAssocIrpSpNext->Parameters;

							pRequestSendDG->SendDatagramInformation = pTdiSendDGParam->SendDatagramInformation;;
							pRequestSendDG->SendLength = dwIrpQueryLength;

						}

						pAssocIrp->MdlAddress = pAllocMdl;
						bAssocIrpMakeDone = TRUE;


						InterlockedExchangeAdd(&pIrp->AssociatedIrp.IrpCount, 1);

						{
							KIRQL IrpSpIrql;
							PDRIVER_CANCEL OldCancelRoutine;

							KeAcquireSpinLock(&pProcessNetWorkTrafficInfo->IrpListLock, &IrpSpIrql);

							m_Cancle_table[pAssocIrp] = pProcessNetWorkTrafficInfo;

							IoMarkIrpPending(pAssocIrp);
							OldCancelRoutine = IoSetCancelRoutine(pAssocIrp, TdiFilterCancel);
							ASSERT(NULL == OldCancelRoutine);

							InsertTailList(&pProcessNetWorkTrafficInfo->IrpList, &pAssocIrp->Tail.Overlay.ListEntry);

							if (pIrp->Cancel)
							{
								OldCancelRoutine = IoSetCancelRoutine(pAssocIrp, NULL);
								if (OldCancelRoutine)
								{
									RemoveEntryList(&pIrp->Tail.Overlay.ListEntry);
									KeReleaseSpinLock(&pProcessNetWorkTrafficInfo->IrpListLock, IrpSpIrql);
									pAssocIrp->IoStatus.Status = STATUS_CANCELLED;
									pAssocIrp->IoStatus.Information = 0;
									IoCompleteRequest(pAssocIrp, IO_NO_INCREMENT);
									continue;
								}
							}

							KeReleaseSpinLock(&pProcessNetWorkTrafficInfo->IrpListLock, IrpSpIrql);
						}
						//ExInterlockedInsertHeadList( &pProcessNetWorkTrafficInfo->IrpList, &pAssocIrp->Tail.Overlay.ListEntry, &pProcessNetWorkTrafficInfo->IrpListLock );

						//#define TDI_ASSOCIATE_ADDRESS    (0x01)
						//#define TDI_DISASSOCIATE_ADDRESS (0x02)
						//#define TDI_CONNECT              (0x03)
						//#define TDI_LISTEN               (0x04)
						//#define TDI_ACCEPT               (0x05)
						//#define TDI_DISCONNECT           (0x06)
						//#define TDI_SEND                 (0x07)
						//#define TDI_RECEIVE              (0x08)
						//#define TDI_SEND_DATAGRAM        (0x09)
						//#define TDI_RECEIVE_DATAGRAM     (0x0A)
						//#define TDI_SET_EVENT_HANDLER    (0x0B)
						//#define TDI_QUERY_INFORMATION    (0x0C)
						//#define TDI_SET_INFORMATION      (0x0D)
						//#define TDI_ACTION               (0x0E)
						//
						//#define TDI_DIRECT_SEND          (0x27)
						//#define TDI_DIRECT_SEND_DATAGRAM (0x29)
						//delay this irp and its associated irps processing to next loop. 

					RELEASE_ASSOCIATED_IRP:
						if (FALSE == bAssocIrpMakeDone)
						{
							//Release previous added associated irps.
							for (; ; )
							{

								if (0 == pIrp->AssociatedIrp.IrpCount)
								{
									break;
								}

								pIrpListEntry = ExInterlockedRemoveHeadList(&pProcessNetWorkTrafficInfo->IrpList,
									&pProcessNetWorkTrafficInfo->IrpListLock);

								if (NULL == pIrpListEntry)
								{
									ASSERT(FALSE);
									InterlockedExchangeAdd(&pIrp->AssociatedIrp.IrpCount, -1);
									continue;
								}

								pIrpListed = CONTAINING_RECORD(pIrpListEntry, IRP, Tail.Overlay.ListEntry);
								pMdl = pIrpListed->MdlAddress;

								for (; ; )
								{
									if (NULL == pMdl)
									{
										break;
									}

									pMdlNext = pMdl->Next;

									IoFreeMdl(pMdl);
									pMdl = pMdlNext;

								}

								IoFreeIrp(pIrpListed);
								InterlockedExchangeAdd(&pIrp->AssociatedIrp.IrpCount, -1);
							}

							goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
						}

						continue;
					}
				}
			}

			dwThreadWaitTime = 0;

			//If sending speed is positive, then it limits the data size of one send time
			for (; ; )
			{
				if (pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart + dwTransferLength > pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart)
				{
					//Delay the sending function to longer time to match the seted sending speed.
					if (dwTransferLength <= pProcessNetWorkTrafficInfo->SendingSpeed.QuadPart)
					{
						KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
						dwThreadWaitTime++;
						if (5 > dwThreadWaitTime)
						{
							continue;
						}

						ExInterlockedInsertHeadList(&pProcessNetWorkTrafficInfo->IrpList,
							&pIrp->Tail.Overlay.ListEntry,
							&pProcessNetWorkTrafficInfo->IrpListLock);

						goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
					}
					else
					{
						break;
					}
				}
				else
				{
					break;
				}
			}


			bIrpContextNotAlloced = FALSE;
			pProcessNetWorkTrafficInfo->SendedSizeOneSec.QuadPart += dwTransferLength;

			ASSERT(pIrpSp->MinorFunction == TDI_SEND ||
				pIrpSp->MinorFunction == TDI_SEND_DATAGRAM);

			if (0 != dwIrpCount)
			{

				pCompletionWrap = (PTDI_COMPLETION_WRAP)ExAllocateFromNPagedLookasideList(&g_CompletionWrapList);
				if (NULL != pCompletionWrap)
				{
					pCompletionWrap->bSendOpera = TRUE;
					pCompletionWrap->bWrap = FALSE;
					pCompletionWrap->bAssocIrp = TRUE;
					pCompletionWrap->pEProcess = pProcessNetWorkTrafficInfo->Process;
					pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;
				}
				else
				{
					bIrpContextNotAlloced = TRUE;
				}

				pIrpSp = IoGetNextIrpStackLocation(pIrp);
				ASSERT(NULL != pIrpSp->DeviceObject);

				if (FALSE == bIrpContextNotAlloced)
				{
					IoSetCompletionRoutine(pIrp,
						TdiFilterCompletion,
						pCompletionWrap,
						TRUE,
						TRUE,
						TRUE
						);
					g_CompletionIrpCount++;
					IoCallDriver(pIrpSp->DeviceObject, pIrp);
					ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
				}
				else
				{
					IoCallDriver(pIrpSp->DeviceObject, pIrp);
				}

				goto RELEASE_PROCESS_IO_INFO_GET_NEXT;
			}

			if (1 >= pIrp->CurrentLocation)
			{
				ASSERT(FALSE);
				goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
			}

			pCompletionWrap = (PTDI_COMPLETION_WRAP)ExAllocateFromNPagedLookasideList(&g_CompletionWrapList);

			if (NULL == pCompletionWrap)
			{
				goto SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC;
			}

			pCompletionWrap->bSendOpera = TRUE;
			pCompletionWrap->bWrap = FALSE;
			pCompletionWrap->bAssocIrp = FALSE;
			pCompletionWrap->pEProcess = pProcessNetWorkTrafficInfo->Process;
			pCompletionWrap->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;

			IoCopyCurrentIrpStackLocationToNext(pIrp);

			IoSetCompletionRoutine(pIrp,
				TdiFilterCompletion,
				pCompletionWrap,
				TRUE,
				TRUE,
				TRUE
				);


			IoSetCancelRoutine(pIrp, NULL);
			m_Cancle_table.erase(pIrp);
			g_CompletionIrpCount++;
			IoCallDriver(pDeviceExtension->LowerDevice, pIrp);
			ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
			goto RELEASE_PROCESS_IO_INFO_GET_NEXT;

		SKIP_CURRENT_STACK_LOCATION_RELEASE_PROCESS_NETWORK_TRAFFIC_GET_NEXT_PROCESS_NETWORK_TRAFFIC:
			IoSkipCurrentIrpStackLocation(pIrp);
			//CALL_PDO_DEVICE_DRIVER:
			IoCallDriver(pDeviceExtension->LowerDevice, pIrp);

		RELEASE_PROCESS_IO_INFO_GET_NEXT:
			release_lmt(pProcessNetWorkTrafficInfo->Process);
			continue;
		}
	}

	PsTerminateSystemThread(STATUS_SUCCESS);
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//	InterlockedExchange( &g_bThreadsRunning, FALSE );
	//	PsTerminateSystemThread( STATUS_SUCCESS );
	//	return;
	//}
}
//////////////////////////////////////////////////////////////////////////
DWORD ReleaseAllEventHandlerWrap()
{
	NTSTATUS ntStatus;
	DWORD dwErrorCount;
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PLIST_ENTRY pListEntryPrev;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrap;

	KeAcquireSpinLock(&g_SpLockTdiEventHandlerInfo, &OldIrql);

	pListEntry = g_TdiEventHandlerInfoList.Flink;

	dwErrorCount = 0;

	for (; ; )
	{
		if (pListEntry == &g_TdiEventHandlerInfoList)
		{
			break;
		}

		pListEntryPrev = pListEntry->Flink;

		pTdiEventHandlerList = (PTDI_EVENT_HANDLER_LIST)pListEntry;

		RemoveEntryList(pListEntry);

		ntStatus = RestoreEventHandler(pTdiEventHandlerList->pTdiEventHandlerWrap);
		if (!NT_SUCCESS(ntStatus))
		{
			dwErrorCount++;
		}

		ExFreePoolWithTag(pTdiEventHandlerList->pTdiEventHandlerWrap, 0);
		ExFreePoolWithTag(pTdiEventHandlerList, 0);

		pListEntry = pListEntryPrev;
	}

	KeReleaseSpinLock(&g_SpLockTdiEventHandlerInfo, OldIrql);
	return dwErrorCount;
}
//////////////////////////////////////////////////////////////////////////
void release_all_lmt()
{
	KLOCK_QUEUE_HANDLE _lock;
	lmt_control_lock.lock(&_lock);
	for (auto item:m_lmt_control)
	{
		auto pLmt = item.second;
		auto dwCurRefCount = InterlockedExchangeAdd(&pLmt->dwRefCount, -1);
		if (1 == dwCurRefCount)
		{
			if (pLmt->TimerOk)
				KeCancelTimer(pLmt->pTimer);
			delete pLmt->pDpc;
			delete pLmt->pTimer;
			delete pLmt;
			m_lmt_control[pLmt->Process] = nullptr;
		}
		else
		{
			//特么逗我！
			
		}
	}
	lmt_control_lock.unlock(&_lock);
}
//////////////////////////////////////////////////////////////////////////
void terminate_tdi_filter()
{
	//卸载
	g_bThreadIrpProcessStop = TRUE;

	ThreadProcessIrp.join();

	ReleaseAllEventHandlerWrap();

	release_all_lmt();

	KeSetEvent(&g_EventCompletion, 0, FALSE);
	ThreadProcessWait.join();

	ExDeleteNPagedLookasideList(&g_CompletionWrapList);
	ExDeleteResourceLite(&g_SyncResource);
}
//////////////////////////////////////////////////////////////////////////
VOID TimerDpcProcess(PKDPC pDpc, PVOID Context, PVOID SystemArgument1, PVOID SystemArgument2)
{
	LARGE_INTEGER UpdatedValue;
	auto Process = (PEPROCESS)Context;
	KLOCK_QUEUE_HANDLE _lock;
	lmt_control_lock.lock(&_lock);
	if (m_lmt_control.find(Process) != m_lmt_control.end())
	{
		auto pLmt = m_lmt_control[Process];
		UpdatedValue.QuadPart = 0;
		InterlockedExchangeAdd(&pLmt->dwRefCount, 1);

		InterlockedExchange64(
			&pLmt->SendedSizeOneSec.QuadPart,
			UpdatedValue.QuadPart);

		InterlockedExchange64(
			&pLmt->RecvedSizeOneSec.QuadPart,
			UpdatedValue.QuadPart);

		if (pLmt->AllSuccSendedDataSize.QuadPart >=
			pLmt->AllSuccSendedDataSizePrev.QuadPart)
		{
			UpdatedValue.QuadPart = pLmt->AllSuccSendedDataSize.QuadPart -
				pLmt->AllSuccSendedDataSizePrev.QuadPart;

			InterlockedExchange64(
				&pLmt->SuccSendedDataSizeOnce.QuadPart,
				UpdatedValue.QuadPart
				);
		}

		InterlockedExchange64(
			&pLmt->AllSuccSendedDataSizePrev.QuadPart,
			pLmt->AllSuccSendedDataSize.QuadPart
			);

		if (pLmt->AllSuccRecvedDataSize.QuadPart >=
			pLmt->AllSuccRecvedDataSizePrev.QuadPart)
		{
			UpdatedValue.QuadPart = pLmt->AllSuccRecvedDataSize.QuadPart -
				pLmt->AllSuccRecvedDataSizePrev.QuadPart;

			InterlockedExchange64(
				&pLmt->SuccRecvedDataSizeOnce.QuadPart,
				UpdatedValue.QuadPart
				);
		}

		InterlockedExchange64(
			&pLmt->AllSuccRecvedDataSizePrev.QuadPart,
			pLmt->AllSuccRecvedDataSize.QuadPart
			);

		KeSetTimer(pLmt->pTimer,
			g_TimerElapse,
			pLmt->pDpc); //Loop the timer

		InterlockedExchangeAdd(&pLmt->dwRefCount, -1);
	}
	lmt_control_lock.unlock(&_lock);
}
//////////////////////////////////////////////////////////////////////////
VOID TdiFilterCancel(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
	)
{
	PIRP pAssocIrp = NULL;
	KIRQL OldIrql;
	KIRQL CancelIrql = Irp->CancelIrql;
	NTSTATUS ntStatus;

	KdBreakPoint();

	IoReleaseCancelSpinLock(CancelIrql);

FIND_ASSOC_IRPS:
	auto pProcessNetWorkTraffic = m_Cancle_table[Irp];
	ASSERT(TRUE == MmIsAddressValid(pProcessNetWorkTraffic));

	KeAcquireSpinLock(&pProcessNetWorkTraffic->IrpListLock, &OldIrql);

	auto pListEntry = pProcessNetWorkTraffic->IrpList.Flink;

	for (; ; )
	{
		if (pListEntry == &pProcessNetWorkTraffic->IrpList)
		{
			break;
		}

		pAssocIrp = CONTAINING_RECORD(pListEntry, IRP, Tail.Overlay.ListEntry);


		if (Irp == pAssocIrp->AssociatedIrp.MasterIrp)
		{

			RemoveEntryList(&pAssocIrp->Tail.Overlay.ListEntry);
			KeReleaseSpinLock(&pProcessNetWorkTraffic->IrpListLock, OldIrql);

			pAssocIrp->IoStatus.Status = STATUS_CANCELLED;
			pAssocIrp->IoStatus.Information = 0;

			IoCompleteRequest(pAssocIrp, IO_NO_INCREMENT);
			goto FIND_ASSOC_IRPS;
		}
		pListEntry = pListEntry->Flink;
	}

	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
	KeReleaseSpinLock(&pProcessNetWorkTraffic->IrpListLock, OldIrql);

	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	KdBreakPoint();
	m_Cancle_table.erase(Irp);

	return;
	//ASSERT( 0 <= ntStatus );
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS TdiFilterCompletion(PDEVICE_OBJECT pDeviceObject, PIRP pIrp, LPVOID pContext)
{
	NTSTATUS ntStatus;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	TDI_LMT* pProcessNetWorkTrafficInfo;
	TDI_LMT* pProcessNetWorkTrafficInfoHost;
	LARGE_INTEGER TransferredDataSize;
	PIRP pMasterIrp;
	PIO_STACK_LOCATION pIrpSp;

	g_CompletionIrpCount--;

	//ASSERT( NULL == pDeviceObject );

	if (FALSE == MmIsAddressValid(pContext))
	{
		ASSERT(FALSE);
		goto RETURN_SUCCESS;
	}

	if (NULL == pIrp ||
		NULL == pContext)
	{
		ASSERT(FALSE);
		goto RETURN_SUCCESS;
	}

	ntStatus = pIrp->IoStatus.Status;

	pCompletionWrap = (PTDI_COMPLETION_WRAP)pContext;

	ASSERT(NULL != pCompletionWrap->pEProcess);

	if (NT_SUCCESS(ntStatus))
	{
		pProcessNetWorkTrafficInfo = get_lmt(pCompletionWrap->pEProcess);
		if (NULL == pProcessNetWorkTrafficInfo)
		{
			goto COMPLETE_IRP;
		} //Check the process of completion context validity.

		TransferredDataSize.QuadPart = pIrp->IoStatus.Information;

		pProcessNetWorkTrafficInfoHost = (TDI_LMT*)pCompletionWrap->pProcessNetWorkTrafficInfo;

		ASSERT(NULL != pProcessNetWorkTrafficInfoHost);
		ASSERT(pProcessNetWorkTrafficInfoHost == pProcessNetWorkTrafficInfo);

		if (pCompletionWrap->bSendOpera)
		{
			InterlockedExchangeAdd64(&pProcessNetWorkTrafficInfoHost->AllSuccSendedDataSize.QuadPart,
				TransferredDataSize.QuadPart);

			InterlockedExchangeAdd64(&g_AllSendedDataSize.QuadPart,
				TransferredDataSize.QuadPart);
		}
		else
		{
			InterlockedExchangeAdd64(&pProcessNetWorkTrafficInfoHost->AllSuccRecvedDataSize.QuadPart,
				TransferredDataSize.QuadPart);

			InterlockedExchangeAdd64(&g_AllRecvedDataSize.QuadPart,
				TransferredDataSize.QuadPart);
		}

		release_lmt(pCompletionWrap->pEProcess);
	}

COMPLETE_IRP:
	ASSERT(FALSE == (pCompletionWrap->bWrap && pCompletionWrap->bAssocIrp));

	if (FALSE == pCompletionWrap->bWrap ||
		NULL == pCompletionWrap->pCompletionRoutine)
	{
		goto CHECK_PENDING_RETURN;
	}

	if (NT_SUCCESS(ntStatus))
	{
		if (SL_INVOKE_ON_SUCCESS & pCompletionWrap->Control)
		{
			goto CALL_ORG_COMPLETION_FUNCTION;
		}
	}
	else
	{
		if (SL_INVOKE_ON_ERROR & pCompletionWrap->Control)
		{
			goto CALL_ORG_COMPLETION_FUNCTION;
		}
	}

	if (TRUE == pIrp->Cancel)
	{
		if (SL_INVOKE_ON_CANCEL | pCompletionWrap->Control)
		{
			goto CALL_ORG_COMPLETION_FUNCTION;
		}
	}

	goto COMPLETE_ASSOCIATED_IRP;

CHECK_PENDING_RETURN:

	if (FALSE == pIrp->PendingReturned)
	{
		goto COMPLETE_ASSOCIATED_IRP;
	}

	if (TRUE == pCompletionWrap->bAssocIrp) //If this irp is the associated irp, it don't need to have the pending flag.
	{
		goto COMPLETE_ASSOCIATED_IRP;
	}

	if (TRUE == pCompletionWrap->bWrap) //If have wraped completion routine, then left this pending flag seting operation to it.
	{
		goto COMPLETE_ASSOCIATED_IRP;
	}

	IoGetCurrentIrpStackLocation(pIrp)->Control |= SL_PENDING_RETURNED;

	goto COMPLETE_ASSOCIATED_IRP;

CALL_ORG_COMPLETION_FUNCTION:

	ntStatus = pCompletionWrap->pCompletionRoutine(pDeviceObject,
		pIrp,
		pCompletionWrap->pContext);

COMPLETE_ASSOCIATED_IRP:

	if (FALSE == pCompletionWrap->bAssocIrp)
	{
		goto FREE_COMPLETION_WRAP;
	}

	if (NULL == pIrp->AssociatedIrp.MasterIrp)
	{
		goto FREE_COMPLETION_WRAP;
	}

	pMasterIrp = pIrp->AssociatedIrp.MasterIrp;
	pMasterIrp->IoStatus.Information += pIrp->IoStatus.Information;
	pMasterIrp->IoStatus.Status = pIrp->IoStatus.Status;

	if (1 == pMasterIrp->AssociatedIrp.IrpCount)
	{

		IoSetCancelRoutine(pMasterIrp, NULL);
		m_Cancle_table.erase(pMasterIrp);
	}


FREE_COMPLETION_WRAP:
	ExFreeToNPagedLookasideList(&g_CompletionWrapList, pCompletionWrap);

	ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
	KeSetEvent(&g_EventCompletion, 0, FALSE);
	return ntStatus;

RETURN_SUCCESS:
	return STATUS_SUCCESS;
}
//////////////////////////////////////////////////////////////////////////
NTSTATUS TdiFilterSyncSendProcess(TDI_LMT* pLmt, PDEVICE_OBJECT lwobj, PDEVICE_OBJECT object, PIRP Irp)
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION pIrpSp;
	LARGE_INTEGER SendedSizeOneSec;
	LARGE_INTEGER SendRequireSize;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	PIO_STACK_LOCATION pIrpSpNext;
	PIRP pAssocIrp;
	PMDL pMdlAlloced;
	PMDL pMdl;
	PBYTE pMdlVA;
	DWORD dwSendLength;
	DWORD dwSendedLength;

	KdBreakPoint();

	ASSERT(NULL == pIrp->AssociatedIrp.SystemBuffer);

	//_try
	//{

	pIrpSp = IoGetCurrentIrpStackLocation(Irp);

	//goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;

	ASSERT(TDI_SEND == pIrpSp->MinorFunction ||
		TDI_SEND_DATAGRAM == pIrpSp->MinorFunction);

	dwSendLength = PtrToUlong(pIrpSp->Parameters.Others.Argument1);

	if (pLmt->SendingSpeed.QuadPart >= dwSendLength)
	{
		if (Irp->CurrentLocation <= 1)
		{
			ASSERT(FALSE);
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		for (; ; )
		{
			SendedSizeOneSec.QuadPart = pLmt->SendedSizeOneSec.QuadPart;
			SendedSizeOneSec.QuadPart += dwSendLength;

			if (SendedSizeOneSec.QuadPart >
				pLmt->Rule.MaxSendSpeed)
			{
				if (pLmt->SendingSpeed.QuadPart >= dwSendLength)
				{
					KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
					continue;
				}
				else
				{
					break;
				}
			}
			else
			{
				break;
			}
		}

		pCompletionWrap = (PTDI_COMPLETION_WRAP)ExAllocateFromNPagedLookasideList(&g_CompletionWrapList);
		if (NULL == pCompletionWrap)
		{
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		pLmt->SendedSizeOneSec.QuadPart += dwSendLength;
		pCompletionWrap->bSendOpera = TRUE;
		pCompletionWrap->bWrap = FALSE;
		pCompletionWrap->bAssocIrp = FALSE;
		pCompletionWrap->bSync = TRUE;

		pCompletionWrap->pEProcess = pLmt->Process;
		pCompletionWrap->pProcessNetWorkTrafficInfo = pLmt; //must got the process inforamtion reference.

		IoCopyCurrentIrpStackLocationToNext(Irp);

		IoSetCompletionRoutine(Irp,
			TdiFilterCompletion,
			pCompletionWrap,
			TRUE,
			TRUE,
			TRUE
			);

		g_CompletionIrpCount++;
		ntStatus = IoCallDriver(lwobj, Irp);

		return ntStatus;
	}
	else
	{
		dwSendedLength = 0;
		pMdl = Irp->MdlAddress;

		if (NULL == pMdl)
		{
			ASSERT(FALSE);
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		if (dwSendLength != MmGetMdlByteCount(pMdl))
		{
			ASSERT(FALSE);
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		pMdlVA = (PBYTE)MmGetMdlVirtualAddress(pMdl);

		if (NULL == pMdlVA)
		{
			ASSERT(pMdlVA);
			goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
		}

		ntStatus = STATUS_UNSUCCESSFUL;

		for (; ; )
		{
			if (dwSendedLength >= dwSendLength)
			{
				return ntStatus;
			}

			SendRequireSize.QuadPart = dwSendLength - dwSendedLength;

			if (pLmt->Rule.MaxSendSpeed < SendRequireSize.QuadPart)
			{
				SendRequireSize.QuadPart = pLmt->Rule.MaxSendSpeed;
			}

			pAssocIrp = IoMakeAssociatedIrp(Irp, lwobj->StackSize);
			if (NULL == pAssocIrp)
			{
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			pMdlAlloced = IoAllocateMdl(
				pMdlVA,
				dwSendLength,
				FALSE,
				0,
				pAssocIrp
				);

			if (NULL == pMdlAlloced)
			{
				IoFreeIrp(pAssocIrp);
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			InterlockedExchangeAdd(&Irp->AssociatedIrp.IrpCount, 1);

			IoBuildPartialMdl(Irp->MdlAddress,
				pMdlAlloced,
				pMdlVA + dwSendedLength,
				SendRequireSize.LowPart);

			dwSendedLength += SendRequireSize.LowPart;

			pIrpSpNext = IoGetNextIrpStackLocation(pAssocIrp);

			pIrpSpNext->MajorFunction = pIrpSp->MajorFunction;
			pIrpSpNext->MinorFunction = pIrpSp->MinorFunction;
			pIrpSpNext->DeviceObject = lwobj;
			pIrpSpNext->FileObject = pIrpSp->FileObject;

			pIrpSpNext->Parameters.Others.Argument1 = (PVOID)SendRequireSize.LowPart;
			pIrpSpNext->Parameters.Others.Argument2 = pIrpSp->Parameters.Others.Argument2;

			pAssocIrp->MdlAddress = pMdlAlloced;

			for (; ; )
			{
				if (pLmt->SendedSizeOneSec.QuadPart + SendRequireSize.QuadPart >
					pLmt->Rule.MaxSendSpeed)
				{
					if (SendRequireSize.QuadPart <= pLmt->Rule.MaxSendSpeed)
					{
						KeDelayExecutionThread(KernelMode, FALSE, &g_SendingDelayTime);
						continue;
					}
					else
					{
						break;
					}
				}
				else
				{
					break;
				}
			}

			pCompletionWrap = (PTDI_COMPLETION_WRAP)ExAllocateFromNPagedLookasideList(&g_CompletionWrapList);
			if (NULL == pCompletionWrap)
			{
				goto SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER;
			}

			pLmt->SendedSizeOneSec.QuadPart += SendRequireSize.LowPart;
			pCompletionWrap->bSendOpera = TRUE;
			pCompletionWrap->bWrap = FALSE; //If synchronized operation, it must not have the completion routine.
			pCompletionWrap->bAssocIrp = FALSE;
			pCompletionWrap->bSync = TRUE;

			pCompletionWrap->pEProcess = pLmt->Process;
			pCompletionWrap->pProcessNetWorkTrafficInfo = pLmt;

			IoSetCompletionRoutine(pAssocIrp,
				TdiFilterCompletion,
				pCompletionWrap,
				TRUE,
				TRUE,
				TRUE
				);

			g_CompletionIrpCount++;
			ntStatus = IoCallDriver(pIrpSpNext->DeviceObject, pAssocIrp);
			ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
		}
	}
	//}
	//_except( EXCEPTION_EXECUTE_HANDLER )
	//{
	//}

SKIP_CURRENT_STACK_LOCATION_CALL_PDO_DRIVER:
	IoSkipCurrentIrpStackLocation(Irp);
	//CALL_PDO_DRIVER:
	return IoCallDriver(lwobj, Irp);
}

//////////////////////////////////////////////////////////////////////////
PIRP DequeueIrp(PLIST_ENTRY pListHead, PKSPIN_LOCK SpLock)
{
	KIRQL oldIrql;
	PIRP nextIrp = NULL;

	KeAcquireSpinLock(SpLock, &oldIrql);

	while (!nextIrp && !IsListEmpty(pListHead))
	{
		PDRIVER_CANCEL oldCancelRoutine;
		PLIST_ENTRY listEntry = RemoveHeadList(pListHead);

		// Get the next IRP off the queue.
		nextIrp = CONTAINING_RECORD(listEntry, IRP, Tail.Overlay.ListEntry);

		if (NULL == nextIrp->AssociatedIrp.MasterIrp)
		{
			//  Clear the IRP's cancel routine
			oldCancelRoutine = IoSetCancelRoutine(nextIrp, NULL);
			//  IoCancelIrp() could have just been called on this IRP.
			//  What we're interested in is not whether IoCancelIrp() was called (nextIrp->Cancel flag set),
			//  but whether IoCancelIrp() called (or is about to call) our cancel routine.
			//  To check that, check the result of the test-and-set macro IoSetCancelRoutine.
			if (oldCancelRoutine) {
				//  Cancel routine not called for this IRP.  Return this IRP.
				ASSERT(oldCancelRoutine == TdiFilterCancel);
			}
			else {
				//  This IRP was just canceled and the cancel routine was (or will be) called.
				//  The cancel routine will complete this IRP as soon as we drop the spin lock,
				//  so don't do anything with the IRP.
				//  Also, the cancel routine will try to dequeue the IRP, 
				//  so make the IRP's listEntry point to itself.
				ASSERT(nextIrp->Cancel);
				InitializeListHead(&nextIrp->Tail.Overlay.ListEntry);
				nextIrp = NULL;
			}
		}
	}

	KeReleaseSpinLock(SpLock, oldIrql);

	return nextIrp;
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS RestoreEventHandler(PTDI_EVENT_HANDLER_WRAP pEventHandlerWrap)
{
	NTSTATUS ntStatus;
	PIRP pIrp = NULL;
	PDEVICE_OBJECT pDeviceObject;

	ASSERT(NULL != pEventHandlerWrap);

	ASSERT(FALSE != MmIsAddressValid(pEventHandlerWrap));
	pDeviceObject = pEventHandlerWrap->pDeviceObject;

	ASSERT(FALSE != MmIsAddressValid(pDeviceObject));

	if (NULL == pDeviceObject ||
		FALSE == MmIsAddressValid(pEventHandlerWrap->pAssocAddr))
		return STATUS_UNSUCCESSFUL;

	if (NULL == pEventHandlerWrap->pOrgEventHandler)
	{
		return STATUS_SUCCESS;
	}

	pIrp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER, pDeviceObject,
		pEventHandlerWrap->pAssocAddr, NULL, NULL);

	if (NULL == pIrp)
	{
		ntStatus = STATUS_UNSUCCESSFUL;
		goto RETURN_;
	}

	TdiBuildSetEventHandler(pIrp,
		pDeviceObject,
		pEventHandlerWrap->pAssocAddr,
		NULL,
		NULL,
		pEventHandlerWrap->dwEventType,
		pEventHandlerWrap->pOrgEventHandler,
		pEventHandlerWrap->pOrgEventContext
		);


	ntStatus = IoCallDriver(pDeviceObject, pIrp);
	pIrp = NULL;

	if (NT_SUCCESS(ntStatus)) {
		//ASSERT( FALSE );

		goto RETURN_;
	}

	// don't wait to complete

RETURN_:
	if (NULL != pIrp)
	{
		IoFreeIrp(pIrp);
	}

	return ntStatus;
}

VOID DeleteEventWrap(PTDI_EVENT_HANDLER_LIST pTdiEventHandlerList)
{
	KIRQL OldIrql;

	KeAcquireSpinLock(&g_SpLockTdiEventHandlerInfo, &OldIrql);

	RemoveEntryList((PLIST_ENTRY)pTdiEventHandlerList);

	ExFreePoolWithTag(pTdiEventHandlerList->pTdiEventHandlerWrap, 0);
	ExFreePoolWithTag(pTdiEventHandlerList, 0);

	KeReleaseSpinLock(&g_SpLockTdiEventHandlerInfo, OldIrql);
	return;
}

VOID UpdateEventHandlerWrap(TDI_LMT* pProcessNetWorkTrafficInfo,
	PEPROCESS pEProcess,
	PDEVICE_OBJECT pDeviceObject,
	PFILE_OBJECT pFileObject,
	DWORD dwEventType,
	PVOID pEventHandler,
	PVOID pEventContext,
	PTDI_EVENT_HANDLER_LIST *ppEventHandlerList,
	DWORD dwFlags)
{
	KIRQL OldIrql;
	PLIST_ENTRY pListEntry;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerListFind;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrapFind;
	PTDI_EVENT_HANDLER_LIST pTdiEventHandlerListNew = NULL;
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrapNew = NULL;

	ASSERT(NULL != ppEventHandlerList);

	*ppEventHandlerList = NULL;

	KeAcquireSpinLock(&g_SpLockTdiEventHandlerInfo, &OldIrql);

	pListEntry = g_TdiEventHandlerInfoList.Flink;

	for (; ; )
	{
		if (pListEntry == &g_TdiEventHandlerInfoList)
		{
			break;
		}

		pTdiEventHandlerListFind = (PTDI_EVENT_HANDLER_LIST)pListEntry;
		pTdiEventHandlerWrapFind = pTdiEventHandlerListFind->pTdiEventHandlerWrap;

		if (pTdiEventHandlerWrapFind->pAssocAddr == pFileObject &&
			pTdiEventHandlerWrapFind->dwEventType == dwEventType)
		{

			ASSERT(TRUE == MmIsAddressValid(pTdiEventHandlerWrapFind->pAssocAddr));
			if (pProcessNetWorkTrafficInfo != NULL &&
				pTdiEventHandlerWrapFind->pProcessNetWorkTrafficInfo != pProcessNetWorkTrafficInfo)
			{
				KdBreakPoint();
			}

			if (DEL_EVENT_WRAP == dwFlags)
			{
				RemoveEntryList(pListEntry);
				ExFreePoolWithTag(pTdiEventHandlerWrapFind, 0);
				ExFreePoolWithTag(pTdiEventHandlerListFind, 0);
			}
			else
			{
				pTdiEventHandlerWrapFind->pOrgEventHandler = pEventHandler;
				pTdiEventHandlerWrapFind->pOrgEventContext = pEventContext;

				*ppEventHandlerList = pTdiEventHandlerListFind;
			}

			KeReleaseSpinLock(&g_SpLockTdiEventHandlerInfo, OldIrql);
			return;
		}

		pListEntry = pListEntry->Flink;
	}

	if (GET_EVENT_WRAP == dwFlags)
	{
		pTdiEventHandlerWrapNew = new TDI_EVENT_HANDLER_WRAP;
		if (NULL == pTdiEventHandlerWrapNew)
		{
			goto RELEASE_POOL_EXIT;
		}

		pTdiEventHandlerListNew = new TDI_EVENT_HANDLER_LIST;
		if (NULL == pTdiEventHandlerListNew)
		{
			goto RELEASE_POOL_EXIT;
		}

		pTdiEventHandlerWrapNew->dwEventContextMark = TDI_EVENT_CONTEXT_MARK;
		pTdiEventHandlerWrapNew->dwEventType = dwEventType;
		pTdiEventHandlerWrapNew->pOrgEventHandler = pEventHandler;
		pTdiEventHandlerWrapNew->pOrgEventContext = pEventContext;
		pTdiEventHandlerWrapNew->pEProcess = pEProcess;
		pTdiEventHandlerWrapNew->pProcessNetWorkTrafficInfo = pProcessNetWorkTrafficInfo;
		pTdiEventHandlerWrapNew->pAssocAddr = pFileObject;
		pTdiEventHandlerWrapNew->pDeviceObject = pDeviceObject;

		pTdiEventHandlerListNew->pTdiEventHandlerWrap = pTdiEventHandlerWrapNew;

		InsertTailList(&g_TdiEventHandlerInfoList, (PLIST_ENTRY)pTdiEventHandlerListNew);

		*ppEventHandlerList = pTdiEventHandlerListNew;

		KeReleaseSpinLock(&g_SpLockTdiEventHandlerInfo, OldIrql);
		return;

	RELEASE_POOL_EXIT:
		if (NULL != pTdiEventHandlerWrapNew)
		{
			ExFreePoolWithTag(pTdiEventHandlerWrapNew, NonPagedPool);
		}

		if (NULL != pTdiEventHandlerListNew)
		{
			ExFreePoolWithTag(pTdiEventHandlerListNew, NonPagedPool);
		}

		KeReleaseSpinLock(&g_SpLockTdiEventHandlerInfo, OldIrql);
		return;
	}

	KeReleaseSpinLock(&g_SpLockTdiEventHandlerInfo, OldIrql);
	return;
}
//////////////////////////////////////////////////////////////////////////

NTSTATUS TdiFilterRecvEventHandler(IN PVOID  TdiEventContext,
	IN CONNECTION_CONTEXT  ConnectionContext,
	IN ULONG  ReceiveFlags,
	IN ULONG  BytesIndicated,
	IN ULONG  BytesAvailable,
	OUT ULONG  *BytesTaken,
	IN PVOID  Tsdu,
	OUT PIRP  *IoRequestPacket
	)
{
	NTSTATUS ntStatus;
	PIO_STACK_LOCATION pIrpSp;
	PTDI_EVENT_HANDLER_WRAP pEventHandlerWrap;
	TDI_LMT* pProcessNetWorkTrafficInfo;
	PTDI_COMPLETION_WRAP pCompletionWrap;
	LARGE_INTEGER RecvedDataSize;

	ASSERT(NULL != TdiEventContext);

	pEventHandlerWrap = (PTDI_EVENT_HANDLER_WRAP)TdiEventContext;

	ASSERT(NULL != pEventHandlerWrap &&
		NULL != pEventHandlerWrap->pOrgEventHandler);

	//KdBreakPoint();

	if (FALSE == MmIsAddressValid(pEventHandlerWrap))
	{
		return STATUS_DATA_NOT_ACCEPTED;
	}
	//goto CALL_ORIGINAL_EVENT_HANDLER;

	if (FALSE == g_bFiltering)
	{

		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	pProcessNetWorkTrafficInfo = get_lmt(pEventHandlerWrap->pEProcess);
	if (NULL == pProcessNetWorkTrafficInfo)
	{
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	if (FALSE != pProcessNetWorkTrafficInfo->bStopRecv)
	{
		ntStatus = STATUS_DATA_NOT_ACCEPTED;

		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	ntStatus = ((ClientEventReceive)pEventHandlerWrap->pOrgEventHandler)(
		pEventHandlerWrap->pOrgEventContext,
		ConnectionContext,
		ReceiveFlags,
		BytesIndicated,
		BytesAvailable,
		BytesTaken,
		Tsdu,
		IoRequestPacket
		);

	if (NULL != BytesTaken &&
		0 != *BytesTaken)
	{
		RecvedDataSize.LowPart = *BytesTaken;
		RecvedDataSize.HighPart = 0;

		InterlockedExchangeAdd64(&pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize.QuadPart, RecvedDataSize.QuadPart);
		InterlockedExchangeAdd64(&g_AllRecvedDataSize.QuadPart, RecvedDataSize.QuadPart);
	}

	if (STATUS_MORE_PROCESSING_REQUIRED != ntStatus)
	{
		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	if (NULL == *IoRequestPacket)
	{
		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	pIrpSp = IoGetCurrentIrpStackLocation(*IoRequestPacket);

	pCompletionWrap = (PTDI_COMPLETION_WRAP)ExAllocateFromNPagedLookasideList(&g_CompletionWrapList);

	if (NULL == pCompletionWrap)
	{
		goto RELEASE_PROCESS_IO_INFO_RETURN;
	}

	pCompletionWrap->bSendOpera = FALSE;
	pCompletionWrap->bWrap = TRUE;
	pCompletionWrap->bAssocIrp = FALSE;
	pCompletionWrap->pCompletionRoutine = pIrpSp->CompletionRoutine;
	pCompletionWrap->pContext = pIrpSp->Context;
	pCompletionWrap->Control = pIrpSp->Control;
	pCompletionWrap->pEProcess = pEventHandlerWrap->pEProcess;
	pCompletionWrap->pProcessNetWorkTrafficInfo = pEventHandlerWrap->pProcessNetWorkTrafficInfo;

	pIrpSp->CompletionRoutine = TdiFilterCompletion;
	pIrpSp->Context = pCompletionWrap;
	pIrpSp->Control = SL_INVOKE_ON_CANCEL |
		SL_INVOKE_ON_SUCCESS |
		SL_INVOKE_ON_ERROR;

	g_CompletionIrpCount++;

	//Note: the recv event handler will add the BytesTaken number bytes to the record, and will add the next serial irp of this recv request recved bytes to record. by the ocmpletion wrap.

RELEASE_PROCESS_IO_INFO_RETURN:
	release_lmt(pProcessNetWorkTrafficInfo->Process);
	return ntStatus;

CALL_ORIGINAL_EVENT_HANDLER:
	return ((ClientEventReceive)pEventHandlerWrap->pOrgEventHandler)(
		pEventHandlerWrap->pOrgEventContext,
		ConnectionContext,
		ReceiveFlags,
		BytesIndicated,
		BytesAvailable,
		BytesTaken,
		Tsdu,
		IoRequestPacket
		);
}
NTSTATUS TdiFilterChainedRecvHandler(
	IN PVOID  TdiEventContext,
	IN CONNECTION_CONTEXT  ConnectionContext,
	IN ULONG  ReceiveFlags,
	IN ULONG  ReceiveLength,
	IN ULONG  StartingOffset,
	IN PMDL  Tsdu,
	IN PVOID  TsduDescriptor
	)
{
	PTDI_EVENT_HANDLER_WRAP pTdiEventHandlerWrap;
	NTSTATUS ntStatus;
	ClientEventChainedReceive pfChainedReceiveEventHandler;
	LPVOID pOriginalContext;
	LARGE_INTEGER RecvedDataSize;

	TDI_LMT* pProcessNetWorkTrafficInfo;
	TDI_LMT* pProcessNetWorkTrafficInfoHost;

	ASSERT(NULL != TdiEventContext);

	pTdiEventHandlerWrap = (PTDI_EVENT_HANDLER_WRAP)TdiEventContext;


	if (FALSE == MmIsAddressValid(pTdiEventHandlerWrap))
	{
		return STATUS_DATA_NOT_ACCEPTED;
	}

	if (pTdiEventHandlerWrap->dwEventContextMark != TDI_EVENT_CONTEXT_MARK)
	{
		return STATUS_DATA_NOT_ACCEPTED;
	}

	ASSERT(NULL != pTdiEventHandlerWrap->pOrgEventHandler);
	ASSERT(NULL != pTdiEventHandlerWrap->pOrgEventContext);
	ASSERT(NULL != pTdiEventHandlerWrap->pEProcess);

	pfChainedReceiveEventHandler = (ClientEventChainedReceive)pTdiEventHandlerWrap->pOrgEventHandler;
	pOriginalContext = pTdiEventHandlerWrap->pOrgEventContext;


	if (FALSE == g_bFiltering)
	{
		goto CALL_ORG_EVENT_HANDLER;
	}

	pProcessNetWorkTrafficInfo = get_lmt(pTdiEventHandlerWrap->pEProcess);
	if (NULL == pProcessNetWorkTrafficInfo)
	{
		goto CALL_ORG_EVENT_HANDLER;
	}

	if (FALSE != pProcessNetWorkTrafficInfo->bStopRecv)
	{
		release_lmt(pProcessNetWorkTrafficInfo->Process);
		return STATUS_DATA_NOT_ACCEPTED;
	}

	ntStatus = pfChainedReceiveEventHandler(
		pOriginalContext,
		ConnectionContext,
		ReceiveFlags,
		ReceiveLength,
		StartingOffset,
		Tsdu,
		TsduDescriptor
		);

	if (NT_SUCCESS(ntStatus))
	{
		RecvedDataSize.LowPart = ReceiveLength;
		RecvedDataSize.HighPart = 0;

		pProcessNetWorkTrafficInfoHost = pTdiEventHandlerWrap->pProcessNetWorkTrafficInfo;
		InterlockedExchangeAdd64(&pProcessNetWorkTrafficInfoHost->AllSuccRecvedDataSize.QuadPart, RecvedDataSize.QuadPart);
		InterlockedExchangeAdd64(&g_AllRecvedDataSize.QuadPart, RecvedDataSize.QuadPart);
	}

	release_lmt(pProcessNetWorkTrafficInfo->Process);
	return ntStatus;

CALL_ORG_EVENT_HANDLER:
	return pfChainedReceiveEventHandler(
		pOriginalContext,
		ConnectionContext,
		ReceiveFlags,
		ReceiveLength,
		StartingOffset,
		Tsdu,
		TsduDescriptor
		);
}

NTSTATUS  TdiFilterRecvDatagramEventHandler(
	IN PVOID  TdiEventContext,
	IN LONG  SourceAddressLength,
	IN PVOID  SourceAddress,
	IN LONG  OptionsLength,
	IN PVOID  Options,
	IN ULONG  ReceiveDatagramFlags,
	IN ULONG  BytesIndicated,
	IN ULONG  BytesAvailable,
	OUT ULONG  *BytesTaken,
	IN PVOID  Tsdu,
	OUT PIRP  *IoRequestPacket
	)
{
	NTSTATUS ntStatus;
	ClientEventReceiveDatagram pfOrgEventHandler;
	TDI_EVENT_HANDLER_WRAP *pEventHandlerWrap;
	TDI_LMT* pProcessNetWorkTrafficInfo;
	LPVOID pOrgEventContext;
	LARGE_INTEGER RecvedDataSize;


	pEventHandlerWrap = (PTDI_EVENT_HANDLER_WRAP)TdiEventContext;

	if (FALSE == MmIsAddressValid(pEventHandlerWrap))
	{
		goto RETRUN_ERROR;
	}

	if (TDI_EVENT_CONTEXT_MARK != pEventHandlerWrap->dwEventContextMark)
	{
		goto RETRUN_ERROR;
	}

	ASSERT(NULL != pEventHandlerWrap->pOrgEventHandler);

	pfOrgEventHandler = (ClientEventReceiveDatagram)pEventHandlerWrap->pOrgEventHandler;
	pOrgEventContext = pEventHandlerWrap->pOrgEventContext;

	//goto CALL_ORIGINAL_EVENT_HANDLER;

	if (FALSE == g_bFiltering)
	{
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	pProcessNetWorkTrafficInfo = get_lmt(pEventHandlerWrap->pEProcess);
	if (NULL == pProcessNetWorkTrafficInfo)
	{
		goto CALL_ORIGINAL_EVENT_HANDLER;
	}

	if (FALSE != pProcessNetWorkTrafficInfo->bStopRecv)
	{
		release_lmt(pProcessNetWorkTrafficInfo->Process);
		return STATUS_DATA_NOT_ACCEPTED;
	}

	ntStatus = pfOrgEventHandler(pOrgEventContext,
		SourceAddressLength,
		SourceAddress,
		OptionsLength,
		Options,
		ReceiveDatagramFlags,
		BytesIndicated,
		BytesAvailable,
		BytesTaken,
		Tsdu,
		IoRequestPacket
		);

	RecvedDataSize.LowPart = BytesAvailable;
	RecvedDataSize.HighPart = 0;

	InterlockedExchangeAdd64(
		&pProcessNetWorkTrafficInfo->AllSuccRecvedDataSize.QuadPart,
		RecvedDataSize.QuadPart);

	InterlockedExchangeAdd64(
		&g_AllRecvedDataSize.QuadPart,
		RecvedDataSize.QuadPart);
	release_lmt(pProcessNetWorkTrafficInfo->Process);

	return ntStatus;

CALL_ORIGINAL_EVENT_HANDLER:
	return pfOrgEventHandler(pOrgEventContext,
		SourceAddressLength,
		SourceAddress,
		OptionsLength,
		Options,
		ReceiveDatagramFlags,
		BytesIndicated,
		BytesAvailable,
		BytesTaken,
		Tsdu,
		IoRequestPacket
		);
RETRUN_ERROR:
	return STATUS_DATA_NOT_ACCEPTED;
}
//////////////////////////////////////////////////////////////////////////
VOID ThreadWaitCompletion()
{
	for (; ; )
	{
		KeWaitForSingleObject(&g_EventCompletion, Executive, KernelMode, FALSE, NULL);

		if (0 == InterlockedExchangeAdd(&g_CompletionIrpCount, 0))
		{
			break;
		}
	}
}