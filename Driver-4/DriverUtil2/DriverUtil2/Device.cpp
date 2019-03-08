#include "Base.h"
#include "Device.h"
#include "ntos_func_def.h"
ddk::CDevice::CDevice():device_object(nullptr)
{
	Asyn_able = false;
	dwDeviceCode = ddk::default_device_code;
	map_ioctrl.clear();
	map_irp_routine.clear();
	set_irp_callback(IRP_MJ_CREATE, ddk::CDevice::default_irp_routine);
	set_irp_callback(IRP_MJ_CLOSE, ddk::CDevice::default_irp_routine);
	set_irp_callback(IRP_MJ_READ, ddk::CDevice::default_irp_routine);
	set_irp_callback(IRP_MJ_WRITE, ddk::CDevice::default_irp_routine);
}


ddk::CDevice::~CDevice()
{
	if (device_object!=nullptr)
	{
		DrvTerminater();
	}
}


void ddk::CDevice::DrvTerminater()
{
	auto DeviceExtension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	if (DeviceExtension->ThreadObject)
	{
		DeviceExtension->bTerminateThread = TRUE;
		KeSetEvent(&DeviceExtension->RequestEvent, 0, FALSE);
		KeWaitForSingleObject(DeviceExtension->ThreadObject, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(DeviceExtension->ThreadObject);
	}

	if (DeviceExtension->SecurityClientCtx)
	{
		SeDeleteClientSecurity(DeviceExtension->SecurityClientCtx);
		ExFreePool(DeviceExtension->SecurityClientCtx);
	}

	IoDeleteSymbolicLink(&nsDosName);
	IoDeleteDevice(device_object);
}


void ddk::CDevice::set_device_code(DWORD dwCode)
{
	dwDeviceCode = dwCode;
}


void ddk::CDevice::set_ioctrl_callback(DWORD code, callback_ioctrl callback)
{
	map_ioctrl[code] = callback;
}


void ddk::CDevice::set_irp_callback(int irp, callback_irp callback)
{
	map_irp_routine[irp] = callback;
}


bool ddk::CDevice::create_device(LPCWSTR device_name, LPCWSTR dos_name, bool b_asyn)
{
	if (device_object)
	{
		return false;
	}
	Asyn_able = b_asyn;
	auto status = AuxKlibInitialize();
	if (!NT_SUCCESS(status)) {
		return false;
	}
	RtlInitUnicodeString(&nsDosName, dos_name);
	RtlInitUnicodeString(&nsDeviceName, device_name);
	status = IoCreateDeviceSecure(g_pDriverObject,
		sizeof(DEVICE_EXTENSION),
		&nsDeviceName,
		dwDeviceCode,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&SDDL_DEVOBJ_SYS_ALL_ADM_ALL, nullptr,
		&device_object);
	if (!NT_SUCCESS(status))
	{
		return false;
	}
	auto DeviceExtension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	device_object->Flags &=	~DO_DEVICE_INITIALIZING;//不在DriverEntry流程里，也就是不收IO管理器控制的DeviceObject创建需要自己清除init标记

	device_object->Flags |= DO_DIRECT_IO;//I/O时使用MmGetSystemAddressForMdlSafe得到buffer
	RtlZeroMemory(DeviceExtension, sizeof(DEVICE_EXTENSION));

	DeviceExtension->bTerminateThread = FALSE;
	InitializeListHead(&DeviceExtension->ListHead);
	/*KeInitializeSpinLock(&DeviceExtension->ListLock);*/
	KeInitializeEvent(&DeviceExtension->RequestEvent, SynchronizationEvent, FALSE);
	DeviceExtension->DeviceThis = this;

	auto scopedIoDeleteDevice = std::experimental::make_scope_exit(
		[&]() { IoDeleteDevice(device_object); });

	if (Asyn_able)
	{
		HANDLE hThread = 0;
		status = PsCreateSystemThread(&hThread,
			THREAD_ALL_ACCESS,
			NULL,
			NULL,
			NULL,
			ddk::CDevice::asyn_thread_routine,
			this);
		if (!NT_SUCCESS(status))
		{
			return false;
		}
		status = ObReferenceObjectByHandle(hThread,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			&DeviceExtension->ThreadObject,
			NULL);
		ZwClose(hThread);
		if (!NT_SUCCESS(status))//线程对象获取失败，也许是线程异常，驱动的业务无法完成
		{
			DeviceExtension->bTerminateThread = TRUE;
			KeSetEvent(&DeviceExtension->RequestEvent, 0, FALSE);
			return false;
		}
	}
	status = IoCreateSymbolicLink(&nsDosName,&nsDeviceName);
	if (!NT_SUCCESS(status)) {
		return false;
	}
	auto scopedIoDeleteSymbolicLink = std::experimental::make_scope_exit(
		[&]() { IoDeleteSymbolicLink(&nsDosName); });

	for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION;i++)
	{
		g_pDriverObject->MajorFunction[i] = ddk::CDevice::DeviceIrpProc;
	}
	scopedIoDeleteDevice.release();
	scopedIoDeleteSymbolicLink.release();
	return true;
}

NTSTATUS ddk::CDevice::DeviceIrpProc(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)
{
	auto dev_ext = reinterpret_cast<PDEVICE_EXTENSION>(DeviceObject->DeviceExtension);
	if (dev_ext)
	{
		auto dev_class = reinterpret_cast<CDevice *>(dev_ext->DeviceThis);
		if(!dev_class->is_asyn())
			return dev_class->device_irp(Irp);
		else
		{
			SECURITY_QUALITY_OF_SERVICE SeQ = { 0 };

			if (dev_ext->SecurityClientCtx != NULL)
			{
				SeDeleteClientSecurity(dev_ext->SecurityClientCtx);
			}
			else
			{
				dev_ext->SecurityClientCtx = (PSECURITY_CLIENT_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(SECURITY_CLIENT_CONTEXT));
			}

			RtlZeroMemory(&SeQ, sizeof(SECURITY_QUALITY_OF_SERVICE));

			SeQ.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
			SeQ.ImpersonationLevel = SecurityImpersonation;
			SeQ.ContextTrackingMode = SECURITY_STATIC_TRACKING;
			SeQ.EffectiveOnly = FALSE;

			SeCreateClientSecurity(
				PsGetCurrentThread(),
				&SeQ,
				FALSE,
				dev_ext->SecurityClientCtx
				);

			IoMarkIrpPending(Irp);

			ExInterlockedInsertTailList(&dev_ext->ListHead, &Irp->Tail.Overlay.ListEntry, &dev_ext->ListLock);

			KeSetEvent(&dev_ext->RequestEvent, 0, FALSE);

			return STATUS_PENDING;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

NTSTATUS ddk::CDevice::device_irp(PIRP Irp)
{
	auto status = STATUS_SUCCESS;
	auto infomation = ULONG_PTR(0);
	auto ioStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if (ioStackIrp)
	{
		auto maj_code = ioStackIrp->MajorFunction;
		auto maj_callback = map_irp_routine.find(maj_code);
		if (maj_callback!=map_irp_routine.end())
		{
			auto func = map_irp_routine[maj_code];
			return func(device_object, Irp);
		}
		else
		{
			//检测是否是IRP_MJ_DEVICE_CONTROL
			if (maj_code==IRP_MJ_DEVICE_CONTROL)
			{
				auto inputBuffer = Irp->AssociatedIrp.SystemBuffer;
				auto outputBuffer = inputBuffer;
				auto ioControlCode = ioStackIrp->Parameters.DeviceIoControl.IoControlCode;
				auto inputBufferLength =
					ioStackIrp->Parameters.DeviceIoControl.InputBufferLength;
				auto outputBufferLength =
					ioStackIrp->Parameters.DeviceIoControl.OutputBufferLength;

				if (map_ioctrl.find(ioControlCode) != map_ioctrl.end())
				{
					switch (METHOD_FROM_CTL_CODE(ioControlCode))
					{
					case METHOD_NEITHER:
						inputBuffer = ioStackIrp->Parameters.DeviceIoControl.Type3InputBuffer;
						outputBuffer = Irp->UserBuffer;
						break;
					case METHOD_BUFFERED:
						break;
					case METHOD_IN_DIRECT:
					case METHOD_OUT_DIRECT:
						outputBuffer = Irp->MdlAddress ? MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) : nullptr;
						break;
					}
					auto func = map_ioctrl[ioControlCode];
					status = func(inputBuffer, inputBufferLength, outputBuffer, outputBufferLength, &infomation);
				}
				else
				{
					status = STATUS_NOT_IMPLEMENTED;
				}
			}
		}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = infomation;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS ddk::CDevice::default_irp_routine(PDEVICE_OBJECT devobj, PIRP Irp)
{
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID ddk::CDevice::asyn_thread_routine(PVOID context)
{
	auto classV = reinterpret_cast<CDevice *>(context);
	classV->asyn_thread_work();
}
void ddk::CDevice::asyn_thread_work()
{
	PDEVICE_EXTENSION   DeviceExtension;
	PLIST_ENTRY         Request;
	PIRP                Irp;

	DeviceExtension = (PDEVICE_EXTENSION)device_object->DeviceExtension;

	KeSetPriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);//设置线程运行于低优先级,否则会一卡一卡的！！

	KeLowerIrql(PASSIVE_LEVEL);

	AdjustPrivilege(SE_IMPERSONATE_PRIVILEGE, TRUE);

	while (TRUE)
	{
		KeWaitForSingleObject(&DeviceExtension->RequestEvent,
			Executive,
			KernelMode,
			FALSE,
			NULL);

		if (DeviceExtension->bTerminateThread)
		{
			PsTerminateSystemThread(STATUS_SUCCESS);//终止线程
		}

		while (Request = ExInterlockedRemoveHeadList(&DeviceExtension->ListHead, &DeviceExtension->ListLock))
		{
			Irp = CONTAINING_RECORD(Request, IRP, Tail.Overlay.ListEntry);
			SeImpersonateClient(DeviceExtension->SecurityClientCtx, NULL);
			device_irp(Irp);
			PsRevertToSelf();
		}
	}
}
 
NTSTATUS ddk::CDevice::
AdjustPrivilege(
	IN ULONG    Privilege,
	IN BOOLEAN  Enable
	)
{
	NTSTATUS            status;
	HANDLE              token_handle;
	TOKEN_PRIVILEGES    token_privileges;

	status = ZwOpenProcessToken(
		NtCurrentProcess(),
		TOKEN_ALL_ACCESS,
		&token_handle
		);

	if (!NT_SUCCESS(status))
	{
		return status;
	}

	token_privileges.PrivilegeCount = 1;
	token_privileges.Privileges[0].Luid = RtlConvertUlongToLuid(Privilege);
	token_privileges.Privileges[0].Attributes = Enable ? SE_PRIVILEGE_ENABLED : 0;

	status = NtAdjustPrivilegesToken(
		token_handle,
		FALSE,
		&token_privileges,
		sizeof(token_privileges),
		NULL,
		NULL
		);

	ZwClose(token_handle);

	return status;
}

bool ddk::CDevice::is_asyn()
{
	return Asyn_able;
}
