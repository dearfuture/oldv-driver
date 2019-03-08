#pragma once
#include "Base.h"
#include "nt_driver.h"
#include "nt_irp_dispatch.h"
#include "lock.h"
#include <functional>
#include <map>
namespace ddk
{
#define VALID_FAST_IO_DISPATCH_HANDLER(_FastIoDispatchPtr, _FieldName) \
	(((_FastIoDispatchPtr) != NULL) && \
	(((_FastIoDispatchPtr)->SizeOfFastIoDispatch) >= \
	(FIELD_OFFSET(FAST_IO_DISPATCH, _FieldName) + sizeof(void *))) && \
	((_FastIoDispatchPtr)->_FieldName != NULL))

	class nt_attach_filter_ex
	{
		//支持fastio过滤的过滤模型
	public:
		using  callback_irp = std::function<NTSTATUS(PDEVICE_OBJECT, PDEVICE_OBJECT, PIRP)>;
		using  filter_dev_ext = struct {
			LIST_ENTRY	ListHead;			//待处理的IRP链表
			KSPIN_LOCK  ListLock;			//IRP链表操作锁   
			KEVENT      RequestEvent;		//控制/请求事件
			PDEVICE_OBJECT TargetDevice;    //被Attach的目标
			PDEVICE_OBJECT LowerDevice;	//Attach后的Lower
			PVOID ThisCtx;
		};
		//callback(LowerDevice,Device,Irp)
		nt_attach_filter_ex() {
			fastIoDispatch = nullptr;
			b_attached = false;
			_self_drv = nullptr;
			_fileobject = nullptr;
			_self_drv = ddk::snapshot::nt_drivers::getInstance().get_new_driver();
			if (_self_drv)
			{
				for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
				{
					_self_drv->MajorFunction[i] = ddk::nt_irp_dispatch::DispatchDrv;
				}
				ddk::nt_irp_dispatch::getInstance().register_dispatch(_self_drv,
					std::bind(&ddk::nt_attach_filter_ex::do_dispatch, this,
						std::placeholders::_1,
						std::placeholders::_2));
				
				make_fast_io_dispatch();
			}
		}
		~nt_attach_filter_ex() {
			KeSetBasePriorityThread(KeGetCurrentThread(), LOW_REALTIME_PRIORITY);
			if (b_attached)
			{
				auto devobj = _self_drv->DeviceObject;
				while (devobj)
				{
					auto pNext = devobj->NextDevice;
					auto pExt = reinterpret_cast<filter_dev_ext*>(devobj->DeviceExtension);
					__try
					{
						IoDetachDevice(pExt->LowerDevice);
						IoDeleteDevice(devobj);
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {}
					devobj = pNext;
				}
			}
			_lock.wait_for_release();
			if (_self_drv)
			{
				if (fastIoDispatch)
				{
					_self_drv->FastIoDispatch = nullptr;
					free(fastIoDispatch);
				}
				ddk::snapshot::nt_drivers::getInstance().del_driver_obj(_self_drv);
			}
		}
		bool attach_driver(std::wstring drvName)
		{
			if (!_self_drv)
			{
				return false;
			}
			PDRIVER_OBJECT object = nullptr;
			if (!ddk::snapshot::nt_driver_snapshot::getInstance().get_driver_object(drvName, object))
			{
				return false;
			}
			auto pTarget = object->DeviceObject;
			while (pTarget)
			{
				PDEVICE_OBJECT fltobj = nullptr;
				PDEVICE_OBJECT lwrobj = nullptr;
				if (!attach_device(pTarget, &fltobj, &lwrobj)
					)
				{
					return false;
				}
				pTarget = pTarget->NextDevice;
			}
			b_attached = true;

			return true;
		}
		bool attach_device(std::wstring devName)
		{
			if (!_self_drv)
			{
				return false;
			}
			UNICODE_STRING nsDevName;
			PDEVICE_OBJECT devObject = nullptr;
			RtlInitUnicodeString(&nsDevName, devName.c_str());
			b_attached = true;
			auto ns = IoGetDeviceObjectPointer(&nsDevName, FILE_ALL_ACCESS,
				&_fileobject,
				&devObject);
			if (ns == STATUS_SUCCESS)
			{
				PDEVICE_OBJECT filt = nullptr;
				PDEVICE_OBJECT lower = nullptr;
				if (attach_device(devObject, &filt, &lower))
				{
					if (_fileobject)
					{
						ObDereferenceObject(_fileobject);
						_fileobject = nullptr;
					}
					b_attached = true;
					return true;
				}
			}
			return false;
		}
	NTSTATUS do_dispatch(PDEVICE_OBJECT object, PIRP Irp)
	{
		_lock.only_acquire();
		auto exit_lock = std::experimental::make_scope_exit([&]() {
			_lock.release();
		});
		NTSTATUS ns = STATUS_NOT_IMPLEMENTED;
		auto DevExt = reinterpret_cast<filter_dev_ext*>(object->DeviceExtension);
		auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
		auto maj_func = IrpStack->MajorFunction;
		if (m_maj_routine.find(maj_func) != m_maj_routine.end())
		{
			ns = m_maj_routine[maj_func](DevExt->LowerDevice, object, Irp);
		}
		else
		{
			switch (maj_func)
			{
			case IRP_MJ_PNP_POWER:
				ns = do_pnp(object, Irp);
				break;
			case IRP_MJ_POWER:
				ns = do_power(object, Irp);
				break;
			default:
				IoSkipCurrentIrpStackLocation(Irp);
				ns = IoCallDriver(DevExt->LowerDevice, Irp);
			}
		}
		return ns;
	}
	void set_callback(int maj, callback_irp callback)
	{
		m_maj_routine[maj] = callback;
	}
	void acquire()
	{
		_lock.only_acquire();
	}
	void release()
	{
		_lock.release();
	}
private:
	NTSTATUS do_pnp(PDEVICE_OBJECT object, PIRP Irp)
	{
		auto irpstack = IoGetCurrentIrpStackLocation(Irp);
		auto ext = reinterpret_cast<filter_dev_ext *>(object->DeviceExtension);
		NTSTATUS ns = STATUS_NOT_IMPLEMENTED;
		switch (irpstack->MinorFunction)
		{
		case IRP_MN_REMOVE_DEVICE:
			IoSkipCurrentIrpStackLocation(Irp);
			IoCallDriver(ext->LowerDevice, Irp);
			IoDetachDevice(ext->LowerDevice);
			IoDeleteDevice(object);
			ns = STATUS_SUCCESS;
			break;
		default:
			IoSkipCurrentIrpStackLocation(Irp);
			ns = IoCallDriver(ext->LowerDevice, Irp);
			break;
		}
		return ns;
	}
	NTSTATUS do_power(PDEVICE_OBJECT object, PIRP Irp)
	{
		auto ext = reinterpret_cast<filter_dev_ext*>(object->DeviceExtension);
		PoStartNextPowerIrp(Irp);
		IoSkipCurrentIrpStackLocation(Irp);
		return PoCallDriver(ext->LowerDevice, Irp);
	}
private:
	void detach(PDEVICE_OBJECT object)
	{
		IoDetachDevice(object);
	}
	bool attach_device(
		PDEVICE_OBJECT targetDev,
		PDEVICE_OBJECT *filterDev,
		PDEVICE_OBJECT *lowerDev)
	{
		auto ns = IoCreateDevice(_self_drv,
			sizeof(filter_dev_ext),
			nullptr,
			targetDev->DeviceType,
			targetDev->Characteristics,
			FALSE,
			filterDev);
		if (!NT_SUCCESS(ns))
		{
			return false;
		}
		auto filtdev = *filterDev;
		filtdev->Flags &= ~DO_DEVICE_INITIALIZING;
		ns = IoAttachDeviceToDeviceStackSafe(filtdev, targetDev, lowerDev);
		if (ns != STATUS_SUCCESS)
		{
			IoDeleteDevice(*filterDev);
			*filterDev = nullptr;
			return false;
		}
		auto lwrdev = *lowerDev;

		auto devExt = reinterpret_cast<filter_dev_ext*>(filtdev->DeviceExtension);
		if (devExt)
		{
			RtlZeroMemory(devExt, sizeof(filter_dev_ext));
			InitializeListHead(&devExt->ListHead);
			/*KeInitializeSpinLock(&DeviceExtension->ListLock);*/
			KeInitializeEvent(&devExt->RequestEvent, SynchronizationEvent, FALSE);
			devExt->LowerDevice = lwrdev;
			devExt->TargetDevice = targetDev;
			devExt->ThisCtx = this;
		}
		filtdev->DeviceType = lwrdev->DeviceType;
		filtdev->Characteristics = lwrdev->Characteristics;
		filtdev->StackSize = lwrdev->StackSize + 1;
		filtdev->Flags |= lwrdev->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);
		return true;
	}
protected:
	nt_attach_filter_ex(const nt_attach_filter_ex&) = delete;
	nt_attach_filter_ex & operator = (const nt_attach_filter_ex &) = delete;
private:
	bool b_attached;
	PDRIVER_OBJECT _self_drv;
	PFILE_OBJECT _fileobject;
	std::map<int, callback_irp> m_maj_routine;
	nt_lock _lock;
	PFAST_IO_DISPATCH fastIoDispatch;
	std::map<int,PVOID>fastIoFilter;
public:
	PVOID getFastIoFilter(int offset)
	{
		if (fastIoFilter.find(offset) != fastIoFilter.end())
			return fastIoFilter[offset];
		return nullptr;
	}
	bool set_fast_io_filter(int offset, PVOID filter_func)
	{
		fastIoFilter[offset] = filter_func;
		return true;
	}
public:
	static BOOLEAN
		SfFastIoCheckIfPossible(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN BOOLEAN Wait,
			IN ULONG LockKey,
			IN BOOLEAN CheckForReadOperation,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDev = dev_ext->LowerDevice;
			auto fastio = nextDev->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoCheckIfPossible);
			auto pfunc = reinterpret_cast<PFAST_IO_CHECK_IF_POSSIBLE>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoCheckIfPossible))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							Wait,
							LockKey,
							CheckForReadOperation,
							IoStatus,
							nextDev);
					}

					return (fastio->FastIoCheckIfPossible)(
							FileObject,
							FileOffset,
							Length,
							Wait,
							LockKey,
							CheckForReadOperation,
							IoStatus,
							nextDev);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoRead(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN BOOLEAN Wait,
			IN ULONG LockKey,
			OUT PVOID Buffer,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDev = dev_ext->LowerDevice;
			auto fastio = nextDev->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoRead);
			auto pfunc = reinterpret_cast<PFAST_IO_READ>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoRead))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							Wait,
							LockKey,
							Buffer,
							IoStatus,
							nextDev);
					}
					return (fastio->FastIoRead)(
						FileObject,
						FileOffset,
						Length,
						Wait,
						LockKey,
						Buffer,
						IoStatus,
						nextDev);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoWrite(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN BOOLEAN Wait,
			IN ULONG LockKey,
			IN PVOID Buffer,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoWrite);
			auto pfunc = reinterpret_cast<PFAST_IO_WRITE>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoWrite))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							Wait,
							LockKey,
							Buffer,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoWrite)(
						FileObject,
						FileOffset,
						Length,
						Wait,
						LockKey,
						Buffer,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoQueryBasicInfo(
			IN PFILE_OBJECT FileObject,
			IN BOOLEAN Wait,
			OUT PFILE_BASIC_INFORMATION Buffer,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoQueryBasicInfo);
			auto pfunc = reinterpret_cast<PFAST_IO_QUERY_BASIC_INFO>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoQueryBasicInfo))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							Wait,
							Buffer,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoQueryBasicInfo)(
						FileObject,
						Wait,
						Buffer,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoQueryStandardInfo(
			IN PFILE_OBJECT FileObject,
			IN BOOLEAN Wait,
			OUT PFILE_STANDARD_INFORMATION Buffer,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoQueryStandardInfo);
			auto pfunc = reinterpret_cast<PFAST_IO_QUERY_STANDARD_INFO>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoQueryStandardInfo))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							Wait,
							Buffer,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoQueryStandardInfo)(
						FileObject,
						Wait,
						Buffer,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoLock(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN PLARGE_INTEGER Length,
			PEPROCESS ProcessId,
			ULONG Key,
			BOOLEAN FailImmediately,
			BOOLEAN ExclusiveLock,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoLock);
			auto pfunc = reinterpret_cast<PFAST_IO_LOCK>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoLock))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							ProcessId,
							Key,
							FailImmediately,
							ExclusiveLock,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoLock)(
						FileObject,
						FileOffset,
						Length,
						ProcessId,
						Key,
						FailImmediately,
						ExclusiveLock,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoUnlockSingle(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN PLARGE_INTEGER Length,
			PEPROCESS ProcessId,
			ULONG Key,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoUnlockSingle);
			auto pfunc = reinterpret_cast<PFAST_IO_UNLOCK_SINGLE>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoUnlockSingle))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							ProcessId,
							Key,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoUnlockSingle)(
						FileObject,
						FileOffset,
						Length,
						ProcessId,
						Key,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoUnlockAll(
			IN PFILE_OBJECT FileObject,
			PEPROCESS ProcessId,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoUnlockAll);
			auto pfunc = reinterpret_cast<PFAST_IO_UNLOCK_ALL>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoUnlockAll))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							ProcessId,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoUnlockAll)(
						FileObject,
						ProcessId,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoUnlockAllByKey(
			IN PFILE_OBJECT FileObject,
			PVOID ProcessId,
			ULONG Key,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoUnlockAllByKey);
			auto pfunc = reinterpret_cast<PFAST_IO_UNLOCK_ALL_BY_KEY>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoUnlockAllByKey))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							ProcessId,
							Key,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoUnlockAllByKey)(
						FileObject,
						ProcessId,
						Key,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoDeviceControl(
			IN PFILE_OBJECT FileObject,
			IN BOOLEAN Wait,
			IN PVOID InputBuffer OPTIONAL,
			IN ULONG InputBufferLength,
			OUT PVOID OutputBuffer OPTIONAL,
			IN ULONG OutputBufferLength,
			IN ULONG IoControlCode,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoDeviceControl);
			auto pfunc = reinterpret_cast<PFAST_IO_DEVICE_CONTROL>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoDeviceControl))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							Wait,
							InputBuffer,
							InputBufferLength,
							OutputBuffer,
							OutputBufferLength,
							IoControlCode,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoDeviceControl)(
						FileObject,
						Wait,
						InputBuffer,
						InputBufferLength,
						OutputBuffer,
						OutputBufferLength,
						IoControlCode,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static VOID
		SfFastIoDetachDevice(
			IN PDEVICE_OBJECT SourceDevice,
			IN PDEVICE_OBJECT TargetDevice
			)
	{
		IoDetachDevice(TargetDevice);
		IoDeleteDevice(SourceDevice);
	}
	static BOOLEAN
		SfFastIoQueryNetworkOpenInfo(
			IN PFILE_OBJECT FileObject,
			IN BOOLEAN Wait,
			OUT PFILE_NETWORK_OPEN_INFORMATION Buffer,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoQueryNetworkOpenInfo);
			auto pfunc = reinterpret_cast<PFAST_IO_QUERY_NETWORK_OPEN_INFO>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoQueryNetworkOpenInfo))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							Wait,
							Buffer,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->FastIoQueryNetworkOpenInfo)(
						FileObject,
						Wait,
						Buffer,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoMdlRead(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN ULONG LockKey,
			OUT PMDL *MdlChain,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, MdlRead);
			auto pfunc = reinterpret_cast<PFAST_IO_MDL_READ>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, MdlRead))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							LockKey,
							MdlChain,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->MdlRead)(
						FileObject,
						FileOffset,
						Length,
						LockKey,
						MdlChain,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoMdlReadComplete(
			IN PFILE_OBJECT FileObject,
			IN PMDL MdlChain,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, MdlReadComplete);
			auto pfunc = reinterpret_cast<PFAST_IO_MDL_READ_COMPLETE>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, MdlReadComplete))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							MdlChain,
							nextDeviceObject);
					}
					return (fastio->MdlReadComplete)(
						FileObject,
						MdlChain,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoPrepareMdlWrite(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN ULONG LockKey,
			OUT PMDL *MdlChain,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, PrepareMdlWrite);
			auto pfunc = reinterpret_cast<PFAST_IO_PREPARE_MDL_WRITE>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, PrepareMdlWrite))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							LockKey,
							MdlChain,
							IoStatus,
							nextDeviceObject);
					}
					return (fastio->PrepareMdlWrite)(
						FileObject,
						FileOffset,
						Length,
						LockKey,
						MdlChain,
						IoStatus,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoMdlWriteComplete(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN PMDL MdlChain,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, MdlWriteComplete);
			auto pfunc = reinterpret_cast<PFAST_IO_MDL_WRITE_COMPLETE>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, MdlWriteComplete))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							MdlChain,
							nextDeviceObject);
					}
					return (fastio->MdlWriteComplete)(
						FileObject,
						FileOffset,
						MdlChain,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoReadCompressed(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN ULONG LockKey,
			OUT PVOID Buffer,
			OUT PMDL *MdlChain,
			OUT PIO_STATUS_BLOCK IoStatus,
			OUT struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
			IN ULONG CompressedDataInfoLength,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoReadCompressed);
			auto pfunc = reinterpret_cast<PFAST_IO_READ_COMPRESSED>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoReadCompressed))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							LockKey,
							Buffer,
							MdlChain,
							IoStatus,
							CompressedDataInfo,
							CompressedDataInfoLength,
							nextDeviceObject);
					}
					return (fastio->FastIoReadCompressed)(
						FileObject,
						FileOffset,
						Length,
						LockKey,
						Buffer,
						MdlChain,
						IoStatus,
						CompressedDataInfo,
						CompressedDataInfoLength,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoWriteCompressed(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN ULONG Length,
			IN ULONG LockKey,
			IN PVOID Buffer,
			OUT PMDL *MdlChain,
			OUT PIO_STATUS_BLOCK IoStatus,
			IN struct _COMPRESSED_DATA_INFO *CompressedDataInfo,
			IN ULONG CompressedDataInfoLength,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoWriteCompressed);
			auto pfunc = reinterpret_cast<PFAST_IO_WRITE_COMPRESSED>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoWriteCompressed))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							Length,
							LockKey,
							Buffer,
							MdlChain,
							IoStatus,
							CompressedDataInfo,
							CompressedDataInfoLength,
							nextDeviceObject);
					}
					return (fastio->FastIoWriteCompressed)(
						FileObject,
						FileOffset,
						Length,
						LockKey,
						Buffer,
						MdlChain,
						IoStatus,
						CompressedDataInfo,
						CompressedDataInfoLength,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoMdlReadCompleteCompressed(
			IN PFILE_OBJECT FileObject,
			IN PMDL MdlChain,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, MdlReadCompleteCompressed);
			auto pfunc = reinterpret_cast<PFAST_IO_MDL_READ_COMPLETE_COMPRESSED>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, MdlReadCompleteCompressed))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							MdlChain,
							nextDeviceObject);
					}
					return (fastio->MdlReadCompleteCompressed)(
						FileObject,
						MdlChain,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoMdlWriteCompleteCompressed(
			IN PFILE_OBJECT FileObject,
			IN PLARGE_INTEGER FileOffset,
			IN PMDL MdlChain,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, MdlWriteCompleteCompressed);
			auto pfunc = reinterpret_cast<PFAST_IO_MDL_WRITE_COMPLETE_COMPRESSED>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, MdlWriteCompleteCompressed))
				{
					if (pfunc)
					{
						return pfunc(
							FileObject,
							FileOffset,
							MdlChain,
							nextDeviceObject);
					}
					return (fastio->MdlWriteCompleteCompressed)(
						FileObject,
						FileOffset,
						MdlChain,
						nextDeviceObject);
				}
			}
		}
		return FALSE;
	}
	static BOOLEAN
		SfFastIoQueryOpen(
			IN PIRP Irp,
			OUT PFILE_NETWORK_OPEN_INFORMATION NetworkInformation,
			IN PDEVICE_OBJECT DeviceObject
			)
	{
		auto dev_ext = reinterpret_cast<filter_dev_ext*>(DeviceObject->DeviceExtension);
		if (dev_ext)
		{
			auto pThis = reinterpret_cast<nt_attach_filter_ex*>(dev_ext->ThisCtx);
			auto nextDeviceObject = dev_ext->LowerDevice;
			auto fastio = nextDeviceObject->DriverObject->FastIoDispatch;
			auto offset = FIELD_OFFSET(FAST_IO_DISPATCH, FastIoQueryOpen);
			auto pfunc = reinterpret_cast<PFAST_IO_QUERY_OPEN>(pThis->getFastIoFilter(offset));
			if (fastio)
			{
				if (VALID_FAST_IO_DISPATCH_HANDLER(fastio, FastIoQueryOpen))
				{
					PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
					irpSp->DeviceObject = nextDeviceObject;

					BOOLEAN res;
					if (pfunc)
					{
						res= pfunc(
							Irp,
							NetworkInformation,
							nextDeviceObject);
					}
					else
					{
						res = (fastio->FastIoQueryOpen)(
							Irp,
							NetworkInformation,
							nextDeviceObject);
					}
					irpSp->DeviceObject = DeviceObject;

					return res;
				}
			}
		}
		return FALSE;
	}
protected:
	void make_fast_io_dispatch()
	{
		fastIoDispatch = reinterpret_cast<PFAST_IO_DISPATCH>(malloc(sizeof(FAST_IO_DISPATCH)));
		if (fastIoDispatch)
		{
			// 内存清零。
			RtlZeroMemory(fastIoDispatch, sizeof(FAST_IO_DISPATCH));
			fastIoDispatch->SizeOfFastIoDispatch = sizeof(FAST_IO_DISPATCH);
			//填写函数接口表
			fastIoDispatch->FastIoCheckIfPossible = SfFastIoCheckIfPossible;
			fastIoDispatch->FastIoRead = SfFastIoRead;
			fastIoDispatch->FastIoWrite = SfFastIoWrite;
			fastIoDispatch->FastIoQueryBasicInfo = SfFastIoQueryBasicInfo;
			fastIoDispatch->FastIoQueryStandardInfo = SfFastIoQueryStandardInfo;
			fastIoDispatch->FastIoLock = SfFastIoLock;
			fastIoDispatch->FastIoUnlockSingle = SfFastIoUnlockSingle;
			fastIoDispatch->FastIoUnlockAll = SfFastIoUnlockAll;
			fastIoDispatch->FastIoUnlockAllByKey = SfFastIoUnlockAllByKey;
			fastIoDispatch->FastIoDeviceControl = SfFastIoDeviceControl;
			fastIoDispatch->FastIoDetachDevice = nullptr;// SfFastIoDetachDevice;
			fastIoDispatch->FastIoQueryNetworkOpenInfo = SfFastIoQueryNetworkOpenInfo;
			fastIoDispatch->MdlRead = SfFastIoMdlRead;
			fastIoDispatch->MdlReadComplete = SfFastIoMdlReadComplete;
			fastIoDispatch->PrepareMdlWrite = SfFastIoPrepareMdlWrite;
			fastIoDispatch->MdlWriteComplete = SfFastIoMdlWriteComplete;
			fastIoDispatch->FastIoReadCompressed = SfFastIoReadCompressed;
			fastIoDispatch->FastIoWriteCompressed = SfFastIoWriteCompressed;
			fastIoDispatch->MdlReadCompleteCompressed = SfFastIoMdlReadCompleteCompressed;
			fastIoDispatch->MdlWriteCompleteCompressed = SfFastIoMdlWriteCompleteCompressed;
			fastIoDispatch->FastIoQueryOpen = SfFastIoQueryOpen;

			_self_drv->FastIoDispatch = fastIoDispatch;
		}
	}
	};
}