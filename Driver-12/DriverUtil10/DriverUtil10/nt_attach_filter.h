#pragma once
#include "Base.h"
#include "nt_driver.h"
#include "nt_irp_dispatch.h"
#include "lock.h"
#include <functional>
#include <map>
namespace ddk
{
	class nt_attach_filter
	{
	public:
		using  callback_irp = std::function<NTSTATUS(PDEVICE_OBJECT,PDEVICE_OBJECT,PIRP)>;
		using  filter_dev_ext = struct {
			LIST_ENTRY	ListHead;			//待处理的IRP链表
			KSPIN_LOCK  ListLock;			//IRP链表操作锁   
			KEVENT      RequestEvent;		//控制/请求事件
			PDEVICE_OBJECT TargetDevice;    //被Attach的目标
			PDEVICE_OBJECT LowerDevice;	//Attach后的Lower
			PVOID ThisCtx;
		};
		//callback(LowerDevice,Device,Irp)
		nt_attach_filter() {
			b_attached = false;
			_self_drv = nullptr;
			_fileobject = nullptr;
			_self_drv = ddk::snapshot::nt_drivers::getInstance().get_new_driver();
			if (_self_drv)
			{
				for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1;i++)
				{
					_self_drv->MajorFunction[i] = ddk::nt_irp_dispatch::DispatchDrv;
				}
				ddk::nt_irp_dispatch::getInstance().register_dispatch(_self_drv,
					std::bind(&ddk::nt_attach_filter::do_dispatch, this,
						std::placeholders::_1,
						std::placeholders::_2));
			}
		}
		~nt_attach_filter() {
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
			if (!ddk::snapshot::nt_driver_snapshot::getInstance().get_driver_object(drvName,object))
			{
				return false;
			}
			auto pTarget = object->DeviceObject;
			while (pTarget)
			{
				PDEVICE_OBJECT fltobj = nullptr;
				PDEVICE_OBJECT lwrobj = nullptr;
				if (!attach_device(pTarget,&fltobj,&lwrobj)
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
			if (ns==STATUS_SUCCESS)
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
			if (m_maj_routine.find(maj_func)!=m_maj_routine.end())
			{
				ns =  m_maj_routine[maj_func](DevExt->LowerDevice, object, Irp);
			}
			else
			{
				switch (maj_func)
				{
				case IRP_MJ_PNP_POWER:
					ns =  do_pnp(object, Irp);
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
				ns =  STATUS_SUCCESS;
				break;
			default:
				IoSkipCurrentIrpStackLocation(Irp);
				ns =  IoCallDriver(ext->LowerDevice, Irp);
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
			if (ns!= STATUS_SUCCESS)
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
		nt_attach_filter(const nt_attach_filter&) = delete;
		nt_attach_filter & operator = (const nt_attach_filter &) = delete;
	private:
		bool b_attached;
		PDRIVER_OBJECT _self_drv;
		PFILE_OBJECT _fileobject;
		std::map<int, callback_irp> m_maj_routine;
		nt_lock _lock;
	};
};