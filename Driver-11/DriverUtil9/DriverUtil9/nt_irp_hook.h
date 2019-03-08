#pragma once
#include "Base.h"
#include "lock.h"
#include "nt_driver.h"
#include <algorithm>
#include <functional>
#include <vector>
#include <string>
#include <map>
#include "nt_irp_dispatch.h"
namespace ddk
{
	class nt_irp_hook
	{
	public:
	//	using fnObMakeTemporaryObject = VOID(NTAPI *)(PVOID);
		using  callback_irp = std::function<NTSTATUS(PDEVICE_OBJECT, PIRP)>;
		nt_irp_hook() {
			//IoCreateDriver
			hook_drv_object = nullptr;
			b_hooked = false;
			pHookDrvObject = nullptr;
		
			/*pAttachDrvObject = nullptr;
			pAttachDrvObject = ddk::snapshot::nt_drivers::getInstance().get_new_driver();*/
		}
		~nt_irp_hook() {
			_lock.wait_for_release();
		}
		void unhook()
		{
			if (b_hooked)
			{
				//需要处理
				RtlCopyMemory(
					pHookDrvObject->MajorFunction,
					hook_drv_object->MajorFunction,
					sizeof(hook_drv_object->MajorFunction));

				for (auto hook_object : m_hook_object_list)
				{

					InterlockedExchangePointer(reinterpret_cast<PVOID *>(&hook_object->DriverObject),
						hook_drv_object);
					//ObDereferenceObject(hook_object);
				}
				ObDereferenceObject(hook_drv_object);
			}
			_lock.wait_for_release();

			if (pHookDrvObject)
			{
				ddk::snapshot::nt_drivers::getInstance().del_driver_obj(pHookDrvObject);
			}
				
		}
		bool hook_driver(std::wstring drvName)
		{
			//hook只能进行一次，而filter_attach可以无穷,除非有无穷个DriverObject可以用
			if (b_hooked)
			{
				return false;
			}
			DBG_PRINT("hook device\r\n");
			pHookDrvObject = ddk::snapshot::nt_drivers::getInstance().get_new_driver();
			if (!pHookDrvObject)
			{
				return false;
			}
			PDRIVER_OBJECT drvobj = nullptr;
			if (!ddk::snapshot::nt_driver_snapshot::getInstance().get_driver_object(drvName,drvobj))
			{
				return false;
			}
			
			pHookDrvObject->DeviceObject = drvobj->DeviceObject;
			pHookDrvObject->DriverExtension = drvobj->DriverExtension;
			pHookDrvObject->DriverStartIo = drvobj->DriverStartIo;
			pHookDrvObject->FastIoDispatch = drvobj->FastIoDispatch;
			RtlCopyMemory(
				pHookDrvObject->MajorFunction,
				drvobj->MajorFunction,
				sizeof(drvobj->MajorFunction));

			pHookDrvObject->HardwareDatabase = drvobj->HardwareDatabase;
			pHookDrvObject->Flags = drvobj->Flags;
			pHookDrvObject->Type = drvobj->Type;
			for (auto i = 0; i < IRP_MJ_MAXIMUM_FUNCTION+1; i++)
				pHookDrvObject->MajorFunction[i] = ddk::nt_irp_dispatch::DispatchDrv;
			ddk::nt_irp_dispatch::getInstance().register_dispatch(pHookDrvObject,
				std::bind(&ddk::nt_irp_hook::do_dispatch, this,
					std::placeholders::_1, std::placeholders::_2));
			hook_drv_object = drvobj;
			//获取DRIVER_OBJECT对应的所有的DEVICEOBJECT
			ddk::snapshot::device_object_list_type dev_list;
			if (ddk::snapshot::nt_driver_snapshot::getInstance().get_driver_devices(drvobj,dev_list))
			{
				for (auto hook_object:dev_list)
				{
					DBG_PRINT("hook object %p\r\n", hook_object);
					InterlockedExchangePointer(reinterpret_cast<PVOID*>(
						&hook_object->DriverObject), pHookDrvObject);
					m_hook_object_list.push_back(hook_object);
				}
				b_hooked = true;
				return true;
			}
			return false;
		}
		NTSTATUS do_dispatch(
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp)
		{
			NTSTATUS ns = STATUS_SUCCESS;
			_lock.only_acquire();
			auto lock_exit = std::experimental::make_scope_exit([&]() {
				_lock.release();
			});
			
			if (std::find(m_hook_object_list.begin(),m_hook_object_list.end(),DeviceObject)!=m_hook_object_list.end())
			{
				auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
				auto _irp_func = IrpStack->MajorFunction;
				if (map_irp_routine.find(_irp_func) != map_irp_routine.end())
				{
					auto _pfn = map_irp_routine[_irp_func];
					ns = _pfn(DeviceObject, Irp);
				}
				else
				{
					ns = hook_drv_object->MajorFunction[IrpStack->MajorFunction](DeviceObject,
						Irp);
				}
			}
			else
			{
				DBG_PRINT("fucker\r\n");
				Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
				Irp->IoStatus.Information = 0;
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return STATUS_NOT_IMPLEMENTED;
			}
			return ns;
		}
		PDRIVER_OBJECT get_drv() {
			return pHookDrvObject;
		}
		PDRIVER_OBJECT get_orig_drv() {
			return hook_drv_object;
		}
		void set_irp_callback(int irp, callback_irp callback)
		{
			map_irp_routine[irp] = callback;
		}
	protected:
		nt_irp_hook & operator = (const nt_irp_hook &) = delete;
		nt_irp_hook(const nt_irp_hook&) = delete;
	private:
		PDRIVER_OBJECT pHookDrvObject;
		nt_lock _lock;
		bool b_hooked;
		PDRIVER_OBJECT hook_drv_object;
		std::vector<PDEVICE_OBJECT>m_hook_object_list;
		std::map<int, callback_irp>map_irp_routine;
	};

	
};