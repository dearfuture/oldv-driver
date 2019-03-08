#pragma once
#include "Base.h"
#include <map>
namespace ddk
{
	class nt_irp_dispatch :public Singleton<nt_irp_dispatch>
	{
	public:
		using do_dispatch_type = std::function<NTSTATUS(PDEVICE_OBJECT, PIRP)>;
		nt_irp_dispatch() {

		}
		~nt_irp_dispatch() {

		}
		NTSTATUS NTAPI do_dispatch(
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp)
		{
			auto m_drv = DeviceObject->DriverObject;
			if (m_dispatch.find(m_drv) != m_dispatch.end())
			{
				return m_dispatch[m_drv](DeviceObject, Irp);
			}
			Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
			Irp->IoStatus.Information = 0;
			IoCompleteRequest(Irp, IO_NO_INCREMENT);
			return STATUS_NOT_IMPLEMENTED;
		}
		void register_dispatch(PDRIVER_OBJECT drv_obj, do_dispatch_type dispatch)
		{
			m_dispatch[drv_obj] = dispatch;
		}
		static NTSTATUS NTAPI DispatchDrv(
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp)
		{
			return ddk::nt_irp_dispatch::getInstance().do_dispatch(DeviceObject, Irp);
		}
	private:
		std::map<PDRIVER_OBJECT, do_dispatch_type>m_dispatch;
	};
};