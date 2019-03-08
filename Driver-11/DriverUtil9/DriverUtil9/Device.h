#pragma once
#include "Base.h"
#include <functional>
#include <map>
namespace ddk
{
	static const auto default_device_code = 0x8000ul;
	typedef struct _DEVICE_EXTENSION
	{
		LIST_ENTRY	ListHead;			//待处理的IRP链表
		KSPIN_LOCK  ListLock;			//IRP链表操作锁   
		KEVENT      RequestEvent;		//控制/请求事件
		PVOID       ThreadObject;		//工作线程对象
		BOOLEAN     bTerminateThread;	//是否需要终止线程
		PSECURITY_CLIENT_CONTEXT SecurityClientCtx;
		PVOID		DeviceThis;
	} DEVICE_EXTENSION, *PDEVICE_EXTENSION;
	using  callback_ioctrl = std::function<NTSTATUS(PVOID, ULONG, PVOID, ULONG, ULONG_PTR *)>;
	using  callback_irp = std::function<NTSTATUS(PDEVICE_OBJECT, PIRP)>;
	class CDevice
	{
	public:
		CDevice();
		~CDevice();
	private:
		PDEVICE_OBJECT device_object;
		UNICODE_STRING nsDosName;
		UNICODE_STRING nsDeviceName;
		void DrvTerminater();
	public:
		void set_device_code(DWORD dwCode);
	private:
		DWORD dwDeviceCode;
		std::map<DWORD, callback_ioctrl> map_ioctrl;
		std::map<int, callback_irp>map_irp_routine;
	public:
		void set_ioctrl_callback(DWORD code,callback_ioctrl callback);
		void set_irp_callback(int irp, callback_irp callback);
		bool create_device(LPCWSTR device_name, LPCWSTR dos_name,bool b_asyn=false);
		void asyn_thread_work();
	public:
		static NTSTATUS DeviceIrpProc(
			IN PDEVICE_OBJECT DeviceObject,
			IN PIRP Irp);
		NTSTATUS device_irp(PIRP Irp);
		static NTSTATUS default_irp_routine(PDEVICE_OBJECT devobj, PIRP Irp);
		static KSTART_ROUTINE asyn_thread_routine;
	private:
		bool Asyn_able;
	private:
		NTSTATUS
			AdjustPrivilege(
				IN ULONG    Privilege,
				IN BOOLEAN  Enable
				);
	public:
		bool is_asyn();
	};
}


