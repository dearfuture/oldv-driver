#pragma once
#include "Base.h"
#include "util_syscall.h"
#include <functional>
#include <algorithm>
#include <vector>
namespace ddk
{
	class nt_process_callback:public Singleton<nt_process_callback>
	{
	public:
		using fnPsSetCreateProcessNotifyRoutineEx = NTSTATUS(NTAPI*)(
			_In_ PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine,
			_In_ BOOLEAN                           Remove
			);
		using nt_process_callback_type = std::function<VOID(HANDLE, HANDLE, BOOLEAN)>;
		using nt_process_callback_ex_type = std::function<VOID(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO)>;
		nt_process_callback()
		{
			_ex_callback.clear();
			_callback.clear();
			b_ex = false;
			ExInitializeRundownProtection(&_run_for);
			ExInitializeRundownProtection(&_run_for_ex);
			auto p = ddk::util::DynImport::Instance().get_proc_address("PsSetCreateProcessNotifyRoutineEx");
			if (p)
			{
				b_ex = true;
				auto ns = SAFE_NATIVE_CALL(PsSetCreateProcessNotifyRoutineEx, ddk::nt_process_callback::_ProcessNotifyRoutineEx, BOOLEAN(FALSE));
				if (NT_SUCCESS(ns))
				{
					return;
				}
				DBG_PRINT("failed PsSetCreateProcessNotifyRoutineEx\r\n");
			}
			{
				auto ns = PsSetCreateProcessNotifyRoutine(ddk::nt_process_callback::_ProcessNotifyRoutine, FALSE);
				if (!NT_SUCCESS(ns))
				{
					DBG_PRINT("failed PsSetCreateProcessNotifyRoutine\r\n");
					KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
				}
			}
		}
		~nt_process_callback()
		{

			if (b_ex)
			{
				ddk::util::DynImport::Instance().safeCall<fnPsSetCreateProcessNotifyRoutineEx>(
					"PsSetCreateProcessNotifyRoutineEx", ddk::nt_process_callback::_ProcessNotifyRoutineEx, BOOLEAN(TRUE));
			}
			{
				PsSetCreateProcessNotifyRoutine(ddk::nt_process_callback::_ProcessNotifyRoutine, TRUE);
			}
			ExWaitForRundownProtectionRelease(&_run_for_ex);
			ExWaitForRundownProtectionRelease(&_run_for);
			_ex_callback.clear();
			_callback.clear();
		}
		static VOID _ProcessNotifyRoutine(
			IN HANDLE  ParentId,
			IN HANDLE  ProcessId,
			IN BOOLEAN  Create)
		{
			ddk::nt_process_callback::getInstance().do_callback(ParentId, ProcessId, Create);
		}
		void do_callback(
			IN HANDLE  ParentId,
			IN HANDLE  ProcessId,
			IN BOOLEAN  Create)
		{
			//ExWaitForRundownProtectionRelease(&_run_for);
			ExAcquireRundownProtection(&_run_for);
			std::for_each(_callback.cbegin(), _callback.cend(),
				[&](auto _pfn) {
				_pfn(ParentId, ProcessId, Create);
			});
			ExReleaseRundownProtection(&_run_for);


		}
		static VOID _ProcessNotifyRoutineEx(
			_Inout_  PEPROCESS              Process,
			_In_     HANDLE                 ProcessId,
			_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
			)
		{
			ddk::nt_process_callback::getInstance().do_callback_ex(Process, ProcessId, CreateInfo);
		}
		void do_callback_ex(
			_Inout_  PEPROCESS              Process,
			_In_     HANDLE                 ProcessId,
			_In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
			)
		{
			//ExWaitForRundownProtectionRelease(&_run_for_ex);
			ExAcquireRundownProtection(&_run_for_ex);
			std::for_each(_ex_callback.cbegin(), _ex_callback.cend(),
				[&](auto _pfn) {
				_pfn(Process, ProcessId, CreateInfo);
			});
			ExReleaseRundownProtection(&_run_for_ex);

		}
		bool reg_callback_ex(nt_process_callback_ex_type callback)
		{
			if (b_ex)
			{
				//ExAcquireRundownProtection(&_run_for_ex);
				_ex_callback.push_back(callback);
				//ExReleaseRundownProtection(&_run_for_ex);
				return true;
			}
			return false;
		}
		bool reg_callback(nt_process_callback_type callback)
		{
			if (!b_ex)
			{
				//ExAcquireRundownProtection(&_run_for);
				_callback.push_back(callback);
				//ExReleaseRundownProtection(&_run_for);
				return true;
			}
			return false;
		}
		bool is_ex() {
			return b_ex;
		}
	private:
		bool b_ex;
		std::vector<nt_process_callback_ex_type> _ex_callback;
		std::vector<nt_process_callback_type> _callback;
		EX_RUNDOWN_REF _run_for;
		EX_RUNDOWN_REF _run_for_ex;
	};
};