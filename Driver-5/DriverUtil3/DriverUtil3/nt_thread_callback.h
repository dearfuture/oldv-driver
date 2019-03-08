#pragma once
#include "Base.h"
#include <functional>
#include <vector>
#include <algorithm>

namespace ddk
{
	class nt_thread_callback:public Singleton<nt_thread_callback>
	{
	public:
		using nt_thread_callback_type = std::function<VOID(HANDLE, HANDLE, BOOLEAN)>;
		nt_thread_callback()
		{
			ExInitializeRundownProtection(&run_for);
			PsSetCreateThreadNotifyRoutine(ddk::nt_thread_callback::_CreateThreadNotifyRoutine);
		}
		~nt_thread_callback()
		{
			PsRemoveCreateThreadNotifyRoutine(ddk::nt_thread_callback::_CreateThreadNotifyRoutine);
			ExWaitForRundownProtectionRelease(&run_for);
			_callback.clear();
		}
		static VOID _CreateThreadNotifyRoutine(
			_In_ HANDLE ProcessId,
			_In_ HANDLE ThreadId,
			_In_ BOOLEAN Create)
		{
			ddk::nt_thread_callback::getInstance()->do_callback(ProcessId,ThreadId,Create);
		}
		void do_callback(
			_In_ HANDLE ProcessId,
			_In_ HANDLE ThreadId,
			_In_ BOOLEAN Create)
		{
			ExAcquireRundownProtection(&run_for);
			std::for_each(_callback.cbegin(), _callback.cend(),
				[&](auto _pfn) {
				_pfn(ProcessId, ThreadId, Create);
			});
			ExReleaseRundownProtection(&run_for);
		}
		void reg_callback(nt_thread_callback_type callback)
		{
			_callback.push_back(callback);
		}
	private:
		std::vector<nt_thread_callback_type> _callback;
		EX_RUNDOWN_REF run_for;
	};
};