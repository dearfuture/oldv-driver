#pragma once
#include "Base.h"
#include <functional>
#include <vector>
namespace ddk
{
	class nt_regcmp_callback:public Singleton<nt_regcmp_callback>
	{
	public:
		using nt_regcmp_callback_type = std::function<NTSTATUS(PVOID, PVOID, PVOID)>;
		nt_regcmp_callback() {
			ExInitializeRundownProtection(&run_for);
			RtlInitUnicodeString(&_altitude, L"40000");
			auto status = CmRegisterCallbackEx(
				ddk::nt_regcmp_callback::_RegistryCallback,
				&_altitude,
				g_pDriverObject, 
				NULL, 
				&_registryCallbackCookie, 
				NULL);
			if (!NT_SUCCESS(status))
			{
				DBG_PRINT("failed CmRegisterCallbackEx\r\n");
				KernelStlRaiseException(KMODE_EXCEPTION_NOT_HANDLED);
			}
		}
		~nt_regcmp_callback() {
			CmUnRegisterCallback(_registryCallbackCookie);
			ExWaitForRundownProtectionRelease(&run_for);
			_callback.clear();
		}
		static NTSTATUS _RegistryCallback(
			_In_ PVOID CallbackContext,
			_In_opt_ PVOID Argument1,
			_In_opt_ PVOID Argument2)
		{
			return ddk::nt_regcmp_callback::getInstance()._do_Callback(CallbackContext,
				Argument1,
				Argument2);
		}
		NTSTATUS _do_Callback(
			_In_ PVOID CallbackContext,
			_In_opt_ PVOID Argument1,
			_In_opt_ PVOID Argument2)
		{
			NTSTATUS ns;
			ExAcquireRundownProtection(&run_for);
			for (auto _pfn:_callback)
			{
				ns = _pfn(CallbackContext,
					Argument1,
					Argument2);
				if (ns== STATUS_CALLBACK_BYPASS)
				{
					break;
				}
				if (!NT_SUCCESS(ns))
				{
					break;
				}
			}
			ExReleaseRundownProtection(&run_for);
			return ns;
		}
		void reg_callback(nt_regcmp_callback_type callback)
		{
			_callback.push_back(callback);
		}
	private:
		EX_RUNDOWN_REF run_for;
		LARGE_INTEGER _registryCallbackCookie;
		UNICODE_STRING _altitude;
		std::vector<nt_regcmp_callback_type>_callback;
	};
};