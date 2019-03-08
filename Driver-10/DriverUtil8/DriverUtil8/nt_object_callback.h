#pragma once
#include "Base.h"
#include <functional>
#include <vector>
#include <algorithm>
namespace ddk
{
	class nt_object_callback:public Singleton<nt_object_callback>
	{
	public:
		using nt_object_pre_callback_type = std::function<VOID(POB_PRE_OPERATION_INFORMATION)>;
		using nt_object_post_callback_type = std::function<VOID(POB_POST_OPERATION_INFORMATION)>;
		nt_object_callback() {
			ref_count = 0;
			_ob_handler = nullptr;
			OB_OPERATION_REGISTRATION ObOperations[] = {
				{ PsProcessType,
				OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
				ddk::nt_object_callback::ObCallbackPreProcess,
				ddk::nt_object_callback::ObCallbackPostProcess
				},
				{ PsThreadType,		
				OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,		
				ddk::nt_object_callback::ObCallbackPreThread,
				ddk::nt_object_callback::ObCallbackPostThread
				}
			};
			OB_CALLBACK_REGISTRATION ObRegistration = {
				OB_FLT_REGISTRATION_VERSION,//ObGetFilterVersion()
				sizeof(ObOperations) / sizeof(OB_OPERATION_REGISTRATION),
				{ sizeof(L"320400") - sizeof(WCHAR), sizeof(L"320400"), L"320400" },
				this,
				ObOperations
			};
			auto ns = ObRegisterCallbacks(&ObRegistration, &_ob_handler);
			if (!NT_SUCCESS(ns))
			{
				DBG_PRINT("ObRegisterCallbacks failed %x\r\n", ns);
			}
		}
		static OB_PREOP_CALLBACK_STATUS ObCallbackPreProcess(
			_In_ PVOID                         RegistrationContext,
			_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
			)
		{
			auto pThis = reinterpret_cast<ddk::nt_object_callback*>(RegistrationContext);
			__try
			{
				pThis->_doPreProcess(OperationInformation);
			}
			__except (1)
			{

			}
			return OB_PREOP_SUCCESS;
		}
		static OB_PREOP_CALLBACK_STATUS ObCallbackPreThread(
			_In_ PVOID                         RegistrationContext,
			_In_ POB_PRE_OPERATION_INFORMATION OperationInformation
			)
		{
			auto pThis = reinterpret_cast<ddk::nt_object_callback*>(RegistrationContext);
			__try
			{
				pThis->_doPreThread(OperationInformation);
			}
			__except (1)
			{

			}
			return OB_PREOP_SUCCESS;
		}
		static VOID ObCallbackPostProcess(
			_In_ PVOID                          RegistrationContext,
			_In_ POB_POST_OPERATION_INFORMATION OperationInformation
			)
		{
			auto pThis = reinterpret_cast<ddk::nt_object_callback*>(RegistrationContext);
			__try
			{
				pThis->_doPostProcess(OperationInformation);
			}
			__except (1)
			{

			}
			
		}
		static VOID ObCallbackPostThread(
			_In_ PVOID                          RegistrationContext,
			_In_ POB_POST_OPERATION_INFORMATION OperationInformation
			)
		{
			auto pThis = reinterpret_cast<ddk::nt_object_callback*>(RegistrationContext);
			__try
			{
				pThis->_doPostThread(OperationInformation);
			}
			__except (1)
			{

			}
		}
		~nt_object_callback()
		{
			if (_ob_handler)
			{
				ObUnRegisterCallbacks(_ob_handler);
			}
			while (InterlockedCompareExchange(&ref_count, 0, 0))
			{
				KeStallExecutionProcessor(10);
			}
		}
		bool set_process_pre_callback(nt_object_pre_callback_type _callback)
		{
			if (!_ob_handler)
			{
				return false;
			}
			_ProcessPreCallbacks.push_back(_callback);
			return true;
		}
		bool set_thread_pre_callback(nt_object_pre_callback_type _callback)
		{
			if (!_ob_handler)
			{
				return false;
			}
			_ThreadPreCallbacks.push_back(_callback);
			return true;
		}
		bool set_process_post_callback(nt_object_post_callback_type _callback)
		{
			if (!_ob_handler)
			{
				return false;
			}
			_ProcessPostCallbacks.push_back(_callback);
			return true;
		}
		bool set_thread_post_callback(nt_object_post_callback_type _callback)
		{
			if (!_ob_handler)
			{
				return false;
			}
			_ThreadPostCallbacks.push_back(_callback);
			return true;
		}
		void _doPreProcess(POB_PRE_OPERATION_INFORMATION info)
		{
			InterlockedIncrement(&ref_count);
			std::for_each(_ProcessPreCallbacks.cbegin(),
				_ProcessPreCallbacks.cend(),
				[&](auto _pfn){
				_pfn(info);
				}
			);
			InterlockedDecrement(&ref_count);
		}
		void _doPreThread(POB_PRE_OPERATION_INFORMATION info)
		{
			InterlockedIncrement(&ref_count);
			std::for_each(_ThreadPreCallbacks.cbegin(),
				_ThreadPreCallbacks.cend(),
				[&](auto _pfn) {
				_pfn(info);
			}
			);
			InterlockedDecrement(&ref_count);
		}
		void _doPostProcess(POB_POST_OPERATION_INFORMATION info)
		{
			InterlockedIncrement(&ref_count);
			std::for_each(_ProcessPostCallbacks.cbegin(),
				_ProcessPostCallbacks.cend(),
				[&](auto _pfn) {
				_pfn(info);
			}
			);
			InterlockedDecrement(&ref_count);
		}
		void _doPostThread(POB_POST_OPERATION_INFORMATION info)
		{
			InterlockedIncrement(&ref_count);
			std::for_each(_ThreadPostCallbacks.cbegin(),
				_ThreadPostCallbacks.cend(),
				[&](auto _pfn) {
				_pfn(info);
			}
			);
			InterlockedDecrement(&ref_count);
		}
	private:
		LONG ref_count;
		PVOID _ob_handler;
		std::vector<nt_object_pre_callback_type> _ProcessPreCallbacks;
		std::vector<nt_object_pre_callback_type> _ThreadPreCallbacks;
		std::vector<nt_object_post_callback_type>_ProcessPostCallbacks;
		std::vector<nt_object_post_callback_type>_ThreadPostCallbacks;
	};
};