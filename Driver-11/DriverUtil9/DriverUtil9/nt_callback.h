#pragma once
#include "Base.h"
#include <string>
#include <functional>
#include <algorithm>
#include <vector>
namespace ddk
{
	class nt_callback
	{
	public:
		using nt_callback_type = std::function<void(PVOID, PVOID)>;
		nt_callback() {
			_callback_registration = nullptr;
			_callback_object = nullptr;
		}
		~nt_callback() {

			if (_callback_registration)
			{
				ExUnregisterCallback(_callback_registration);
			}
			if (_callback_object)
			{
				ObDereferenceObject(_callback_object);
			}
			_callback.clear();
		}
		nt_callback(std::wstring callback_name) {
			open(callback_name);
		}
		nt_callback & operator = (nt_callback & _nt_cb) {
			this->_callback_object = _nt_cb.get_callback_object();
			_nt_cb.get_callback(this->_callback);
			if (this->_callback_object)
			{
				this->_callback_registration = ExRegisterCallback(
					reinterpret_cast<PCALLBACK_OBJECT>(this->_callback_object),
					ddk::nt_callback::_ExCallback,
					this);
			}
			_nt_cb.clear();
			return (*this);
		}
		bool create(std::wstring callback_name) {
			UNICODE_STRING nsCallBackName;
			RtlInitUnicodeString(&nsCallBackName, callback_name.c_str());
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa,
				&nsCallBackName,
				OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
				nullptr,
				nullptr);
			auto ns = ExCreateCallback(reinterpret_cast<PCALLBACK_OBJECT*>(&_callback_object),
				&oa,
				TRUE,
				TRUE);
			if (NT_SUCCESS(ns) && _callback_object)
			{
				return true;
			}
			return false;
		}
		bool open(std::wstring callback_name) {
			UNICODE_STRING nsCallBackName;
			RtlInitUnicodeString(&nsCallBackName, callback_name.c_str());
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa,
				&nsCallBackName,
				OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
				nullptr,
				nullptr);
			auto ns = ExCreateCallback(reinterpret_cast<PCALLBACK_OBJECT*>(&_callback_object),
				&oa,
				FALSE,
				TRUE);
			if (NT_SUCCESS(ns) && _callback_object)
			{
				return true;
			}
			return false;
		}
		bool set_callback(nt_callback_type callback) {
			if (!_callback_object)
			{
				return false;
			}
			if (_callback_registration)
			{
				_callback.push_back(callback);
				return true;
			}
			else
			{
				_callback_registration = ExRegisterCallback(reinterpret_cast<PCALLBACK_OBJECT>(_callback_object),
					ddk::nt_callback::_ExCallback, this);
				if (_callback_registration)
				{
					_callback.push_back(callback);
					return true;
				}
			}
			return false;
		}
		bool notify_callback(PVOID Arg1, PVOID Arg2) {
			if (_callback_object)
			{
				ExNotifyCallback(_callback_object,
					Arg1, Arg2);
				return true;
			}
			return false;
		}
		PVOID get_callback_object() {
			return _callback_object;
		}
		void get_callback(std::vector<nt_callback_type> & new_callback) {
			new_callback = _callback;
		}
		void clear() {
			_callback_object = nullptr;
			_callback.clear();
			if (_callback_registration)
			{
				ExUnregisterCallback(_callback_registration);
			}
			_callback_registration = nullptr;
		}
		void do_callback(PVOID Arg1, PVOID Arg2)
		{
			std::for_each(_callback.cbegin(),
				_callback.cend(),
				[&](auto _pfn) {
				_pfn(Arg1, Arg2);
			});
		}
		static VOID _ExCallback(
			_In_opt_ PVOID CallbackContext,
			_In_opt_ PVOID Argument1,
			_In_opt_ PVOID Argument2) {
			auto pThis = reinterpret_cast<ddk::nt_callback*>(CallbackContext);
			__try {
				pThis->do_callback(Argument1, Argument2);
			}
			__except (1)
			{

			}
		}
	private:
		PVOID _callback_object;
		PVOID _callback_registration;
		std::vector<nt_callback_type> _callback;
	};
};