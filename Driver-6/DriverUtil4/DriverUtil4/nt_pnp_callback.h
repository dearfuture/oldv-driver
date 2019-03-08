#pragma once
#include "Base.h"
#include <algorithm>
#include <vector>
#include <functional>
namespace ddk
{
	class nt_pnp_callback {
	public:
		enum nt_pnp_callback_class
		{
			DISK=1,
			CDROM,
			VOLUME,
			PARTITION,
			ALL,
		};
		using nt_pnp_callback_type = std::function<NTSTATUS(PVOID)>;
		nt_pnp_callback() {
			_NotificationEntry = nullptr;
		}
		~nt_pnp_callback() {
			if (_NotificationEntry)
			{
				IoUnregisterPlugPlayNotification(_NotificationEntry);
			}
		}
		nt_pnp_callback(nt_pnp_callback_class _class)
		{
			create_callback(_class);
		}
		bool set_callback(nt_pnp_callback_type _function)
		{
			if (!_NotificationEntry)
			{
				return false;
			}
			_callbacks.push_back(_function);
			return true;
		}
		bool create_callback(nt_pnp_callback_class _class)
		{
			NTSTATUS ns = STATUS_UNSUCCESSFUL;
			this->_class = _class;
			switch (_class)
			{
			case ddk::nt_pnp_callback::VOLUME:
				ns = IoRegisterPlugPlayNotification(
					EventCategoryDeviceInterfaceChange,
					PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,//0 Magic
					(PVOID)(&GUID_DEVINTERFACE_VOLUME),
					g_pDriverObject,
					(PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)ddk::nt_pnp_callback::DriverDevInterxNotifyCallBack,
					this,
					&_NotificationEntry);
				break;
			case ddk::nt_pnp_callback::PARTITION:
				ns = IoRegisterPlugPlayNotification(
					EventCategoryDeviceInterfaceChange,
					PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,//0 Magic
					(PVOID)(&GUID_DEVINTERFACE_PARTITION),
					g_pDriverObject,
					(PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)ddk::nt_pnp_callback::DriverDevInterxNotifyCallBack,
					this,
					&_NotificationEntry);
				break;
			case ddk::nt_pnp_callback::ALL:
				ns = IoRegisterPlugPlayNotification(
					EventCategoryHardwareProfileChange,
					PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,//0 Magic
					nullptr,
					g_pDriverObject,
					(PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)ddk::nt_pnp_callback::DriverDevInterxNotifyCallBack,
					this,
					&_NotificationEntry);
				break;
			case ddk::nt_pnp_callback::DISK:
				ns = IoRegisterPlugPlayNotification(
					EventCategoryDeviceInterfaceChange,
					PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,//0 Magic
					(PVOID)(&GUID_DEVINTERFACE_DISK),
					g_pDriverObject,
					(PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)ddk::nt_pnp_callback::DriverDevInterxNotifyCallBack,
					this,
					&_NotificationEntry);
				break;
			case ddk::nt_pnp_callback::CDROM:
				ns = IoRegisterPlugPlayNotification(
					EventCategoryDeviceInterfaceChange,
					PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
					(PVOID)(&GUID_DEVINTERFACE_CDROM),
					g_pDriverObject,
					(PDRIVER_NOTIFICATION_CALLBACK_ROUTINE)ddk::nt_pnp_callback::DriverDevInterxNotifyCallBack,
					this,
					&_NotificationEntry);
				break;
			default:
				break;
			}
			if (!NT_SUCCESS(ns))
			{
				return false;
			}
			return true;
		}
		static NTSTATUS NTAPI DriverDevInterxNotifyCallBack(
			IN PVOID NotificationStructure,
			IN PVOID Context)
		{
			auto pThis = reinterpret_cast<ddk::nt_pnp_callback*>(Context);
			__try
			{
				return pThis->do_callback(NotificationStructure);
			}
			__except (1)
			{

			}
			return STATUS_SUCCESS;
		}
		NTSTATUS do_callback(PVOID NotificationStructure)
		{
			for (auto _pfn:_callbacks)
			{
				auto ns = _pfn(NotificationStructure);
				if (!NT_SUCCESS(ns))
				{
					return ns;
				}
			}
			return STATUS_SUCCESS;
		}
		nt_pnp_callback & operator = (nt_pnp_callback &_pnp)
		{
			this->_class = _pnp.get_class();
			_pnp.get_callbacks(this->_callbacks);
			if (_pnp.get_entry())
			{
				this->create_callback(this->_class);
			}
			_pnp.clear();
			return (*this);
		}
		PVOID get_entry() {
			return _NotificationEntry;
		}
		nt_pnp_callback_class get_class() {
			return _class;
		}
		void clear()
		{
			if (_NotificationEntry)
			{
				IoUnregisterPlugPlayNotification(_NotificationEntry);
			}
			_NotificationEntry = nullptr;
			_callbacks.clear();
		}
		void get_callbacks(std::vector<nt_pnp_callback_type> &_new_callbacks)
		{
			_new_callbacks = _callbacks;
		}
	private:
		nt_pnp_callback_class _class;
		PVOID _NotificationEntry;
		std::vector<nt_pnp_callback_type>_callbacks;
	};
};