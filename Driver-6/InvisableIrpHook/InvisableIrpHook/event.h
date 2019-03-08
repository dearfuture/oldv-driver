#pragma once
#include "Base.h"
#include <string>
namespace ddk
{
	class nt_event
	{
	public:
		nt_event(std::wstring event_name)
		{

			h_event = nullptr;
			event_full_name = L"";
			SECURITY_DESCRIPTOR Se;
			auto ns = RtlCreateSecurityDescriptor(&Se, SECURITY_DESCRIPTOR_REVISION);
			if (NT_SUCCESS(ns))
			{
				ns = RtlSetDaclSecurityDescriptor(&Se, TRUE, NULL, TRUE);
				if (NT_SUCCESS(ns))
				{
					OBJECT_ATTRIBUTES oa;
					UNICODE_STRING nsEvent;
					event_full_name = std::wstring(L"\\BaseNamedObjects\\") + event_name;
					RtlInitUnicodeString(&nsEvent, event_full_name.c_str());
					InitializeObjectAttributes(&oa, &nsEvent, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
						NULL, &Se);
					ns = ZwCreateEvent(&h_event, EVENT_ALL_ACCESS,
						&oa,
						SynchronizationEvent,
						FALSE);
					if (!NT_SUCCESS(ns))
					{
						h_event = nullptr;
					}
				}
			}

		}
		nt_event()
		{
			h_event = nullptr;
			event_full_name = L"";
		}
		nt_event(DWORD nn)
		{
			h_event = nullptr;
			event_full_name = L"";
			UNREFERENCED_PARAMETER(nn);
			SECURITY_DESCRIPTOR Se;
			auto ns = RtlCreateSecurityDescriptor(&Se, SECURITY_DESCRIPTOR_REVISION);
			if (NT_SUCCESS(ns))
			{
				ns = RtlSetDaclSecurityDescriptor(&Se, TRUE, NULL, TRUE);
				if (NT_SUCCESS(ns))
				{
					OBJECT_ATTRIBUTES oa;
					UNICODE_STRING nsEvent;
					InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE | OBJ_PERMANENT,
						NULL, &Se);
					ns = ZwCreateEvent(&h_event, EVENT_ALL_ACCESS,
						&oa,
						SynchronizationEvent,
						FALSE);
					if (!NT_SUCCESS(ns))
					{
						h_event = nullptr;
					}
				}
			}
		}
		~nt_event()
		{
			if (h_event)
			{
				ZwClose(h_event);
				DBG_PRINT("EVENT RELEASE\r\n");
			}
		}
		void wait()
		{
			NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
			ZwWaitForSingleObject(h_event, FALSE, NULL);
		}
		void wait_alert()
		{
			NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
			ZwWaitForSingleObject(h_event, TRUE, NULL);
		}
		void set()
		{
			LONG oldState;
			ZwSetEvent(h_event, &oldState);
		}
		HANDLE get_handle()
		{
			return h_event;
		}
		void set_rel()
		{
			h_event = nullptr;
		}
		nt_event & operator = (nt_event &event_)
		{
			this->h_event = event_.get_handle();
			event_.set_rel();
			return (*this);
		}
	private:
		std::wstring event_full_name;
		HANDLE h_event;
	};
}