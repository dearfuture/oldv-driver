#pragma once
#include "Base.h"
#include "lock.h"
#include "ntos_func_def.h"
#include "util_syscall.h"
#include <vector>
#include <algorithm>
#include "ntos.h"
namespace ddk {

	namespace snapshot
	{
		using driver_info = struct {
			std::wstring driver_name;
			PDRIVER_OBJECT driver_object;
		};
		using device_object_list_type = std::vector<PDEVICE_OBJECT>;
		using driver_info_list_type = std::vector<driver_info>;

		class nt_drivers:public Singleton<nt_drivers>
		{
			public:
				nt_drivers() {
					m_count = 0;
				}
				PDRIVER_OBJECT get_new_driver()
				{
					GUID Attach;
					wchar_t szGuid[MAX_PATH] = { 0 };
					_lock.acquire();
					auto lock_free = std::experimental::make_scope_exit([&]() {
						_lock.release();
					});
					auto ns = ExUuidCreate(&Attach);
					if (!NT_SUCCESS(ns))
					{
						DBG_PRINT("ExUuidCreate ns = %x\r\n", ns);
						return nullptr;
					}
					RtlStringCchPrintfW(szGuid, MAX_PATH,
						L"\\Driver\\{%08x-%04x-%04x-%02x-%02x-%02x-%02x}",
						Attach.Data1,
						Attach.Data2,
						Attach.Data3,
						Attach.Data4[0],
						Attach.Data4[1],
						Attach.Data4[2],
						Attach.Data4[3]);
					UNICODE_STRING nsAttachName;
					RtlInitUnicodeString(&nsAttachName, szGuid);
					ns = SAFE_NATIVE_CALL(IoCreateDriver, &nsAttachName, ddk::snapshot::nt_drivers::new_driver_object);
					if (NT_SUCCESS(ns))
					{
						if (!m_drvobj_list.empty())
						{
							return m_drvobj_list.back();
						}
					}
					return nullptr;
				}
				static
					NTSTATUS NTAPI
					new_driver_object(
						IN PDRIVER_OBJECT driverObject,
						IN PUNICODE_STRING registryPath
						)
				{
					ddk::snapshot::nt_drivers::getInstance().add_driver_obj(driverObject);
					return STATUS_SUCCESS;
				}
				void add_driver_obj(PDRIVER_OBJECT drv_obj)
				{
					drv_obj->DriverUnload = nullptr;
					m_drvobj_list.push_back(drv_obj);
					InterlockedIncrement(&m_count);
				}
				void del_driver_obj(PDRIVER_OBJECT drv_obj)
				{
					_lock.acquire();
					if (drv_obj->DriverUnload)
					{
						drv_obj->DriverUnload(drv_obj);
					}
					SAFE_CALL(IoDeleteDriver, drv_obj);
					//ObMakeTemporaryObject(drv_obj); 这样子删除时，有一定几率爆炸
					_lock.release();
				}
			private:
				LONG m_count;
				std::vector<PDRIVER_OBJECT>m_drvobj_list;
				nt_lock _lock;
		};
		class nt_driver_snapshot :public Singleton<nt_driver_snapshot>
		{
		public:
			nt_driver_snapshot() {
				
			}
			~nt_driver_snapshot() {

			}
			bool get_driver_devices(PDRIVER_OBJECT drv_obj, device_object_list_type &dev_obj_list)
			{
				//枚举driver_object的device_object
				ULONG ArrayLength = 0;
				PDEVICE_OBJECT *DeviceArray = nullptr;
				auto exit_free = std::experimental::make_scope_exit(
					[&]() {
					if (DeviceArray)
					{
						free(DeviceArray);
					}
				});
				auto ns = STATUS_SUCCESS;
				do 
				{
					ns = IoEnumerateDeviceObjectList(drv_obj, DeviceArray, ArrayLength * sizeof(PDEVICE_OBJECT), &ArrayLength);
					if (ns == STATUS_BUFFER_TOO_SMALL) {
						if (DeviceArray != nullptr)
							free(DeviceArray);
						DeviceArray = nullptr;
						DeviceArray = reinterpret_cast<PDEVICE_OBJECT *>(malloc(ArrayLength * sizeof(PDEVICE_OBJECT)));
						if (!DeviceArray)
							ns = STATUS_INSUFFICIENT_RESOURCES;
					}
				} while (ns == STATUS_BUFFER_TOO_SMALL);
				if (NT_SUCCESS(ns))
				{
					for (auto i = 0UL; i < ArrayLength; i++)
						dev_obj_list.push_back(DeviceArray[i]);
					return true;
				}
				return false;
			}
			bool get_driver_objects_list(std::wstring dir_name, driver_info_list_type &_list)
			{
				UNICODE_STRING nsDirName;
				RtlInitUnicodeString(&nsDirName, dir_name.c_str());
				OBJECT_ATTRIBUTES oa = {};
				InitializeObjectAttributes(&oa,
					&nsDirName,
					OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					nullptr,
					nullptr);
				HANDLE DirectoryHandle = nullptr;
				auto ns = ZwOpenDirectoryObject(&DirectoryHandle, DIRECTORY_QUERY, &oa);
				if (NT_SUCCESS(ns))
				{
					ULONG QueryContext = 0;
					UNICODE_STRING DriverTypeStr;
					RtlInitUnicodeString(&DriverTypeStr, L"Driver");
					do 
					{
						UCHAR Buffer[1024] = { 0 };
						POBJECT_DIRECTORY_INFORMATION DirInfo = (POBJECT_DIRECTORY_INFORMATION)Buffer;
						ns = ZwQueryDirectoryObject(
							DirectoryHandle,
							DirInfo, 
							sizeof(Buffer), 
							TRUE, 
							FALSE,
							&QueryContext, 
							NULL);
						if (NT_SUCCESS(ns))
						{
							if (RtlCompareUnicodeString(&DirInfo->TypeName, &DriverTypeStr, TRUE) == 0)
							{
								UNICODE_STRING FullDriverName;
								wchar_t wcsfullname[MAX_PATH] = { 0 };
								RtlInitEmptyUnicodeString(&FullDriverName, wcsfullname, sizeof(wcsfullname));
								RtlCopyUnicodeString(&FullDriverName, &nsDirName);
								RtlAppendUnicodeToString(&FullDriverName, L"\\");
								RtlAppendUnicodeStringToString(&FullDriverName, &DirInfo->Name);
								{
									PDRIVER_OBJECT DriverPtr = NULL;
									auto Status = ObReferenceObjectByName(&FullDriverName, OBJ_CASE_INSENSITIVE, NULL, GENERIC_READ, *IoDriverObjectType, KernelMode, NULL, (PVOID *)&DriverPtr);
									if (NT_SUCCESS(Status)) 
									{
										driver_info info;
										info.driver_name = std::wstring(wcsfullname);
										info.driver_object = DriverPtr;
										ObDereferenceObject(DriverPtr);
										_list.push_back(info);
									}
								}
							}
						}
					} while (NT_SUCCESS(ns));
					ZwClose(DirectoryHandle);
					return true;
				}
				return false;
			}
			bool get_all_driver_object(driver_info_list_type &all_drv_obj)
			{
				// Driver目录和FileSystem目录
				auto bret = get_driver_objects_list(L"\\Driver",all_drv_obj);
				if (!bret)
				{
					return false;
				}
				bret = get_driver_objects_list(L"\\FileSystem", all_drv_obj);
				if (!bret)
				{
					return false;
				}
				return true;
			}
			bool get_driver_object(std::wstring drvname,PDRIVER_OBJECT &drv_object)
			{
				UNICODE_STRING nsDrvName;
				RtlInitUnicodeString(&nsDrvName, drvname.c_str());
				auto ns = ObReferenceObjectByName(&nsDrvName,
					OBJ_CASE_INSENSITIVE,
					nullptr,
					0,
					*IoDriverObjectType,
					KernelMode,
					nullptr,
					reinterpret_cast<PVOID*>(&drv_object));
				if (NT_SUCCESS(ns))
				{
					return true;
				}
				return false;
			}
		};
	};
};