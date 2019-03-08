#pragma once
#include "Base.h"
#include "ntos_func_def.h"
#include <vector>
#include <string>
#include <unordered_map>
namespace ddk
{
	namespace snapshot {

		class nt_object_types:public Singleton<nt_object_types>
		{
		public:
			nt_object_types() {
				m_init = false;
			}
			~nt_object_types() {

			}
			POBJECT_TYPE get_object_type(std::wstring name) {
				if (!m_init)
				{
					take_snapshot();
				}
				if (m_objTypes.find(name)!=m_objTypes.end())
				{
					return m_objTypes[name];
				}
				return nullptr;
			}
			void print_all()
			{
				if (!m_init)
				{
					take_snapshot();
				}
				auto count = 0;
				for (auto info:m_objTypes)
				{
					count++;
					DBG_PRINT("object_type %ws,%p\r\n", info.first.c_str(), info.second);
				}
				DBG_PRINT("object type count=%d\r\n", count);
			}
		private:
			void take_snapshot()
			{
				OBJECT_ATTRIBUTES oa;
				UNICODE_STRING nsObjectTypes;
				RtlInitUnicodeString(&nsObjectTypes, L"\\ObjectTypes");
				InitializeObjectAttributes(&oa,
					&nsObjectTypes,
					OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
					nullptr,
					nullptr);
				HANDLE DirectoryHandle = nullptr;
				auto ns = ZwOpenDirectoryObject(&DirectoryHandle, DIRECTORY_QUERY, &oa);
				if (NT_SUCCESS(ns))
				{
					PVOID dir_object = nullptr;
					ns = ObReferenceObjectByHandle(DirectoryHandle,
						0,
						nullptr,
						KernelMode,
						&dir_object,
						nullptr);
					if (NT_SUCCESS(ns))
					{
						DBG_PRINT("get objecttypes diretory ok\r\n");
						auto pDirectoryObject = reinterpret_cast<POBJECT_DIRECTORY>(dir_object);
						for (auto Bucket = 0; Bucket < 37; Bucket++)
						{
							auto DirectoryEntry = pDirectoryObject->HashBuckets[Bucket];
							while (DirectoryEntry != NULL)
							{
								wchar_t buffer[MAX_PATH*2] = { 0 };
								auto d_size = 0UL;
								POBJECT_NAME_INFORMATION wcName = (POBJECT_NAME_INFORMATION)buffer;
								auto ns = ObQueryNameString(DirectoryEntry->Object,
									(POBJECT_NAME_INFORMATION)wcName,
									sizeof(buffer),
									&d_size);
								if (NT_SUCCESS(ns))
								{
									DBG_PRINT("%wZ\r\n", &wcName->Name);
									m_objTypes[std::wstring(wcName->Name.Buffer)]=reinterpret_cast<POBJECT_TYPE>(DirectoryEntry->Object);
								}
								DirectoryEntry = DirectoryEntry->ChainLink;
							}
						}
						ObDereferenceObject(dir_object);
						m_init = true;
					}
					ZwClose(DirectoryHandle);
				}
			}
		private:
			std::unordered_map<std::wstring, POBJECT_TYPE> m_objTypes;
			bool m_init;
		};
	};
};