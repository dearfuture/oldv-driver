#pragma once
#include "Base.h"
#include "ntos.h"
#include "nt_process_callback.h"
namespace ddk
{
	namespace protect
	{ 
		class nt_process_protect :public Singleton<nt_process_protect>
		{
			//protect(processid)
		public:
			nt_process_protect() {
				protect_offset = ddk::special_data::getInstance().get_protect_offset();
				ddk::nt_process_callback::getInstance().reg_callback_ex(std::bind(
					&ddk::protect::nt_process_protect::callback_protect_process,
					this, 
					std::placeholders::_1,
					std::placeholders::_2,
					std::placeholders::_3));
			}
			~nt_process_protect()
			{

			}
		public:
			void callback_protect_process(
				PEPROCESS Process,
				HANDLE ProcessId,
				PPS_CREATE_NOTIFY_INFO CreateInfo)
			{
				if (!CreateInfo)
				{
					//處理infomask問題
					auto object_header = reinterpret_cast<ddk::ntos_space::win10_14393_x64::POBJECT_HEADER>((ULONG_PTR)Process - 0x30);
					object_header->InfoMask &= ~0x10;
				}
			}
			bool protect(HANDLE ProcessId)
			{
				PEPROCESS Process = nullptr;
				auto ns = PsLookupProcessByProcessId(ProcessId, &Process);
				if (!NT_SUCCESS(ns))
				{
					return false;
				}
				//Protect位方式
				if (protect_offset)
				{
					auto ProcessPointer = reinterpret_cast<PBYTE>(Process);
					if (ddk::util::IsWindow8Point1OrGreater())
					{
						*(BYTE*)(ProcessPointer + protect_offset) |= 7;
					}
					else if (ddk::util::IsWindows80())
					{
						*(BYTE*)(ProcessPointer + protect_offset) |= 1;
					}
					else 
					{
						BitTestAndSet(reinterpret_cast<LONG*>(ProcessPointer + protect_offset), 11);
					}
				}

				//篡改 handle_entry大法，不夠猥瑣，拋棄
				//PspCidTable-->*(*(ULONG_PTR**)get_kdblock()->PspCidTable);

				//dispatch_header的Type修改，32位下可以，64位DeliverApc直接藍屏

				//修改進程狀態處於初始化模式，PsLookupProcessByProcessId會判斷這個
				auto os = ddk::util::get_version();
				if (os==WIN7SP1)
				{
					auto process2 = reinterpret_cast<ddk::ntos<WIN7SP1>::PEPROCESS>(Process);
					process2->ProcessInserted = 0;
				}
				if (os == WIN7)
				{
					auto process2 = reinterpret_cast<ddk::ntos<WIN7>::PEPROCESS>(Process);
					process2->ProcessInserted = 0;
				}
				if (os == WIN8)
				{
					auto process2 = reinterpret_cast<ddk::ntos<WIN8>::PEPROCESS>(Process);
					process2->ProcessInserted = 0;
				}
				if (os == WIN81)
				{
					auto process2 = reinterpret_cast<ddk::ntos<WIN81>::PEPROCESS>(Process);
					process2->ProcessInserted = 0;
				}
				if (os == WIN10_10586)
				{
					auto process2 = reinterpret_cast<ddk::ntos<WIN10_10586>::PEPROCESS>(Process);
					process2->ProcessInserted = 0;
				}
				if (os == WIN10_now)
				{
					auto process2 = reinterpret_cast<ddk::ntos<WIN10_now>::PEPROCESS>(Process);
					process2->ProcessInserted = 0;
				}

				//修改object屬性禁止應用層
				auto object_header = reinterpret_cast<ddk::ntos_space::win10_14393_x64::POBJECT_HEADER>((ULONG_PTR)Process - 0x30);

				object_header->Flags |= 4;//禁止应用层打开对象
				LOG_DEBUG("infomask = %x\r\n", object_header->InfoMask);

				//對象獨佔 大法！！這裏有一些很操蛋的事情！
				//Exclusive Object 獨佔對象大法
				//objectHeader = object-0x30
				//ObjectHeader->Flags & OB_FLAG_EXCLUSIVE_OBJECT &&
				//OBJECT_HEADER_TO_EXCLUSIVE_PROCESS(ObjectHeader) != NULL
				//_OBJECT_HEADER_PROCESS_INFO
				//Vista开始 object_header_to_exclusive_process需要复杂的操作
				/*
				char *__fastcall OBJECT_HEADER_TO_PROCESS_INFO(_OBJECT_HEADER *a1)
				{
				char *v1; // rcx@2

				if ( a1->InfoMask & 0x10 )
				v1 = (char *)a1 - ObpInfoMaskToOffset[a1->InfoMask & 0x1F];
				else
				v1 = 0i64;
				return v1;
				}
				__int64 ObpInitInfoBlockOffsets()
				{
				char *v0; // rdx@1
				int v1; // ecx@1
				char v2; // al@2
				__int64 result; // rax@18

				v0 = ObpInfoMaskToOffset;
				v1 = 0;
				do
				{
				v2 = 0;
				if ( v1 & 1 )
				v2 = 32;
				if ( v1 & 2 )
				v2 += 32;
				if ( v1 & 4 )
				v2 += 16;
				if ( v1 & 8 )
				v2 += 32;
				if ( v1 & 0x10 )
				v2 += 16;
				if ( v1 & 0x20 )
				v2 += 16;
				if ( v1 & 0x40 )
				v2 += 16;
				if ( (char)v1 < 0 )
				v2 += 4;
				++v1;
				*v0 = v2;
				result = v1;
				++v0;
				}
				while ( (unsigned __int64)v1 < 0x100 );
				return result;
				}
				*/
				object_header->Flags |= 8;
				if(object_header->InfoMask & 0x10)
				{
					auto pExclusiveInfo = reinterpret_cast<ddk::ntos_space::win10_14393_x64::POBJECT_HEADER_PROCESS_INFO>((ULONG_PTR)object_header - 48);
					pExclusiveInfo->ExclusiveProcess = (ddk::ntos_space::win10_14393_x64::_EPROCESS *)IoGetCurrentProcess();
				}
				else
				{
					//不能寫啊啊啊，不讓爆炸給你看
					//FileObject可以寫，我想你知道為什麽
					//情況！！
				}
				object_header->InfoMask |= 0x10;
				//使用獨佔大法，不能釋放object了
				//ObDereferenceObject(Process);
				return true;
			}
			bool protect_process(std::wstring process_name)
			{
				UNICODE_STRING nsProcessName;
				RtlInitUnicodeString(&nsProcessName, process_name.c_str());
				auto pFin = ddk::util::GetSysInf(SystemProcessInformation);
				auto pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pFin);
				if (!pInfo)
				{
					return false;
				}
				auto fin = pFin;
				auto exit_1 = std::experimental::make_scope_exit([&]() {if (fin)free(fin); });
				bool b_ret = false;
				for (;;)
				{
					if (RtlEqualUnicodeString(&pInfo->ImageName,&nsProcessName,TRUE))
					{
						b_ret = protect(pInfo->UniqueProcessId);
					}

					if (pInfo->NextEntryOffset == 0)
					{
						break;
					}
					pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>((ULONG_PTR)pInfo + pInfo->NextEntryOffset);
				}
				return b_ret;
			}
		private:
			ULONG protect_offset;
		};
	};
};