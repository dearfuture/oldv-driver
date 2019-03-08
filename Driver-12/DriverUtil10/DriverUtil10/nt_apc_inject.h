#pragma once
#include "Base.h"
#include "payload_makecode.h"
namespace ddk
{
	namespace inject
	{
		//APC注入大法
		class nt_apc_inject :public Singleton<nt_apc_inject>
		{
		public:
			nt_apc_inject() {
				
			}
			~nt_apc_inject() {

			}
			bool inject_dll(HANDLE ProcessId,std::wstring dll_path)
			{
				PVOID shellcode = nullptr;
				auto b_1 = ddk::inject::make_shellcode_loaddll(ProcessId, &shellcode, dll_path);
				if (b_1)
				{
					return inject_code(ProcessId, shellcode);
				}
				return false;
			}
			bool inject_code(HANDLE ProcessId, PVOID code_address)
			{
				PETHREAD thread = nullptr;
				auto b_1 = look_up_process_thread(ProcessId, thread);
				if (!b_1)
				{
					return false;
				}
				return query_apc(thread,code_address,nullptr,nullptr,nullptr,true);
			}
		private:
			bool look_up_process_thread(HANDLE ProcessId, PETHREAD &ret_thread)
			{
				ret_thread = nullptr;
				//查找合适的thread进行apc注入
				PSYSTEM_PROCESS_INFORMATION FindInfo = nullptr;
				auto pFin = ddk::util::GetSysInf(SystemProcessInformation);
				auto pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pFin);
				if (!pInfo)
				{
					return false;
				}
				auto fin = pFin;
				auto exit_1 = std::experimental::make_scope_exit([&]() {if (fin)free(fin); });

				for (;;)
				{
					if (pInfo->UniqueProcessId == ProcessId)
					{
						FindInfo = pInfo;
						break;
					}

					if (pInfo->NextEntryOffset==0)
					{
						break;
					}
					pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>((ULONG_PTR)pInfo + pInfo->NextEntryOffset);
				}
				if (!FindInfo)
				{
					return false;
				}
				for (auto i = 0; i < FindInfo->NumberOfThreads;i++)
				{
					if (FindInfo->thread_info[i].ClientId.UniqueThread == PsGetCurrentThreadId())
					{
						continue;
					}
					PETHREAD thread = nullptr;
					auto ns = PsLookupThreadByThreadId(FindInfo->thread_info[i].ClientId.UniqueThread, &thread);
					if (NT_SUCCESS(ns))
					{
						ret_thread = thread;
						break;
					}
				}
				if (ret_thread)
				{
					return true;
				}
				return false;
			}
		public:
			static VOID NTAPI KernelApcInjectCallback(
				PRKAPC Apc,
				PKNORMAL_ROUTINE* NormalRoutine,
				PVOID* NormalContext,
				PVOID* SystemArgument1,
				PVOID* SystemArgument2
				)
			{
				UNREFERENCED_PARAMETER(SystemArgument1);
				UNREFERENCED_PARAMETER(SystemArgument2);

				// Skip execution
				if (PsIsThreadTerminating(PsGetCurrentThread()))
					*NormalRoutine = NULL;

				// Fix Wow64 APC
				if (PsGetCurrentProcessWow64Process() != NULL)
					PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);

				free(Apc);
			}
			static VOID NTAPI KernelApcPrepareCallback(
				PRKAPC Apc,
				PKNORMAL_ROUTINE* NormalRoutine,
				PVOID* NormalContext,
				PVOID* SystemArgument1,
				PVOID* SystemArgument2
				)
			{
				UNREFERENCED_PARAMETER(NormalRoutine);
				UNREFERENCED_PARAMETER(NormalContext);
				UNREFERENCED_PARAMETER(SystemArgument1);
				UNREFERENCED_PARAMETER(SystemArgument2);


				KeTestAlertThread(UserMode);

				free(Apc);
			}

		private:
			bool query_apc(PETHREAD pThread,PVOID UserFunc,PVOID Arg1,PVOID Arg2,PVOID Arg3,bool force)
			{
				PKAPC pPrepareApc = nullptr;
				auto pInjectApc = reinterpret_cast<PKAPC>(malloc(sizeof(KAPC)));
				if (!pInjectApc)
				{
					return false;
				}
				KeInitializeApc(
					pInjectApc, (PKTHREAD)pThread,
					OriginalApcEnvironment, &ddk::inject::nt_apc_inject::KernelApcInjectCallback,
					NULL, (PKNORMAL_ROUTINE)(ULONG_PTR)UserFunc, UserMode, Arg1
					);
				if (force)
				{
					pPrepareApc = reinterpret_cast<PKAPC>(malloc(sizeof(KAPC)));
					KeInitializeApc(
						pPrepareApc, (PKTHREAD)pThread,
						OriginalApcEnvironment, &KernelApcPrepareCallback,
						NULL, NULL, KernelMode, NULL
						);
				}
				if (KeInsertQueueApc(pInjectApc, Arg2, Arg3, 0))
				{
					if (force && pPrepareApc)
						KeInsertQueueApc(pPrepareApc, NULL, NULL, 0);
					return true;
				}
				else
				{
					free(pInjectApc);
					if (pPrepareApc)
						free(pPrepareApc);
				}
				return false;
			}
			
		};
	};
};