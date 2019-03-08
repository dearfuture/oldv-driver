#pragma once
#include "Base.h"
#include "payload_makecode.h"
namespace ddk
{
	namespace inject
	{
		class nt_thread_inject:public Singleton<nt_thread_inject>
		{
		public:
			nt_thread_inject()
			{

			}
			~nt_thread_inject() {

			}
			bool inject_dll(HANDLE ProcessId, std::wstring dll_path)
			{
				PVOID shell_code = nullptr;
				if (make_shellcode_loaddll(ProcessId, &shell_code, dll_path))
				{
					return inject_thread(ProcessId, shell_code);
				}
				return false;
			}
			bool inject_thread(HANDLE ProcessId, PVOID thread_func)
			{
				return ExecuteThread(ProcessId,thread_func,nullptr, THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
			}
		};
	};
};