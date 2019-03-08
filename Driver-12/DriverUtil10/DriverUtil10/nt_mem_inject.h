#pragma once
#include "Base.h"
#include "payload_makecode.h"
#include "NtFile.h"
namespace ddk
{
	namespace inject
	{
		class nt_mem_inject:public Singleton<nt_mem_inject>
		{
		public:
			nt_mem_inject() {

			}
			~nt_mem_inject() {

			}
			bool mem_load_dll(HANDLE ProcessId, std::wstring dll_path)
			{
				auto file = ddk::CNtFile(dll_path);
				auto file_size = ULONG(file.get_file_size());
				auto pfile_data = new CHAR[file_size];
				if (pfile_data)
				{
					size_t size = 0;
					file.read((PVOID)pfile_data, file_size, size);
					auto b_2 = mem_load_dll(ProcessId, pfile_data, file_size);
					delete[] pfile_data;
					return b_2;
				}
				return false;
			}
			bool mem_load_dll(HANDLE ProcessId, PVOID dll_data, ULONG dll_size)
			{
				//仅支持32位！！64位dll手工加载参考BlackBone里的那个复杂的代码
				//shellcode版内存加载器！！
				PVOID shell_code = nullptr;
				auto b_1 = make_shellcode_memload32(ProcessId, &shell_code, dll_data, dll_size);
				if (b_1)
				{
					return ExecuteThread(ProcessId, shell_code, nullptr, THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH | THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);
				}
				return false;
			}
		private:
		};
	};
};