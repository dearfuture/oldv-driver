#pragma once
#include "Base.h"
#include "util_syscall.h"
#include "payload.h"
#pragma warning(disable:4311)
#pragma warning(disable:4302)
namespace ddk
{
	namespace inject
	{
		static const auto THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x00000001;
		static const auto THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002;
		static const auto THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004;
		typedef struct _INJECT_BUFFER
		{
			UCHAR code[0x200];
			UCHAR original_code[8];
			PVOID hook_func;
			union
			{
				UNICODE_STRING path;
				UNICODE_STRING32 path32;
			};

			wchar_t buffer[488];
			PVOID module;
			ULONG complete;
		} INJECT_BUFFER, *PINJECT_BUFFER;

		static PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName, IN BOOLEAN isWow64)
		{
			INT i;

			if (pProcess == NULL)
				return NULL;

			// Protect from UserMode AV
			__try
			{
				LARGE_INTEGER time = { 0 };
				time.QuadPart = -250ll * 10 * 1000;     // 250 msec.
				if (isWow64)
				{
					PLIST_ENTRY32 pListEntry;
					PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(pProcess);
					if (pPeb32 == NULL)
					{
						LOG_DEBUG("%s: No PEB present. Aborting\n", __FUNCTION__);
						return NULL;
					}

					// Wait for loader a bit
					for (i = 0; !pPeb32->Ldr && i < 10; i++)
					{
						LOG_DEBUG("%s: Loader not intialiezd, waiting\n", __FUNCTION__);
						KeDelayExecutionThread(KernelMode, TRUE, &time);
					}

					// Still no loader
					if (!pPeb32->Ldr)
					{
						LOG_DEBUG("%s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
						return NULL;
					}

					// Search in InLoadOrderModuleList
					for (pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
					pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
						pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
					{
						UNICODE_STRING ustr;
						PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

						RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer);

						if (RtlCompareUnicodeString(&ustr, ModuleName, TRUE) == 0)
							return (PVOID)pEntry->DllBase;
					}
				}
				// Native process
				else
				{
					PLIST_ENTRY pListEntry;
					PPEB pPeb = (PPEB)PsGetProcessPeb(pProcess);
					if (!pPeb)
					{
						LOG_DEBUG("%s: No PEB present. Aborting\n", __FUNCTION__);
						return NULL;
					}

					// Wait for loader a bit
					for (i = 0; !pPeb->Ldr && i < 10; i++)
					{
						LOG_DEBUG("%s: Loader not intialiezd, waiting\n", __FUNCTION__);
						KeDelayExecutionThread(KernelMode, TRUE, &time);
					}

					// Still no loader
					if (!pPeb->Ldr)
					{
						LOG_DEBUG("%s: Loader was not intialiezd in time. Aborting\n", __FUNCTION__);
						return NULL;
					}

					// Search in InLoadOrderModuleList
					for (pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
					pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
						pListEntry = pListEntry->Flink)
					{
						PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
						if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
							return pEntry->DllBase;
					}

				}

			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				LOG_DEBUG("%s: Exception, Code: 0x%X\n", __FUNCTION__, GetExceptionCode());
			}

			return NULL;
		}

		static PVOID BBGetModuleExport(IN PVOID pBase, IN PCCHAR name_ord)
		{
			PIMAGE_DOS_HEADER pDosHdr = (PIMAGE_DOS_HEADER)pBase;
			PIMAGE_NT_HEADERS32 pNtHdr32 = NULL;
			PIMAGE_NT_HEADERS64 pNtHdr64 = NULL;
			PIMAGE_EXPORT_DIRECTORY pExport = NULL;
			ULONG expSize = 0;
			ULONG_PTR pAddress = 0;
			PUSHORT pAddressOfOrds;
			PULONG  pAddressOfNames;
			PULONG  pAddressOfFuncs;
			ULONG i;

			ASSERT(pBase != NULL);
			if (pBase == NULL)
				return NULL;

			/// Not a PE file
			if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
				return NULL;

			pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)pBase + pDosHdr->e_lfanew);
			pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)pBase + pDosHdr->e_lfanew);

			// Not a PE file
			if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
				return NULL;

			// 64 bit image
			if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
				expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			}
			// 32 bit image
			else
			{
				pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + (ULONG_PTR)pBase);
				expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
			}

			pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)pBase);
			pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)pBase);
			pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)pBase);

			for (i = 0; i < pExport->NumberOfFunctions; ++i)
			{
				USHORT OrdIndex = 0xFFFF;
				PCHAR  pName = NULL;

				// Find by index
				if ((ULONG_PTR)name_ord <= 0xFFFF)
				{
					OrdIndex = (USHORT)i;
				}
				// Find by name
				else if ((ULONG_PTR)name_ord > 0xFFFF && i < pExport->NumberOfNames)
				{
					pName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)pBase);
					OrdIndex = pAddressOfOrds[i];
				}
				// Weird params
				else
					return NULL;

				if (((ULONG_PTR)name_ord <= 0xFFFF && (USHORT)((ULONG_PTR)name_ord) == OrdIndex + pExport->Base) ||
					((ULONG_PTR)name_ord > 0xFFFF && strcmp(pName, name_ord) == 0))
				{
					pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)pBase;

					// Check forwarded export
					if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize)
					{
						return NULL;
					}

					break;
				}
			}

			return (PVOID)pAddress;
		}
		static NTSTATUS NTAPI NewNtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength)
		{
			NTSTATUS status = STATUS_SUCCESS;
			status = SAFE_SYSCALL(NtQueryVirtualMemory, ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
		//	LOG_DEBUG("NtQueryVirtualMemory %x\r\n", status);
			return status;
		}
		static NTSTATUS NTAPI NewNtWriteVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
		{
			NTSTATUS status = STATUS_SUCCESS;
			status = SAFE_SYSCALL(NtWriteVirtualMemory,ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
			return status;
		}
		static NTSTATUS NTAPI NewNtReadVirtualMemory(IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG BufferLength, OUT PULONG ReturnLength OPTIONAL)
		{
			NTSTATUS status = STATUS_SUCCESS;
			status = SAFE_SYSCALL(NtReadVirtualMemory,ProcessHandle, BaseAddress, Buffer, BufferLength, ReturnLength);
			return status;
		}
		static NTSTATUS NTAPI NewNtProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection)
		{
			NTSTATUS status = STATUS_SUCCESS;
			status = SAFE_SYSCALL(NtProtectVirtualMemory,ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
			return status;
		}
		static NTSTATUS NTAPI ZwCreateThreadEx(OUT PHANDLE hThread, IN ACCESS_MASK DesiredAccess, IN PVOID ObjectAttributes, IN HANDLE ProcessHandle, IN PVOID lpStartAddress, IN PVOID lpParameter, IN ULONG Flags, IN SIZE_T StackZeroBits, IN SIZE_T SizeOfStackCommit, IN SIZE_T SizeOfStackReserve, IN PNT_PROC_THREAD_ATTRIBUTE_LIST AttributeList)
		{
			NTSTATUS status = STATUS_UNSUCCESSFUL;
			status = SAFE_SYSCALL(NtCreateThreadEx,
					hThread, DesiredAccess, ObjectAttributes,
					ProcessHandle, lpStartAddress, lpParameter,
					Flags, StackZeroBits, SizeOfStackCommit,
					SizeOfStackReserve, AttributeList
					);
			return status;
		}
		static PVOID AllocateInjectMemory(IN HANDLE ProcessHandle, IN PVOID DesiredAddress, IN SIZE_T DesiredSize)
		{
			MEMORY_BASIC_INFORMATION mbi;
			SIZE_T AllocateSize = DesiredSize;

			if ((ULONG_PTR)DesiredAddress >= 0x70000000 && (ULONG_PTR)DesiredAddress < 0x80000000)
				DesiredAddress = (PVOID)0x70000000;

			while (1)
			{
				if (!NT_SUCCESS(NewNtQueryVirtualMemory(ProcessHandle, DesiredAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL)))
				{
					LOG_DEBUG("faield QueryVirtualMemory\r\n");
					return NULL;
				}
				if (DesiredAddress != mbi.AllocationBase)
				{
					DesiredAddress = mbi.AllocationBase;
				}
				else
				{
					DesiredAddress = (PVOID)((ULONG_PTR)mbi.AllocationBase - 0x10000);
				}

				if (mbi.State == MEM_FREE)
				{
					if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
					{
						if (NT_SUCCESS(ZwAllocateVirtualMemory(ProcessHandle, &mbi.BaseAddress, 0, &AllocateSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
						{
							return mbi.BaseAddress;
						}
					}
				}
			}
			return NULL;
		}
		static bool make_shellcode_memload32(HANDLE ProcessId, PVOID *out_mem, PVOID file_data, DWORD file_size)
		{
			PEPROCESS Process = nullptr;
			auto ns = PsLookupProcessByProcessId(ProcessId, &Process);
			if (!NT_SUCCESS(ns))
			{
				return false;
			}
			auto exit_1 = std::experimental::make_scope_exit([&]() {
				if (Process)
				{
					ObDereferenceObject(Process);
				}
			});
			if (!PsGetProcessWow64Process(Process))
			{
				//shellcode只准备了32位版
				return false;
			}
			//这里打开进程
			HANDLE ProcessHandle;
			auto ns2 = ObOpenObjectByPointer(Process,
				OBJ_KERNEL_HANDLE,
				NULL,
				PROCESS_ALL_ACCESS,
				*PsProcessType,
				KernelMode,
				(PHANDLE)&ProcessHandle
				);
			if (!NT_SUCCESS(ns2))
			{
				return false;
			}
			auto exit_2 = std::experimental::make_scope_exit([&]() {if (ProcessHandle) { ZwClose(ProcessHandle); }});
			PVOID shellcode = nullptr;
			DWORD ShellCodeSize = sizeof(shellcode_mem_load_32);
			DWORD TotolSize = ShellCodeSize + file_size + 4;
			SIZE_T AllocSize = TotolSize+0x100;
			auto ns3 = ZwAllocateVirtualMemory(
				ProcessHandle, 
				&shellcode, 
				0,
				&AllocSize, 
				MEM_COMMIT,
				PAGE_EXECUTE_READWRITE
				);
			if (!NT_SUCCESS(ns3))
			{
				return false;
			}
			auto mem_shellcode = (PBYTE)malloc(sizeof(shellcode_mem_load_32));
			if (!mem_shellcode)
			{
				return false;
			}
			auto exit_3 = std::experimental::make_scope_exit([&]() {if (mem_shellcode)free(mem_shellcode); });

			RtlCopyMemory(mem_shellcode, shellcode_mem_load_32, sizeof(shellcode_mem_load_32));

			int flag = 0xAFAFAFAF;

			for (UINT i = 0; i < sizeof(shellcode_mem_load_32); i++)
			{
				if (memcmp(mem_shellcode + i, &flag, 4) == 0)
				{
					*(int*)(mem_shellcode + i) = file_size;
					break;
				}
			}
			KAPC_STATE ApcState;
#define FIND_FLAG 0xAFBFAFBF
			DWORD dwFlag = FIND_FLAG;
			PBYTE p_mem = (PBYTE)malloc(TotolSize);
			if (!p_mem)
			{
				return false;
			}
			auto exit_4 = std::experimental::make_scope_exit([&]() {if (p_mem)free(p_mem); });

			RtlCopyMemory(p_mem, mem_shellcode, ShellCodeSize);
			RtlCopyMemory(p_mem + ShellCodeSize, &dwFlag, 4);
			RtlCopyMemory(p_mem + ShellCodeSize + 4, file_data, file_size);
			ULONG ReturnLength = 0;
			ns = NewNtWriteVirtualMemory(ProcessHandle, shellcode, p_mem, TotolSize, &ReturnLength);
			if (!NT_SUCCESS(ns))
			{
				return false;
			}
			/*KeStackAttachProcess(Process, &ApcState);
			RtlCopyMemory(BaseAddress, p_mem, TotolSize);
			KeUnstackDetachProcess(&ApcState);*/

			if(out_mem)
				*out_mem = shellcode;
			return true;
		}
		static bool make_shellcode_loaddll(HANDLE ProcessId, PVOID *out_mem, std::wstring dll_path)
		{
			PEPROCESS Process = nullptr;
			UNICODE_STRING dllPath;
			RtlInitUnicodeString(&dllPath, dll_path.c_str());
			auto ns = PsLookupProcessByProcessId(ProcessId, &Process);
			if (!NT_SUCCESS(ns))
			{
				return false;
			}
			auto exit_1 = std::experimental::make_scope_exit([&]() {
				if (Process)
				{
					ObDereferenceObject(Process);
				}
			});
			HANDLE ProcessHandle;
			auto ns2 = ObOpenObjectByPointer(Process,
				OBJ_KERNEL_HANDLE,
				NULL,
				PROCESS_ALL_ACCESS,
				*PsProcessType,
				KernelMode,
				(PHANDLE)&ProcessHandle
				);
			if (!NT_SUCCESS(ns2))
			{
				return false;
			}
			auto exit_2 = std::experimental::make_scope_exit([&]() {if (ProcessHandle) { ZwClose(ProcessHandle); }});
			auto Wow32 = PsGetProcessWow64Process(Process);
			PVOID pNtDllBase = nullptr;
			PVOID pfnLdrLoadDll = nullptr;
			UNICODE_STRING NtdllName;
			KAPC_STATE kApc;
			KeStackAttachProcess(Process, &kApc);
			RtlInitUnicodeString(&NtdllName, L"ntdll.dll");
			if (Wow32)
			{
				pNtDllBase = BBGetUserModule(Process, &NtdllName, TRUE);
			}
			else
			{
				pNtDllBase = BBGetUserModule(Process, &NtdllName, FALSE);
			}
			if (pNtDllBase)
			{
				pfnLdrLoadDll = BBGetModuleExport(pNtDllBase, "LdrLoadDll");
			}
			KeUnstackDetachProcess(&kApc);
			INJECT_BUFFER Buffer = { 0 };
			auto pBuffer = (PINJECT_BUFFER)AllocateInjectMemory(ProcessHandle, (PVOID)pNtDllBase, PAGE_SIZE);
			if (!pBuffer)
			{
				return false;
			}
			if (Wow32)
			{
				const UCHAR ldr_code32[] =
				{
					0x68, 0, 0, 0, 0,                       // push        ModuleHandle            offset +1 
					0x68, 0, 0, 0, 0,                       // push        ModuleFileName          offset +6
					0x6A, 0x00,								// push        0
					0x6A, 0x00,								// push        0
					0xE8, 0, 0, 0, 0,						// call        LdrLoadDll               //offset +15
					0x33, 0xC0,								// xor         eax,eax
					0xC2, 0x04, 0x00,			            // ret         4
					0xCC,									// padding
				};
				Buffer.path32.Length = min(dllPath.Length, sizeof(Buffer.buffer));
				Buffer.path32.MaximumLength = min(dllPath.MaximumLength, sizeof(Buffer.buffer));
				Buffer.path32.Buffer = (ULONG32)(pBuffer->buffer);
				memcpy(Buffer.buffer, dllPath.Buffer, Buffer.path32.Length);
				memcpy(Buffer.code, ldr_code32, sizeof(ldr_code32));

				// Fill code
				*(DWORD*)((PUCHAR)Buffer.code + 1) = (DWORD)&pBuffer->module;
				*(DWORD*)((PUCHAR)Buffer.code + 6) = (DWORD)&pBuffer->path32;
				*(DWORD*)((PUCHAR)Buffer.code + 15) = (DWORD)((DWORD)pfnLdrLoadDll - ((DWORD)pBuffer + 19));

			}
			else
			{
				const UCHAR ldr_code64[] =
				{
					0x48, 0x83, 0xEC, 0x28,							// sub rsp, 0x28
					0x48, 0x31, 0xC9,								// xor rcx, rcx
					0x48, 0x31, 0xD2,								// xor rdx, rdx
					0x49, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,				// mov r9, pModuleHandle //offset+12
					0x49, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,				// mov r8, pModulePath   //offset+22
					0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,				// mov rax, LdrLoadDll  //offset+32
					0xFF, 0xD0,										// call rax
					0x48, 0x83, 0xC4, 0x28,							// add rsp, 0x28
					0xC3											// ret
				};
				// Fill data
				Buffer.path.Length = min(dllPath.Length, sizeof(Buffer.buffer));
				Buffer.path.MaximumLength = min(dllPath.MaximumLength, sizeof(Buffer.buffer));
				Buffer.path.Buffer = (PWCH)pBuffer->buffer;
				memcpy(Buffer.buffer, dllPath.Buffer, Buffer.path.Length);
				memcpy(Buffer.code, ldr_code64, sizeof(ldr_code64));

				// Fill stubs
				*(ULONGLONG*)((PUCHAR)Buffer.code + 12) = (ULONGLONG)&pBuffer->module;
				*(ULONGLONG*)((PUCHAR)Buffer.code + 22) = (ULONGLONG)&pBuffer->path;
				*(ULONGLONG*)((PUCHAR)Buffer.code + 32) = (ULONGLONG)pfnLdrLoadDll;
			}
			ns = NewNtWriteVirtualMemory(ProcessHandle, pBuffer, &Buffer, sizeof(Buffer), NULL);
			if (!NT_SUCCESS(ns))
			{
				return false;
			}
			if (out_mem)
			{
				*out_mem = (PVOID)pBuffer;
			}
			return true;
		}
		static bool ExecuteThread(HANDLE ProcessId,PVOID ThreadRoutine,PVOID param,ULONG Flags)
		{
			PEPROCESS Process = nullptr;
			auto ns = PsLookupProcessByProcessId(ProcessId, &Process);
			if (!NT_SUCCESS(ns))
			{
				return false;
			}
			auto exit_1 = std::experimental::make_scope_exit([&]() {
				if (Process)
				{
					ObDereferenceObject(Process);
				}
			});
			HANDLE ProcessHandle;
			auto ns2 = ObOpenObjectByPointer(Process,
				OBJ_KERNEL_HANDLE,
				NULL,
				PROCESS_ALL_ACCESS,
				*PsProcessType,
				KernelMode,
				(PHANDLE)&ProcessHandle
				);
			if (!NT_SUCCESS(ns2))
			{
				return false;
			}
			auto exit_2 = std::experimental::make_scope_exit([&]() {if (ProcessHandle) { ZwClose(ProcessHandle); }});
			
			HANDLE hThread = nullptr;
			OBJECT_ATTRIBUTES ob = { 0 };

			InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
			auto status = ZwCreateThreadEx(
				&hThread, THREAD_ALL_ACCESS, &ob,
				ProcessHandle, ThreadRoutine, param, Flags,
				0, 0x1000, 0x100000, NULL
				);
			auto exit_3 = std::experimental::make_scope_exit([&]() {if (hThread)
				ZwClose(hThread); });

			if (!NT_SUCCESS(status))
			{
				LOG_DEBUG("%s: ZwCreateThreadEx failed with status 0x%X\n", __FUNCTION__, status);
				return false;
			}

			
			return true;
		}
	};
};