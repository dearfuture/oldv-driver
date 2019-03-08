#pragma once
#include "Base.h"
#include <unordered_map>
#include <string>
#include "util_version.h"
#include "mem_util.h"
#include "ntos_func_def.h"
#include "native_func_def.h"
namespace ddk
{
	namespace util
	{
#pragma pack(1)
		typedef struct _KSERVICE_TABLE_DESCRIPTOR {
#ifdef _X86_
			PULONG_PTR	Base;
#else
			LONG	*OffsetToService;
#endif
			PULONG Count;
			ULONG Limit;
			PUCHAR Number;
		} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
#define CV_SIGNATURE_NB10   '01BN'
#define CV_SIGNATURE_RSDS   'SDSR'

		// CodeView header 
		struct CV_HEADER
		{
			DWORD CvSignature; // NBxx
			LONG  Offset;      // Always 0 for NB10
		};

		// CodeView NB10 debug information 
		// (used when debug information is stored in a PDB 2.00 file) 
		struct CV_INFO_PDB20
		{
			CV_HEADER  Header;
			DWORD      Signature;       // seconds since 01.01.1970
			DWORD      Age;             // an always-incrementing value 
			BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
		};

		// CodeView RSDS debug information 
		// (used when debug information is stored in a PDB 7.00 file) 
		struct CV_INFO_PDB70
		{
			DWORD      CvSignature;
			GUID       Signature;       // unique identifier 
			DWORD      Age;             // an always-incrementing value 
			BYTE       PdbFileName[1];  // zero terminated string with the name of the PDB file 
		};
#pragma pack()
#ifdef _X86_
#define EX_FAST_REF_MASK	0x07
#else
#define EX_FAST_REF_MASK	0x0f
#endif

#define mask3bits(addr)	 (((ULONG_PTR) (addr)) & ~EX_FAST_REF_MASK)

#ifndef SEC_IMAGE
#define SEC_IMAGE         0x1000000  
#endif // !
		class DynImport
		{
		public:
			DynImport() {
				PrevModeOffset = 0;
				get_proc_address("ZwOpenProcess");
				GetPreviousModeOffset();
			}
			~DynImport() {
			}
			static DynImport& Instance()
			{
				static DynImport instance;
				return instance;
			}
			template<typename T>
			inline T get(const std::string& name)
			{
				auto iter = _funcs.find(name);
				if (iter != _funcs.end())
					return reinterpret_cast<T>(iter->second);
				else
				{
					auto pfn = get_proc_address(name);
					if (pfn)
					{
						return  reinterpret_cast<T>(pfn);
					}
				}
				return nullptr;
			}

			template<typename T, typename... Args>
			inline NTSTATUS safeNativeCall(const std::string& name, Args&&... args)
			{
				auto pfn = DynImport::get<T>(name);
				return pfn ? pfn(std::forward<Args>(args)...) : STATUS_ORDINAL_NOT_FOUND;
			}
			template<typename T, typename... Args>
			inline NTSTATUS safeSysCall(const std::string& name, Args&&... args)
			{
				auto pfn = DynImport::get<T>(name);
				PUCHAR pPrevMode = (PUCHAR)PsGetCurrentThread() + GetPreviousModeOffset();
				UCHAR prevMode = *pPrevMode;
				*pPrevMode = KernelMode;
				auto ret = pfn ? pfn(std::forward<Args>(args)...) : STATUS_ORDINAL_NOT_FOUND;
				*pPrevMode = prevMode;
				return ret;
			}
			template<typename T, typename... Args>
			inline auto safeCall(const std::string& name, Args&&... args) -> typename std::result_of<T(Args...)>::type
			{
				auto pfn = DynImport::get<T>(name);
				return pfn ? pfn(std::forward<Args>(args)...) : (std::result_of<T(Args...)>::type)(0);
			}
			inline PVOID get_proc_address(const std::string &name)
			{
				//首先识别是否Zw,如果是Zw的函数则需要特殊的方式
				auto is_zw = false;
				if ((name.at(0) == 'Z' && name.at(1) == 'w')
					|| (name.at(0) == 'N' && name.at(1) == 't'))
				{
					is_zw = true;
				}
				if (is_zw)
				{
					//第二种取出方案
					auto pfn = get_ssdt_function_address(name);
					if (pfn)
					{
						_funcs.insert(std::make_pair(name, pfn));
						return pfn;
					}
				}
				ANSI_STRING asName;
				UNICODE_STRING usName;
				NTSTATUS ns;
				RtlInitAnsiString(&asName, name.c_str());
				ns = RtlAnsiStringToUnicodeString(&usName, &asName, TRUE);
				if (NT_SUCCESS(ns))
				{
					LOG_DEBUG("%wZ\r\n", &usName);
					auto exit_us_name = std::experimental::make_scope_exit([&] {RtlFreeUnicodeString(&usName); });
					auto pfn = MmGetSystemRoutineAddress(&usName);
					if (pfn)
					{
						_funcs.insert(std::make_pair(name, pfn));
						return pfn;
					}
				}
				return nullptr;
			}
			PKSERVICE_TABLE_DESCRIPTOR get_ssdt()
			{
				static PKSERVICE_TABLE_DESCRIPTOR Ssdt = nullptr;
				if (Ssdt)
				{
					return Ssdt;
				}
				PVOID ptrKiSystemCall64 = NULL;
				ptrKiSystemCall64 = (PVOID)__readmsr(0xC0000082);
				UCHAR PTRN_WALL_Ke[] = { 0x00, 0x00, 0x4d, 0x0f, 0x45, 0xd3, 0x42, 0x3b, 0x44, 0x17, 0x10, 0x0f, 0x83 };
				LONG OFFS_WNO8_Ke = -19;
				LONG OFFS_WIN8_Ke = -16;
				auto ns = ddk::mem_util::MmGenericPointerSearch((PUCHAR *)&Ssdt,
					((PUCHAR)ptrKiSystemCall64) - (1 * PAGE_SIZE),
					((PUCHAR)ptrKiSystemCall64) + (1 * PAGE_SIZE),
					PTRN_WALL_Ke,
					sizeof(PTRN_WALL_Ke),
					IsWindows8OrGreater() ? OFFS_WIN8_Ke : OFFS_WNO8_Ke);
				if (NT_SUCCESS(ns))
				{
					DBG_PRINT("SSDT %p\r\n", Ssdt);
					return Ssdt;
				}
				return nullptr;
			}

			PVOID get_ssdt_function_address(DWORD index)
			{
				auto SystemTable = get_ssdt();
				if (index == DWORD(-1))
				{
					return nullptr;
				}
				auto OldFunction = (ULONG_PTR)SystemTable->OffsetToService;
				if (!IsWindowsVistaOrGreater())
				{
					OldFunction += SystemTable->OffsetToService[index] & ~EX_FAST_REF_MASK;
					//	NewOffset = ((LONG)(Function - (ULONG_PTR)KeServiceDescriptorTable->OffsetToService)) | EX_FAST_REF_MASK + KeServiceDescriptorTable->OffsetToService[ssdtNumber] & EX_FAST_REF_MASK;
				}
				else
				{
					OldFunction += SystemTable->OffsetToService[index] >> 4;
					//NewOffset = (((LONG)(Function - (ULONG_PTR)KeServiceDescriptorTable->OffsetToService)) << 4) + KeServiceDescriptorTable->OffsetToService[ssdtNumber] & 0x0F;
				}
				return reinterpret_cast<PVOID>(OldFunction);
			}
			PVOID get_ssdt_function_address(std::string function)
			{
				return get_ssdt_function_address(get_sys_call_index(function));
			}
			DWORD get_sys_call_index(std::string syscallname)
			{
				auto NtdllBase = load_dll(std::wstring(L"\\SystemRoot\\System32\\ntdll.dll"));
				auto exit_1 = std::experimental::make_scope_exit([&]() {
					if (NtdllBase)
						free_dll(NtdllBase); });

				if (NtdllBase)
				{
					// get function addres by name hash
					ULONG_PTR FuncRva = get_proc_address(NtdllBase, syscallname);
					if (FuncRva)
					{
						PUCHAR Func = (PUCHAR)NtdllBase + FuncRva;
#ifdef _X86_
						// check for mov eax,imm32
						if (*Func == 0xB8)
						{
							// return imm32 argument (syscall numbr)
							return *(PULONG)((PUCHAR)Func + 1);
						}
#elif _AMD64_
						// check for mov eax,imm32
						if (*(Func + 3) == 0xB8)
						{
							// return imm32 argument (syscall numbr)
							return *(PULONG)(Func + 4);
						}
#endif
					}
				}
				return DWORD(-1);
			}
			PVOID load_dll(std::wstring filename)
			{
				HANDLE hSection, hFile;
				UNICODE_STRING dllName;
				PVOID BaseAddress = NULL;
				SIZE_T size = 0;
				NTSTATUS stat;
				OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &dllName, OBJ_CASE_INSENSITIVE };
				IO_STATUS_BLOCK iosb;
				auto full_dll_path = filename.c_str();
				DBG_PRINT("DBG: ABout to load %ws at IRQL %d\n", full_dll_path,
					KeGetCurrentIrql());
				RtlInitUnicodeString(&dllName, full_dll_path);


				//_asm int 3;
				stat = ZwOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb,
					FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

				if (!NT_SUCCESS(stat)) {
					DBG_PRINT("WRN: Can't open %ws: %x\n", full_dll_path, stat);
					return 0;
				}

				oa.ObjectName = 0;

				stat = ZwCreateSection(&hSection, SECTION_ALL_ACCESS, &oa, 0, PAGE_EXECUTE,
					SEC_IMAGE, hFile);

				if (!NT_SUCCESS(stat)) {
					DBG_PRINT("WRN: Can't create section %ws: %x\n", full_dll_path, stat);
					return 0;
				}

				stat = ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0,
					1000, 0, &size, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE);

				if (!NT_SUCCESS(stat)) {
					DBG_PRINT("WRN: Can't map section %ws: %x\n", full_dll_path, stat);
					return 0;
				}

				ZwClose(hSection);
				ZwClose(hFile);

				DBG_PRINT("DBG: Successfully loaded %ws\n", full_dll_path);
				return BaseAddress;
			}
			void free_dll(HANDLE hMod)
			{
				ZwUnmapViewOfSection(NtCurrentProcess(), hMod);
			}
			ULONG_PTR get_proc_address(PVOID Image, std::string functionname)
			{
#define RVATOVA(_base_, _offset_) ((PUCHAR)(_base_) + (ULONG)(_offset_))
				__try
				{
					PIMAGE_EXPORT_DIRECTORY pExport = NULL;

					PIMAGE_NT_HEADERS32 pHeaders32 = (PIMAGE_NT_HEADERS32)
						((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

					if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
					{
						// 32-bit image
						if (pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
						{
							pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
								Image,
								pHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
								);
						}
					}
					else if (pHeaders32->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
					{
						// 64-bit image
						PIMAGE_NT_HEADERS64 pHeaders64 = (PIMAGE_NT_HEADERS64)
							((PUCHAR)Image + ((PIMAGE_DOS_HEADER)Image)->e_lfanew);

						if (pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress)
						{
							pExport = (PIMAGE_EXPORT_DIRECTORY)RVATOVA(
								Image,
								pHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
								);
						}
					}

					if (pExport)
					{
						PULONG AddressOfFunctions = (PULONG)RVATOVA(Image, pExport->AddressOfFunctions);
						PSHORT AddrOfOrdinals = (PSHORT)RVATOVA(Image, pExport->AddressOfNameOrdinals);
						PULONG AddressOfNames = (PULONG)RVATOVA(Image, pExport->AddressOfNames);
						ULONG i = 0;
						for (i = 0; i < pExport->NumberOfFunctions; i++)
						{
							if (!strcmp((char *)RVATOVA(Image, AddressOfNames[i]), functionname.c_str()))
							{
								return AddressOfFunctions[AddrOfOrdinals[i]];
							}
						}
					}
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{

				}
				return 0;
			}
			bool get_sys_module_list(std::vector<AUX_MODULE_EXTENDED_INFO> &syslist)
			{
				ULONG modulesSize = 0;
				AUX_MODULE_EXTENDED_INFO*  modules;
				ULONG  numberOfModules;
				auto status = AuxKlibInitialize();
				//DbgPrint("AuxKlibInitialize return %x\r\n",status);
				if (NT_SUCCESS(status))
				{
					status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), NULL);
					//DbgPrint("AuxKlibQueryModuleInformation return %x\r\n",status);
					if (NT_SUCCESS(status))
					{
						//	DbgPrint("modulesSize %d\r\n",modulesSize);
						if (modulesSize > 0)
						{
							numberOfModules = modulesSize / sizeof(AUX_MODULE_EXTENDED_INFO);
							modules = (AUX_MODULE_EXTENDED_INFO*)malloc(modulesSize);
							auto mem_exit = std::experimental::make_scope_exit([&]() {if (modules)free(modules); });
							if (modules != NULL)
							{
								status = AuxKlibQueryModuleInformation(&modulesSize, sizeof(AUX_MODULE_EXTENDED_INFO), modules);
								//	DbgPrint("AuxKlibQueryModuleInformation return %x\r\n",status);

								if (NT_SUCCESS(status))
								{
									for (ULONG i = 0; i < numberOfModules; i++)
									{
										syslist.push_back(modules[i]);
									}
									return true;
								}
							}
						}
					}
				}
				return false;
			}

			PVOID get_module_base(std::string modulename)
			{
				std::vector<AUX_MODULE_EXTENDED_INFO> syslist;
				UNICODE_STRING usCommonHalName, usCommonNtName;
				RtlInitUnicodeString(&usCommonHalName, L"hal.dll");
				RtlInitUnicodeString(&usCommonNtName, L"ntoskrnl.exe");
				if (get_sys_module_list(syslist))
				{
#define HAL_NAMES_NUM 6
					wchar_t *wcHalNames[] =
					{
						L"hal.dll",      // Non-ACPI PIC HAL 
						L"halacpi.dll",  // ACPI PIC HAL
						L"halapic.dll",  // Non-ACPI APIC UP HAL
						L"halmps.dll",   // Non-ACPI APIC MP HAL
						L"halaacpi.dll", // ACPI APIC UP HAL
						L"halmacpi.dll"  // ACPI APIC MP HAL
					};

#define NT_NAMES_NUM 4
					wchar_t *wcNtNames[] =
					{
						L"ntoskrnl.exe", // UP
						L"ntkrnlpa.exe", // UP PAE
						L"ntkrnlmp.exe", // MP
						L"ntkrpamp.exe"  // MP PAE
					};

					ANSI_STRING asModuleName;
					UNICODE_STRING usModuleName;
					NTSTATUS ns;
					RtlInitAnsiString(&asModuleName, modulename.c_str());
					ns = RtlAnsiStringToUnicodeString(&usModuleName, &asModuleName, TRUE);
					if (NT_SUCCESS(ns))
					{
						auto exit_us_name = std::experimental::make_scope_exit([&]() {RtlFreeUnicodeString(&usModuleName); });

						for (auto n = size_t(0); n < syslist.size(); n++)
						{
							ANSI_STRING asEnumModuleName;
							UNICODE_STRING usEnumModuleName;
							NTSTATUS ns;
							RtlInitAnsiString(
								&asEnumModuleName,
								(char *)syslist[n].FullPathName + syslist[n].FileNameOffset
								);

							ns = RtlAnsiStringToUnicodeString(&usEnumModuleName, &asEnumModuleName, TRUE);
							if (NT_SUCCESS(ns))
							{
								auto exit_us_name2 = std::experimental::make_scope_exit([&]() {RtlFreeUnicodeString(&usEnumModuleName); });

								if (RtlEqualUnicodeString(&usModuleName, &usCommonHalName, TRUE))
								{
									int i_m = 0;
									for (i_m = 0; i_m < HAL_NAMES_NUM; i_m++)
									{
										UNICODE_STRING usHalName;
										RtlInitUnicodeString(&usHalName, wcHalNames[i_m]);
										if (RtlEqualUnicodeString(&usEnumModuleName, &usHalName, TRUE))
										{
											return reinterpret_cast<PVOID>(syslist[n].BasicInfo.ImageBase);
										}
									}
								}
								else if (RtlEqualUnicodeString(&usModuleName, &usCommonNtName, TRUE))
								{
									int i_m = 0;
									for (i_m = 0; i_m < NT_NAMES_NUM; i_m++)
									{
										UNICODE_STRING usNtName;
										RtlInitUnicodeString(&usNtName, wcNtNames[i_m]);
										if (RtlEqualUnicodeString(&usEnumModuleName, &usNtName, TRUE))
										{
											return reinterpret_cast<PVOID>(syslist[n].BasicInfo.ImageBase);
										}
									}
								}
								else if (RtlEqualUnicodeString(&usModuleName, &usEnumModuleName, TRUE))
								{
									return reinterpret_cast<PVOID>(syslist[n].BasicInfo.ImageBase);
								}

							}
						}
					}
				}
				return nullptr;
			}
		private:
			DynImport(const DynImport&) = delete;

		private:
			std::unordered_map<std::string, PVOID> _funcs;    // function database
			ULONG PrevModeOffset;
		public:
			//GetPdbInfo
			bool getPdbInfo(PVOID ImageBase, std::string &pdbFileName, std::string &symSignature)
			{
				ULONG nsize = 0;
				auto pDebug = RtlImageDirectoryEntryToData(ImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_DEBUG, &nsize);
				if (pDebug)
				{
					auto image_base = reinterpret_cast<char *>(ImageBase);
					auto dbg_header = reinterpret_cast<PIMAGE_DEBUG_DIRECTORY>(pDebug);
					for (unsigned int i = 0; i < nsize / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
					{
						if (dbg_header[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
						{
							auto cvinfo = reinterpret_cast<CV_HEADER *>(image_base + dbg_header[i].AddressOfRawData);
							if (cvinfo->CvSignature == CV_SIGNATURE_NB10)
							{
								auto p_cv_info = reinterpret_cast<CV_INFO_PDB20 *>(image_base + dbg_header[i].AddressOfRawData);
								continue;
							}
							if (cvinfo->CvSignature == CV_SIGNATURE_RSDS)
							{
								CHAR szSymSignature[65] = { 0 };
								auto pCvData = reinterpret_cast<CV_INFO_PDB70 *>(image_base + dbg_header[i].AddressOfRawData);
								RtlStringCchPrintfA(szSymSignature, 64,
									"%08X%04X%04X%02hX%02hX%02hX%02hX%02hX%02hX%02hX%02hX%d",
									pCvData->Signature.Data1, pCvData->Signature.Data2,
									pCvData->Signature.Data3, pCvData->Signature.Data4[0],
									pCvData->Signature.Data4[1], pCvData->Signature.Data4[2],
									pCvData->Signature.Data4[3], pCvData->Signature.Data4[4],
									pCvData->Signature.Data4[5], pCvData->Signature.Data4[6],
									pCvData->Signature.Data4[7], pCvData->Age);
								//std::cout << "pdb filename = " << reinterpret_cast<char *>(pCvData->PdbFileName) << std::endl;
								//std::cout << "pdb sig = " << szSymSignature << std::endl;
								auto pdb_name = reinterpret_cast<char *>(pCvData->PdbFileName);
								pdbFileName = std::string(pdb_name);
								symSignature = szSymSignature;
								return true;
							}
						}
						if (dbg_header[i].Type == IMAGE_DEBUG_TYPE_MISC)
						{
							auto dbg_misc = reinterpret_cast<IMAGE_DEBUG_MISC *>(image_base + dbg_header[i].AddressOfRawData);
							continue;
							//std::cout << "pdb filename = " << reinterpret_cast<char*>(dbg_misc->Data) << std::endl;
						}
					}
				}
				return false;
			}
			public:
				ULONG GetPreviousModeOffset()
				{
					if (PrevModeOffset)
					{
						return PrevModeOffset;
					}
					auto fnExGetPreviousMode = get_proc_address("ExGetPreviousMode");
					if (fnExGetPreviousMode)
					{
						LOG_DEBUG("ExGetPreviousMode %p\r\n", fnExGetPreviousMode);
						UCHAR PreviousModePattern[] = "\x00\x00\xC3";
						auto pFound = ddk::mem_util::MmMemMem(fnExGetPreviousMode, 32, PreviousModePattern,sizeof(PreviousModePattern)-1);
						if(pFound)
							PrevModeOffset = *(DWORD *)((PUCHAR)pFound- 2);
					}
					return PrevModeOffset;
				}
		};

		static PVOID GetSysInf(SYSTEM_INFORMATION_CLASS InfoClass)
		{
			NTSTATUS ns;
			ULONG RetSize, Size = 0x1100;
			PVOID Info;

			while (1)
			{
				if ((Info = malloc(Size)) == NULL)
				{
					return NULL;
				}

				RetSize = 0;
				ns = ZwQuerySystemInformation(InfoClass, Info, Size, &RetSize);
				if (ns == STATUS_INFO_LENGTH_MISMATCH)
				{
					free(Info);
					Info = NULL;

					if (RetSize > 0)
					{
						Size = RetSize + 0x1000;
					}
					else
						break;
				}
				else
					break;
			}

			if (!NT_SUCCESS(ns))
			{
				if (Info)
					free(Info);

				return NULL;
			}
			return Info;
		}
#define GET_IMPORT(name) (ddk::util::DynImport::Instance().get<fn ## name>( #name ))
#define SAFE_NATIVE_CALL(name, ...) (ddk::util::DynImport::Instance().safeNativeCall<fn ## name>( #name, __VA_ARGS__ ))
#define SAFE_CALL(name, ...) (ddk::util::DynImport::Instance().safeCall<fn ## name>( #name, __VA_ARGS__ ))
#define SAFE_SYSCALL(name, ...) (ddk::util::DynImport::Instance().safeSysCall<fn ## name>( #name, __VA_ARGS__ ))

	};
};