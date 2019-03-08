#pragma once
#include "Base.h"
#include "kdblock_def.h"
#include "util_version.h"
#include "mem_util.h"
#include "distorm3.hpp"
#pragma warning(disable:4091)
#pragma warning(disable:4200)
#pragma warning(disable:4005)
#pragma warning(disable:4146)
namespace ddk
{
	template<OS_VERSION>
	class ntos;
	namespace ntos_space
	{
		namespace win7x64
		{
			#include "win7_64.h"
		}
		namespace win7sp1x64
		{
			#include "win7_sp1_64.h"
		}
		namespace win8_x64
		{
#include "win8_0_9200.h"
		}
		namespace win8_1_x64
		{
			#include "win8_1_9600.h"
		}
		namespace win10_10586_x64
		{
			#include "win10_10586.h"
		}
		namespace win10_14393_x64
		{
			#include "win10_14393.h"
		}
	};
	template<>
	class ntos<WIN7>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win7x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win7x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win7x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win7x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win7x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win7x64::POBJECT_TYPE;
	};

	template<>
	class ntos<WIN7SP1>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win7sp1x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win7sp1x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win7sp1x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win7sp1x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win7sp1x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win7sp1x64::POBJECT_TYPE;
	};
	
	template<>
	class ntos<WIN81>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win8_1_x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win8_1_x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win8_1_x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win8_1_x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win8_1_x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win8_1_x64::POBJECT_TYPE;
	};

	template<>
	class ntos<WIN8>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win8_x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win8_x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win8_x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win8_x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win8_x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win8_x64::POBJECT_TYPE;
	};

	template<>
	class ntos<WIN10_10586>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win10_10586_x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win10_10586_x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win10_10586_x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win10_10586_x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win10_10586_x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win10_10586_x64::POBJECT_TYPE;
	};

	template<>
	class ntos<WIN10_now>
	{
	public:
		using PEPROCESS = ddk::ntos_space::win10_14393_x64::PEPROCESS;
		using PETHREAD = ddk::ntos_space::win10_14393_x64::PETHREAD;
		using POBJECT_DIRECTORY = ddk::ntos_space::win10_14393_x64::POBJECT_DIRECTORY;
		using PKPCR = ddk::ntos_space::win10_14393_x64::PKPCR;
		using PLDR_DATA_TABLE_ENTRY = ddk::ntos_space::win10_14393_x64::PLDR_DATA_TABLE_ENTRY;
		using POBJECT_TYPE = ddk::ntos_space::win10_14393_x64::POBJECT_TYPE;
	};
	class special_data:public Singleton<special_data>
	{
	public:
		special_data()
		{
			_kdblock = nullptr;
			os = ddk::util::get_version();
		}
		~special_data()
		{
			if (_kdblock)
				delete _kdblock;
		}
		ULONG get_protect_offset()
		{
			auto pAddress = ddk::util::DynImport::Instance().get_proc_address("PsIsProtectedProcess");
			if (pAddress)
			{
				return *(ULONG*)((ULONG_PTR)pAddress + 2);
			}
			return 0;
		}
		PKDDEBUGGER_DATA64 get_kdblock()
		{
			if (_kdblock)
			{
				return _kdblock;
			}
			auto block_size = 0;
			switch (os)
			{
			case ddk::WIN7:
			case ddk::WIN7SP1:
				block_size = 0x340;
				break;
			case ddk::WIN8:
			case ddk::WIN81:
				block_size = 0x360;
				break;
			case ddk::WIN10_10586:
				block_size = 0x360;
				break;
			case ddk::WIN10_now:
				block_size = 0x368;
				break;
			default:
				return nullptr;
				break;
			}
			PVOID KdDebuggerDataBlock_ = nullptr;
			 KiWaitNever_ = nullptr;
			 KdpDataBlockEncoded_ = nullptr;
			 KiWaitAlways_ = nullptr;
			UCHAR Win7_pattern[] = { 0x49,0x8b,0x00,0x41,0x8B,0xCA,0x49,0x33,0xC2,0x48,0xD3,0xC0 };
			UCHAR Win81_pattern[] = { 0x48,0xD3,0xC2,0x48,0x33,0xD0,0x48,0x0F,0xCA };
			UCHAR Win80_pattern[] = { 0x48,0x8B,0x02,0x41,0x8B,0xCA,0x49,0x33,0xC2,0x48,0xD3,0xC0 };
			UCHAR Win10_pattern[] = { 0x48,0xD3,0xC2,0x48,0x33,0xD0,0x48,0x0F,0xCA };
			PUCHAR p_pattern = nullptr;
			SIZE_T size_pattern = 0;
			LONG off_KdDDB= -19;
			LONG off_KiWN = 0;
			LONG off_KiWA = 0;
			LONG off_KdpDBE = 0;
			auto p_func = PVOID(nullptr);
			switch (os)
			{
			case ddk::WIN7:
			case ddk::WIN7SP1:
				//Windows 7从KdChangeOption开始搜索
				p_func= ddk::util::DynImport::Instance().get_proc_address("KdChangeOption");
				p_pattern = Win7_pattern;
				size_pattern = sizeof(Win7_pattern);
				off_KdDDB = -13;
				off_KiWN = -20;
				off_KiWA = 28;
				off_KdpDBE = 15;
				break;
			case ddk::WIN8:
				p_func = ddk::util::DynImport::Instance().get_proc_address("KdChangeOption");
				p_pattern = Win80_pattern;
				size_pattern = sizeof(Win80_pattern);
				off_KdDDB = -29;
				off_KiWN = -20;
				off_KiWA = -13;
				off_KdpDBE = 15;
				break;
			case ddk::WIN81:
				p_func = ddk::util::DynImport::Instance().get_proc_address("KdDeregisterPowerHandler");
				p_pattern = Win81_pattern;
				size_pattern = sizeof(Win81_pattern);
				off_KdDDB = -37;
				off_KiWN = -19;
				off_KiWA = 12;
				off_KdpDBE = -4;
				break;
			case ddk::WIN10_10586:
				p_func = ddk::util::DynImport::Instance().get_proc_address("KdDeregisterPowerHandler");
				p_pattern = Win10_pattern;
				size_pattern = sizeof(Win10_pattern);
				off_KdDDB = -40;
				off_KiWN = -19;
				off_KiWA = 12;
				off_KdpDBE = -4;
				break;
			case ddk::WIN10_now:
				p_func = ddk::util::DynImport::Instance().get_proc_address("KdDeregisterPowerHandler");
				p_pattern = Win10_pattern;
				size_pattern = sizeof(Win10_pattern);
				off_KdDDB = -40;
				off_KiWN = -19;
				off_KiWA = 12;
				off_KdpDBE = -4;
				break;
			}
			if (!p_func || !p_pattern)
			{
				return nullptr;
			}
			auto ns = ddk::mem_util::MmGenericPointerSearch(
				(PUCHAR *)&KdDebuggerDataBlock_,
				((PUCHAR)p_func) - (1 * PAGE_SIZE),
				((PUCHAR)p_func) + (1 * PAGE_SIZE),
				p_pattern,
				size_pattern,
				off_KdDDB);
			if (!NT_SUCCESS(ns))
			{
				return nullptr;
			}
			ns = ddk::mem_util::MmGenericPointerSearch(
				(PUCHAR *)&KdpDataBlockEncoded_,
				((PUCHAR)p_func) - (1 * PAGE_SIZE),
				((PUCHAR)p_func) + (1 * PAGE_SIZE),
				p_pattern,
				size_pattern,
				off_KdpDBE);
			if (!NT_SUCCESS(ns))
			{
				return nullptr;
			}
			ns = ddk::mem_util::MmGenericPointerSearch(
				(PUCHAR *)&KiWaitAlways_,
				((PUCHAR)p_func) - (1 * PAGE_SIZE),
				((PUCHAR)p_func) + (1 * PAGE_SIZE),
				p_pattern,
				size_pattern,
				off_KiWA);
			if (!NT_SUCCESS(ns))
			{
				return nullptr;
			}
			ns = ddk::mem_util::MmGenericPointerSearch(
				(PUCHAR *)&KiWaitNever_,
				((PUCHAR)p_func) - (1 * PAGE_SIZE),
				((PUCHAR)p_func) + (1 * PAGE_SIZE),
				p_pattern,
				size_pattern,
				off_KiWN);
			if (!NT_SUCCESS(ns))
			{
				return nullptr;
			}
			_kdblock = new KDDEBUGGER_DATA64;
			if (!_kdblock)
			{
				return nullptr;
			}
			RtlCopyMemory(_kdblock, KdDebuggerDataBlock_, block_size);
			if (*KdpDataBlockEncoded_)
			{
				DBG_PRINT("need decode\r\n");
				DBG_PRINT("kwaitalways %p kwaitnever %p\r\n", KiWaitAlways_, KiWaitNever_);
				//需要解密
				for (int i = 0; i < block_size / 8; i++) {
					auto tmpEncodedData = ((DWORD64*)KdDebuggerDataBlock_)[i];
					((DWORD64*)_kdblock)[i] = uncipherData(tmpEncodedData, *KiWaitNever_, *KiWaitAlways_, (DWORD64)KdpDataBlockEncoded_);
				}
			}
			return _kdblock;
		}
		KIRQL get_debug_irql()
		{
			KIRQL irql = KeGetCurrentIrql();
			switch (os)
			{
			case ddk::WIN7:
			case ddk::WIN7SP1:
				irql = static_cast<KIRQL>(__readgsbyte(0x4898));
				break;
			case ddk::WIN8:
			case ddk::WIN81:
				irql = static_cast<KIRQL>(__readgsbyte(0x5498));
				break;
			case ddk::WIN10_10586:
				//5C98
			case ddk::WIN10_now:
				irql = static_cast<KIRQL>(__readgsbyte(0x5C98));
				break;
			}
			return irql;
		}
	private:
		DWORD64 uncipherData(DWORD64 data, DWORD64 KiWaitNever, DWORD64 KiWaitAlways, DWORD64 KdpDataBlockEncoded)
		{
			data = data^KiWaitNever;
			data = RotateLeft64(data, KiWaitNever & 0xFF);
			data = data^KdpDataBlockEncoded;
			data = RtlUlonglongByteSwap(data);
			data = data^KiWaitAlways;
			return data;
		}
	public:
		PVOID get_kebugcheck2_addr()
		{
			//反汇编找到KeBugCheckEx下的第三个CALL
			return nullptr;
		}
		PVOID GetKiRetireDpcList()
		{
			UCHAR Pg_PTN_Win7[] = { 0xFF,0xF3,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x68,0x48,0x8B,0x71,0x08,0xBD,0x01,0x00,0x00,0x00 };
			UCHAR Pg_PTN_Win8[] = { 0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x6C,0x24,0x18,0x48,0x89,0x74,0x24,0x20,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x81,0xEC,0x40,0x01,0x00,0x00,0x48,0x8B };
			UCHAR Pg_PTN_Win81[] = { 0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7C,0x24,0x20,0x55,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0xB0,0xFE,0xFF,0xFF,0x48,0x81,0xEC,0x50,0x02,0x00,0x00 };
			UCHAR Pg_PTN_Win10_10586[] = { 0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7C,0x24,0x20,0x55,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24,0xE0,0xFE,0xFF,0xFF,0x48,0x81 };
			UCHAR Pg_PTN_Win10_14393[] = { 0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x74,0x24,0x18,0x48,0x89,0x7C,0x24,0x20,0x55,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x48,0x8D,0xAC,0x24 };

			PVOID p_begin = nullptr;
			PVOID p_end = nullptr;
			PUCHAR p_pattern = nullptr;
			SIZE_T size_pattern = 0;

			auto os = ddk::util::get_version();
			switch (os)
			{
			case ddk::WIN7:
				p_begin = ddk::util::DynImport::Instance().get_proc_address("KeReleaseMutant");
				p_end = ddk::util::DynImport::Instance().get_proc_address("KeSetTimerEx");
				p_pattern = Pg_PTN_Win7;
				size_pattern = sizeof(Pg_PTN_Win7);
				break;
			case ddk::WIN7SP1:
				p_begin = ddk::util::DynImport::Instance().get_proc_address("KeReleaseMutant");
				p_end = ddk::util::DynImport::Instance().get_proc_address("KeSetTimerEx");
				p_pattern = Pg_PTN_Win7;
				size_pattern = sizeof(Pg_PTN_Win7);
				break;
			case ddk::WIN8:
				p_begin = ddk::util::DynImport::Instance().get_proc_address("KeWaitForSingleObject");
				p_end = ddk::util::DynImport::Instance().get_proc_address("KeInsertQueueDpc");
				p_pattern = Pg_PTN_Win8;
				size_pattern = sizeof(Pg_PTN_Win8);
				break;
			case ddk::WIN81:
				p_begin = ddk::util::DynImport::Instance().get_proc_address("KeInitializeEvent");
				p_end = ddk::util::DynImport::Instance().get_proc_address("KeInsertQueueDpc");
				p_pattern = Pg_PTN_Win81;
				size_pattern = sizeof(Pg_PTN_Win81);
				break;
			case ddk::WIN10_10586:
				p_begin = ddk::util::DynImport::Instance().get_proc_address("KeInsertQueueDpc");
				p_end = ddk::util::DynImport::Instance().get_proc_address("MmMapLockedPagesSpecifyCache");
				p_pattern = Pg_PTN_Win10_10586;
				size_pattern = sizeof(Pg_PTN_Win10_10586);
				break;
			case ddk::WIN10_now:
				p_begin = ddk::util::DynImport::Instance().get_proc_address("KeReleaseMutex");
				p_end = ddk::util::DynImport::Instance().get_proc_address("KeWaitForMultipleObjects");
				p_pattern = Pg_PTN_Win10_14393;
				size_pattern = sizeof(Pg_PTN_Win10_14393);
				break;
			default:
				break;
			}
			if (p_pattern && p_end && p_begin)
			{
				PVOID _KiRetireDpcList = nullptr;
				auto ns = ddk::mem_util::MmSearch(
					reinterpret_cast<PUCHAR>(p_begin),
					reinterpret_cast<PUCHAR>(p_end),
					p_pattern,
					reinterpret_cast<PUCHAR *>(&_KiRetireDpcList),
					size_pattern);
				if (NT_SUCCESS(ns))
				{
					return _KiRetireDpcList;
				}
			}
			return nullptr;
		}
	public:
		void dump_kdblock_info()
		{
			auto tmpKDBG = get_kdblock();
			if (!tmpKDBG)
			{
				return;
			}
			DBG_PRINT("-------------KDBG-----------------------\r\n");
			DBG_PRINT("List[0] : %p\r\n", tmpKDBG->Header.List.Blink);
			DBG_PRINT("List[1] : %p\r\n", tmpKDBG->Header.List.Flink);
			DBG_PRINT("OwnerTag : %04x\r\n", tmpKDBG->Header.OwnerTag);
			DBG_PRINT("Size : %04x\r\n", tmpKDBG->Header.Size);
			DBG_PRINT("KernBase : %p\r\n", tmpKDBG->KernBase);
			DBG_PRINT("BreakpointWithStatus : %p\r\n", tmpKDBG->BreakpointWithStatus);
			DBG_PRINT("SavedContext : %p\r\n", tmpKDBG->SavedContext);
			DBG_PRINT("ThCallbackStack : %04x\r\n", tmpKDBG->ThCallbackStack);
			DBG_PRINT("NextCallback : %04x\r\n", tmpKDBG->NextCallback);
			DBG_PRINT("FramePointer : %04x\r\n", tmpKDBG->FramePointer);
			DBG_PRINT("PaeEnabled : %04x\r\n", tmpKDBG->PaeEnabled);
			DBG_PRINT("KiCallUserMode : %p\r\n", tmpKDBG->KiCallUserMode);
			DBG_PRINT("KeUserCallbackDispatcher : %p\r\n", tmpKDBG->KeUserCallbackDispatcher);
			DBG_PRINT("PsLoadedModuleList : %p\r\n", tmpKDBG->PsLoadedModuleList);
			DBG_PRINT("PsActiveProcessHead : %p\r\n", tmpKDBG->PsActiveProcessHead);
			DBG_PRINT("PspCidTable : %p\r\n", tmpKDBG->PspCidTable);
			DBG_PRINT("ExpSystemResourcesList : %p\r\n", tmpKDBG->ExpSystemResourcesList);
			DBG_PRINT("ExpPagedPoolDescriptor : %p\r\n", tmpKDBG->ExpPagedPoolDescriptor);
			DBG_PRINT("ExpNumberOfPagedPools : %p\r\n", tmpKDBG->ExpNumberOfPagedPools);
			DBG_PRINT("KeTimeIncrement : %p\r\n", tmpKDBG->KeTimeIncrement);
			DBG_PRINT("KeBugCheckCallbackListHead : %p\r\n", tmpKDBG->KeBugCheckCallbackListHead);
			DBG_PRINT("KiBugcheckData : %p\r\n", tmpKDBG->KiBugcheckData);
			DBG_PRINT("IopErrorLogListHead : %p\r\n", tmpKDBG->IopErrorLogListHead);
			DBG_PRINT("ObpRootDirectoryObject : %p\r\n", tmpKDBG->ObpRootDirectoryObject);
			DBG_PRINT("ObpTypeObjectType : %p\r\n", tmpKDBG->ObpTypeObjectType);
			DBG_PRINT("MmSystemCacheStart : %p\r\n", tmpKDBG->MmSystemCacheStart);
			DBG_PRINT("MmSystemCacheEnd : %p\r\n", tmpKDBG->MmSystemCacheEnd);
			DBG_PRINT("MmSystemCacheWs : %p\r\n", tmpKDBG->MmSystemCacheWs);
			DBG_PRINT("MmPfnDatabase : %p\r\n", tmpKDBG->MmPfnDatabase);
			DBG_PRINT("MmSystemPtesStart : %p\r\n", tmpKDBG->MmSystemPtesStart);
			DBG_PRINT("MmSystemPtesEnd : %p\r\n", tmpKDBG->MmSystemPtesEnd);
			DBG_PRINT("MmSubsectionBase : %p\r\n", tmpKDBG->MmSubsectionBase);
			DBG_PRINT("MmNumberOfPagingFiles : %p\r\n", tmpKDBG->MmNumberOfPagingFiles);
			DBG_PRINT("MmLowestPhysicalPage : %p\r\n", tmpKDBG->MmLowestPhysicalPage);
			DBG_PRINT("MmHighestPhysicalPage : %p\r\n", tmpKDBG->MmHighestPhysicalPage);
			DBG_PRINT("MmNumberOfPhysicalPages : %p\r\n", tmpKDBG->MmNumberOfPhysicalPages);
			DBG_PRINT("MmMaximumNonPagedPoolInBytes : %p\r\n", tmpKDBG->MmMaximumNonPagedPoolInBytes);
			DBG_PRINT("MmNonPagedSystemStart : %p\r\n", tmpKDBG->MmNonPagedSystemStart);
			DBG_PRINT("MmNonPagedPoolStart : %p\r\n", tmpKDBG->MmNonPagedPoolStart);
			DBG_PRINT("MmNonPagedPoolEnd : %p\r\n", tmpKDBG->MmNonPagedPoolEnd);
			DBG_PRINT("MmPagedPoolStart : %p\r\n", tmpKDBG->MmPagedPoolStart);
			DBG_PRINT("MmPagedPoolEnd : %p\r\n", tmpKDBG->MmPagedPoolEnd);
			DBG_PRINT("MmPagedPoolInformation : %p\r\n", tmpKDBG->MmPagedPoolInformation);
			DBG_PRINT("MmPageSize : %p\r\n", tmpKDBG->MmPageSize);
			DBG_PRINT("MmSizeOfPagedPoolInBytes : %p\r\n", tmpKDBG->MmSizeOfPagedPoolInBytes);
			DBG_PRINT("MmTotalCommitLimit : %p\r\n", tmpKDBG->MmTotalCommitLimit);
			DBG_PRINT("MmTotalCommittedPages : %p\r\n", tmpKDBG->MmTotalCommittedPages);
			DBG_PRINT("MmSharedCommit : %p\r\n", tmpKDBG->MmSharedCommit);
			DBG_PRINT("MmDriverCommit : %p\r\n", tmpKDBG->MmDriverCommit);
			DBG_PRINT("MmProcessCommit : %p\r\n", tmpKDBG->MmProcessCommit);
			DBG_PRINT("MmPagedPoolCommit : %p\r\n", tmpKDBG->MmPagedPoolCommit);
			DBG_PRINT("MmExtendedCommit : %p\r\n", tmpKDBG->MmExtendedCommit);
			DBG_PRINT("MmZeroedPageListHead : %p\r\n", tmpKDBG->MmZeroedPageListHead);
			DBG_PRINT("MmFreePageListHead : %p\r\n", tmpKDBG->MmFreePageListHead);
			DBG_PRINT("MmStandbyPageListHead : %p\r\n", tmpKDBG->MmStandbyPageListHead);
			DBG_PRINT("MmModifiedPageListHead : %p\r\n", tmpKDBG->MmModifiedPageListHead);
			DBG_PRINT("MmModifiedNoWritePageListHead : %p\r\n", tmpKDBG->MmModifiedNoWritePageListHead);
			DBG_PRINT("MmAvailablePages : %p\r\n", tmpKDBG->MmAvailablePages);
			DBG_PRINT("MmResidentAvailablePages : %p\r\n", tmpKDBG->MmResidentAvailablePages);
			DBG_PRINT("PoolTrackTable : %p\r\n", tmpKDBG->PoolTrackTable);
			DBG_PRINT("NonPagedPoolDescriptor : %p\r\n", tmpKDBG->NonPagedPoolDescriptor);
			DBG_PRINT("MmHighestUserAddress : %p\r\n", tmpKDBG->MmHighestUserAddress);
			DBG_PRINT("MmSystemRangeStart : %p\r\n", tmpKDBG->MmSystemRangeStart);
			DBG_PRINT("MmUserProbeAddress : %p\r\n", tmpKDBG->MmUserProbeAddress);
			DBG_PRINT("KdPrintCircularBuffer : %p\r\n", tmpKDBG->KdPrintCircularBuffer);
			DBG_PRINT("KdPrintCircularBufferEnd : %p\r\n", tmpKDBG->KdPrintCircularBufferEnd);
			DBG_PRINT("KdPrintWritePointer : %p\r\n", tmpKDBG->KdPrintWritePointer);
			DBG_PRINT("KdPrintRolloverCount : %p\r\n", tmpKDBG->KdPrintRolloverCount);
			DBG_PRINT("MmLoadedUserImageList : %p\r\n", tmpKDBG->MmLoadedUserImageList);
			DBG_PRINT("NtBuildLab : %p\r\n", tmpKDBG->NtBuildLab);
			DBG_PRINT("KiNormalSystemCall : %p\r\n", tmpKDBG->KiNormalSystemCall);
			DBG_PRINT("KiProcessorBlock : %p\r\n", tmpKDBG->KiProcessorBlock);
			DBG_PRINT("MmUnloadedDrivers : %p\r\n", tmpKDBG->MmUnloadedDrivers);
			DBG_PRINT("MmLastUnloadedDriver : %p\r\n", tmpKDBG->MmLastUnloadedDriver);
			DBG_PRINT("MmTriageActionTaken : %p\r\n", tmpKDBG->MmTriageActionTaken);
			DBG_PRINT("MmSpecialPoolTag : %p\r\n", tmpKDBG->MmSpecialPoolTag);
			DBG_PRINT("KernelVerifier : %p\r\n", tmpKDBG->KernelVerifier);
			DBG_PRINT("MmVerifierData : %p\r\n", tmpKDBG->MmVerifierData);
			DBG_PRINT("MmAllocatedNonPagedPool : %p\r\n", tmpKDBG->MmAllocatedNonPagedPool);
			DBG_PRINT("MmPeakCommitment : %p\r\n", tmpKDBG->MmPeakCommitment);
			DBG_PRINT("MmTotalCommitLimitMaximum : %p\r\n", tmpKDBG->MmTotalCommitLimitMaximum);
			DBG_PRINT("CmNtCSDVersion : %p\r\n", tmpKDBG->CmNtCSDVersion);
			DBG_PRINT("MmPhysicalMemoryBlock : %p\r\n", tmpKDBG->MmPhysicalMemoryBlock);
			DBG_PRINT("MmSessionBase : %p\r\n", tmpKDBG->MmSessionBase);
			DBG_PRINT("MmSessionSize : %p\r\n", tmpKDBG->MmSessionSize);
			DBG_PRINT("MmSystemParentTablePage : %p\r\n", tmpKDBG->MmSystemParentTablePage);
			DBG_PRINT("MmVirtualTranslationBase : %p\r\n", tmpKDBG->MmVirtualTranslationBase);
			DBG_PRINT("OffsetKThreadNextProcessor : %04x\r\n", tmpKDBG->OffsetKThreadNextProcessor);
			DBG_PRINT("OffsetKThreadTeb : %04x\r\n", tmpKDBG->OffsetKThreadTeb);
			DBG_PRINT("OffsetKThreadKernelStack : %04x\r\n", tmpKDBG->OffsetKThreadKernelStack);
			DBG_PRINT("OffsetKThreadInitialStack : %04x\r\n", tmpKDBG->OffsetKThreadInitialStack);
			DBG_PRINT("OffsetKThreadApcProcess : %04x\r\n", tmpKDBG->OffsetKThreadApcProcess);
			DBG_PRINT("OffsetKThreadState : %04x\r\n", tmpKDBG->OffsetKThreadState);
			DBG_PRINT("OffsetKThreadBStore : %04x\r\n", tmpKDBG->OffsetKThreadBStore);
			DBG_PRINT("OffsetKThreadBStoreLimit : %04x\r\n", tmpKDBG->OffsetKThreadBStoreLimit);
			DBG_PRINT("SizeEProcess : %04x\r\n", tmpKDBG->SizeEProcess);
			DBG_PRINT("OffsetEprocessPeb : %04x\r\n", tmpKDBG->OffsetEprocessPeb);
			DBG_PRINT("OffsetEprocessParentCID : %04x\r\n", tmpKDBG->OffsetEprocessParentCID);
			DBG_PRINT("OffsetEprocessDirectoryTableBase : %04x\r\n", tmpKDBG->OffsetEprocessDirectoryTableBase);
			DBG_PRINT("SizePrcb : %04x\r\n", tmpKDBG->SizePrcb);
			DBG_PRINT("OffsetPrcbDpcRoutine : %04x\r\n", tmpKDBG->OffsetPrcbDpcRoutine);
			DBG_PRINT("OffsetPrcbCurrentThread : %04x\r\n", tmpKDBG->OffsetPrcbCurrentThread);
			DBG_PRINT("OffsetPrcbMhz : %04x\r\n", tmpKDBG->OffsetPrcbMhz);
			DBG_PRINT("OffsetPrcbCpuType : %04x\r\n", tmpKDBG->OffsetPrcbCpuType);
			DBG_PRINT("OffsetPrcbVendorString : %04x\r\n", tmpKDBG->OffsetPrcbVendorString);
			DBG_PRINT("OffsetPrcbProcStateContext : %04x\r\n", tmpKDBG->OffsetPrcbProcStateContext);
			DBG_PRINT("OffsetPrcbNumber : %04x\r\n", tmpKDBG->OffsetPrcbNumber);
			DBG_PRINT("SizeEThread : %04x\r\n", tmpKDBG->SizeEThread);
			DBG_PRINT("KdPrintCircularBufferPtr : %p\r\n", tmpKDBG->KdPrintCircularBufferPtr);
			DBG_PRINT("KdPrintBufferSize : %p\r\n", tmpKDBG->KdPrintBufferSize);
			DBG_PRINT("KeLoaderBlock : %p\r\n", tmpKDBG->KeLoaderBlock);
			DBG_PRINT("SizePcr : %04x\r\n", tmpKDBG->SizePcr);
			DBG_PRINT("OffsetPcrSelfPcr : %04x\r\n", tmpKDBG->OffsetPcrSelfPcr);
			DBG_PRINT("OffsetPcrCurrentPrcb : %04x\r\n", tmpKDBG->OffsetPcrCurrentPrcb);
			DBG_PRINT("OffsetPcrContainedPrcb : %04x\r\n", tmpKDBG->OffsetPcrContainedPrcb);
			DBG_PRINT("OffsetPcrInitialBStore : %04x\r\n", tmpKDBG->OffsetPcrInitialBStore);
			DBG_PRINT("OffsetPcrBStoreLimit : %04x\r\n", tmpKDBG->OffsetPcrBStoreLimit);
			DBG_PRINT("OffsetPcrInitialStack : %04x\r\n", tmpKDBG->OffsetPcrInitialStack);
			DBG_PRINT("OffsetPcrStackLimit : %04x\r\n", tmpKDBG->OffsetPcrStackLimit);
			DBG_PRINT("OffsetPrcbPcrPage : %04x\r\n", tmpKDBG->OffsetPrcbPcrPage);
			DBG_PRINT("OffsetPrcbProcStateSpecialReg : %04x\r\n", tmpKDBG->OffsetPrcbProcStateSpecialReg);
			DBG_PRINT("GdtR0Code : %04x\r\n", tmpKDBG->GdtR0Code);
			DBG_PRINT("GdtR0Data : %04x\r\n", tmpKDBG->GdtR0Data);
			DBG_PRINT("GdtR0Pcr : %04x\r\n", tmpKDBG->GdtR0Pcr);
			DBG_PRINT("GdtR3Code : %04x\r\n", tmpKDBG->GdtR3Code);
			DBG_PRINT("GdtR3Data : %04x\r\n", tmpKDBG->GdtR3Data);
			DBG_PRINT("GdtR3Teb : %04x\r\n", tmpKDBG->GdtR3Teb);
			DBG_PRINT("GdtLdt : %04x\r\n", tmpKDBG->GdtLdt);
			DBG_PRINT("GdtTss : %04x\r\n", tmpKDBG->GdtTss);
			DBG_PRINT("Gdt64R3CmCode : %04x\r\n", tmpKDBG->Gdt64R3CmCode);
			DBG_PRINT("Gdt64R3CmTeb : %04x\r\n", tmpKDBG->Gdt64R3CmTeb);
			DBG_PRINT("IopNumTriageDumpDataBlocks : %p\r\n", tmpKDBG->IopNumTriageDumpDataBlocks);
			DBG_PRINT("IopTriageDumpDataBlocks : %p\r\n", tmpKDBG->IopTriageDumpDataBlocks);
			DBG_PRINT("VfCrashDataBlock : %p\r\n", tmpKDBG->VfCrashDataBlock);
			DBG_PRINT("----------------------------------------\r\n");
		}
	private:
		PKDDEBUGGER_DATA64 _kdblock;
		OS_VERSION os;
		PDWORD64 KiWaitNever_;
		PBYTE KdpDataBlockEncoded_;
		PDWORD64 KiWaitAlways_;
	};
}