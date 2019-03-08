#pragma once
#include "Base.h"
namespace ddk
{
	namespace mem_util
	{
		NTSTATUS MmSearch(
			IN PUCHAR adresseBase,
			IN PUCHAR adresseMaxMin,
			IN PUCHAR pattern,
			OUT PUCHAR *addressePattern,
			IN SIZE_T longueur);

		NTSTATUS MmGenericPointerSearch(
			OUT PUCHAR *addressePointeur,
			IN PUCHAR adresseBase,
			IN PUCHAR adresseMaxMin,
			IN PUCHAR pattern,
			IN SIZE_T longueur,
			IN LONG offsetTo);

		bool MmIsAddressNonCanonical(DWORD64 address);

		bool MmIsAccessibleAddress(const void *Address);

		bool MmIsExecutableAddress(const void *Address);

		UCHAR *UtilFpToData(FARPROC FunctionPointer);

		FARPROC UtilDataToFp(UCHAR *FunctionAddress);

		NTSTATUS MmForceMemCpy(void *Destination,
			const void *Source,
			SIZE_T Length);

		void MmInvalidateInstructionCache(
			void *BaseAddress, SIZE_T Length);

		void *MmMemMem(const void *SearchBase,
			SIZE_T SearchSize,
			const void *Pattern,
			SIZE_T PatternSize);
//////////////////////////////////////////////////////////////////////////
		struct WINDOWS_RT_PTE {
			ULONG NoExecute : 1;
			ULONG Present : 1;
			ULONG Unknown1 : 5;
			ULONG Writable : 1;
			ULONG Unknown2 : 4;
			ULONG PageFrameNumber : 20;
		};
		static_assert(sizeof(WINDOWS_RT_PTE) == 4, "Size check");

		struct WINDOWS_AMD64_PTE {
			ULONG64 Present : 1;
			ULONG64 Write : 1;
			ULONG64 Owner : 1;
			ULONG64 WriteThrough : 1;
			ULONG64 CacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Dirty : 1;
			ULONG64 LargePage : 1;
			ULONG64 Global : 1;
			ULONG64 CopyOnWrite : 1;
			ULONG64 Prototype : 1;
			ULONG64 reserved0 : 1;
			ULONG64 PageFrameNumber : 28;
			ULONG64 reserved1 : 12;
			ULONG64 SoftwareWsIndex : 11;
			ULONG64 NoExecute : 1;
		};
		static_assert(sizeof(WINDOWS_AMD64_PTE) == 8, "Size check");

#ifdef _AMD64_
		using HARDWARE_PTE = WINDOWS_AMD64_PTE;
#else
		using HARDWARE_PTE = WINDOWS_RT_PTE;
#endif
#ifdef _AMD64_
		HARDWARE_PTE *UtilpAddressToPxe(_In_ const void *Address);

		HARDWARE_PTE *UtilpAddressToPpe(_In_ const void *Address);
#endif

		HARDWARE_PTE *UtilpAddressToPde(_In_ const void *Address);

		HARDWARE_PTE *UtilpAddressToPte(_In_ const void *Address);
	};
};