#pragma once
#include "Base.h"
namespace ddk
{
	namespace mem_util
	{

		// Virtual Address Interpretation For Handling PTEs
		//
		// -- On x64
		// Sign extension                     16 bits
		// Page map level 4 selector           9 bits
		// Page directory pointer selector     9 bits
		// Page directory selector             9 bits
		// Page table selector                 9 bits
		// Byte within page                   12 bits
		// 11111111 11111111 11111000 10000000 00000011 01010011 00001010 00011000
		// ^^^^^^^^ ^^^^^^^^ ~~~~~~~~ ~^^^^^^^ ^^~~~~~~ ~~~^^^^^ ^^^^~~~~ ~~~~~~~~
		// Sign extension    PML4      PDPT      PD        PT        Offset
		//
		// -- On x86(PAE)
		// Page directory pointer selector     2 bits
		// Page directory selector             9 bits
		// Page table selector                 9 bits
		// Byte within page                   12 bits
		// 10 000011011 000001101 001001110101
		// ^^ ~~~~~~~~~ ^^^^^^^^^ ~~~~~~~~~~~~
		// PDPT PD      PT        Offset
		//
		// -- On x86 and ARM
		// Page directory selector            10 bits
		// Page table selector                10 bits
		// Byte within page                   12 bits
		// 1000001101 1000001101 001001110101
		// ~~~~~~~~~~ ^^^^^^^^^^ ~~~~~~~~~~~~
		// PD         PT         Offset
		//
		//
		//                                   x64   x86(PAE)  x86   ARM
		// Page map level 4 selector           9          -    -     -
		// Page directory pointer selector     9          2    -     -
		// Page directory selector             9          9   10    10
		// Page table selector                 9          9   10    10
		// Byte within page                   12         12   12    12
		//
		// 6666555555555544444444443333333333222222222211111111110000000000
		// 3210987654321098765432109876543210987654321098765432109876543210
		// ----------------------------------------------------------------
		// aaaaaaaaaaaaaaaabbbbbbbbbcccccccccdddddddddeeeeeeeeeffffffffffff  x64
		// ................................ccdddddddddeeeeeeeeeffffffffffff  x86(PAE)
		// ................................ddddddddddeeeeeeeeeeffffffffffff  x86
		// ................................ddddddddddeeeeeeeeeeffffffffffff  ARM
		//
		// a = Sign extension, b = PML4, c = PDPT, d = PD, e = PT, f = Offset

#if defined(_AMD64_)

		// Base addresses of page structures. Use !pte to obtain them.
		static auto kUtilpPxeBase = 0xfffff6fb7dbed000ull;
		static auto kUtilpPpeBase = 0xfffff6fb7da00000ull;
		static auto kUtilpPdeBase = 0xfffff6fb40000000ull;
		static auto kUtilpPteBase = 0xfffff68000000000ull;

		// Get the highest 25 bits
		static const auto kUtilpPxiShift = 39ull;

		// Get the highest 34 bits
		static const auto kUtilpPpiShift = 30ull;

		// Get the highest 43 bits
		static const auto kUtilpPdiShift = 21ull;

		// Get the highest 52 bits
		static const auto kUtilpPtiShift = 12ull;

		// Use  9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
		static const auto kUtilpPxiMask = 0x1ffull;

		// Use 18 bits; 0b0000_0000_0000_0000_0011_1111_1111_1111_1111
		static const auto kUtilpPpiMask = 0x3ffffull;

		// Use 27 bits; 0b0000_0000_0111_1111_1111_1111_1111_1111_1111
		static const auto kUtilpPdiMask = 0x7ffffffull;

		// Use 36 bits; 0b1111_1111_1111_1111_1111_1111_1111_1111_1111
		static const auto kUtilpPtiMask = 0xfffffffffull;

#elif defined(_X86_)

		// Base addresses of page structures. Use !pte to obtain them.
		static auto kUtilpPdeBase = 0xc0300000;
		static auto kUtilpPteBase = 0xc0000000;

		// Get the highest 10 bits
		static const auto kUtilpPdiShift = 22;

		// Get the highest 20 bits
		static const auto kUtilpPtiShift = 12;

		// Use 10 bits; 0b0000_0000_0000_0000_0000_0000_0011_1111_1111
		static const auto kUtilpPdiMask = 0x3ff;

		// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
		static const auto kUtilpPtiMask = 0xfffff;

		// unused but defined to compile without ifdef

		static auto kUtilpPxeBase = 0;
		static auto kUtilpPpeBase = 0;
		static const auto kUtilpPxiShift = 0;
		static const auto kUtilpPpiShift = 0;
		static const auto kUtilpPxiMask = 0;
		static const auto kUtilpPpiMask = 0;

#endif

		// Base addresses of page structures. Use !pte to obtain them.
		static const auto kUtilpPdeBasePae = 0xc0600000;
		static const auto kUtilpPteBasePae = 0xc0000000;

		// Get the highest 11 bits
		static const auto kUtilpPdiShiftPae = 21;

		// Get the highest 20 bits
		static const auto kUtilpPtiShiftPae = 12;

		// Use 11 bits; 0b0000_0000_0000_0000_0000_0000_0111_1111_1111
		static const auto kUtilpPdiMaskPae = 0x7ff;

		// Use 20 bits; 0b0000_0000_0000_0000_1111_1111_1111_1111_1111
		static const auto kUtilpPtiMaskPae = 0xfffff;

		static ULONG_PTR g_utilp_pxe_base = 0;
		static ULONG_PTR g_utilp_ppe_base = 0;
		static ULONG_PTR g_utilp_pde_base = 0;
		static ULONG_PTR g_utilp_pte_base = 0;

		static ULONG_PTR g_utilp_pxi_shift = 0;
		static ULONG_PTR g_utilp_ppi_shift = 0;
		static ULONG_PTR g_utilp_pdi_shift = 0;
		static ULONG_PTR g_utilp_pti_shift = 0;

		static ULONG_PTR g_utilp_pxi_mask = 0;
		static ULONG_PTR g_utilp_ppi_mask = 0;
		static ULONG_PTR g_utilp_pdi_mask = 0;
		static ULONG_PTR g_utilp_pti_mask = 0;

		static auto b_init = false;

		static void* g_MmPfnDatabase = nullptr;

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

		void init_mem_util();
	};
};