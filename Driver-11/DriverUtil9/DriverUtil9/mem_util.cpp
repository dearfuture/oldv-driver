#include "Base.h"
#include "mem_util.h"
#include "pte.h"
#include "util_syscall.h"

namespace ddk
{
	namespace mem_util
	{
		bool MmIsExecutableAddress(
			const void *Address) 
		{
			if (!MmIsAccessibleAddress(Address)) {
				return false;
			}

#ifdef _AMD64_
			const auto pde = UtilpAddressToPde(Address);
			const auto pte = UtilpAddressToPte(Address);
			if (pde->NoExecute || (!pde->LargePage && (!pte || pte->NoExecute))) {
				return false;
			}
#else
			const auto pte = UtilpAddressToPte(Address);
			if (pte->NoExecute) {
				return false;
			}
#endif
			return true;
		}

		bool MmIsAccessibleAddress(const void *Address) 
		{
#ifdef _AMD64_
			const auto pxe = UtilpAddressToPxe(Address);
			if (!pxe->Present)
			{
				return false;
			}
			const auto ppe = UtilpAddressToPpe(Address);
			if (!ppe->Present)
			{
				return false;
			}
			const auto pde = UtilpAddressToPde(Address);
			if (!pde->Present)
			{
				return false;
			}
			const auto pte = UtilpAddressToPte(Address);
			//PTE
			if ((!pde->LargePage && (!pte || !pte->Present)))
			{
				return false;
			}
#else
			const auto pde = UtilpAddressToPde(Address);
			const auto pte = UtilpAddressToPte(Address);
			if (!pde->Present || !pde->PageFrameNumber || !pte->Present ||
				!pte->PageFrameNumber) {
				return false;
			}
#endif
			return true;
		}

#ifdef _AMD64_

		// Return an address of PXE
		HARDWARE_PTE *UtilpAddressToPxe(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto pxe_index = (addr >> g_utilp_pxi_shift) & g_utilp_pxi_mask;
			const auto offset = pxe_index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(g_utilp_pxe_base + offset);
		}

		// Return an address of PPE
		HARDWARE_PTE *UtilpAddressToPpe(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto ppe_index = (addr >> g_utilp_ppi_shift) & g_utilp_ppi_mask;
			const auto offset = ppe_index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(g_utilp_ppe_base + offset);
		}

#endif

		// Return an address of PDE
		HARDWARE_PTE *UtilpAddressToPde(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto pde_index = (addr >> g_utilp_pdi_shift) & g_utilp_pdi_mask;
			const auto offset = pde_index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(g_utilp_pde_base + offset);
		}

		// Return an address of PTE
		HARDWARE_PTE *UtilpAddressToPte(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto pte_index = (addr >> g_utilp_pti_shift) & g_utilp_pti_mask;
			const auto offset = pte_index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(g_utilp_pte_base + offset);
		}

		bool MmIsAddressNonCanonical(DWORD64 address)
		{
			//48 位-63 位和47 位都是一个值的地址就是规范地址

			if ((address >> 47) < 0xFFFFFFFFFFFFFFFFui64 && (address >> 47) != 0)
			{
				//X64地址规则
				return true;
			}
			return false;
		}
		// Converts a function pointer to a function address.
		UCHAR *UtilFpToData(FARPROC FunctionPointer) {
			if (IsX64()) {
				return reinterpret_cast<UCHAR *>(FunctionPointer);
			}
			else {
				return reinterpret_cast<UCHAR *>(
					reinterpret_cast<ULONG_PTR>(FunctionPointer) & ~1);
			}
		}

		// Converts a function address to a function pointer.
		FARPROC UtilDataToFp(UCHAR *FunctionAddress) {
			if (IsX64()) {
				return reinterpret_cast<FARPROC>(FunctionAddress);
			}
			else {
				return reinterpret_cast<FARPROC>(
					reinterpret_cast<ULONG_PTR>(FunctionAddress) | 1);
			}
		}

		void MmInvalidateInstructionCache(
			void *BaseAddress, SIZE_T Length) {
#ifdef _AMD64_
			UNREFERENCED_PARAMETER(BaseAddress);
			UNREFERENCED_PARAMETER(Length);
			__faststorefence();
#else
			/*KeSweepIcacheRange(TRUE, BaseAddress, Length);*/
#endif
		}
		// Does memcpy safely even if Destination is a read only region.
		NTSTATUS MmForceMemCpy(void *Destination,
			const void *Source,
			SIZE_T Length) {
			auto mdl = std::experimental::make_unique_resource(
				IoAllocateMdl(Destination, static_cast<ULONG>(Length), FALSE, FALSE,
					nullptr),
				&IoFreeMdl);
			if (!mdl) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			MmBuildMdlForNonPagedPool(mdl.get());

#pragma warning(push)
#pragma warning(disable : 28145)
			//
			// Following MmMapLockedPagesSpecifyCache() call causes bug check in case
			// you are using Driver Verifier. The reason is explained as follows:
			//
			// A driver must not try to create more than one system-address-space
			// mapping for an MDL. Additionally, because an MDL that is built by the
			// MmBuildMdlForNonPagedPool routine is already mapped to the system
			// address space, a driver must not try to map this MDL into the system
			// address space again by using the MmMapLockedPagesSpecifyCache routine.
			// -- MSDN
			//
			// This flag modification hacks Driver Verifier's check and prevent leading
			// bug check.
			//
			mdl.get()->MdlFlags &= ~MDL_SOURCE_IS_NONPAGED_POOL;
			mdl.get()->MdlFlags |= MDL_PAGES_LOCKED;
#pragma warning(pop)

			auto writableDest = MmMapLockedPagesSpecifyCache(
				mdl.get(), KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
			if (!writableDest) {
				return STATUS_INSUFFICIENT_RESOURCES;
			}
			memcpy(writableDest, Source, Length);
			MmUnmapLockedPages(writableDest, mdl.get());
			return STATUS_SUCCESS;
		}
		void *MmMemMem(const void *SearchBase,
			SIZE_T SearchSize,
			const void *Pattern,
			SIZE_T PatternSize) {
			if (PatternSize > SearchSize) {
				return nullptr;
			}
			auto searchBase = static_cast<const char *>(SearchBase);
			for (size_t i = 0; i <= SearchSize - PatternSize; i++) {
				if (!memcmp(Pattern, &searchBase[i], PatternSize)) {
					return const_cast<char *>(&searchBase[i]);
				}
			}
			return nullptr;
		}
		NTSTATUS MmSearch(
			IN PUCHAR adresseBase,
			IN PUCHAR adresseMaxMin,
			IN PUCHAR pattern,
			OUT PUCHAR *addressePattern,
			IN SIZE_T longueur)
		{
			for (*addressePattern = adresseBase;
			(adresseMaxMin > adresseBase) ? (*addressePattern <= adresseMaxMin) : (*addressePattern >= adresseMaxMin);
				*addressePattern += (adresseMaxMin > adresseBase) ? 1 : -1)
				if (RtlEqualMemory(pattern, *addressePattern, longueur))
					return STATUS_SUCCESS;
			*addressePattern = NULL;
			return STATUS_NOT_FOUND;
		}

		NTSTATUS MmGenericPointerSearch(
			OUT PUCHAR *addressePointeur,
			IN PUCHAR adresseBase,
			IN PUCHAR adresseMaxMin,
			IN PUCHAR pattern,
			IN SIZE_T longueur,
			IN LONG offsetTo)
		{
			NTSTATUS status = MmSearch(adresseBase,
				adresseMaxMin,
				pattern,
				addressePointeur,
				longueur);
			if (NT_SUCCESS(status))
			{
				*addressePointeur += offsetTo;
#ifdef _AMD64_
				*addressePointeur += sizeof(LONG) + *(PLONG)(*addressePointeur);
#else
				*addressePointeur = *(PUCHAR *)(*addressePointeur);
#endif

				if (!*addressePointeur)
					status = STATUS_INVALID_HANDLE;
			}
			return status;
		}

		void init_mem_util()
		{
			if (b_init)
			{
				return;
			}

			// Check OS version to know if page table base addresses need to be relocated
			RTL_OSVERSIONINFOW os_version = { sizeof(os_version) };
			auto status = RtlGetVersion(&os_version);
			if (!NT_SUCCESS(status)) {
				return;
			}

			// Win 10 build 14316 is the first version implements randomized page tables
			// Use fixed values if a systems is either: x86, older than Windows 7, or
			// older than build 14316.
			if (os_version.dwMajorVersion < 10 ||
				os_version.dwBuildNumber < 14316)
			{
				g_utilp_pxe_base = kUtilpPxeBase;
				g_utilp_ppe_base = kUtilpPpeBase;
				g_utilp_pxi_shift = kUtilpPxiShift;
				g_utilp_ppi_shift = kUtilpPpiShift;
				g_utilp_pxi_mask = kUtilpPxiMask;
				g_utilp_ppi_mask = kUtilpPpiMask;

				g_utilp_pde_base = kUtilpPdeBase;
				g_utilp_pte_base = kUtilpPteBase;
				g_utilp_pdi_shift = kUtilpPdiShift;
				g_utilp_pti_shift = kUtilpPtiShift;
				g_utilp_pdi_mask = kUtilpPdiMask;
				g_utilp_pti_mask = kUtilpPtiMask;

				g_MmPfnDatabase = reinterpret_cast<void *>(0xfffffa8000000000);

				b_init = true;
				return;
			}

			// Get PTE_BASE from MmGetVirtualForPhysical
			const auto p_MmGetVirtualForPhysical = ddk::util::DynImport::Instance().get_proc_address("MmGetVirtualForPhysical");
			if (!p_MmGetVirtualForPhysical) {
				return;
			}

			static const UCHAR kPatternWin10x64[] = {
				0x48, 0x8b, 0x04, 0xd0,  // mov     rax, [rax+rdx*8]
				0x48, 0xc1, 0xe0, 0x19,  // shl     rax, 19h
				0x48, 0xba,              // mov     rdx, ????????`????????  ; PTE_BASE
			};



			auto found = reinterpret_cast<ULONG_PTR>(MmMemMem(p_MmGetVirtualForPhysical, 0x30, kPatternWin10x64,
				sizeof(kPatternWin10x64)));
			if (!found) {
				return;
			}

			
			found += sizeof(kPatternWin10x64);
			
			const auto pte_base = *reinterpret_cast<ULONG_PTR *>(found);

			DBG_PRINT("PTEBASE = %p\r\n", PVOID(pte_base));

			const auto index = (pte_base >> kUtilpPxiShift) & kUtilpPxiMask;
			const auto pde_base = pte_base | (index << kUtilpPpiShift);
			const auto ppe_base = pde_base | (index << kUtilpPdiShift);
			const auto pxe_base = ppe_base | (index << kUtilpPtiShift);

			g_utilp_pxe_base = static_cast<ULONG_PTR>(pxe_base);
			g_utilp_ppe_base = static_cast<ULONG_PTR>(ppe_base);
			g_utilp_pde_base = static_cast<ULONG_PTR>(pde_base);
			g_utilp_pte_base = static_cast<ULONG_PTR>(pte_base);

			g_utilp_pxi_shift = kUtilpPxiShift;
			g_utilp_ppi_shift = kUtilpPpiShift;
			g_utilp_pdi_shift = kUtilpPdiShift;
			g_utilp_pti_shift = kUtilpPtiShift;

			g_utilp_pxi_mask = kUtilpPxiMask;
			g_utilp_ppi_mask = kUtilpPpiMask;
			g_utilp_pdi_mask = kUtilpPdiMask;
			g_utilp_pti_mask = kUtilpPtiMask;

			static const UCHAR kPatternWin10x64_pfn[] = {
				0x48, 0x8B, 0xC1,        // mov     rax, rcx
				0x48, 0xC1, 0xE8, 0x0C,  // shr     rax, 0Ch
				0x48, 0x8D, 0x14, 0x40,  // lea     rdx, [rax + rax * 2]
				0x48, 0x03, 0xD2,        // add     rdx, rdx
				0x48, 0xB8,              // mov     rax, 0FFFFFA8000000008h
			};

			auto found2 = reinterpret_cast<ULONG_PTR>(MmMemMem(p_MmGetVirtualForPhysical, 0x20, kPatternWin10x64_pfn,
				sizeof(kPatternWin10x64_pfn)));
			if (!found2)
			{
				return;
			}
			found2 += sizeof(kPatternWin10x64_pfn);
			g_MmPfnDatabase = *reinterpret_cast<void **>(found2);
			DBG_PRINT("PfnBase = %p\r\n", PVOID(g_MmPfnDatabase));

			b_init = true;
		}

	};
};