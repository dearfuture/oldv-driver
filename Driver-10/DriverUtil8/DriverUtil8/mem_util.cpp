#include "Base.h"
#include "mem_util.h"
#include "pte.h"
namespace ddk
{
	namespace mem_util
	{
#ifdef _AMD64_
		static const auto UTILP_PXI_MASK = 0x1ff;
		static const auto UTILP_PPI_MASK = 0x3ffff;
		static const auto UTILP_PDI_MASK = 0x7ffffff;
		static const auto UTILP_PTI_MASK = 0xfffffffff;
#else
		static const auto UTILP_PDI_MASK = 0xffffffff;
		static const auto UTILP_PTI_MASK = 0xffffffff;
#endif
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
			const auto index = (addr >> PXI_SHIFT) & UTILP_PXI_MASK;
			const auto offset = index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(PXE_BASE + offset);
		}

		// Return an address of PPE
		HARDWARE_PTE *UtilpAddressToPpe(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto index = (addr >> PPI_SHIFT) & UTILP_PPI_MASK;
			const auto offset = index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(PPE_BASE + offset);
		}

#endif

		// Return an address of PDE
		HARDWARE_PTE *UtilpAddressToPde(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto index = (addr >> PDI_SHIFT) & UTILP_PDI_MASK;
			const auto offset = index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(PDE_BASE + offset);
		}

		// Return an address of PTE
		HARDWARE_PTE *UtilpAddressToPte(
			const void *Address) {
			const auto addr = reinterpret_cast<ULONG_PTR>(Address);
			const auto index = (addr >> PTI_SHIFT) & UTILP_PTI_MASK;
			const auto offset = index * sizeof(HARDWARE_PTE);
			return reinterpret_cast<HARDWARE_PTE *>(PTE_BASE + offset);
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


	};
};