#pragma once
#include "Base.h"
#include <functional>
#include <array>
#include <set>
#include "pte.h"
namespace ddk
{
	class mm_independ_scan:public Singleton<mm_independ_scan>
	{
	public:
		mm_independ_scan() {

		}
		~mm_independ_scan() {

		}
	private:
		// The number of bytes to examine to calculate the number of distinctive
		// bytes and randomness
		static const auto EXAMINATION_BYTES = 100;

		// It is not a PatchGuard page if the number of distinctive bytes are bigger
		// than this number
		static const auto MAXIMUM_DISTINCTIVE_NUMBER = 5;

		// It is not a PatchGuard page if randomness is smaller than this number
		static const auto MINIMUM_RANDOMNESS = 50;

		// It is not a PatchGuard page if the size of the page is smaller than this
		static const auto MINIMUM_REGION_SIZE = 0x004000;

		// It is not a PatchGuard page if the size of the page is larger than this
		static const auto MAXIMUM_REGION_SIZE = 0xf00000;

	private:
		bool ReadMemSafe(PVOID Dest, ULONG64 Src, ULONG Size)
		{
			auto pSrc = reinterpret_cast<PUCHAR>(Src);
			auto pDest = reinterpret_cast<PUCHAR>(Dest);
			__try
			{
				for (auto i = 0UL; i < Size; i++)
				{
					pDest[i] = pSrc[i];
				}
			}
			__except (1)
			{
				
			}
			return true;
		}
		std::array<HARDWARE_PTE, 512> GetPtes(
			__in ULONG64 PteBase)
		{
			std::array<HARDWARE_PTE, 512> ptes;
			auto PteDir = reinterpret_cast<PHARDWARE_PTE>(PteBase);
			__try
			{
				for (auto i = 0; i < 512;i++)
				{
					ptes[i] = PteDir[i];
				}
			}
			__except (1)
			{
				
			}
			//auto result = m_Data->ReadVirtual(PteBase, ptes.data(),
			//	static_cast<ULONG>(ptes.size() * sizeof(HARDWARE_PTE)), &readBytes);
			//if (!SUCCEEDED(result))
			//{
			//	throw std::runtime_error("The given address could not be read.");
			//}
			return ptes;
		}
		ULONG GetRamdomness(
			__in void* Addr,
			__in SIZE_T Size)
		{
			const auto p = static_cast<UCHAR*>(Addr);
			std::set<UCHAR> dic;
			for (SIZE_T i = 0; i < Size; ++i)
			{
				dic.insert(p[i]);
			}
			return static_cast<ULONG>(dic.size());
		}
		ULONG GetNumberOfDistinctiveNumbers(
			__in void* Addr,
			__in SIZE_T Size)
		{
			const auto p = static_cast<UCHAR*>(Addr);
			ULONG count = 0;
			for (SIZE_T i = 0; i < Size; ++i)
			{
				if (p[i] == 0xff || p[i] == 0x00)
				{
					count++;
				}
			}
			return count;
		}

	public:

		void scanner(std::function<void(PVOID, SIZE_T)> _callback)
		{
			const auto startPxe = reinterpret_cast<ULONG64>(
				MiAddressToPxe(reinterpret_cast<void*>(MmSystemRangeStart)));
			const auto endPxe = PXE_TOP;
			const auto pxes = GetPtes(PXE_BASE);
			for (auto currentPxe = startPxe; currentPxe < endPxe;
			currentPxe += sizeof(HARDWARE_PTE))
			{
				// Make sure that this PXE is valid
				const auto pxeIndex = (currentPxe - PXE_BASE) / sizeof(HARDWARE_PTE);
				const auto pxe = pxes[pxeIndex];
				if (!pxe.Valid)
				{
					continue;
				}

				// If the PXE is valid, analyze PPE belonging to this
				const auto startPpe = PPE_BASE + 0x1000 * pxeIndex;
				const auto endPpe = PPE_BASE + 0x1000 * (pxeIndex + 1);
				const auto ppes = GetPtes(startPpe);
				for (auto currentPpe = startPpe; currentPpe < endPpe;
				currentPpe += sizeof(HARDWARE_PTE))
				{
					// Make sure that this PPE is valid
					const auto ppeIndex1 = (currentPpe - PPE_BASE) / sizeof(HARDWARE_PTE);
					const auto ppeIndex2 = (currentPpe - startPpe) / sizeof(HARDWARE_PTE);
					const auto ppe = ppes[ppeIndex2];
					if (!ppe.Valid)
					{
						continue;
					}

					// If the PPE is valid, analyze PDE belonging to this
					const auto startPde = PDE_BASE + 0x1000 * ppeIndex1;
					const auto endPde = PDE_BASE + 0x1000 * (ppeIndex1 + 1);
					const auto pdes = GetPtes(startPde);
					for (auto currentPde = startPde; currentPde < endPde;
					currentPde += sizeof(HARDWARE_PTE))
					{
						// Make sure that this PDE is valid as well as is not handling
						// a large page as an independent page does not use a large page
						const auto pdeIndex1 = (currentPde - PDE_BASE) / sizeof(HARDWARE_PTE);
						const auto pdeIndex2 = (currentPde - startPde) / sizeof(HARDWARE_PTE);
						const auto pde = pdes[pdeIndex2];
						if (!pde.Valid || pde.LargePage)
						{
							continue;
						}
						//++progress;

						// If the PDE is valid, analyze PTE belonging to this
						const auto startPte = PTE_BASE + 0x1000 * pdeIndex1;
						const auto endPte = PTE_BASE + 0x1000 * (pdeIndex1 + 1);
						const auto ptes = GetPtes(startPte);
						for (auto currentPte = startPte; currentPte < endPte;
						currentPte += sizeof(HARDWARE_PTE))
						{
							// Make sure that this PPE is valid,
							// Readable/Writable/Executable
							const auto pteIndex2 = (currentPte - startPte)
								/ sizeof(HARDWARE_PTE);
							const auto pte = ptes[pteIndex2];
							if (!pte.Valid ||
								!pte.Write ||
								pte.NoExecute)
							{
								continue;
							}

							// This page might be PatchGuard page, so let's analyze it
							const auto virtualAddress = reinterpret_cast<ULONG64>(
								MiPteToAddress(
									reinterpret_cast<HARDWARE_PTE*>(currentPte)))
								| 0xffff000000000000;

							//// Read the contents of the address that is managed by the
							//// PTE
							////ULONG readBytes = 0;
							std::array<std::uint8_t, EXAMINATION_BYTES + sizeof(ULONG64)>
								contents;
							
							if (!ReadMemSafe(contents.data(), virtualAddress, static_cast<ULONG>(contents.size())))
							{
								continue;
							}
							//DBG_PRINT("Scan %p\r\n", PVOID(virtualAddress));
							//// Check randomness of the contents
							const auto numberOfDistinctiveNumbers =
								GetNumberOfDistinctiveNumbers(
									contents.data() + sizeof(ULONG64), EXAMINATION_BYTES);
							const auto randomness = GetRamdomness(
								contents.data() + sizeof(ULONG64), EXAMINATION_BYTES);
							if (numberOfDistinctiveNumbers > MAXIMUM_DISTINCTIVE_NUMBER
								|| randomness < MINIMUM_RANDOMNESS)
							{
								continue;
							}

							//// Also, check the size of the region. The first page of
							//// allocated pages as independent pages has its own page
							//// size in bytes at the first 8 bytes
							const auto independentPageSize =
								*reinterpret_cast<ULONG64*>(contents.data());
							if (MINIMUM_REGION_SIZE > independentPageSize
								|| independentPageSize > MAXIMUM_REGION_SIZE)
							{
								continue;
							}
							DBG_PRINT("Scan %p %x\r\n", PVOID(virtualAddress),independentPageSize);
							// It seems to be a PatchGuard page so do callback
							_callback(PVOID(virtualAddress), independentPageSize);
						}
					}
				}
			}
		}
	};
};