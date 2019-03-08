#pragma once
#include "Base.h"
#include <functional>
#include "pte.h"
namespace ddk
{
	class PhysicalMemScan :public Singleton<PhysicalMemScan>
	{
	public:
		PhysicalMemScan() {

		}
		~PhysicalMemScan() {

		}
	private:
		typedef struct _MAP_STRUCT {
			PVOID OrigPage;
			PVOID MapPage;
			PMDL Mdl;
			PHYSICAL_ADDRESS MapPagePhys;
		} MAP_STRUCT, *PMAP_STRUCT;

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONG_PTR)1) << VIRTUAL_ADDRESS_BITS) - 1)



#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_SHIFT 3

#define _HARDWARE_PTE_WORKING_SET_BITS 11

		typedef struct _MMPTE {
			ULONGLONG Valid : 1;
			ULONGLONG Writable : 1; // changed for MP version
			ULONGLONG Owner : 1;
			ULONGLONG WriteThrough : 1;
			ULONGLONG CacheDisable : 1;
			ULONGLONG Accessed : 1;
			ULONGLONG Dirty : 1;
			ULONGLONG LargePage : 1;
			ULONGLONG Global : 1;
			ULONGLONG CopyOnWrite : 1; // software field
			ULONGLONG Prototype : 1; // software field
			ULONGLONG Write : 1; // software field - MP change
			ULONGLONG PageFrameNumber : 28;
			ULONG64 reserved1 : 24 - (_HARDWARE_PTE_WORKING_SET_BITS + 1);
			ULONGLONG SoftwareWsIndex : _HARDWARE_PTE_WORKING_SET_BITS;
			ULONG64 NoExecute : 1;
		} MMPTE, *PMMPTE;

#define MiGetPteAddress(va) \
    ((PMMPTE)(((((ULONG_PTR)(va) & VIRTUAL_ADDRESS_MASK) >> PTI_SHIFT) << PTE_SHIFT) + PTE_BASE))

		NTSTATUS
			InitMapPage(
				OUT PMAP_STRUCT MapHandle
				)
		{
			NTSTATUS Status = STATUS_SUCCESS;
			PMMPTE pte;

			RtlZeroMemory(MapHandle, sizeof(*MapHandle));

			__try {

				MapHandle->OrigPage = ExAllocatePool(NonPagedPool,
					PAGE_SIZE);

				if (MapHandle->OrigPage == NULL)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}

				MapHandle->Mdl = IoAllocateMdl(MapHandle->OrigPage,
					PAGE_SIZE,
					FALSE,
					FALSE,
					NULL);

				if (MapHandle->Mdl == NULL)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}

				//
				// Remap
				//

				MapHandle->MapPage = MmMapLockedPagesSpecifyCache(MapHandle->Mdl,
					KernelMode,
					MmCached,
					NULL,
					FALSE,
					HighPagePriority);

				if (MapHandle->MapPage == NULL)
				{
					Status = STATUS_INSUFFICIENT_RESOURCES;
					__leave;
				}

				pte = MiGetPteAddress(MapHandle->MapPage);

				MapHandle->MapPagePhys.QuadPart = *(PULONGLONG)pte;

			}
			__finally {

				if (!NT_SUCCESS(Status))
				{
					if (MapHandle->Mdl != NULL)
					{
						IoFreeMdl(MapHandle->Mdl);
					}

					if (MapHandle->OrigPage != NULL)
					{
						ExFreePool(MapHandle->OrigPage);
					}
				}
			}

			return Status;
		}

		PVOID
			MapSpecifiedPage(
				IN PMAP_STRUCT MapHandle,
				IN PHYSICAL_ADDRESS PhysicalAddress
				)
		{
			PMMPTE pte = MiGetPteAddress(MapHandle->MapPage);

			pte->PageFrameNumber = PhysicalAddress.QuadPart >> 12;

			_ReadWriteBarrier();

			__invlpg(MapHandle->MapPage);

			return MapHandle->MapPage;
		}

		VOID
			FiniMapPage(
				IN PMAP_STRUCT MapHandle
				)
		{
			PMMPTE pte = MiGetPteAddress(MapHandle->MapPage);

			pte->PageFrameNumber = MapHandle->MapPagePhys.QuadPart >> 12;

			MmUnmapLockedPages(MapHandle->MapPage, MapHandle->Mdl);

			IoFreeMdl(MapHandle->Mdl);

			ExFreePool(MapHandle->OrigPage);
		}


public:
	NTSTATUS Scanner(std::function<bool(PVOID,SIZE_T)> _callback)
	{
			
			auto PhysicalMemoryBlock = MmGetPhysicalMemoryRanges();

			if (PhysicalMemoryBlock == NULL)
			{
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			//MAP_STRUCT MapHandle = {};
			//auto Status = InitMapPage(&MapHandle);

			//if (!NT_SUCCESS(Status))
			//{
			//	ExFreePool(PhysicalMemoryBlock);

			//	return Status;
			//}

			auto i = 0;

			while (PhysicalMemoryBlock[i].NumberOfBytes.QuadPart != 0)
			{
				PHYSICAL_ADDRESS BaseAddress = PhysicalMemoryBlock[i].BaseAddress;
				LARGE_INTEGER NumberOfBytes = PhysicalMemoryBlock[i].NumberOfBytes;

				DBG_PRINT("BaseAddress: %I64x\r\n", BaseAddress.QuadPart);
				DBG_PRINT("NumberOfBytes: %I64x\r\n", NumberOfBytes.QuadPart);
				auto VA = MmGetVirtualForPhysical(BaseAddress);
				DBG_PRINT("VA %p\r\n", VA);
				//大块扫
				DBG_PRINT("huge Block Scan\r\n");
				auto mapped_buffer = MmMapIoSpace(BaseAddress, NumberOfBytes.QuadPart, MmNonCached);
				if (mapped_buffer)
				{
					DBG_PRINT("Scan Map Address %p\r\n",mapped_buffer);
					_callback(mapped_buffer, NumberOfBytes.QuadPart);
					MmUnmapIoSpace(mapped_buffer, NumberOfBytes.QuadPart);
				}
				//小块扫
				DBG_PRINT("mini Block Scan\r\n");
				//正确做法是要研究MmGetVirtualForPhysical把连续的地址连起来，
				//主义啦 PgContext有一定概率跨页
				while (NumberOfBytes.QuadPart > 0)
				{
					auto MapAddress = MmGetVirtualForPhysical(BaseAddress);
					auto ulAddress = reinterpret_cast<ULONG_PTR>(MapAddress);
					if (MapAddress)
					{
						auto mapped_buffer = MmMapIoSpace(BaseAddress, PAGE_SIZE, MmNonCached);
						if (mapped_buffer)
						{
							_callback(mapped_buffer, PAGE_SIZE);
							MmUnmapIoSpace(mapped_buffer, PAGE_SIZE);
						}
					}
					BaseAddress.QuadPart += PAGE_SIZE;
					NumberOfBytes.QuadPart -= PAGE_SIZE;
				}
				i++;
			}
		/*	FiniMapPage(&MapHandle);*/
			ExFreePool(PhysicalMemoryBlock);
			return STATUS_SUCCESS;
	}

	};
};