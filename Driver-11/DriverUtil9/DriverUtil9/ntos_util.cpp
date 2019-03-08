
#include "Base.h"
namespace ddk
{
	namespace ntos_util
	{
		EXTERN_C
			ULONG KeQueryActiveProcessorCountCompatible(
				__out_opt PKAFFINITY ActiveProcessors)
		{
#if (NTDDI_VERSION >= NTDDI_VISTA)
			return KeQueryActiveProcessorCount(ActiveProcessors);
#else
			ULONG numberOfProcessors = 0;
			KAFFINITY affinity = KeQueryActiveProcessors();

			if (ActiveProcessors)
			{
				*ActiveProcessors = affinity;
			}

			for (; affinity; affinity >>= 1)
			{
				if (affinity & 1)
				{
					numberOfProcessors++;
				}
			}
			return numberOfProcessors;
#endif
		}
		EXTERN_C
			NTSTATUS ForEachProcessors(
				__in NTSTATUS(*CallbackRoutine)(void*),
				__in_opt void* Context)
		{
			const auto numberOfProcessors = ddk::ntos_util::KeQueryActiveProcessorCountCompatible(nullptr);
			for (ULONG processorNumber = 0; processorNumber < numberOfProcessors;
			processorNumber++)
			{
				// Switch the current processor
				KeSetSystemAffinityThread(static_cast<KAFFINITY>(1ull << processorNumber));
				const auto oldIrql = KeRaiseIrqlToDpcLevel();

				// Execute callback
				const auto status = CallbackRoutine(Context);
				KeLowerIrql(oldIrql);
				KeRevertToUserAffinityThread();
				if (!NT_SUCCESS(status))
				{
					return status;
				}
			}
			return STATUS_SUCCESS;
		}
	};
};