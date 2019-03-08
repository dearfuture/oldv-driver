#pragma once
#include "Base.h"
namespace ddk
{
	namespace ntos_util
	{
		EXTERN_C
			ULONG KeQueryActiveProcessorCountCompatible(
				__out_opt PKAFFINITY ActiveProcessors);
		EXTERN_C
			NTSTATUS ForEachProcessors(
				__in NTSTATUS(*CallbackRoutine)(void*),
				__in_opt void* Context);
		
	};
};