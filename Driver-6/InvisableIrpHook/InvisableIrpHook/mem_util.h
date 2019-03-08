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
	};
};