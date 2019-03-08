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