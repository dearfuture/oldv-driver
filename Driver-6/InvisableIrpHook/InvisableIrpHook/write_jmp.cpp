#include "Base.h"
namespace ddk
{
	namespace util
	{
		void write_jmp(VOID *pAddress, ULONG_PTR JumpTo)
		{
			KIRQL oldIrql;
			BYTE *pCur;
			pCur = (BYTE *)pAddress;

			KeRaiseIrql(HIGH_LEVEL, &oldIrql);
			*pCur = 0xff;		// jmp [rip+addr]
			*(++pCur) = 0x25;
			*((DWORD *) ++pCur) = 0; // addr = 0
			pCur += sizeof(DWORD);
			*((ULONG_PTR *)pCur) = JumpTo;
			KeLowerIrql(oldIrql);
		}
	};
};
