#pragma once
#include "Base.h"
EXTERN_C ULONG64 _IdtBase();
namespace ddk
{
	namespace util
	{
#pragma pack(1)
		typedef struct
		{
			USHORT Limit;
			ULONG64 Base;
		} IDT_INFO, *PIDT_INFO;

		typedef struct
		{
			USHORT lowOffset;
			USHORT segSelector;
			USHORT flags;
			USHORT MidOffset;
			ULONG  HighOffset;
			ULONG  Zero;
		} IDT_ENTRY, *PIDT_ENTRY;
#pragma pack()
		void hook_idt(USHORT Index,
			PVOID NewIdtTrapRoutine,
			PVOID *OldIdtTrapRoutine);
		bool copy_idt(UINT nIdtNum, UINT nNewIdtNum);
	};
};