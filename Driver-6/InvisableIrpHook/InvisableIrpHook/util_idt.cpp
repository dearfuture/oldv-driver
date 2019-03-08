#include "Base.h"
#include "util_idt.h"
#include "ntos_util.h"
namespace ddk
{
	namespace util
	{
		void hook_idt(USHORT Index,
			PVOID NewIdtTrapRoutine,
			PVOID *OldIdtTrapRoutine)
		{
			auto OldIrql = KeGetCurrentIrql();
			auto NewTrap = (ULONG_PTR)NewIdtTrapRoutine;
			const auto numberOfProcessors = ddk::ntos_util::KeQueryActiveProcessorCountCompatible(nullptr);
			for (ULONG processorNumber = 0; processorNumber < numberOfProcessors;
			processorNumber++)
			{
				KeSetSystemAffinityThread(static_cast<KAFFINITY>(1ull << processorNumber));
				{
					KeRaiseIrql(HIGH_LEVEL, &OldIrql);
					auto idt_entries = (IDT_ENTRY*)_IdtBase();

					//////////////////////////////////////////////////////////////////////////
					auto OldTrap = (ULONG_PTR)((((ULONGLONG)idt_entries[Index].HighOffset) << 32) |
						(ULONGLONG)(((idt_entries[Index].MidOffset << 16) | idt_entries[Index].lowOffset) & 0x00000000ffffffff));

					auto LowPart = (ULONG)((ULONGLONG)NewTrap);
					idt_entries[Index].lowOffset = (USHORT)LowPart;
					idt_entries[Index].MidOffset = (USHORT)(LowPart >> 16);
					idt_entries[Index].HighOffset = (ULONG)((ULONGLONG)NewTrap >> 32);
					KeLowerIrql(OldIrql);
					if (OldIdtTrapRoutine)
					{
						*OldIdtTrapRoutine = (PVOID)OldTrap;
					}
					//////////////////////////////////////////////////////////////////////////
				}
				KeRevertToUserAffinityThread();
			}

			return;
		}
		bool copy_idt(UINT nIdtNum, UINT nNewIdtNum)
		{
			auto OldIrql = KeGetCurrentIrql();
			const auto numberOfProcessors = ddk::ntos_util::KeQueryActiveProcessorCountCompatible(nullptr);
			for (ULONG processorNumber = 0; processorNumber < numberOfProcessors;
			processorNumber++)
			{
				// Switch the current processor
				KeSetSystemAffinityThread(static_cast<KAFFINITY>(1ull << processorNumber));
				{
					auto idt_entries = (IDT_ENTRY*)::_IdtBase();
					//////////////////////////////////////////////////////////////////////////
					KeRaiseIrql(HIGH_LEVEL, &OldIrql);
					memcpy(&(idt_entries[nNewIdtNum]), &(idt_entries[nIdtNum]), sizeof(IDT_ENTRY));
					KeLowerIrql(OldIrql);
					//////////////////////////////////////////////////////////////////////////
				}
				KeRevertToUserAffinityThread();
			}
			return true;
		}
	};
};