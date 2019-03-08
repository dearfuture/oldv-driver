#pragma once
#include "Base.h"
namespace ddk
{
	class cpu_lock
	{
	public:
		struct DPC_CONTEXT
		{
			union
			{
				KIRQL OldIrql;
				void *Reserved;
			};
			KDPC Dpcs[1];  // This field is used as a variadic array
		};
		cpu_lock()
		{
			dpc_ctx = nullptr;
			g_ExclpReleaseAllProcessors = 0;
			g_ExclpNumberOfLockedProcessors = 0;
			g_CpuNumber = 0;
			g_CurrentCpu = 0;
			const auto numberOfProcessors = KeQueryActiveProcessorCount(nullptr);
			auto context = reinterpret_cast<DPC_CONTEXT *>(malloc(sizeof(void *) + (numberOfProcessors * sizeof(KDPC))));
			if (!context)
			{
				return;
			}
			dpc_ctx = context;
			const auto currentCpu = KeGetCurrentProcessorNumber();
			g_CpuNumber = numberOfProcessors;
			g_CurrentCpu = currentCpu;
		}
		~cpu_lock()
		{
			if (!dpc_ctx)
				return;
			while(!InterlockedCompareExchange(&g_ExclpReleaseAllProcessors, 1, 1))
			{
				KeStallExecutionProcessor(10);
			}
			free(dpc_ctx);
		}
		void lock()
		{
			NT_ASSERT(InterlockedAdd(&g_ExclpNumberOfLockedProcessors, 0) == 0);
			InterlockedAnd(&g_ExclpReleaseAllProcessors, 0);

			for (auto i = 0ul; i < g_CpuNumber; i++)
			{
				// Queue a lock DPC.
				if (i==g_CurrentCpu)
				{
					continue;
				}
				KeInitializeDpc(&dpc_ctx->Dpcs[i], ddk::cpu_lock::_cpu_lock, this);
				KeSetTargetProcessorDpc(&dpc_ctx->Dpcs[i], static_cast<CCHAR>(i));
				KeInsertQueueDpc(&dpc_ctx->Dpcs[i], nullptr, nullptr);
			}
			const auto needToBeLocked = g_CpuNumber-1;
			while (_InterlockedCompareExchange(&g_ExclpNumberOfLockedProcessors,
				needToBeLocked, needToBeLocked) !=
				static_cast<LONG>(needToBeLocked))
			{
				KeStallExecutionProcessor(10);
			}
		}
		void unlock()
		{
			InterlockedIncrement(&g_ExclpReleaseAllProcessors);

			// Wait until all other processors were unlocked.
			while (InterlockedCompareExchange(&g_ExclpNumberOfLockedProcessors, 0, 0))
			{
				KeStallExecutionProcessor(10);
			}
		}
		static VOID _cpu_lock(
			PKDPC Dpc,
			PVOID DeferredContext,
			PVOID SystemArgument1,
			PVOID SystemArgument2)
		{
			auto p_this = reinterpret_cast<ddk::cpu_lock*>(DeferredContext);
			__try
			{
				//DBG_PRINT("do callback\r\n");
				p_this->_lock();
			}
			__except (1)
			{
				DBG_PRINT("callback failed\r\n");
			}
		}
		void _lock()
		{
			InterlockedIncrement(&g_ExclpNumberOfLockedProcessors);

			KIRQL OldIrql;
			KeRaiseIrql(HIGH_LEVEL, &OldIrql);
			// Wait until g_ReleaseAllProcessors becomes 1.
			while (!InterlockedCompareExchange(&g_ExclpReleaseAllProcessors, 1, 1))
			{
				//_mm_pause();
				KeStallExecutionProcessor(10);
			}
			KeLowerIrql(OldIrql);
			// Decrease the number of locked processors.
			InterlockedDecrement(&g_ExclpNumberOfLockedProcessors);
		}
	private:
		DPC_CONTEXT *dpc_ctx;
		LONG g_ExclpReleaseAllProcessors;
		LONG g_ExclpNumberOfLockedProcessors;
		ULONG g_CpuNumber;
		ULONG g_CurrentCpu;
	};
};