#pragma once
#include "Base.h"
namespace ddk
{
	class dpc;
	class _ddkPad_dpc
	{
	public:
		virtual void _Go() = 0;
		virtual void _Release() = 0;
	};

	static VOID _launch_callback_dpc(
		PKDPC Dpc,
		PVOID DeferredContext,
		PVOID SystemArgument1,
		PVOID SystemArgument2)
	{
		//DBG_PRINT("_launch_callback\r\n");
		//KeLowerIrql(PASSIVE_LEVEL);
		auto p_this = reinterpret_cast<ddk::_ddkPad_dpc*>(DeferredContext);
		__try
		{
			//DBG_PRINT("do callback\r\n");
			p_this->_Go();
			p_this->_Release();
		}
		__except (1)
		{
			DBG_PRINT("callback failed\r\n");
		}
	}
	template<class _Target>
	class _LaunchPad_dpc :public _ddkPad_dpc
	{	// template class for launching threads
	public:
		template<class _Other> inline
			_LaunchPad_dpc(_Other&& _Tgt)
			: _MyTarget(_STD forward<_Other>(_Tgt))
		{	// construct from target
			
		}
		virtual void _Release() {
			//	DBG_PRINT("free myself\r\n");
			delete this;
		};
		virtual void _Go()
		{	// run the thread function object
			//	DBG_PRINT("_GO GO\r\n");
			_dpc->increment_cpu();
			_Run(this);
			_dpc->increment_working();
		}
		void _Launch(dpc *work)
		{
			_dpc = work;
			//
			auto context = work->dpc_ctx;
			auto i = work->g_run_cpu;
			KeInitializeDpc(&context->Dpcs[i], ddk::_launch_callback_dpc, this);
			KeSetTargetProcessorDpc(&context->Dpcs[i], static_cast<CCHAR>(i));
			KeInsertQueueDpc(&context->Dpcs[i], nullptr, nullptr);
		}
	private:
		template<std::size_t... _Idxs>
		static void _Execute(typename _Target::element_type& _Tup,
			std::integer_sequence<std::size_t, _Idxs...>)
		{	// invoke function object packed in tuple
			//	DBG_PRINT("_Execute\r\n");
			_STD invoke(_STD move(_STD get<_Idxs>(_Tup))...);
		}

		static void _Run(_LaunchPad_dpc *_Ln) _NOEXCEPT	// enforces termination
		{	// construct local unique_ptr and call function object within
			//	DBG_PRINT("_Run\r\n");
			
			_Target _Local(std::forward<_Target>(_Ln->_MyTarget));
			
			_Execute(*_Local,
				std::make_integer_sequence<size_t,
				std::tuple_size<typename _Target::element_type>::value>());
			//_Ln->_MyTarget = std::forward<_Target>(_Local);

		}
		_Target _MyTarget;
		dpc *_dpc;
	};
	template<class _Target> inline
		void _Launch_dpc(dpc *_Thr, _Target&& _Tg)
	{	// launch a new thread
		auto _Launcher = new ddk::_LaunchPad_dpc<_Target>(std::forward<_Target>(_Tg));
		_Launcher->_Launch(_Thr);
		//_Launcher._Release();
	}
	class dpc
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
		dpc()
		{
			b_run_ok = false;
			dpc_ctx = nullptr;
			g_ExclpReleaseAllProcessors = 0;
			g_ExclpNumberOfLockedProcessors = 0;
			g_CpuNumber = 0;
		}
		template<class _Fn,
		class... _Args,
		class = typename std::enable_if<
			!std::is_same<typename std::decay<_Fn>::type, CThread>::value>::type>
			explicit dpc(_Fn&& _Fx, _Args&&... _Ax)
		{	// construct with _Fx(_Ax...)
			b_run_ok = false;
			dpc_ctx = nullptr;
			g_ExclpReleaseAllProcessors = 0;
			g_ExclpNumberOfLockedProcessors = 0;
			g_CpuNumber = 0;
			const auto numberOfProcessors = KeQueryActiveProcessorCount(nullptr);

			// Allocates DPCs for all processors.
			auto context = reinterpret_cast<DPC_CONTEXT *>(malloc(sizeof(void *) + (numberOfProcessors * sizeof(KDPC))));
			if (!context)
			{
				return ;
			}
			dpc_ctx = context;
			// Execute a lock DPC for all processors but this.
			//context->OldIrql = KeRaiseIrqlToDpcLevel();
			const auto currentCpu = KeGetCurrentProcessorNumber();
			g_current = currentCpu;
			DBG_PRINT("cur cpu = %d\r\n", g_current);
			for (auto i = 0ul; i < numberOfProcessors; i++)
			{
				// Queue a lock DPC.
				g_run_cpu = i;
				ddk::_Launch_dpc(this,
					std::make_unique<std::tuple<std::decay_t<_Fn>, std::decay_t<_Args>...> >(
						std::forward<_Fn>(_Fx), std::forward<_Args>(_Ax)...));
			}
			DBG_PRINT("wait for working\r\n");
			const auto needToBeLocked = numberOfProcessors;
			g_CpuNumber = numberOfProcessors;
			while (_InterlockedCompareExchange(&g_ExclpNumberOfLockedProcessors,
				needToBeLocked, needToBeLocked) !=
				static_cast<LONG>(needToBeLocked))
			{
				KeStallExecutionProcessor(10);
			}
			DBG_PRINT("wait ok\r\n");
		}
		~dpc()
		{
			if (!dpc_ctx)
			{
				return;
			}
			const auto needToBeLocked = g_CpuNumber;
			while (_InterlockedCompareExchange(&g_ExclpReleaseAllProcessors,
				needToBeLocked, needToBeLocked) !=
				static_cast<LONG>(needToBeLocked))
			{
				//DBG_PRINT("hh\r\n");
				KeStallExecutionProcessor(10);
			}
			free(dpc_ctx);
			DBG_PRINT("release ok\r\n");
		}
		void set_ok()
		{
			b_run_ok = true;
		}
		bool get_dpc_run()
		{
			return b_run_ok;
		}
		void increment_cpu()
		{
			InterlockedIncrement(&g_ExclpNumberOfLockedProcessors);
		}
		void increment_working()
		{
			InterlockedIncrement(&g_ExclpReleaseAllProcessors);
		}
		bool b_run_ok;
		DPC_CONTEXT *dpc_ctx;
		LONG g_ExclpReleaseAllProcessors;
		LONG g_ExclpNumberOfLockedProcessors;
		ULONG g_CpuNumber;
		ULONG  g_run_cpu;
		ULONG g_current;
	};
};