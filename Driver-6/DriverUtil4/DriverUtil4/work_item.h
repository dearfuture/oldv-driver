#pragma once
#include "Base.h"
namespace ddk
{
	class work_item;
	class _ddkPad_WI
	{
	public:
		virtual void _Go() = 0;
		virtual void _Release() = 0;
	};

	static VOID _launch_callback_WI(IN PVOID _Data)
	{
		//DBG_PRINT("_launch_callback\r\n");
		auto p_this = reinterpret_cast<ddk::_ddkPad_WI*>(_Data);
		__try
		{
			//DBG_PRINT("do callback\r\n");
			p_this->_Go();
			//p_this->_Release();
		}
		__except (1)
		{
			DBG_PRINT("callback failed\r\n");
		}
	}
	template<class _Target>
	class _LaunchPad_WI :public _ddkPad_WI
	{	// template class for launching threads
	public:
		template<class _Other> inline
			_LaunchPad_WI(_Other&& _Tgt)
			: _MyTarget(_STD forward<_Other>(_Tgt))
		{	// construct from target
		}
		virtual void _Release() {
			//	DBG_PRINT("free myself\r\n");
			free(wk);
			delete this;
		};
		virtual void _Go()
		{	// run the thread function object
			//	DBG_PRINT("_GO GO\r\n");
			_Run(this);
		}
		void _Launch(work_item *work)
		{
			wk = work->get_work_item();
			ExInitializeWorkItem(wk, ddk::_launch_callback_WI, this);
			NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);
			ExQueueWorkItem(wk, work->get_type());
		}
	private:
		template<std::size_t... _Idxs>
		static void _Execute(typename _Target::element_type& _Tup,
			std::integer_sequence<std::size_t, _Idxs...>)
		{	// invoke function object packed in tuple
			//	DBG_PRINT("_Execute\r\n");
			_STD invoke(_STD move(_STD get<_Idxs>(_Tup))...);
		}

		static void _Run(_LaunchPad_WI *_Ln) _NOEXCEPT	// enforces termination
		{	// construct local unique_ptr and call function object within
			//	DBG_PRINT("_Run\r\n");
			_Target _Local(_STD forward<_Target>(_Ln->_MyTarget));
			_Ln->_Release();
			_Execute(*_Local,
				std::make_integer_sequence<size_t,
				std::tuple_size<typename _Target::element_type>::value>());
		}
		_Target _MyTarget;
		PWORK_QUEUE_ITEM wk;
	};
	template<class _Target> inline
		void _Launch_work_item(work_item *_Thr, _Target&& _Tg)
	{	// launch a new thread
		auto _Launcher = new ddk::_LaunchPad_WI<_Target>(std::forward<_Target>(_Tg));
		_Launcher->_Launch(_Thr);
	}
	class work_item
	{
	public:
		work_item()
		{

		}
		~work_item()
		{
			//这里不析构！
		}
		template<class _Fn,
		class... _Args,
		class = typename std::enable_if<
			!std::is_same<typename std::decay<_Fn>::type, CThread>::value>::type>
			explicit work_item(WORK_QUEUE_TYPE w_type,_Fn&& _Fx, _Args&&... _Ax)
		{	// construct with _Fx(_Ax...)
			m_type = w_type;
			m_work_item = (PWORK_QUEUE_ITEM)malloc(sizeof(WORK_QUEUE_ITEM));
			ddk::_Launch_work_item(this,
				std::make_unique<std::tuple<std::decay_t<_Fn>, std::decay_t<_Args>...> >(
					std::forward<_Fn>(_Fx), std::forward<_Args>(_Ax)...));
		}
		PWORK_QUEUE_ITEM get_work_item()
		{
			return m_work_item;
		}
		WORK_QUEUE_TYPE get_type()
		{
			return m_type;
		}
	private:
		PWORK_QUEUE_ITEM m_work_item;
		WORK_QUEUE_TYPE m_type;
	};
};