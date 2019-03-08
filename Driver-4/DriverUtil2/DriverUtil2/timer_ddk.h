#pragma once
#include "Base.h"

namespace ddk
{
	static VOID _launch_callback_timer(
		PKDPC Dpc,
		PVOID DeferredContext,
		PVOID SystemArgument1,
		PVOID SystemArgument2);
	class nt_timer
	{
	public:
		nt_timer()
		{
			ltime = 0;
			ltimes = 0;
			p_dd = false;
		}
		template<class _Fn,
		class... _Args,
		class = typename std::enable_if<
			!std::is_same<typename std::decay<_Fn>::type, CThread>::value>::type>
		explicit nt_timer(LONGLONG timer_time,LONG timer_times, _Fn&& _Fx, _Args&&... _Ax)
		{
			ltime = -timer_time;
			ltimes = timer_times;
			p_dd = true;
			if (timer_times)
				KeInitializeTimerEx(&ltimer, SynchronizationTimer);
			else
				KeInitializeTimer(&ltimer);
			m_function = std::bind(std::forward<_Fn>(_Fx), std::forward<_Args>(_Ax)...);
			
			KeInitializeDpc(&_dpc, ddk::_launch_callback_timer, this);
			_timer.QuadPart = this->ltime;
			if (this->ltimes != 0)
			{
				_timer.QuadPart = 0;
				KeSetTimerEx(&this->ltimer, _timer, this->ltimes, &_dpc);
			}
			else
			{
				KeSetTimer(&this->ltimer, _timer, &_dpc);
			}
		}
		nt_timer & operator = ( nt_timer &timer_)
		{
			this->p_dd = timer_.p_dd;
			this->ltime = timer_.ltime;
			this->ltimes = timer_.ltimes;
			this->m_function = timer_.m_function;
			this->ltimer = timer_.ltimer;
			timer_.set_rel();
			return (*this);
		}
		~nt_timer()
		{
			if(!p_dd)
				return;
			DBG_PRINT("Begin Timer Release\r\n");
			KeSetTimer(&this->ltimer, _timer, NULL);
			KeCancelTimer(&ltimer);
			if (this->ltimes!=0)
			{
				KeFlushQueuedDpcs();
			}
			DBG_PRINT("Release Timer\r\n");
		}
		void set_rel()
		{
			p_dd = false;
		}
		void timer_function()
		{
			m_function();
			if (this->ltimes!=0)
			{
				return;
			}
			_timer.QuadPart = this->ltime;
			KeSetTimer(&this->ltimer, _timer, &_dpc);
		}
		LARGE_INTEGER _timer;
		KDPC _dpc;
		LONGLONG ltime;
		LONG ltimes;
		KTIMER ltimer;
		std::function<void()>m_function;
		bool p_dd;
	};
	static VOID _launch_callback_timer(
		PKDPC Dpc,
		PVOID DeferredContext,
		PVOID SystemArgument1,
		PVOID SystemArgument2)
	{
		//DBG_PRINT("_launch_callback\r\n");
		auto p_this = reinterpret_cast<ddk::nt_timer*>(DeferredContext);
		__try
		{
			DBG_PRINT("do timer\r\n");
			p_this->timer_function();
			//p_this->_Release();
		}
		__except (1)
		{
			DBG_PRINT("callback failed\r\n");
		}
	}
};