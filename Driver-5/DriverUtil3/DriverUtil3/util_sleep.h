#pragma once
#include "Base.h"
namespace ddk
{
	namespace util
	{
		static void sleep(LONGLONG ltime)
		{
			LARGE_INTEGER sleep_time;
			sleep_time.QuadPart = -ltime;
			KeDelayExecutionThread(KernelMode,
				FALSE,
				&sleep_time);
		}
	};
};