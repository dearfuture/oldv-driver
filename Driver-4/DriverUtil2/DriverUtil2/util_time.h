#pragma once
#include "Base.h"
namespace ddk
{
	namespace util
	{
		class time
		{
		public:
			static LONGLONG nano_seconds(LONG nanos) {
				return (((signed __int64)(nanos)) / 100L);
			}
			static LONGLONG micro_seconds(LONG micros) {
				return  (((signed __int64)(micros)) * nano_seconds(1000L));
			}
			static LONGLONG milli_seconds(LONG millis) {
				return (((signed __int64)(millis)) * micro_seconds(1000L));
			}
			static LONGLONG seconds(LONG sec) {
				return (((signed __int64)(sec)) * milli_seconds(1000L));
			}
			static LONGLONG minutes(LONG minu) {
				return (((signed __int64)(minu)) * seconds(60L));
			}
			static LONGLONG get_tick_count() {
				LARGE_INTEGER tick_count = {};
				auto time_inc = KeQueryTimeIncrement();
				KeQueryTickCount(&tick_count);
				tick_count.QuadPart *= time_inc;
				tick_count.QuadPart /= milli_seconds(1);
				return tick_count.QuadPart;
			}
			static LONGLONG get_timestamp()
			{
				LARGE_INTEGER CurTime, Freq;
				CurTime = KeQueryPerformanceCounter(&Freq);
				return ((CurTime.QuadPart * 1000 * 1000) / Freq.QuadPart); 
			}
			static LONGLONG get_now_time()
			{
				LARGE_INTEGER system_time;
				KeQuerySystemTime(&system_time);
				LARGE_INTEGER local_time;
				ExSystemTimeToLocalTime(&system_time, &local_time);
				return local_time.QuadPart;
			}
			static void get_now_time(PTIME_FIELDS now_time)
			{
				auto now = get_now_time();
				LARGE_INTEGER i_now;
				i_now.QuadPart = now;
				RtlTimeToTimeFields(&i_now, now_time);
			}
			static void get_now_time(std::wstring &wtime)
			{
				WCHAR w_time[100] = { 0 };
				TIME_FIELDS now = {};
				get_now_time(&now);
				RtlStringCchPrintfW(w_time, 100,
					L"%4d-%2d-%2d %2d-%2d-%2d",
					now.Year, now.Month, now.Day,
					now.Hour, now.Minute, now.Second);
				wtime = std::wstring(w_time);
			}
		};
	};
};