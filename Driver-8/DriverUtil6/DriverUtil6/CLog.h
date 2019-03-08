#pragma once
#include "Base.h"
#include "NtFile.h"
#include "lock.h"
namespace ddk
{
	class nt_log:public Singleton<nt_log>
	{
	public:
		nt_log() {
			TIME_FIELDS tf;
			LARGE_INTEGER time;
			wchar_t fname[MAX_PATH];
			KeQuerySystemTime(&time);
			LARGE_INTEGER ltime;
			ExSystemTimeToLocalTime(&time, &ltime);
			RtlTimeToTimeFields(&ltime, &tf);
			RtlStringCchPrintfW(fname, MAX_PATH, L"\\??\\Global\\C:\\%d-%.2d-%.2d-%.2d%.2d.log",
				tf.Year, 
				tf.Month,
				tf.Day,
				tf.Hour,
				tf.Minute);
			file = CNtFile(std::wstring(fname),ddk::CNtFile::OPEN_IF);
		}
		~nt_log() {
			_lock.wait_for_release();
			file.close();
		}
		void log(char *ptr, va_list args)
		{
			_lock.only_acquire();
			char buf[1024];
			NTSTATUS stat;
			size_t wsize = 0;	
			stat = RtlStringCchVPrintfA(buf, sizeof(buf), ptr, args);
			if (!NT_SUCCESS(stat)) {
					buf[1023] = 0;
				}
			
			file.write(buf, strlen(buf), wsize);
			_lock.release();
		}
	private:
		CNtFile file;
		nt_lock _lock;
	};
};