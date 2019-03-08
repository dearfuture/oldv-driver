#include "Base.h"
#include "CLog.h"

void write_log(char *format, ...)
{

	va_list args;
	va_start(args, format);
	ddk::nt_log::getInstance().log(format, args);
	va_end(args);
}
