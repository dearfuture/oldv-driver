#pragma once
#include "Base.h"
namespace ddk
{
	namespace util
	{
		bool init_version();
		bool IsWindows8OrGreater();
		bool IsWindow8Point1OrGreater();
		bool IsWindows10();
		bool IsWindowsVistaOrGreater();
		bool IsWindowsXp();
	};
};