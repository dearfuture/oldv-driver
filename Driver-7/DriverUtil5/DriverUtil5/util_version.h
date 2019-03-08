#pragma once
#include "Base.h"
namespace ddk
{
	enum OS_VERSION
	{
		WINXP = 0,
		WIN2003,
		WIN7,
		WIN7SP1,
		WIN8,
		WIN81,
		WIN10_other,
		WIN10_10586,
		WIN10_now,
		MaxOSIndex,
		OS_not_support,
	};
	namespace util
	{
		bool init_version();
		bool IsWindows8OrGreater();
		bool IsWindow8Point1OrGreater();
		bool IsWindows10();
		bool IsWindowsVistaOrGreater();
		bool IsWindowsXp();
		OS_VERSION get_version();
	};
};