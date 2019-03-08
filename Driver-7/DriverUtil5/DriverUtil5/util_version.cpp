#include "Base.h"
#include "util_version.h"
namespace ddk
{
	namespace util
	{
		static RTL_OSVERSIONINFOEXW g_WindowsVersion = {};
		static bool ver = false;
		bool init_version()
		{
			if (ver)
			{
				return true;
			}
			g_WindowsVersion.dwOSVersionInfoSize = sizeof(g_WindowsVersion);
			auto status = RtlGetVersion(
				reinterpret_cast<RTL_OSVERSIONINFOW*>(&g_WindowsVersion));
			if (!NT_SUCCESS(status))
			{
				return false;
			}
			ver = true;
			return true;
		}
		bool IsWindows8OrGreater()
		{
			init_version();
			return (g_WindowsVersion.dwMajorVersion > 6
				|| (g_WindowsVersion.dwMajorVersion == 6 && g_WindowsVersion.dwMinorVersion >= 2));
		}
		bool IsWindow8Point1OrGreater()
		{
			init_version();
			return (g_WindowsVersion.dwMajorVersion > 6
				|| (g_WindowsVersion.dwMajorVersion == 6 && g_WindowsVersion.dwMinorVersion >= 3));
		}
		bool IsWindows10()
		{
			init_version();
			return (g_WindowsVersion.dwMajorVersion == 10);
		}
		bool IsWindowsVistaOrGreater()
		{
			init_version();
			return (g_WindowsVersion.dwMajorVersion >= 6);
		}
		bool IsWindowsXp()
		{
			init_version();
#ifndef _AMD64_
			return (g_WindowsVersion.dwMajorVersion == 5 && g_WindowsVersion.dwMinorVersion == 1);
#else
			return (g_WindowsVersion.dwMajorVersion == 5 && g_WindowsVersion.dwMinorVersion == 2);
#endif
		}
		bool IsWin2003()
		{
			init_version();
			return (g_WindowsVersion.dwMajorVersion == 5 && g_WindowsVersion.dwMinorVersion == 2);
		}
		OS_VERSION get_version()
		{
			init_version();
			if (IsWindowsXp())
			{
				return WINXP;
			}
			if (IsWin2003())
			{
				return WIN2003;
			}
			if (g_WindowsVersion.dwMajorVersion == 6 && g_WindowsVersion.dwMinorVersion == 1)
			{
				if (g_WindowsVersion.wServicePackMajor == 0)
				{
					return WIN7;
				}
				else
					return WIN7SP1;
			}
			if(g_WindowsVersion.dwMajorVersion == 6 && g_WindowsVersion.dwMinorVersion == 2)
				return WIN8;
			if (g_WindowsVersion.dwMajorVersion == 6 && g_WindowsVersion.dwMinorVersion == 3)
			{
				return WIN81;
			}
			if (IsWindows10())
			{
				if (g_WindowsVersion.dwBuildNumber == 10586)
					return WIN10_10586;
				if (g_WindowsVersion.dwBuildNumber == 14393)
					return WIN10_now;
				return WIN10_other;
			}
			return OS_not_support;
		}
	};
};