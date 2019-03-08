#include "Base.h"
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
			return (g_WindowsVersion.dwMajorVersion == 5 && g_WindowsVersion.dwMinorVersion == 2);
		}
	};
};