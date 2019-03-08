// TestApp.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <tchar.h>
#include <windows.h>
#include "../Device/ioctrl.h"
#include "../Device/scope_exit.h"
#include "../Device/unique_resource.h"
int main()
{
	/*\\??\\DeviceTest*/
	const auto handle = std::experimental::make_unique_resource(
		CreateFile(TEXT("\\\\.\\DeviceTest"), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr),
		&CloseHandle);
	auto returned = DWORD(0);
	auto bRet = DeviceIoControl(handle.get(), DRV_IOCTL_HELLO2, NULL,0,NULL,0,
		&returned, nullptr);
	
    return 0;
}

