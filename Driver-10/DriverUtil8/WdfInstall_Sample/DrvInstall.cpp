#include "stdafx.h"
#include "DrvInstall.h"
namespace WDMSetup
{
#include "WDMSetup.h"
};

CDrvInstall::CDrvInstall()
{
}


CDrvInstall::~CDrvInstall()
{
}


bool CDrvInstall::Inf_install(LPCSTR lpszInfFile)
{
	//WDF和WDM驱动安装时其实都一样调用,区别：需要coinstallerxXX.dll和不需要dll
	auto ok = WDMSetup::StartInstallWDMDriver(lpszInfFile);
	if (ok==1)
	{
		return true;
	}
	return false;
}


bool CDrvInstall::install_miniflt(TCHAR * ServiceName, 
	TCHAR * DriverFile, 
	TCHAR * instantName, 
	TCHAR * instanceNumber)
{
	//写注册表，然后SVC启动即可
	std::basic_string<TCHAR> registry =
		TEXT("SYSTEM\\CurrentControlSet\\Services\\");
	registry += ServiceName;
	registry += TEXT("\\Instances");

	// Create registry key for the service
	HKEY key = nullptr;
	auto result = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, registry.c_str(), 0,
		nullptr, 0, KEY_ALL_ACCESS, nullptr, &key, nullptr);
	if (result != ERROR_SUCCESS)
	{
		return false;
	}
	auto keyDeleter = std::experimental::make_scope_exit(
		[key]() { ::RegCloseKey(key); });

	// Set 'DefaultInstance'. It may be used when the service is a file system
	// mini-filter driver. Otherwise, it will simply be ignored.
	result = ::RegSetValueEx(key, TEXT("DefaultInstance"), 0, REG_SZ,
		reinterpret_cast<const BYTE*>(instantName), (_tcslen(instantName)+1)*sizeof(TCHAR));
	if (result != ERROR_SUCCESS)
	{
		return false;
	}

	registry += TEXT("\\");
	registry += instantName;

	// Create a sub key
	HKEY keySub = nullptr;
	result = ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, registry.c_str(), 0,
		nullptr, 0, KEY_ALL_ACCESS, nullptr, &keySub, nullptr);
	if (result != ERROR_SUCCESS)
	{
		return false;
	}
	auto keySubDeleter = std::experimental::make_scope_exit(
		[keySub]() { ::RegCloseKey(keySub); });

	// Set 'Altitude'. It may be used when the service is a file system
	// mini-filter driver. Otherwise, it will simply be ignored.
	result = ::RegSetValueEx(keySub, TEXT("Altitude"), 0,
		REG_SZ, reinterpret_cast<const BYTE*>(instanceNumber), sizeof(TCHAR)*(_tcslen(instanceNumber)+1));
	if (result != ERROR_SUCCESS)
	{
		return false;
	}

	// Set 'Flags'. It may be used when the service is a file system
	// mini-filter driver. Otherwise, it will simply be ignored
	DWORD regValue = 0;
	result = ::RegSetValueEx(keySub, TEXT("Flags"), 0,
		REG_DWORD, reinterpret_cast<const BYTE*>(&regValue), sizeof(regValue));
	if (result != ERROR_SUCCESS)
	{
		return false;
	}

	auto scmHandle = std::experimental::make_unique_resource(
		::OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE),
		&::CloseServiceHandle);
	if (!scmHandle)
	{
		return false;
	}

	// Create a service as a file system mini-filter driver regardless of its
	// actual type since it is just more capable.
	auto serviceHandle = std::experimental::make_unique_resource(
		::CreateService(
			scmHandle, ServiceName, ServiceName,
			SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER,
			SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DriverFile,
			TEXT("FSFilter Activity Monitor"), nullptr, TEXT("FltMgr"), nullptr,
			nullptr),
		&::CloseServiceHandle);
	if (!serviceHandle)
	{
		return false;
	}

	// Start the service and wait until its status becomes anything but
	// SERVICE_START_PENDING.
	SERVICE_STATUS status = {};
	if (::StartService(serviceHandle, 0, nullptr))
	{
		while (::QueryServiceStatus(serviceHandle, &status))
		{
			if (status.dwCurrentState != SERVICE_START_PENDING)
			{
				break;
			}
			::Sleep(500);
		}
	}
	::DeleteService(serviceHandle);
	// Error if the status is not SERVICE_RUNNING.
	if (status.dwCurrentState != SERVICE_RUNNING)
	{
		return false;
	}
	return true;
}


bool CDrvInstall::install_svc(LPSTR lpszSvcName, LPSTR lpszDrvFile)
{
	//最基础的：SVC服务安装
	auto scmHandle = std::experimental::make_unique_resource(
		::OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE),
		&::CloseServiceHandle);
	if (!scmHandle)
	{
		return false;
	}
	// Create a service as a file system mini-filter driver regardless of its
	// actual type since it is just more capable.
	auto serviceHandle = std::experimental::make_unique_resource(
		::CreateServiceA(
			scmHandle, lpszSvcName, lpszSvcName,
			SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, lpszDrvFile,
			nullptr, nullptr, nullptr, nullptr,
			nullptr),
		&::CloseServiceHandle);
	if (!serviceHandle)
	{
		return false;
	}

	// Start the service and wait until its status becomes anything but
	// SERVICE_START_PENDING.
	SERVICE_STATUS status = {};
	if (::StartServiceA(serviceHandle, 0, nullptr))
	{
		while (::QueryServiceStatus(serviceHandle, &status))
		{
			if (status.dwCurrentState != SERVICE_START_PENDING)
			{
				break;
			}
			::Sleep(500);
		}
	}
	::DeleteService(serviceHandle);


	// Error if the status is not SERVICE_RUNNING.
	if (status.dwCurrentState != SERVICE_RUNNING)
	{
		return false;
	}
	return true;
}
//classGuid 设备GUIDCLASS比如磁盘常用的GUID_DEVINTERFACE_DISK GUID_DEVINTERFACE_CDROM
//键盘的GUID_DEVINTERFACE_KEYBOARD 等等
//DeviceName 非空，则对classGuid指定设备
//FilterName始终非空
//lpszDrvFile 非空，是安装；空是删除！！！！注意只删除了filter没有删除服务！！！
//upper ture安装upper filter,false安装lower filter
bool CDrvInstall::install_filter(const GUID * classGuid,LPTSTR DeviceName,LPTSTR filterName,LPTSTR lpszDrvFile,bool upper)
{
	//用安装好SVC服务后，用setupapi设置filter(upper,lower)然后RestartDevice
	//部分filter可以注册表写入后自己重启计算机，比如diskflt和sfilter
	if (filterName && lpszDrvFile)
	{

		auto scmHandle = std::experimental::make_unique_resource(
			::OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE),
			&::CloseServiceHandle);
		if (!scmHandle)
		{
			return false;
		}
		// Create a service as a file system mini-filter driver regardless of its
		// actual type since it is just more capable.
		auto serviceHandle = std::experimental::make_unique_resource(
			::CreateService(
				scmHandle, filterName, filterName,
				SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
				SERVICE_BOOT_START, SERVICE_ERROR_NORMAL, lpszDrvFile,
				nullptr, nullptr, nullptr, nullptr,
				nullptr),
			&::CloseServiceHandle);
		if (!serviceHandle)
		{
			return false;
		}
	}
	bool ok = false;
	//这里安装filter
	auto devinfo = std::experimental::make_unique_resource(
		::SetupDiGetClassDevs(classGuid,
			NULL,
			NULL,
			DIGCF_PROFILE |
			DIGCF_DEVICEINTERFACE |
			DIGCF_PRESENT),
		&::SetupDiDestroyDeviceInfoList);
	if (!devinfo)
	{
		return false;
	}
	SP_DEVINFO_DATA          devInfoData;
	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	auto keepGoing = FALSE;
	auto needReboot = FALSE;
	// step through the list of devices for this handle
	// get device info at index deviceIndex, the function returns FALSE
	// when there is no device at the given index.
	for (auto deviceIndex = 0;
	SetupDiEnumDeviceInfo(devinfo, deviceIndex, &devInfoData);
		deviceIndex++) {

		// setting this variable to FALSE will cause all of the if
		// statements to fall through, cutting off processing for this
		// device.
		keepGoing = TRUE;
		auto deviceMatch = FALSE;
		// if a device name was specified, and it doesn't match this one,
		// stop. If there is a match (or no name was specified), mark that
		// there was a match.
		if (DeviceName&&
			!DeviceNameMatches(devinfo, &devInfoData, DeviceName)
			) {
			keepGoing = FALSE;
		}
		else {
			deviceMatch = TRUE;
		}

		PrintDeviceName(devinfo, &devInfoData);
		PrintFilters(devinfo, &devInfoData, upper);
		
		// add the filter, then try to restart the device
		if (keepGoing && filterName != NULL) {

			if (!AddFilterDriver(devinfo,
				&devInfoData,
				filterName,
				upper)) {

				printf("Unable to add filter!\n");
			}
			else {
				ok = true;
				if (!RestartDevice(devinfo, &devInfoData)) {
					needReboot = TRUE;

				}
			}
		}

		//// remove the filter, then try to restart the device
		if (keepGoing && lpszDrvFile==nullptr) {

			if (!RemoveFilterDriver(devinfo,
				&devInfoData,
				filterName,
				upper)) {

				printf("Unable to remove filter!\n");
			}
			else {
				ok = true;
				if (!RestartDevice(devinfo, &devInfoData)) {
					needReboot = TRUE;
				}

			}

		}

		// end of main processing loop
	}
	return ok;
}


bool CDrvInstall::wdf_install(LPSTR lpszInfFile, LPSTR ServiceName, LPSTR wdf_section_name)
{
	//WDF驱动安装
	auto version = GetCoinstallerVersion();
	auto library = LoadWdfCoInstaller();

	if (library == NULL) {
		printf("The WdfCoInstaller%s.dll library needs to be "
			"in same directory as nonpnpapp.exe\n", version);
		return false;
	}

	//
	// The driver is not started yet so let us the install the driver.
	// First setup full path to driver name.
	//
	CHAR     driverLocation[MAX_PATH];
	auto ok = SetupDriverName(driverLocation,ServiceName,MAX_PATH);

	if (!ok) {
		return false;
	}

	auto schSCManager = OpenSCManager(NULL,                   // local machine
		NULL,                   // local database
		SC_MANAGER_ALL_ACCESS   // access required
		);

	if (!schSCManager) {

		printf("Open SC Manager failed! Error = %d \n", GetLastError());

		return false;
	}
	bool ret = false;
	USES_CONVERSION;
	auto ok1 = InstallDriver(schSCManager,
		A2T(ServiceName),
		A2T(driverLocation),
		lpszInfFile,
		A2T(wdf_section_name));
	if (ok1)
	{
		auto ok2 = StartDriver(schSCManager, A2T(ServiceName));
		if (ok2)
		{
			ret = true;
		}
	}
	//
	// Close handle to service control manager.
	//
	CloseServiceHandle(schSCManager);
	return ret;
}
