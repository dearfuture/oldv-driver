#pragma once
#define KMDF_VERSION_MAJOR 1
#define KMDF_VERSION_MINOR 11
#include "base.h"
#define _CONVERSION_DONT_USE_THREAD_LOCALE
#include <atlconv.h>
#include <newdev.h>
#include <SetupAPI.h>
#include <wdfinstaller.h>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")
#define MAX_VERSION_SIZE 6
#define DRIVER_FUNC_INSTALL     0x01
#define DRIVER_FUNC_REMOVE      0x02
#define ARRAY_SIZE(x)        (sizeof(x) /sizeof(x[0]))
class CDrvInstall
{
public:
	CDrvInstall();
	~CDrvInstall();
	bool Inf_install(LPCSTR lpszInfFile);
	bool install_miniflt(TCHAR * ServiceName, TCHAR * DriverFile, TCHAR * instantName, TCHAR * instanceNumber);
	bool install_svc(LPSTR lpszSvcName, LPSTR lpszDrvFile);
	bool install_filter(const GUID * classGuid, LPTSTR DeviceName, LPTSTR filterName, LPTSTR lpszDrvFile, bool upper);
	bool wdf_install(LPSTR lpszInfFile, LPSTR ServiceName, LPSTR wdf_section_name);
private:
	CHAR G_coInstallerVersion[MAX_VERSION_SIZE];
	PFN_WDFPREDEVICEINSTALLEX pfnWdfPreDeviceInstallEx;
	PFN_WDFPOSTDEVICEINSTALL   pfnWdfPostDeviceInstall;
	PFN_WDFPREDEVICEREMOVE     pfnWdfPreDeviceRemove;
	PFN_WDFPOSTDEVICEREMOVE   pfnWdfPostDeviceRemove;
private:
	PCHAR
		GetCoinstallerVersion(
			VOID
			)
	{
		if (FAILED(StringCchPrintfA(G_coInstallerVersion,
			MAX_VERSION_SIZE,
			"%02d%03d",    // for example, "01009"
			KMDF_VERSION_MAJOR,
			KMDF_VERSION_MINOR)))
		{
			printf("StringCchCopy failed with error \n");
		}

		return (PCHAR)&G_coInstallerVersion;
	}
	HMODULE
		LoadWdfCoInstaller(
			VOID
			)
	{
		HMODULE library = NULL;
		DWORD   error = ERROR_SUCCESS;
		CHAR   szCurDir[MAX_PATH];
		CHAR   tempCoinstallerName[MAX_PATH];
		PCHAR  coinstallerVersion;

		do {

			if (GetCurrentDirectoryA(MAX_PATH, szCurDir) == 0) {

				printf("GetCurrentDirectory failed!  Error = %d \n", GetLastError());
				break;
			}
			coinstallerVersion = GetCoinstallerVersion();
			if (FAILED(StringCchPrintfA(tempCoinstallerName,
				MAX_PATH,
				"\\WdfCoInstaller%s.dll",
				coinstallerVersion))) {
				break;
			}
			if (FAILED(StringCchCatA(szCurDir, MAX_PATH, tempCoinstallerName))) {
				break;
			}

			library = LoadLibraryA(szCurDir);

			if (library == NULL) {
				error = GetLastError();
				printf("LoadLibrary(%s) failed: %d\n", szCurDir, error);
				break;
			}

			pfnWdfPreDeviceInstallEx =
				(PFN_WDFPREDEVICEINSTALLEX)GetProcAddress(library, "WdfPreDeviceInstallEx");

			if (pfnWdfPreDeviceInstallEx == NULL) {
				error = GetLastError();
				printf("GetProcAddress(\"WdfPreDeviceInstallEx\") failed: %d\n", error);
				return NULL;
			}

			pfnWdfPostDeviceInstall =
				(PFN_WDFPOSTDEVICEINSTALL)GetProcAddress(library, "WdfPostDeviceInstall");

			if (pfnWdfPostDeviceInstall == NULL) {
				error = GetLastError();
				printf("GetProcAddress(\"WdfPostDeviceInstall\") failed: %d\n", error);
				return NULL;
			}

			pfnWdfPreDeviceRemove =
				(PFN_WDFPREDEVICEREMOVE)GetProcAddress(library, "WdfPreDeviceRemove");

			if (pfnWdfPreDeviceRemove == NULL) {
				error = GetLastError();
				printf("GetProcAddress(\"WdfPreDeviceRemove\") failed: %d\n", error);
				return NULL;
			}

			pfnWdfPostDeviceRemove =
				(PFN_WDFPREDEVICEREMOVE)GetProcAddress(library, "WdfPostDeviceRemove");

			if (pfnWdfPostDeviceRemove == NULL) {
				error = GetLastError();
				printf("GetProcAddress(\"WdfPostDeviceRemove\") failed: %d\n", error);
				return NULL;
			}

		} while(0);

		if (error != ERROR_SUCCESS) {
			if (library) {
				FreeLibrary(library);
			}
			library = NULL;
		}

		return library;
	}


	VOID
		UnloadWdfCoInstaller(
			HMODULE Library
			)
	{
		if (Library) {
			FreeLibrary(Library);
		}
	}
private:
	BOOLEAN
		StartDriver(
			IN SC_HANDLE    SchSCManager,
			IN LPCTSTR      DriverName
			)
	{
		SC_HANDLE   schService;
		DWORD       err;
		BOOL        ok;

		//
		// Open the handle to the existing service.
		//
		schService = OpenService(SchSCManager,
			DriverName,
			SERVICE_ALL_ACCESS
			);

		if (schService == NULL) {
			//
			// Indicate failure.
			//
			printf("OpenService failed!  Error = %d\n", GetLastError());
			return FALSE;
		}

		//
		// Start the execution of the service (i.e. start the driver).
		//
		ok = StartService(schService, 0, NULL);

		if (!ok) {

			err = GetLastError();

			if (err == ERROR_SERVICE_ALREADY_RUNNING) {
				//
				// Ignore this error.
				//
				return TRUE;

			}
			else {
				//
				// Indicate failure.
				// Fall through to properly close the service handle.
				//
				printf("StartService failure! Error = %d\n", err);
				return FALSE;
			}
		}

		//
		// Close the service object.
		//
		CloseServiceHandle(schService);

		return TRUE;

	}   // StartDriver



	BOOLEAN
		StopDriver(
			IN SC_HANDLE    SchSCManager,
			IN LPCTSTR      DriverName
			)
	{
		BOOLEAN         rCode = TRUE;
		SC_HANDLE       schService;
		SERVICE_STATUS  serviceStatus;

		//
		// Open the handle to the existing service.
		//

		schService = OpenService(SchSCManager,
			DriverName,
			SERVICE_ALL_ACCESS
			);

		if (schService == NULL) {

			printf("OpenService failed!  Error = %d \n", GetLastError());

			return FALSE;
		}

		//
		// Request that the service stop.
		//

		if (ControlService(schService,
			SERVICE_CONTROL_STOP,
			&serviceStatus
			)) {

			//
			// Indicate success.
			//

			rCode = TRUE;

		}
		else {

			printf("ControlService failed!  Error = %d \n", GetLastError());

			//
			// Indicate failure.  Fall through to properly close the service handle.
			//

			rCode = FALSE;
		}

		//
		// Close the service object.
		//
		CloseServiceHandle(schService);

		return rCode;

	}   //  StopDriver
private:
	//
	// Caller must free returned pathname string.
	//
	PCHAR
		BuildDriversDirPath(
			_In_ PSTR DriverName
			)
	{
		size_t  remain;
		size_t  len;
		PCHAR   dir;

		if (!DriverName || strlen(DriverName) == 0) {
			return NULL;
		}

		remain = MAX_PATH;
#define SYSTEM32_DRIVERS "\\System32\\Drivers\\"

		//
		// Allocate string space
		//
		dir = (PCHAR)malloc(remain + 1);

		if (!dir) {
			return NULL;
		}

		//
		// Get the base windows directory path.
		//
		len = GetWindowsDirectoryA(dir, (UINT)remain);

		if (len == 0 ||
			(remain - len) < sizeof(SYSTEM32_DRIVERS)) {
			free(dir);
			return NULL;
		}
		remain -= len;

		//
		// Build dir to have "%windir%\System32\Drivers\<DriverName>".
		//
		if (FAILED(StringCchCatA(dir, remain, SYSTEM32_DRIVERS))) {
			free(dir);
			return NULL;
		}

		remain -= sizeof(SYSTEM32_DRIVERS);
		len += sizeof(SYSTEM32_DRIVERS);
		len += strlen(DriverName);

		if (remain < len) {
			free(dir);
			return NULL;
		}

		if (FAILED(StringCchCatA(dir, remain, DriverName))) {
			free(dir);
			return NULL;
		}
		if (FAILED(StringCchCatA(dir, remain, ".sys"))) {
			free(dir);
			return NULL;
		}
		dir[len] = '\0';  // keeps prefast happy

		return dir;
	}

	BOOLEAN
		SetupDriverName(
			_Inout_updates_all_(BufferLength) PCHAR DriverLocation,
			PCHAR DriverName,
			_In_ ULONG BufferLength
			)
	{
		HANDLE fileHandle;
		DWORD  driverLocLen = 0;
		BOOL   ok;
		PCHAR  driversDir;

		//
		// Setup path name to driver file.
		//
		driverLocLen =
			GetCurrentDirectoryA(BufferLength, DriverLocation);

		if (!driverLocLen) {

			printf("GetCurrentDirectory failed!  Error = %d \n",
				GetLastError());

			return FALSE;
		}

		if (FAILED(StringCchCatA(DriverLocation, BufferLength, "\\"))) {
			return FALSE;
		}

		if (FAILED(StringCchCatA(DriverLocation, BufferLength, DriverName))) {
			return FALSE;
		}

		if (FAILED(StringCchCatA(DriverLocation, BufferLength, ".sys"))) {
			return FALSE;
		}

		//
		// Insure driver file is in the specified directory.
		//
		fileHandle = CreateFileA(DriverLocation,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (fileHandle == INVALID_HANDLE_VALUE) {
			//
			// Indicate failure.
			//
			printf("Driver: %s.SYS is not in the %s directory. \n",
				DriverName, DriverLocation);
			return FALSE;
		}

		//
		// Build %windir%\System32\Drivers\<DRIVER_NAME> path.
		// Copy the driver to %windir%\system32\drivers
		//
		driversDir = BuildDriversDirPath(DriverName);

		if (!driversDir) {
			printf("BuildDriversDirPath failed!\n");
			return FALSE;
		}

		ok = CopyFileA(DriverLocation, driversDir, FALSE);

		if (!ok) {
			printf("CopyFile failed: error(%d) - \"%s\"\n",
				GetLastError(), driversDir);
			free(driversDir);
			return FALSE;
		}

		if (FAILED(StringCchCopyA(DriverLocation, BufferLength, driversDir))) {
			free(driversDir);
			return FALSE;
		}

		free(driversDir);

		//
		// Close open file handle.
		//
		if (fileHandle) {
			CloseHandle(fileHandle);
		}

		//
		// Indicate success.
		//
		return TRUE;

	}   // SetupDriverName

	LONG
		GetPathToInf(
			_Out_writes_(InfFilePathSize) PWCHAR InfFilePath,
			PCHAR InfName,
			IN ULONG InfFilePathSize
			)
	{
		LONG    error = ERROR_SUCCESS;
		std::wstring winfName;
		std::string narrow = std::string(InfName);
		std::wstringstream cls;
		cls << narrow.c_str();
		winfName = cls.str();

		if (GetCurrentDirectoryW(InfFilePathSize, InfFilePath) == 0) {
			error = GetLastError();
			printf("InstallDriver failed!  Error = %d \n", error);
			return error;
		}
		if (FAILED(StringCchCatW(InfFilePath,
			InfFilePathSize,
			winfName.c_str()))) {
			error = ERROR_BUFFER_OVERFLOW;
			return error;
		}
		return error;
	}

	BOOLEAN
		InstallDriver(
			IN SC_HANDLE  SchSCManager,
			IN LPCTSTR    DriverName,
			IN LPCTSTR    ServiceExe,
			IN LPSTR    InfName,
			IN LPCTSTR	  SectionName
			)
		/*++

		Routine Description:

		Arguments:

		Return Value:

		--*/
	{
		SC_HANDLE   schService;
		DWORD       err;
		WCHAR      infPath[MAX_PATH];
		WDF_COINSTALLER_INSTALL_OPTIONS clientOptions;

		WDF_COINSTALLER_INSTALL_OPTIONS_INIT(&clientOptions);

		//
		// NOTE: This creates an entry for a standalone driver. If this
		//       is modified for use with a driver that requires a Tag,
		//       Group, and/or Dependencies, it may be necessary to
		//       query the registry for existing driver information
		//       (in order to determine a unique Tag, etc.).
		//
		//
		// PRE-INSTALL for WDF support
		//
		err = GetPathToInf(infPath,InfName,ARRAY_SIZE(infPath));
		if (err != ERROR_SUCCESS) {
			return  FALSE;
		}
		err = pfnWdfPreDeviceInstallEx(infPath, SectionName, &clientOptions);

		if (err != ERROR_SUCCESS) {
			if (err == ERROR_SUCCESS_REBOOT_REQUIRED) {
				printf("System needs to be rebooted, before the driver installation can proceed.\n");
			}

			return  FALSE;
		}

		//
		// Create a new a service object.
		//

		schService = CreateService(SchSCManager,           // handle of service control manager database
			DriverName,             // address of name of service to start
			DriverName,             // address of display name
			SERVICE_ALL_ACCESS,     // type of access to service
			SERVICE_KERNEL_DRIVER,  // type of service
			SERVICE_DEMAND_START,   // when to start service
			SERVICE_ERROR_NORMAL,   // severity if service fails to start
			ServiceExe,             // address of name of binary file
			NULL,                   // service does not belong to a group
			NULL,                   // no tag requested
			NULL,                   // no dependency names
			NULL,                   // use LocalSystem account
			NULL                    // no password for service account
			);

		if (schService == NULL) {

			err = GetLastError();

			if (err == ERROR_SERVICE_EXISTS) {

				//
				// Ignore this error.
				//

				return TRUE;

			}
			else {

				printf("CreateService failed!  Error = %d \n", err);

				//
				// Indicate an error.
				//

				return  FALSE;
			}
		}

		//
		// Close the service object.
		//
		CloseServiceHandle(schService);

		//
		// POST-INSTALL for WDF support
		//
		err = pfnWdfPostDeviceInstall(infPath, SectionName);

		if (err != ERROR_SUCCESS) {
			return  FALSE;
		}

		//
		// Indicate success.
		//

		return TRUE;

	}   // InstallDriver
private:
	/*
	* return true if DeviceName matches the name of the device specified by
	* DeviceInfoData
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*   DeviceName     - the name to try to match
	*/
	BOOLEAN
		DeviceNameMatches(
			IN HDEVINFO DeviceInfoSet,
			IN PSP_DEVINFO_DATA DeviceInfoData,
			_In_ IN LPTSTR DeviceName
			)
	{
		BOOLEAN matching = FALSE;
		DWORD   regDataType;

		// get the device name
		LPTSTR  deviceName =
			(LPTSTR)GetDeviceRegistryProperty(DeviceInfoSet,
				DeviceInfoData,
				SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
				&regDataType);

		if (deviceName != NULL)
		{
			// just to make sure we are getting the expected type of buffer
			if (regDataType != REG_SZ)
			{
				printf("in DeviceNameMatches(): registry key is not an SZ!\n");
				matching = FALSE;
			}
			else
			{
				// if the device name starts with \Device, cut that off (all
				// devices will start with it, so it is redundant)

				if (_tcsncmp(deviceName, _T("\\Device"), 7) == 0)
				{
					memmove(deviceName,
						deviceName + 7,
						(_tcslen(deviceName) - 6)*sizeof(_TCHAR));
				}

				// do the strings match?
				matching = (_tcscmp(deviceName, DeviceName) == 0) ? TRUE : FALSE;
			}
			free(deviceName);
		}
		else
		{
			printf("in DeviceNameMatches(): registry key is NULL!\n");
			matching = FALSE;
		}

		return (matching);
	}
	/*
	* add the given filter driver to the list of upper filter drivers for the
	* device.
	*
	* After the call, the device must be restarted in order for the new setting to
	* take effect. This can be accomplished with a call to RestartDevice(), or by
	* rebooting the machine.
	*
	* returns TRUE if successful, FALSE otherwise
	*
	* note: The filter is prepended to the list of drivers, which will put it at
	* the bottom of the filter driver stack
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*   Filter         - the filter to add
	*/
	BOOLEAN
		AddFilterDriver(
			IN HDEVINFO DeviceInfoSet,
			IN PSP_DEVINFO_DATA DeviceInfoData,
			_In_ IN LPTSTR Filter,
			IN BOOLEAN UpperFilter
			)
	{
		size_t length = 0; // character length
		size_t size = 0; // buffer size
		LPTSTR buffer = GetFilters(DeviceInfoSet, DeviceInfoData, UpperFilter);

		//ASSERT(DeviceInfoData != NULL);
		//ASSERT(Filter != NULL);

		if (buffer == NULL)
		{
			// if there is no such value in the registry, then there are no upper
			// filter drivers loaded, and we can just put one there

			// make room for the string, string null terminator, and multisz null
			// terminator
			length = _tcslen(Filter) + 1;
			size = (length + 1)*sizeof(_TCHAR);
			buffer = (LPTSTR)malloc(size);
			if (buffer == NULL)
			{
				printf("in AddUpperFilterDriver(): unable to allocate memory!\n");
				return (FALSE);
			}
			memset(buffer, 0, size);

			// copy the string into the new buffer

			memcpy(buffer, Filter, length*sizeof(_TCHAR));

		}
		else
		{
			LPTSTR buffer2;
			// remove all instances of filter from driver list
			MultiSzSearchAndDeleteCaseInsensitive(Filter, buffer, &length);

			// allocate a buffer large enough to add the new filter
			// MultiSzLength already includes length of terminating NULL

			// determing the new length of the string
			length = MultiSzLength(buffer) + _tcslen(Filter) + 1;
			size = length*sizeof(_TCHAR);

			buffer2 = (LPTSTR)malloc(size);
			if (buffer2 == NULL) {
				printf("Out of memory adding filter\n");
				return (0);
			}
			memset(buffer2, 0, size);

			// swap the buffers out
			memcpy(buffer2, buffer, MultiSzLength(buffer)*sizeof(_TCHAR));
			free(buffer);
			buffer = buffer2;

			// add the driver to the driver list
			PrependSzToMultiSz(Filter, &buffer);

		}

		// set the new list of filters in place
		if (!SetupDiSetDeviceRegistryProperty(DeviceInfoSet,
			DeviceInfoData,
			(UpperFilter ? SPDRP_UPPERFILTERS : SPDRP_LOWERFILTERS),
			(PBYTE)buffer,
			(DWORD)(MultiSzLength(buffer)*sizeof(_TCHAR)))
			)
		{
			printf("in AddUpperFilterDriver(): "
				"couldn't set registry value! error: %u\n", GetLastError());
			free(buffer);
			return (FALSE);
		}

		// no need for buffer anymore
		free(buffer);

		return (TRUE);
	}
	/*
	* remove all instances of the given filter driver from the list of upper
	* filter drivers for the device.
	*
	* After the call, the device must be restarted in order for the new setting to
	* take effect. This can be accomplished with a call to RestartDevice(), or by
	* rebooting the machine.
	*
	* returns TRUE if successful, FALSE otherwise
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*   Filter - the filter to remove
	*/
	BOOLEAN
		RemoveFilterDriver(
			IN HDEVINFO DeviceInfoSet,
			IN PSP_DEVINFO_DATA DeviceInfoData,
			_In_ IN LPTSTR Filter,
			IN BOOLEAN UpperFilter
			)
	{
		size_t length = 0;
		size_t size = 0;
		LPTSTR buffer = GetFilters(DeviceInfoSet, DeviceInfoData, UpperFilter);
		BOOL   success = FALSE;

//		ASSERT(DeviceInfoData != NULL);
		//ASSERT(Filter != NULL);

		if (buffer == NULL)
		{
			// if there is no such value in the registry, then there are no upper
			// filter drivers loaded, and we are done
			return (TRUE);
		}
		else
		{
			// remove all instances of filter from driver list
			MultiSzSearchAndDeleteCaseInsensitive(Filter, buffer, &length);
		}

		length = MultiSzLength(buffer);

//		ASSERT(length > 0);

		if (length == 1)
		{
			// if the length of the list is 1, the return value from
			// MultiSzLength() was just accounting for the trailing '\0', so we can
			// delete the registry key, by setting it to NULL.
			success = SetupDiSetDeviceRegistryProperty(DeviceInfoSet,
				DeviceInfoData,
				(UpperFilter ? SPDRP_UPPERFILTERS : SPDRP_LOWERFILTERS),
				NULL,
				0);
		}
		else
		{
			// set the new list of drivers into the registry
			size = length*sizeof(_TCHAR);
			success = SetupDiSetDeviceRegistryProperty(DeviceInfoSet,
				DeviceInfoData,
				(UpperFilter ? SPDRP_UPPERFILTERS : SPDRP_LOWERFILTERS),
				(PBYTE)buffer,
				(DWORD)size);
		}

		// no need for buffer anymore
		free(buffer);

		if (!success)
		{
			printf("in RemoveUpperFilterDriver(): "
				"couldn't set registry value! error: %u\n", GetLastError());
			return (FALSE);
		}

		return (TRUE);
	}
	/*
	* restarts the given device
	*
	* call CM_Query_And_Remove_Subtree (to unload the driver)
	* call CM_Reenumerate_DevNode on the _parent_ (to reload the driver)
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*/
	BOOLEAN
		RestartDevice(
			IN HDEVINFO DeviceInfoSet,
			IN OUT PSP_DEVINFO_DATA DeviceInfoData
			)
	{
		SP_PROPCHANGE_PARAMS params;
		SP_DEVINSTALL_PARAMS installParams;

		// for future compatibility; this will zero out the entire struct, rather
		// than just the fields which exist now
		memset(&params, 0, sizeof(SP_PROPCHANGE_PARAMS));

		// initialize the SP_CLASSINSTALL_HEADER struct at the beginning of the
		// SP_PROPCHANGE_PARAMS struct, so that SetupDiSetClassInstallParams will
		// work
		params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
		params.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;

		// initialize SP_PROPCHANGE_PARAMS such that the device will be stopped.
		params.StateChange = DICS_STOP;
		params.Scope = DICS_FLAG_CONFIGSPECIFIC;
		params.HwProfile = 0; // current profile

							  // prepare for the call to SetupDiCallClassInstaller (to stop the device)
		if (!SetupDiSetClassInstallParams(DeviceInfoSet,
			DeviceInfoData,
			(PSP_CLASSINSTALL_HEADER)&params,
			sizeof(SP_PROPCHANGE_PARAMS)
			))
		{
			printf("in RestartDevice(): couldn't set the install parameters!");
			printf(" error: %u\n", GetLastError());
			return (FALSE);
		}

		// stop the device
		if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE,
			DeviceInfoSet,
			DeviceInfoData)
			)
		{
			printf("in RestartDevice(): call to class installer (STOP) failed!");
			printf(" error: %u\n", GetLastError());
			return (FALSE);
		}

		// restarting the device
		params.StateChange = DICS_START;

		// prepare for the call to SetupDiCallClassInstaller (to stop the device)
		if (!SetupDiSetClassInstallParams(DeviceInfoSet,
			DeviceInfoData,
			(PSP_CLASSINSTALL_HEADER)&params,
			sizeof(SP_PROPCHANGE_PARAMS)
			))
		{
			printf("in RestartDevice(): couldn't set the install parameters!");
			printf(" error: %u\n", GetLastError());
			return (FALSE);
		}

		// restart the device
		if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE,
			DeviceInfoSet,
			DeviceInfoData)
			)
		{
			printf("in RestartDevice(): call to class installer (START) failed!");
			printf(" error: %u\n", GetLastError());
			return (FALSE);
		}

		installParams.cbSize = sizeof(SP_DEVINSTALL_PARAMS);

		// same as above, the call will succeed, but we still need to check status
		if (!SetupDiGetDeviceInstallParams(DeviceInfoSet,
			DeviceInfoData,
			&installParams)
			)
		{
			printf("in RestartDevice(): couldn't get the device install params!");
			printf(" error: %u\n", GetLastError());
			return (FALSE);
		}

		// to see if the machine needs to be rebooted
		if (installParams.Flags & DI_NEEDREBOOT)
		{
			return (FALSE);
		}

		// if we get this far, then the device has been stopped and restarted
		return (TRUE);
	}
	/*
	* Returns a buffer containing the list of upper filters for the device. (NULL
	* is returned if there is no buffer, or an error occurs)
	* The buffer must be freed by the caller.
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*/
	LPTSTR
		GetFilters(
			IN HDEVINFO DeviceInfoSet,
			IN PSP_DEVINFO_DATA DeviceInfoData,
			IN BOOLEAN UpperFilters
			)
	{
		DWORD  regDataType;
		LPTSTR buffer = (LPTSTR)GetDeviceRegistryProperty(DeviceInfoSet,
			DeviceInfoData,
			(UpperFilters ? SPDRP_UPPERFILTERS : SPDRP_LOWERFILTERS),
			&regDataType);

		// just to make sure we are getting the expected type of buffer
		if (buffer != NULL && regDataType != REG_MULTI_SZ)
		{
			printf("in GetUpperFilters(): "
				"registry key is not a MULTI_SZ!\n");
			free(buffer);
			return (NULL);
		}

		return (buffer);
	}
	/*
	* A wrapper around SetupDiGetDeviceRegistryProperty, so that I don't have to
	* deal with memory allocation anywhere else
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*   Property       - which property to get (SPDRP_XXX)
	*   PropertyRegDataType - the type of registry property
	*/
	PBYTE
		GetDeviceRegistryProperty(
			IN HDEVINFO DeviceInfoSet,
			IN PSP_DEVINFO_DATA DeviceInfoData,
			IN DWORD Property,
			OUT PDWORD PropertyRegDataType
			)
	{
		DWORD length = 0;
		PBYTE buffer = NULL;

		// get the required length of the buffer
		if (SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
			DeviceInfoData,
			Property,
			NULL,   // registry data type
			NULL,   // buffer
			0,      // buffer size
			&length // required size
			))
		{
			// we should not be successful at this point, so this call succeeding
			// is an error condition
			printf("in GetDeviceRegistryProperty(): "
				"call SetupDiGetDeviceRegistryProperty did not fail? (%x)\n",
				GetLastError());
			return (NULL);
		}

		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			// this means there are no upper filter drivers loaded, so we can just
			// return.
			return (NULL);
		}

		// since we don't have a buffer yet, it is "insufficient"; we allocate
		// one and try again.
		buffer = (PBYTE)malloc(length);
		if (buffer == NULL)
		{
			printf("in GetDeviceRegistryProperty(): "
				"unable to allocate memory!\n");
			return (NULL);
		}
		if (!SetupDiGetDeviceRegistryProperty(DeviceInfoSet,
			DeviceInfoData,
			Property,
			PropertyRegDataType,
			buffer,
			length,
			NULL // required size
			))
		{
			printf("in GetDeviceRegistryProperty(): "
				"couldn't get registry property! error: %u\n",
				GetLastError());
			free(buffer);
			return (NULL);
		}

		// ok, we are finally done, and can return the buffer
		return (buffer);
	}
private:

	/*
	* prepend the given string to a MultiSz
	*
	* returns true if successful, false if not (will only fail in memory
	* allocation)
	*
	* note: This WILL allocate and free memory, so don't keep pointers to the
	* MultiSz passed in.
	*
	* parameters:
	*   SzToPrepend - string to prepend
	*   MultiSz     - pointer to a MultiSz which will be prepended-to
	*/
	BOOLEAN
		PrependSzToMultiSz(
			_In_        LPTSTR  SzToPrepend,
			_Inout_ LPTSTR *MultiSz
			)
	{
		size_t szLen;
		size_t multiSzLen;
		LPTSTR newMultiSz = NULL;

//		ASSERT(SzToPrepend != NULL);
//		ASSERT(MultiSz != NULL);

		if (SzToPrepend == NULL || MultiSz == NULL) {
			return (FALSE);
		}

		// get the size, in bytes, of the two buffers
		szLen = (_tcslen(SzToPrepend) + 1)*sizeof(_TCHAR);
		multiSzLen = MultiSzLength(*MultiSz)*sizeof(_TCHAR);
		newMultiSz = (LPTSTR)malloc(szLen + multiSzLen);

		if (newMultiSz == NULL)
		{
			return (FALSE);
		}

		// recopy the old MultiSz into proper position into the new buffer.
		// the (char*) cast is necessary, because newMultiSz may be a wchar*, and
		// szLen is in bytes.

		memcpy(((char*)newMultiSz) + szLen, *MultiSz, multiSzLen);

		// copy in the new string
		StringCbCopy(newMultiSz, szLen, SzToPrepend);

		free(*MultiSz);
		*MultiSz = newMultiSz;

		return (TRUE);
	}


	/*
	* returns the length (in characters) of the buffer required to hold this
	* MultiSz, INCLUDING the trailing null.
	*
	* example: MultiSzLength("foo\0bar\0") returns 9
	*
	* note: since MultiSz cannot be null, a number >= 1 will always be returned
	*
	* parameters:
	*   MultiSz - the MultiSz to get the length of
	*/
	size_t
		MultiSzLength(
			_In_ IN LPTSTR MultiSz
			)
	{
		size_t len = 0;
		size_t totalLen = 0;

//		ASSERT(MultiSz != NULL);

		// search for trailing null character
		while (*MultiSz != _T('\0'))
		{
			len = _tcslen(MultiSz) + 1;
			MultiSz += len;
			totalLen += len;
		}

		// add one for the trailing null character
		return (totalLen + 1);
	}


	/*
	* Deletes all instances of a string from within a multi-sz.
	*
	* parameters:
	*   FindThis        - the string to find and remove
	*   FindWithin      - the string having the instances removed
	*   NewStringLength - the new string length
	*/
	size_t
		MultiSzSearchAndDeleteCaseInsensitive(
			_In_ IN  LPTSTR FindThis,
			_In_ IN  LPTSTR FindWithin,
			OUT size_t *NewLength
			)
	{
		LPTSTR search;
		size_t currentOffset;
		DWORD  instancesDeleted;
		size_t searchLen;

//		ASSERT(FindThis != NULL);
//		ASSERT(FindWithin != NULL);
//		ASSERT(NewLength != NULL);

		currentOffset = 0;
		instancesDeleted = 0;
		search = FindWithin;

		*NewLength = MultiSzLength(FindWithin);

		// loop while the multisz null terminator is not found
		while (*search != _T('\0'))
		{
			// length of string + null char; used in more than a couple places
			searchLen = _tcslen(search) + 1;

			// if this string matches the current one in the multisz...
			if (_tcsicmp(search, FindThis) == 0)
			{
				// they match, shift the contents of the multisz, to overwrite the
				// string (and terminating null), and update the length
				instancesDeleted++;
				*NewLength -= searchLen;
				memmove(search,
					search + searchLen,
					(*NewLength - currentOffset) * sizeof(TCHAR));
			}
			else
			{
				// they don't mactch, so move pointers, increment counters
				currentOffset += searchLen;
				search += searchLen;
			}
		}

		return (instancesDeleted);
	}
private:
	/*
	* print the device name
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*/
	void PrintDeviceName(
		IN HDEVINFO DeviceInfoSet,
		IN PSP_DEVINFO_DATA DeviceInfoData
		)
	{
		DWORD  regDataType;
		LPTSTR deviceName =
			(LPTSTR)GetDeviceRegistryProperty(DeviceInfoSet,
				DeviceInfoData,
				SPDRP_PHYSICAL_DEVICE_OBJECT_NAME,
				&regDataType);

		if (deviceName != NULL)
		{
			// just to make sure we are getting the expected type of buffer
			if (regDataType != REG_SZ)
			{
				printf("in PrintDeviceName(): registry key is not an SZ!\n");
			}
			else
			{
				// if the device name starts with \Device, cut that off (all
				// devices will start with it, so it is redundant)

				if (_tcsncmp(deviceName, _T("\\Device"), 7) == 0)
				{
					memmove(deviceName,
						deviceName + 7,
						(_tcslen(deviceName) - 6)*sizeof(_TCHAR));
				}

				_tprintf(_T("%s\n"), deviceName);
			}
			free(deviceName);
		}
		else
		{
			printf("in PrintDeviceName(): registry key is NULL! error: %u\n",
				GetLastError());
		}

		return;
	}
	/*
	* print the list of upper filters for the given device
	*
	* parameters:
	*   DeviceInfoSet  - The device information set which contains DeviceInfoData
	*   DeviceInfoData - Information needed to deal with the given device
	*/
	void
		PrintFilters(
			IN HDEVINFO DeviceInfoSet,
			IN PSP_DEVINFO_DATA DeviceInfoData,
			IN BOOLEAN UpperFilters
			)
	{
		// get the list of filters
		LPTSTR buffer = GetFilters(DeviceInfoSet, DeviceInfoData, UpperFilters);
		LPTSTR filterName;
		size_t filterPosition;

		if (buffer == NULL)
		{
			// if there is no such value in the registry, then there are no upper
			// filter drivers loaded
			printf("There are no upper filter drivers loaded for this device.\n");
		}
		else
		{
			// go through the multisz and print out each driver
			filterPosition = 0;
			filterName = buffer;
			while (*filterName != _T('\0'))
			{
				_tprintf(_T("%u: %s\n"), filterPosition, filterName);
				filterName += _tcslen(filterName) + 1;
				filterPosition++;
			}

			// no need for buffer anymore
			free(buffer);
		}

		return;
	}
};

