
#include "Base.h"

extern "C"
{
	DRIVER_INITIALIZE MainDriverEntry;
	DRIVER_UNLOAD UnLoad;
	DRIVER_INITIALIZE DriverEntry;
};

PDRIVER_OBJECT g_pDriverObject = nullptr;

#define STATIC_DRIVER_OBJECT g_pDriverObject
#define CPP_MAIN MainDriverEntry
#define EPILOGUE UnLoad(STATIC_DRIVER_OBJECT);


//---------------------------
//-----   UNINSTALL   -------
//---------------------------
void
OnUnload(
	__in DRIVER_OBJECT* driverObject
	)
{
	UNREFERENCED_PARAMETER(driverObject);
	EPILOGUE
	cc_doexit(0, 0, 0);//call dtors
} // end OnUnload

  //---------------------------
  //------   INSTALL   --------
  //---------------------------
_Use_decl_annotations_
EXTERN_C
NTSTATUS
DriverEntry(
	__in DRIVER_OBJECT* driverObject,
	__in UNICODE_STRING* registryPath
	)
{
	
	cc_init(0);

	driverObject->DriverUnload = reinterpret_cast<DRIVER_UNLOAD*>(OnUnload);
	STATIC_DRIVER_OBJECT = driverObject;
	*(PULONG)((PCHAR)driverObject->DriverSection + 13 * sizeof(void*)) |= 0x20;
	return CPP_MAIN(driverObject, registryPath);
}
