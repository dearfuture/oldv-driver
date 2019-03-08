
#include "Base.h"
#include "Utils.h"
#include "HookX64.h"
#include "ntos_func_def.h"
#include "native_func_def.h"
#include <ntddkbd.h>
//void ProcessNotifyRoutine(
//	int context,
//	PEPROCESS Process,
//	HANDLE ProcessId,
//	PPS_CREATE_NOTIFY_INFO CreateInfo)
//{
//	DBG_PRINT("context = %d\r\n", context);
//	if (CreateInfo != NULL)
//	{
//		DBG_PRINT("CreateProcess ProcessId=%d CurrentThreadId =%d ParentProcessId=%d  %d ParentThreadId=%d ProcessName = %wZ\r\n",
//			ProcessId,
//			PsGetCurrentThreadId(),
//			CreateInfo->ParentProcessId,
//			CreateInfo->CreatingThreadId.UniqueProcess,
//			CreateInfo->CreatingThreadId.UniqueThread,
//			CreateInfo->ImageFileName);
//		if (CreateInfo->CommandLine)
//		{
//			DBG_PRINT("cmd = %wZ\r\n", CreateInfo->CommandLine);
//		}
//		if (CreateInfo->FileObject)
//		{
//			//TODO:可以通过文件FileObject来读文件，然后验证hash
//		}
//	}
//	else
//	{
//		DBG_PRINT("TerminateProcess ProcessId = %d CurrentThreadId= %d\r\n", ProcessId, PsGetCurrentThreadId());
//	}
//}
//class thread_mon
//{
//public:
//	thread_mon()
//	{
//		xx = std::string("hehe");
//	}
//	VOID thread_create_routine(
//		HANDLE ProcessId,
//		HANDLE ThreadId,
//		BOOLEAN Create)
//	{
//		hello();
//		if (Create)
//		{
//			DBG_PRINT("CreateThread ProcessId = %d ThreadId = %d CurrentProcessId = %d CurrentThreadId=%d\r\n",
//				ProcessId,
//				ThreadId,
//				PsGetCurrentProcessId(),
//				PsGetCurrentThreadId());
//		}
//		else
//		{
//			DBG_PRINT("ExitThread ProcessId = %d ThreadId = %d CurrentProcessId = %d CurrentThreadId=%d\r\n",
//				ProcessId,
//				ThreadId,
//				PsGetCurrentProcessId(),
//				PsGetCurrentThreadId());
//		}
//	}
//private:
//	void hello()
//	{
//		static bool print_ok = false;
//		if (!print_ok)
//			DBG_PRINT("hello thread mon %s\r\n", xx.c_str());
//		print_ok = true;
//	}
//	std::string xx;
//};
//thread_mon threadA;
//
//void LoadImageNotifyRoutine(
//	__in_opt PUNICODE_STRING  FullImageName,
//	__in HANDLE  ProcessId,
//	__in PIMAGE_INFO  ImageInfo)
//{
//	PFILE_OBJECT file_object = nullptr;
//	if (ImageInfo->SystemModeImage)
//	{
//		DBG_PRINT("Load Image In System\r\n");
//	}
//	if (FullImageName)
//	{
//		DBG_PRINT("Image %wZ ProcessId %d\r\n", FullImageName, ProcessId);
//	}
//	DBG_PRINT("LoadImageBase %p LoadImageSize %llu\r\n", ImageInfo->ImageBase, ImageInfo->ImageSize);
//	if (ImageInfo->ExtendedInfoPresent)
//	{
//		auto pInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
//		file_object = pInfoEx->FileObject;
//		ObReferenceObject(file_object);
//	}
//	else
//	{
//		//通过打开FullPath
//		// XP环境下， 就需要自己获取FILE_OBJECT对象了
//		OBJECT_ATTRIBUTES oa = { 0 };
//		InitializeObjectAttributes(&oa, FullImageName,
//			/*OBJ_CASE_INSENSITIVE |*/ OBJ_KERNEL_HANDLE, NULL, NULL);
//
//		IO_STATUS_BLOCK iosb = { 0 };
//		HANDLE  FileHandle = NULL;
//		auto ns = ZwOpenFile(&FileHandle,
//			GENERIC_READ | SYNCHRONIZE,
//			&oa, &iosb,
//			FILE_SHARE_READ | FILE_SHARE_DELETE,
//			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
//		if (NT_SUCCESS(ns)) {
//			ns = ObReferenceObjectByHandle(FileHandle,
//				0,
//				*IoFileObjectType,
//				KernelMode,
//				(PVOID *)&file_object,
//				NULL);
//			ZwClose(FileHandle);
//			FileHandle = NULL;
//
//		}
//		else {
//
//			// xp下， 如果路径是\WINDOWS\SYSTEM32\kernel32.dll这样的格式
//			// 就只能通过这种方式才解决了
//
//			__try {
//
//				file_object = CONTAINING_RECORD(FullImageName, FILE_OBJECT, FileName);
//
//				if (file_object->Type != 5) {
//					//FILE_OBJECT的这个值是固定的
//					file_object = nullptr;
//				}
//
//			}
//			__except (EXCEPTION_EXECUTE_HANDLER) {
//
//				file_object = NULL;
//			}
//			if (file_object)
//			{
//				ObReferenceObject(file_object);
//			}
//		}
//	}
//	if (file_object)
//	{
//		//获取完整路径
//		WCHAR szFullPath[MAX_PATH] = { 0 };
//		UNICODE_STRING usPath = { 0 };
//		RtlInitEmptyUnicodeString(&usPath, szFullPath, sizeof(szFullPath));
//		if (ddk::filesystem::get_file_object_full_path(file_object, &usPath))
//		{
//			DBG_PRINT("full path = %wZ\r\n", &usPath);
//		}
//		ObDereferenceObject(file_object);
//	}
//}
//BOOLEAN GetRegistryObjectCompleteName(
//	PUNICODE_STRING pRegistryPath,
//	PUNICODE_STRING pPartialRegistryPath,
//	PVOID pRegistryObject)
//{
//	BOOLEAN foundCompleteName = FALSE;
//	BOOLEAN partial = FALSE;
//	if ((!MmIsAddressValid(pRegistryObject)) ||
//		(pRegistryObject == NULL))
//	{
//		return FALSE;
//	}
//	if (pPartialRegistryPath != NULL)
//	{
//		if ((((pPartialRegistryPath->Buffer[0] == '\\')
//			|| (pPartialRegistryPath->Buffer[0] == '%'))
//			|| ((pPartialRegistryPath->Buffer[0] == 'T')
//				&& (pPartialRegistryPath->Buffer[1] == 'R')
//				&& (pPartialRegistryPath->Buffer[2] == 'Y')
//				&& (pPartialRegistryPath->Buffer[3] == '\\'))))
//		{
//			RtlUnicodeStringCopy(pRegistryPath, pPartialRegistryPath);
//			partial = TRUE;
//			foundCompleteName = TRUE;
//		}
//	}
//	if (!foundCompleteName)
//	{
//		ULONG returnedLength = 0;
//		auto status = ObQueryNameString(pRegistryObject, nullptr, 0, &returnedLength);
//		if (status == STATUS_INFO_LENGTH_MISMATCH)
//		{
//			auto pObjectName = reinterpret_cast<PUNICODE_STRING>(malloc(returnedLength));
//			status = ObQueryNameString(pRegistryObject, (POBJECT_NAME_INFORMATION)pObjectName, returnedLength, &returnedLength);
//			if (NT_SUCCESS(status))
//			{
//				RtlUnicodeStringCopy(pRegistryPath, pObjectName);
//				foundCompleteName = TRUE;
//			}
//			free(pObjectName);
//		}
//	}
//	return foundCompleteName;
//}
//NTSTATUS cmp_callback(
//	PVOID context,
//	PVOID Arg1,
//	PVOID Arg2)
//{
//	UNICODE_STRING registryPath, valueName;
//	PVOID p_valueData = nullptr;
//	registryPath.Length = 0;
//	registryPath.MaximumLength = NTSTRSAFE_UNICODE_STRING_MAX_CCH * sizeof(WCHAR);
//	registryPath.Buffer = new WCHAR[NTSTRSAFE_UNICODE_STRING_MAX_CCH];
//	valueName.Length = 0;
//	valueName.MaximumLength = MAX_PATH * sizeof(WCHAR);
//	valueName.Buffer = new WCHAR[MAX_PATH];
//
//	auto exit_buff_free = std::experimental::make_scope_exit([&]() {
//		if (valueName.Buffer)
//		{
//			delete[] valueName.Buffer;
//		}
//		if (registryPath.Buffer)
//		{
//			delete[] registryPath.Buffer;
//		}
//		if (p_valueData)
//		{
//			free(p_valueData);
//		}
//	});
//	REG_NOTIFY_CLASS opType = (REG_NOTIFY_CLASS)(ULONG_PTR)(Arg1);
//	switch (opType)
//	{
//		//Pre
//	case RegNtPreCreateKeyEx:
//	{
//		auto pInfo = reinterpret_cast<PREG_CREATE_KEY_INFORMATION>(Arg2);
//		if (pInfo->RootObject == NULL)
//			DBG_PRINT("RegNtPreCreateKeyEx %wZ\r\n", pInfo->CompleteName);
//		else
//		{
//			auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->RootObject);
//			if (ok)
//			{
//				if (pInfo->CompleteName->Buffer[0] != L'\\')
//				{
//					RtlAppendUnicodeToString(&registryPath, L"\\");
//					RtlAppendUnicodeStringToString(&registryPath, pInfo->CompleteName);
//				}
//				else
//				{
//					RtlCopyUnicodeString(&registryPath, pInfo->CompleteName);
//				}
//				DBG_PRINT("RegNtPreCreateKeyEx full %wZ\r\n", &registryPath);
//			}
//		}
//	}
//	break;
//	case RegNtPreCreateKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_PRE_CREATE_KEY_INFORMATION>(Arg2);
//		DBG_PRINT("RegNtPreCreateKey %wZ\r\n", pInfo->CompleteName);
//	}
//	break;
//	case RegNtPreOpenKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_PRE_OPEN_KEY_INFORMATION>(Arg2);
//		DBG_PRINT("RegNtPreCreateKey %wZ\r\n", pInfo->CompleteName);
//	}
//	break;
//	case RegNtPreOpenKeyEx:
//	{
//		auto pInfo = reinterpret_cast<PREG_OPEN_KEY_INFORMATION>(Arg2);
//		if (pInfo->RootObject == NULL)
//			DBG_PRINT("RegNtPreOpenKeyEx %wZ\r\n", pInfo->CompleteName);
//		else
//		{
//			auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->RootObject);
//			if (ok)
//			{
//				if (pInfo->CompleteName->Buffer[0] != L'\\')
//				{
//					RtlAppendUnicodeToString(&registryPath, L"\\");
//					RtlAppendUnicodeStringToString(&registryPath, pInfo->CompleteName);
//				}
//				else
//				{
//					RtlCopyUnicodeString(&registryPath, pInfo->CompleteName);
//				}
//				DBG_PRINT("RegNtPreOpenKeyEx full %wZ\r\n", &registryPath);
//			}
//		}
//	}
//	break;
//	case RegNtSetValueKey:
//		//
//	{
//		auto pInfo = reinterpret_cast<PREG_SET_VALUE_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtSetValueKey Key=%wZ Value=%wZ\r\n", &registryPath, pInfo->ValueName);
//			p_valueData = malloc(pInfo->DataSize + 2);
//			if (p_valueData)
//			{
//				RtlZeroBytes(p_valueData, pInfo->DataSize + 2);
//				RtlCopyBytes(p_valueData, pInfo->Data, pInfo->DataSize);
//				if (pInfo->Type == REG_SZ)
//				{
//					DBG_PRINT("value data= %ws\r\n", p_valueData);
//				}
//			}
//		}
//	}
//	break;
//	case RegNtDeleteKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_DELETE_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtDeleteKey %wZ\r\n", &registryPath);
//		}
//	}
//	break;
//	case RegNtDeleteValueKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_DELETE_VALUE_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			//正确情况下应该把ValueName复制出来
//			DBG_PRINT("RegNtDeleteValueKey %wZ value = %wZ\r\n", &registryPath, pInfo->ValueName);
//		}
//	}
//	break;
//	case RegNtEnumerateKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_ENUMERATE_KEY_INFORMATION>(Arg2);
//		//枚举key的操作
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtEnumerateKey %wZ index = %d info_class = %d\r\n", &registryPath, pInfo->Index, pInfo->KeyInformationClass);
//		}
//	}
//	break;
//	case RegNtRenameKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_RENAME_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtRenameKey %wZ newName %wZ\r\n", &registryPath, pInfo->NewName);
//		}
//	}
//	break;
//	case RegNtEnumerateValueKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_ENUMERATE_VALUE_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtEnumerateValueKey %wZ index = %d info_class = %d\r\n", &registryPath, pInfo->Index, pInfo->KeyValueInformationClass);
//		}
//	}
//	break;
//	case RegNtQueryKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_QUERY_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtQueryKey %wZ info_class = %d\r\n", &registryPath, pInfo->KeyInformationClass);
//		}
//	}
//	break;
//	case RegNtQueryValueKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_QUERY_VALUE_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtQueryValueKey %wZ value = %wZ info_class = %d\r\n", &registryPath, pInfo->ValueName, pInfo->KeyValueInformationClass);
//		}
//	}
//	break;
//	case RegNtQueryMultipleValueKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_QUERY_MULTIPLE_VALUE_KEY_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtQueryMultipleValueKey %wZ\r\n", &registryPath);
//			for (auto i = 0ul; i < pInfo->EntryCount; i++)
//			{
//				auto pEntry = &pInfo->ValueEntries[i];
//				DBG_PRINT("RegNtQueryMultipleValueKey Value = %wZ\r\n", pEntry->ValueName);
//			}
//		}
//	}
//	break;
//	case RegNtKeyHandleClose:
//	{
//		auto pInfo = reinterpret_cast<PREG_KEY_HANDLE_CLOSE_INFORMATION>(Arg2);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, pInfo->Object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtKeyHandleClose %wZ\r\n", &registryPath);
//		}
//	}
//	break;
//	//POST
//	case RegNtPostOpenKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_POST_OPEN_KEY_INFORMATION>(Arg2);
//		auto object = reinterpret_cast<PVOID*>(pInfo->Object);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, pInfo->CompleteName, *object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtPostOpenKey %wZ\r\n", &registryPath);
//		}
//	}
//	break;
//	case RegNtPostCreateKey:
//	{
//		auto pInfo = reinterpret_cast<PREG_POST_CREATE_KEY_INFORMATION>(Arg2);
//		auto object = reinterpret_cast<PVOID*>(pInfo->Object);
//		auto ok = GetRegistryObjectCompleteName(&registryPath, pInfo->CompleteName, *object);
//		if (ok)
//		{
//			DBG_PRINT("RegNtPostCreateKey %wZ\r\n", &registryPath);
//		}
//	}
//	break;
//	case RegNtPostCreateKeyEx:
//	{
//		auto pInfo = reinterpret_cast<PREG_POST_OPERATION_INFORMATION>(Arg2);
//		auto object = reinterpret_cast<PVOID*>(pInfo->Object);
//		auto preInfo = reinterpret_cast<PREG_CREATE_KEY_INFORMATION>(pInfo->PreInformation);
//		if (pInfo->Status == STATUS_SUCCESS)
//		{
//			auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, *object);
//			if (ok)
//			{
//				DBG_PRINT("RegNtPostCreateKeyEx %wZ\r\n", &registryPath);
//			}
//		}
//		else
//		{
//			//PreInfo
//			if (preInfo->RootObject == NULL)
//				DBG_PRINT("RegNtPostCreateKeyEx %x %wZ\r\n", pInfo->Status, preInfo->CompleteName);
//			else
//			{
//				auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, preInfo->RootObject);
//				if (ok)
//				{
//					if (preInfo->CompleteName->Buffer[0] != L'\\')
//					{
//						RtlAppendUnicodeToString(&registryPath, L"\\");
//						RtlAppendUnicodeStringToString(&registryPath, preInfo->CompleteName);
//					}
//					else
//					{
//						RtlCopyUnicodeString(&registryPath, preInfo->CompleteName);
//					}
//					DBG_PRINT("RegNtPostCreateKeyEx full %x %wZ\r\n",pInfo->Status, &registryPath);
//				}
//			}
//		}
//	}
//	break;
//	case RegNtPostOpenKeyEx:
//	{
//		auto pInfo = reinterpret_cast<PREG_POST_OPERATION_INFORMATION>(Arg2);
//		auto object = reinterpret_cast<PVOID*>(pInfo->Object);
//		auto preInfo = reinterpret_cast<PREG_OPEN_KEY_INFORMATION>(pInfo->PreInformation);
//		if (pInfo->Status == STATUS_SUCCESS)
//		{
//			auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, *object);
//			if (ok)
//			{
//				DBG_PRINT("RegNtPostOpenKeyEx %wZ\r\n", &registryPath);
//			}
//		}
//		else
//		{
//			//PreInfo
//			if (preInfo->RootObject == NULL)
//				DBG_PRINT("RegNtPostOpenKeyEx %x %wZ\r\n", pInfo->Status, preInfo->CompleteName);
//			else
//			{
//				auto ok = GetRegistryObjectCompleteName(&registryPath, NULL, preInfo->RootObject);
//				if (ok)
//				{
//					if (preInfo->CompleteName->Buffer[0] != L'\\')
//					{
//						RtlAppendUnicodeToString(&registryPath, L"\\");
//						RtlAppendUnicodeStringToString(&registryPath, preInfo->CompleteName);
//					}
//					else
//					{
//						RtlCopyUnicodeString(&registryPath, preInfo->CompleteName);
//					}
//					DBG_PRINT("RegNtPostOpenKeyEx full %x %wZ\r\n",pInfo->Status, &registryPath);
//				}
//			}
//		}
//	}
//	break;
//
//	}
//	return STATUS_SUCCESS;
//}
//VOID
//PowerStateCallback(
//	__in PVOID Argument1,
//	__in PVOID Argument2
//	)
//{
//	//See this https://technet.microsoft.com/zh-cn/ff545534(v=vs.105)
//	if (Argument1 != (PVOID)PO_CB_SYSTEM_STATE_LOCK) {
//		return;
//	}
//
//	if (Argument2 == (PVOID)0)
//	{
//		//退出S0
//		DBG_PRINT("Exit S0\r\n");
//	}
//	else if (Argument2 == (PVOID)1)
//	{
//		//重新进入S0
//		DBG_PRINT("Entre S0\r\n");
//	}
//}
//NTSTATUS disk_callback(PVOID NotificationStructure)
//{
//	auto Notify = reinterpret_cast<PDEVICE_INTERFACE_CHANGE_NOTIFICATION>(NotificationStructure);
//	if (IsEqualGUID(Notify->Event, GUID_DEVICE_INTERFACE_REMOVAL))
//	{
//		DBG_PRINT("Remove Disk %wZ\r\n", Notify->SymbolicLinkName);
//	}
//	if (IsEqualGUID(Notify->Event, GUID_DEVICE_INTERFACE_ARRIVAL))
//	{
//		DBG_PRINT("Arrive Disk %wZ\r\n", Notify->SymbolicLinkName);
//	}
//	//GUID_HWPROFILE_QUERY_CHANGE
//	if (IsEqualGUID(Notify->Event, GUID_HWPROFILE_QUERY_CHANGE)){
//		DBG_PRINT("PHWPROFILE_CHANGE_NOTIFICATION \r\n");
//	}
//
//	//为了安全起见一般都用WorkItem形式做一些操作
//	//PS：：对于ARRIVAL返回STATUS_ACCESS_VIOLATION或者STATUS_ACCESS_DENIED 可以拒绝加载
//	return STATUS_SUCCESS;
//}
//void ProcessPre(POB_PRE_OPERATION_INFORMATION info)
//{
//	switch (info->Operation)
//	{
//	case OB_OPERATION_HANDLE_CREATE:
//		DBG_PRINT("OB_OPERATION_HANDLE_CREATE ProcessId = %d OpenId = %d ACCESS-MASK = %x\r\n",
//			PsGetCurrentProcessId(),
//			PsGetProcessId(reinterpret_cast<PEPROCESS>(info->Object)),
//			info->Parameters->CreateHandleInformation.OriginalDesiredAccess);
//		break;
//	case OB_OPERATION_HANDLE_DUPLICATE:
//		DBG_PRINT("OB_OPERATION_HANDLE_DUPLICATE ProcessId = %d OpenId = %d ACCESS-MASK = %x SourceId = %d TargetId= %d\r\n",
//			PsGetCurrentProcessId(),
//			PsGetProcessId(reinterpret_cast<PEPROCESS>(info->Object)),
//			info->Parameters->DuplicateHandleInformation.OriginalDesiredAccess,
//			PsGetProcessId(reinterpret_cast<PEPROCESS>(info->Parameters->DuplicateHandleInformation.SourceProcess)),
//			PsGetProcessId(reinterpret_cast<PEPROCESS>(info->Parameters->DuplicateHandleInformation.TargetProcess))
//			);
//		break;
//	}
//}
//ddk::nt_callback power_callback;
//ddk::nt_pnp_callback pnp_callback;

T_NtOpenProcess OldNtOpenProcess = nullptr;
NTSTATUS NTAPI OnNtOpenProcess(
	__out PHANDLE ProcessHandle,
	__in ACCESS_MASK DesiredAccess,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt PCLIENT_ID ClientId
	)
{
	auto ns = OldNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
	if (NT_SUCCESS(ns))
	{
		auto hProcess = *ProcessHandle;
		PEPROCESS ProcessObject = nullptr;
		auto ns2 = ObReferenceObjectByHandle(hProcess,
			0,
			*PsProcessType,
			KernelMode,
			reinterpret_cast<PVOID *>(&ProcessObject),
			nullptr);
		if (NT_SUCCESS(ns2))
		{
			auto exp = std::experimental::make_scope_exit([&]() {ObDereferenceObject(ProcessObject); });
			PUNICODE_STRING Image, CurImage;
			ns2 = SeLocateProcessImageName(ProcessObject, &Image);
			if (!NT_SUCCESS(ns2))
			{
				DBG_PRINT("failed get image\r\n");
				return ns;
			}
			ns2 = SeLocateProcessImageName(PsGetCurrentProcess(), &CurImage);
			if (!NT_SUCCESS(ns2))
			{
				DBG_PRINT("failed get curimage\r\n");
				return ns;
			}

			DBG_PRINT("OpenProcess Id = %d Image= %wZ CurProcessId = %d CurImage = %wZ\r\n",
				PsGetProcessId(ProcessObject),
				Image,
				PsGetCurrentProcessId(),
				CurImage);
		}
	}
	return ns;
}
//NTSTATUS onScsiDisk(PDEVICE_OBJECT dev_obj,
//	PIRP Irp)
//{
//	auto drv = hook_disk.get_orig_drv();
//	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
//	DBG_PRINT("Scsi Disk\r\n");
//	return drv->MajorFunction[IrpStack->MajorFunction](dev_obj, Irp);
//}
ddk::nt_irp_hook hook_disk;
NTSTATUS onWriteDisk(PDEVICE_OBJECT dev_obj,
	PIRP Irp)
{
	auto drv = hook_disk.get_orig_drv();
	auto IrpStack = IoGetCurrentIrpStackLocation(Irp);
//	DBG_PRINT("Write Disk\r\n");
	return drv->MajorFunction[IrpStack->MajorFunction](dev_obj, Irp);
}
//////////////////////////////////////////////////////////////////////////
ddk::nt_attach_filter hook_key;
// flags for keyboard status
#define	S_SHIFT				1
#define	S_CAPS				2
#define	S_NUM				4
static int kb_status = S_NUM;
unsigned char asciiTbl[] = {
	0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x08, 0x09,	//normal
	0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x5B, 0x5D, 0x0D, 0x00, 0x61, 0x73,
	0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x7A, 0x78, 0x63, 0x76,
	0x62, 0x6E, 0x6D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E,
	0x00, 0x1B, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x2D, 0x3D, 0x08, 0x09,	//caps
	0x51, 0x57, 0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4F, 0x50, 0x5B, 0x5D, 0x0D, 0x00, 0x41, 0x53,
	0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B, 0x4C, 0x3B, 0x27, 0x60, 0x00, 0x5C, 0x5A, 0x58, 0x43, 0x56,
	0x42, 0x4E, 0x4D, 0x2C, 0x2E, 0x2F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E,
	0x00, 0x1B, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x08, 0x09,	//shift
	0x51, 0x57, 0x45, 0x52, 0x54, 0x59, 0x55, 0x49, 0x4F, 0x50, 0x7B, 0x7D, 0x0D, 0x00, 0x41, 0x53,
	0x44, 0x46, 0x47, 0x48, 0x4A, 0x4B, 0x4C, 0x3A, 0x22, 0x7E, 0x00, 0x7C, 0x5A, 0x58, 0x43, 0x56,
	0x42, 0x4E, 0x4D, 0x3C, 0x3E, 0x3F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E,
	0x00, 0x1B, 0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A, 0x28, 0x29, 0x5F, 0x2B, 0x08, 0x09,	//caps + shift
	0x71, 0x77, 0x65, 0x72, 0x74, 0x79, 0x75, 0x69, 0x6F, 0x70, 0x7B, 0x7D, 0x0D, 0x00, 0x61, 0x73,
	0x64, 0x66, 0x67, 0x68, 0x6A, 0x6B, 0x6C, 0x3A, 0x22, 0x7E, 0x00, 0x7C, 0x7A, 0x78, 0x63, 0x76,
	0x62, 0x6E, 0x6D, 0x3C, 0x3E, 0x3F, 0x00, 0x2A, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x38, 0x39, 0x2D, 0x34, 0x35, 0x36, 0x2B, 0x31,
	0x32, 0x33, 0x30, 0x2E
};
void __stdcall print_keystroke(UCHAR sch)
{
	UCHAR	ch = 0;
	int		off = 0;

	if ((sch & 0x80) == 0)	//make
	{
		if ((sch < 0x47) ||
			((sch >= 0x47 && sch < 0x54) && (kb_status & S_NUM))) // Num Lock
		{
			ch = asciiTbl[off + sch];
		}

		switch (sch)
		{
		case 0x3A:
			kb_status ^= S_CAPS;
			break;

		case 0x2A:
		case 0x36:
			kb_status |= S_SHIFT;
			break;

		case 0x45:
			kb_status ^= S_NUM;
		}
	}
	else		//break
	{
		if (sch == 0xAA || sch == 0xB6)
			kb_status &= ~S_SHIFT;
	}

	if (ch >= 0x20 && ch < 0x7F)
	{
		DBG_PRINT("%C \n", ch);
	}

}
NTSTATUS KeyReadComplete(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp,
	IN PVOID Context
	)
{
	//auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
	if (NT_SUCCESS(Irp->IoStatus.Status))
	{
		auto buf = reinterpret_cast<PUCHAR>(Irp->AssociatedIrp.SystemBuffer);
		auto buf_len = Irp->IoStatus.Information;
		auto KeyData = reinterpret_cast<PKEYBOARD_INPUT_DATA>(buf);
		auto numKeys = buf_len / sizeof(KEYBOARD_INPUT_DATA);
		for (auto i = 0UL; i < numKeys; ++i)
		{
			
			DBG_PRINT("\n");
			DBG_PRINT("numKeys : %d", numKeys);
			DBG_PRINT("ScanCode: %x ", KeyData->MakeCode);
			DBG_PRINT("%s\n", KeyData->Flags ? "Up" : "Down");
			print_keystroke((UCHAR)KeyData->MakeCode);
		}
	}
	hook_key.release();
	if (Irp->PendingReturned)
	{
		IoMarkIrpPending(Irp);
	}
	return Irp->IoStatus.Status;
}
NTSTATUS OnKeyRead(PDEVICE_OBJECT LwDev, PDEVICE_OBJECT Object, PIRP Irp)
{
	KEVENT waitEvent;
	KeInitializeEvent(&waitEvent, NotificationEvent, FALSE);

	if (Irp->CurrentLocation == 1)
	{
		ULONG ReturnedInformation = 0;
		auto status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Status = status;
		Irp->IoStatus.Information = ReturnedInformation;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		return status;
	}
	hook_key.acquire();
	auto currentIrpStack = IoGetCurrentIrpStackLocation(Irp);
	IoCopyCurrentIrpStackLocationToNext(Irp);
	IoSetCompletionRoutine(Irp, KeyReadComplete,
		Object, TRUE, TRUE, TRUE);
	return  IoCallDriver(LwDev, Irp);
}
//////////////////////////////////////////////////////////////////////////
void test_util(PUNICODE_STRING RegistryPath)
{
	/*ddk::nt_process_callback::getInstance().reg_callback_ex(std::bind(&ProcessNotifyRoutine, 0x1111,
		std::placeholders::_1,
		std::placeholders::_2,
		std::placeholders::_3));
	ddk::nt_thread_callback::getInstance().reg_callback(std::bind(&thread_mon::thread_create_routine,
		&threadA,
		std::placeholders::_1,
		std::placeholders::_2,
		std::placeholders::_3));
	ddk::nt_image_callback::getInstance().reg_callback(LoadImageNotifyRoutine);
	ddk::nt_regcmp_callback::getInstance().reg_callback(cmp_callback);
*/
	//power_callback.open(L"\\Callback\\PowerState");
	//power_callback.set_callback(PowerStateCallback);
	//pnp_callback.create_callback(ddk::nt_pnp_callback::nt_pnp_callback_class::VOLUME);
	//pnp_callback.set_callback(disk_callback);

	//ddk::nt_object_callback::getInstance().set_process_pre_callback(ProcessPre);
	//
	//ddk::nt_irp_hook::getInstance().hook_device(L"\\Device\\Harddisk0\\DR0");

	hook_disk.set_irp_callback(IRP_MJ_WRITE, onWriteDisk);
//	hook_disk.hook_driver(L"\\FileSystem\\Ntfs");
	hook_disk.hook_driver(L"\\Driver\\Disk");

	ddk::snapshot::driver_info_list_type _list;
	ddk::snapshot::nt_driver_snapshot::getInstance().get_all_driver_object(_list);
	for (auto info:_list)
	{
		DBG_PRINT("driverobject %ws %p\r\n", info.driver_name.c_str(), info.driver_object);
	}

	ddk::snapshot::nt_object_types::getInstance().print_all();

	hook_key.set_callback(IRP_MJ_READ, OnKeyRead);
	hook_key.attach_driver(L"\\Driver\\Kbdclass");
	//CHookX64::instance().hook_syscall(std::string("ZwOpenProcess"), PVOID(OnNtOpenProcess), reinterpret_cast<PVOID *>(&OldNtOpenProcess));
}

void test_util_free()
{
	hook_disk.unhook();
}